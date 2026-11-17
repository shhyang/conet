//! UDP-LI endpoint: profile queues, scheduling, and datagram demux.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use conet_core::{
    AppliedDecision, ControlDisposition, ControlMessage, ControlType, DiscreteRatePacer,
    EnqueueError, EnqueueErrorKind, EnqueueStatus, Feedback, FixedRateController, HeaderBuf,
    MonoNs, Observation, OpaqueBytes, PacketBuilder, PacketHandle, PacketQueue, QosClass,
    QueueLimits, RateControlPolicy, ReferenceWireCodec, RxController, TxController, WireError,
    WireHeader,
};

use crate::association::{AssociationError, AssociationState, Role};
use crate::scheduler::{ControlWindow, SchedulerConfig, SendClass};
use crate::transport::{DatagramTransport, InboundDatagram, WireIoStats};

const WIRE_HEADER_LEN: usize = conet_core::REFERENCE_WIRE_HEADER_LEN;
const CC_PREFIX_LEN: usize = 1;

/// Profile configuration. Security remains fail-closed by default.
#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub role: Role,
    pub target_rate: u64,
    pub max_datagram: usize,
    pub max_piggyback: usize,
    pub max_control_body: usize,
    /// Explicit test-only override for association and probe-hint
    /// authenticity. CC controller input remains fail-closed. Production
    /// profiles leave this false.
    pub allow_unauthenticated_cc: bool,
    pub scheduler: SchedulerConfig,
    pub link_control_limits: QueueLimits,
    pub feedback_limits: QueueLimits,
    pub file_data_limits: QueueLimits,
    pub inbound_limit: usize,
    /// Start of the local diagnostic association-ID sequence; never serialized.
    pub initial_association_id: u32,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::new(Role::Initiator, 1_000_000)
    }
}

impl EndpointConfig {
    pub fn new(role: Role, target_rate: u64) -> Self {
        let max_datagram = 1280;
        let packet_max = max_datagram - WIRE_HEADER_LEN;
        Self {
            role,
            target_rate,
            max_datagram,
            max_piggyback: 256,
            max_control_body: 256,
            allow_unauthenticated_cc: false,
            scheduler: SchedulerConfig::default(),
            link_control_limits: QueueLimits::new(32, 32 * 1024, 32 * 1024)
                .with_max_packet_bytes(packet_max),
            feedback_limits: QueueLimits::new(16, 32 * 1024, 32 * 1024)
                .with_max_packet_bytes(packet_max),
            file_data_limits: QueueLimits::new(256, 512 * 1024, 512 * 1024)
                .with_max_packet_bytes(packet_max),
            inbound_limit: 256,
            initial_association_id: 1,
        }
    }

    /// Explicit test-only override. Production profiles leave this false.
    pub fn test_open(mut self) -> Self {
        self.allow_unauthenticated_cc = true;
        self
    }
}

/// Profile enqueue/admission error. Every variant retains the caller's handle.
#[derive(Debug)]
pub enum ProfileEnqueueError {
    Closed {
        pkt: PacketHandle,
    },
    Queue(EnqueueError),
    DatagramTooLarge {
        pkt: PacketHandle,
        len: usize,
        max: usize,
    },
    ControlBodyTooLarge {
        pkt: PacketHandle,
        len: usize,
        max: usize,
    },
}

impl ProfileEnqueueError {
    pub fn kind(&self) -> ProfileEnqueueErrorKind {
        match self {
            Self::Closed { .. } => ProfileEnqueueErrorKind::Closed,
            Self::Queue(error) => ProfileEnqueueErrorKind::Queue(error.kind()),
            Self::DatagramTooLarge { .. } => ProfileEnqueueErrorKind::DatagramTooLarge,
            Self::ControlBodyTooLarge { .. } => ProfileEnqueueErrorKind::ControlBodyTooLarge,
        }
    }

    pub fn packet(&self) -> &PacketHandle {
        match self {
            Self::Closed { pkt } => pkt,
            Self::Queue(error) => error.packet(),
            Self::DatagramTooLarge { pkt, .. } | Self::ControlBodyTooLarge { pkt, .. } => pkt,
        }
    }

    pub fn into_packet(self) -> PacketHandle {
        match self {
            Self::Closed { pkt } => pkt,
            Self::Queue(error) => error.into_packet(),
            Self::DatagramTooLarge { pkt, .. } | Self::ControlBodyTooLarge { pkt, .. } => pkt,
        }
    }
}

/// Non-owning failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileEnqueueErrorKind {
    Closed,
    Queue(EnqueueErrorKind),
    DatagramTooLarge,
    ControlBodyTooLarge,
}

impl std::fmt::Display for ProfileEnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed { .. } => f.write_str("UDP-LI endpoint is closed"),
            Self::Queue(error) => error.fmt(f),
            Self::DatagramTooLarge { len, max, .. } => {
                write!(f, "UDP payload length {len} exceeds profile maximum {max}")
            }
            Self::ControlBodyTooLarge { len, max, .. } => {
                write!(f, "control body length {len} exceeds profile maximum {max}")
            }
        }
    }
}

impl std::error::Error for ProfileEnqueueError {}

pub type UdpLiEnqueueStatus = EnqueueStatus;

/// One successful socket-boundary send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentDatagram {
    pub at: MonoNs,
    pub bytes: usize,
    pub class: SendClass,
    pub link_seq: u32,
    pub ready_at: MonoNs,
}

/// Explicit result of one local datagram send attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalSendOutcome {
    /// The transport completed a full local write. Only this outcome consumes
    /// a link sequence and updates sent/controller/pacer accounting.
    Accepted,
    /// The socket could not accept the write due to local backpressure. The
    /// front item remains queued with its provisional sequence cleared.
    WouldBlock,
    /// A transient ICMP/unreachable error rejected the write. The attempted
    /// datagram is dropped locally and is not retried by the link.
    TransientDrop,
    /// A local syscall was interrupted before socket acceptance. The front
    /// item remains queued for a later attempt.
    Interrupted,
    /// A hard serialization, configuration, socket, or I/O error.
    Fatal,
}

/// One validated datagram delivered upward.
#[derive(Debug)]
pub struct ReceivedDatagram {
    pub recv_ts: MonoNs,
    pub boundary_len: usize,
    pub class: QosClass,
    pub packet: PacketHandle,
    pub header: WireHeader,
    pub control: Option<ControlMessage>,
}

/// Result of one explicit `drive(now)` call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DriveReport {
    pub sent: usize,
    pub received: usize,
    pub dropped: usize,
    /// The final local send attempt in this drive did not write successfully.
    pub send_failed: bool,
    /// A local send hit backpressure; the front item remains queued and was
    /// not reported to the controller or transfer accounting as sent.
    pub send_would_block: bool,
    /// Explicit classification of the final local send attempt.
    pub send_outcome: Option<LocalSendOutcome>,
    pub clock_discontinuity: bool,
    /// Transport-near counters observed when this drive completed.
    pub wire_io: WireIoStats,
    /// The TX controller's next hook deadline after this drive completed.
    pub next_wakeup: Option<MonoNs>,
}

#[derive(Clone, Copy, Debug)]
enum ControlSpec {
    Cc { ctrl_type: ControlType },
}

impl ControlSpec {
    const fn ctrl_type(self) -> ControlType {
        match self {
            Self::Cc { ctrl_type } => ctrl_type,
        }
    }

    const fn prefix_len(self) -> usize {
        match self {
            Self::Cc { .. } => CC_PREFIX_LEN,
        }
    }
}

struct ProfileQueue {
    queue: PacketQueue,
    metadata: VecDeque<Option<ControlSpec>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendStep {
    Sent,
    CapBlocked,
    WouldBlock,
    TransientDrop,
    Interrupted,
    Failed,
}

impl ProfileQueue {
    fn new(limits: QueueLimits) -> Self {
        Self {
            queue: PacketQueue::new(limits),
            metadata: VecDeque::new(),
        }
    }

    fn enqueue(
        &mut self,
        pkt: PacketHandle,
        control: Option<ControlSpec>,
    ) -> Result<EnqueueStatus, EnqueueError> {
        let status = self.queue.enqueue(pkt)?;
        self.metadata.push_back(control);
        Ok(status)
    }

    fn front(&self) -> Option<(&PacketHandle, Option<ControlSpec>)> {
        Some((self.queue.front()?, *self.metadata.front()?))
    }

    fn front_header_mut(&mut self) -> Option<(&mut HeaderBuf, Option<ControlSpec>)> {
        let control = *self.metadata.front()?;
        Some((self.queue.front_header_mut()?, control))
    }

    fn pop(&mut self) -> Option<PacketHandle> {
        self.metadata.pop_front();
        self.queue.dequeue()
    }

    fn clear(&mut self) -> usize {
        let count = self.queue.len();
        while self.pop().is_some() {}
        count
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn occupancy(&self) -> conet_core::Occupancy {
        self.queue.occupancy()
    }
}

/// One UDP-LI attachment over a datagram boundary.
pub struct UdpLiEndpoint<T: DatagramTransport> {
    transport: T,
    config: EndpointConfig,
    wire: ReferenceWireCodec,
    association: AssociationState,
    association_id: Option<u32>,
    epoch: u16,
    next_association_id: u32,
    next_link_seq: u32,
    link_control_queue: ProfileQueue,
    feedback_queue: ProfileQueue,
    file_queue: ProfileQueue,
    pacer: DiscreteRatePacer,
    inflight_limit_bytes: Option<u64>,
    control_window: ControlWindow,
    consecutive_non_file: u8,
    controller: Box<dyn TxController>,
    rx_controller: Option<Box<dyn RxController>>,
    pending_tx_control: Option<OpaqueBytes>,
    pending_rx_control: Option<OpaqueBytes>,
    sent: Vec<SentDatagram>,
    observations: Vec<Observation>,
    received: VecDeque<ReceivedDatagram>,
    drops: std::collections::BTreeMap<&'static str, u64>,
    cancelled: usize,
    last_now: Option<MonoNs>,
    wire_io: WireIoStats,
    send_scratch: Vec<u8>,
    receive_scratch: Vec<InboundDatagram>,
}

impl<T: DatagramTransport> UdpLiEndpoint<T> {
    pub fn new(transport: T, config: EndpointConfig) -> Self {
        let target_rate = config.target_rate;
        Self::with_controllers(
            transport,
            config,
            Box::new(FixedRateController::new(target_rate)) as Box<dyn TxController>,
            None,
        )
    }

    pub fn with_controllers(
        transport: T,
        config: EndpointConfig,
        tx_controller: Box<dyn TxController>,
        rx_controller: Option<Box<dyn RxController>>,
    ) -> Self {
        let initial_association_id = config.initial_association_id;
        let wire = ReferenceWireCodec::new(conet_core::WireLimits {
            max_datagram: config.max_datagram,
            max_control_body: config.max_control_body,
        });
        let pacer = DiscreteRatePacer::new(config.target_rate);
        let send_scratch = Vec::with_capacity(config.max_datagram);
        let receive_scratch = Vec::with_capacity(config.inbound_limit);
        Self {
            transport,
            link_control_queue: ProfileQueue::new(config.link_control_limits),
            feedback_queue: ProfileQueue::new(config.feedback_limits),
            file_queue: ProfileQueue::new(config.file_data_limits),
            next_association_id: config.initial_association_id.wrapping_add(1).max(1),
            config,
            wire,
            association: AssociationState::Ready,
            association_id: Some(initial_association_id.max(1)),
            epoch: 1,
            next_link_seq: 0,
            pacer,
            inflight_limit_bytes: None,
            control_window: ControlWindow::default(),
            consecutive_non_file: 0,
            controller: tx_controller,
            rx_controller,
            pending_tx_control: None,
            pending_rx_control: None,
            sent: Vec::new(),
            observations: Vec::new(),
            received: VecDeque::new(),
            drops: std::collections::BTreeMap::new(),
            cancelled: 0,
            last_now: None,
            wire_io: WireIoStats::default(),
            send_scratch,
            receive_scratch,
        }
    }

    pub const fn state(&self) -> AssociationState {
        self.association
    }

    /// Local diagnostic identity; it is not part of the wire header or peer key.
    pub const fn association_id(&self) -> Option<u32> {
        self.association_id
    }

    pub const fn epoch(&self) -> u16 {
        self.epoch
    }

    pub const fn next_link_seq(&self) -> u32 {
        self.next_link_seq
    }

    pub const fn config(&self) -> &EndpointConfig {
        &self.config
    }

    pub fn target_rate(&self) -> u64 {
        conet_core::RatePacer::target_rate(&self.pacer)
    }

    pub fn ready_at(&self) -> MonoNs {
        conet_core::RatePacer::ready_at(&self.pacer)
    }

    /// The TX controller's currently armed hook wakeup, if any.
    pub fn next_wakeup(&self) -> Option<MonoNs> {
        self.controller.next_wakeup()
    }

    /// Earliest time this endpoint may have useful drive work.
    ///
    /// This aggregates the TX and RX controller hooks and a waiting pacer. It
    /// deliberately does not alter
    /// [`Self::next_wakeup`], which remains the TX controller hook only.
    /// Transport keepalive / challenge wakeups are wall-clock and are applied
    /// in [`Self::drive_when_ready_with_timeout`] via
    /// [`DatagramTransport::next_io_wake`].
    pub fn next_drive(&self) -> Option<MonoNs> {
        let now = self.last_now.unwrap_or(MonoNs::ZERO);
        let mut deadline = self.controller.next_wakeup();
        if let Some(rx_deadline) = self
            .rx_controller
            .as_ref()
            .and_then(|controller| controller.next_wakeup())
        {
            deadline = earliest(deadline, Some(rx_deadline));
        }
        if self.send_waiting(now) {
            deadline = earliest(deadline, Some(self.ready_at()));
        }
        deadline
    }

    /// Wait for inbound socket readiness or the aggregate next-drive deadline,
    /// then call [`Self::drive`] exactly once at the observed time.
    ///
    /// The caller supplies the injected clock so the endpoint retains its
    /// no-wall-clock-in-protocol-state contract. Supported transports wake
    /// early when a datagram arrives, even while the pacer or a controller
    /// deadline is further in the future.
    pub fn drive_when_ready(&mut self, mut now: impl FnMut() -> MonoNs) -> io::Result<DriveReport> {
        self.drive_when_ready_with_timeout(&mut now, None)
    }

    /// Wait for inbound readiness, a drive deadline, or a caller-supplied cap.
    ///
    /// The cap bounds a wait when [`Self::next_drive`] has no deadline. It
    /// does not synthesize or change a protocol deadline; an expired cap simply
    /// samples the injected clock and performs one ordinary drive.
    pub fn drive_when_ready_with_timeout(
        &mut self,
        mut now: impl FnMut() -> MonoNs,
        max_wait: Option<Duration>,
    ) -> io::Result<DriveReport> {
        let current = now();
        let deadline = self.next_drive();
        let io_wake = self.transport.next_io_wake();
        if deadline.is_some_and(|deadline| deadline <= current)
            || io_wake.is_some_and(|wait| wait.is_zero())
        {
            return Ok(self.drive(current));
        }

        let deadline_wait = deadline.map(|deadline| {
            let nanos = deadline.as_nanos().saturating_sub(current.as_nanos());
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        });
        let timeout = match (deadline_wait, max_wait, io_wake) {
            (Some(a), Some(b), Some(c)) => Some(a.min(b).min(c)),
            (Some(a), Some(b), None) => Some(a.min(b)),
            (Some(a), None, Some(c)) => Some(a.min(c)),
            (None, Some(b), Some(c)) => Some(b.min(c)),
            (Some(a), None, None) => Some(a),
            (None, Some(b), None) => Some(b),
            (None, None, Some(c)) => Some(c),
            (None, None, None) => None,
        };
        let inbound_ready = self.transport.wait_readable(timeout)?;
        let drive_at = if inbound_ready
            || deadline_wait.is_some_and(|wait| max_wait.is_some_and(|max_wait| max_wait < wait))
            || io_wake.is_some()
        {
            now()
        } else {
            deadline.unwrap_or_else(|| now())
        };
        Ok(self.drive(drive_at))
    }

    /// The controller's currently accepted inflight/window cap.
    ///
    /// The cap is enforced immediately before a bulk data `sendto`, while the
    /// packet remains queued on backpressure. Control and reliability-feedback
    /// datagrams bypass the data cap so acknowledgement progress can continue.
    pub const fn inflight_limit_bytes(&self) -> Option<u64> {
        self.inflight_limit_bytes
    }

    /// Current controller-reported data inflight sample, when available.
    pub fn controller_inflight_bytes(&self) -> Option<u64> {
        self.controller.inflight_bytes()
    }

    pub fn sent(&self) -> &[SentDatagram] {
        &self.sent
    }

    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    pub fn take_received(&mut self) -> Vec<ReceivedDatagram> {
        self.received.drain(..).collect()
    }

    pub fn received_len(&self) -> usize {
        self.received.len()
    }

    pub fn drop_count(&self, reason: &'static str) -> u64 {
        self.drops.get(reason).copied().unwrap_or(0)
    }

    pub fn drops(&self) -> &std::collections::BTreeMap<&'static str, u64> {
        &self.drops
    }

    /// Transport-near counters accumulated by this endpoint.
    pub fn wire_io_stats(&self) -> WireIoStats {
        self.wire_io.merge(self.transport.io_stats())
    }

    pub const fn cancelled_packets(&self) -> usize {
        self.cancelled
    }

    pub fn queued(&self, class: SendClass) -> usize {
        self.queue(class).len()
    }

    pub fn queue_occupancy(&self, class: SendClass) -> conet_core::Occupancy {
        self.queue(class).occupancy()
    }

    /// Diagnostic access to the queued exclusive transmit header.
    pub fn queued_front_header(&self, class: SendClass) -> Option<&[u8]> {
        self.queue(class)
            .front()
            .map(|(packet, _)| packet.header().as_bytes())
    }

    /// Reset the local datagram epoch and diagnostic ID.
    ///
    /// This sends no setup datagram; transmission is available before and
    /// after the reset.
    pub fn start_association(&mut self) -> Result<(), AssociationError> {
        if self.config.role != Role::Initiator {
            return Err(AssociationError::WrongState {
                state: self.association,
            });
        }
        self.cancel_profile_queues();
        self.association_id = Some(self.allocate_association_id());
        self.epoch = 1;
        self.next_link_seq = 0;
        self.association = AssociationState::Ready;
        self.transport.set_emit_controls(true);
        Ok(())
    }

    /// Legacy test helper for selecting a fixed local epoch.
    ///
    /// It performs no setup exchange and does not gate datagrams; newer tests
    /// use the default ready state directly.
    #[doc(hidden)]
    pub fn establish_for_test(
        &mut self,
        association_id: u32,
        epoch: u16,
    ) -> Result<(), AssociationError> {
        if epoch == 0 {
            return Err(AssociationError::WrongState {
                state: self.association,
            });
        }
        self.association_id = Some(association_id);
        self.epoch = epoch;
        self.next_link_seq = 0;
        self.association = AssociationState::Ready;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), AssociationError> {
        if self.association.is_closed() {
            return Err(AssociationError::WrongState {
                state: self.association,
            });
        }
        self.cancel_profile_queues();
        self.association = AssociationState::Closed;
        // Receive may still drain, but must not emit keepalives / challenge replies.
        self.transport.set_emit_controls(false);
        Ok(())
    }

    /// In-place restart: bump epoch, reset this direction's link sequence,
    /// cancel queued reliability users, and retain the association binding.
    ///
    /// Validated UDP peer bindings survive. In-flight path challenges are
    /// invalidated so a delayed prior-epoch response cannot redirect the new
    /// epoch.
    pub fn restart(&mut self) -> Result<u16, AssociationError> {
        if !self.association.is_ready() {
            return Err(AssociationError::WrongState {
                state: self.association,
            });
        }
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or(AssociationError::WrongState {
                state: self.association,
            })?;
        self.next_link_seq = 0;
        self.cancel_profile_queues();
        self.consecutive_non_file = 0;
        self.controller.restart();
        if let Some(controller) = self.rx_controller.as_mut() {
            controller.restart();
        }
        self.transport.on_association_restart();
        self.apply_controller_pace(RateControlPolicy::authenticated());
        Ok(self.epoch)
    }

    pub fn enqueue_file_data(
        &mut self,
        pkt: PacketHandle,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        if !self.association.is_ready() {
            return Err(ProfileEnqueueError::Closed { pkt });
        }
        self.enqueue_user_class(SendClass::FileData, pkt, None)
    }

    pub fn enqueue_feedback(
        &mut self,
        pkt: PacketHandle,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        if !self.association.is_ready() {
            return Err(ProfileEnqueueError::Closed { pkt });
        }
        self.enqueue_user_class(SendClass::Feedback, pkt, None)
    }

    pub fn enqueue_feedback_value(
        &mut self,
        feedback: Feedback,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        let body = conet_core::encode_reliability_feedback(feedback);
        self.enqueue_feedback(bytes_packet(body.into(), WIRE_HEADER_LEN))
    }

    /// Standalone opaque controller body. It remains uninterpreted by the link.
    pub fn enqueue_link_control(
        &mut self,
        body: OpaqueBytes,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        self.enqueue_cc_body(SendClass::LinkControl, ControlType::CcOpaque, body)
    }

    pub fn drive(&mut self, now: MonoNs) -> DriveReport {
        let mut report = DriveReport::default();
        let sent_before = self.sent.len();
        if self.last_now.is_some_and(|previous| now < previous) {
            report.clock_discontinuity = true;
            let rate = self.target_rate();
            self.pacer = DiscreteRatePacer::new(rate);
        }
        self.last_now = Some(now);

        // Closed endpoints still drain inbound (and drop it) so callers can
        // observe peer close, but they never enqueue or emit further datagrams.
        if self.association.is_ready() {
            // UL-4: transport-level NAT keepalives (outside the 10% control budget).
            let _ = self.transport.drive_keepalive();

            self.controller.on_clock(now);
            self.apply_controller_pace(RateControlPolicy::authenticated());
            self.poll_controller_control(now);
            self.poll_rx_control(now);

            while self.pace_ready(now) {
                let Some(class) = self.select_class(now) else {
                    break;
                };
                match self.send_one(now, class, &mut report) {
                    SendStep::Sent => {}
                    SendStep::CapBlocked => continue,
                    SendStep::WouldBlock
                    | SendStep::TransientDrop
                    | SendStep::Interrupted
                    | SendStep::Failed => break,
                }
            }
        }

        while self.received.len() < self.config.inbound_limit {
            let max = self.config.inbound_limit - self.received.len();
            let received = match self.transport.recv_batch(
                now,
                &mut self.receive_scratch,
                max,
                &mut self.wire_io,
            ) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            };
            if received == 0 {
                break;
            }
            report.received += received;
            let mut batch = std::mem::take(&mut self.receive_scratch);
            for datagram in batch.drain(..) {
                if !self.receive_datagram(now, datagram) {
                    report.dropped += 1;
                }
            }
            self.receive_scratch = batch;
        }
        self.poll_rx_control(now);
        report.sent = self.sent.len() - sent_before;
        report.next_wakeup = self.next_wakeup();
        report.wire_io = self.wire_io_stats();
        report
    }

    fn allocate_association_id(&mut self) -> u32 {
        let id = self.next_association_id;
        self.next_association_id = self.next_association_id.wrapping_add(1).max(1);
        id.max(1)
    }

    fn cancel_profile_queues(&mut self) -> usize {
        self.pending_tx_control = None;
        self.pending_rx_control = None;
        let cancelled =
            self.file_queue.clear() + self.feedback_queue.clear() + self.link_control_queue.clear();
        self.cancelled = self.cancelled.saturating_add(cancelled);
        cancelled
    }

    fn queue(&self, class: SendClass) -> &ProfileQueue {
        match class {
            SendClass::LinkControl => &self.link_control_queue,
            SendClass::Feedback => &self.feedback_queue,
            SendClass::FileData => &self.file_queue,
        }
    }

    fn queue_mut(&mut self, class: SendClass) -> &mut ProfileQueue {
        match class {
            SendClass::LinkControl => &mut self.link_control_queue,
            SendClass::Feedback => &mut self.feedback_queue,
            SendClass::FileData => &mut self.file_queue,
        }
    }

    fn queue_and_send_scratch_mut(
        &mut self,
        class: SendClass,
    ) -> (&mut ProfileQueue, &mut Vec<u8>) {
        let queue = match class {
            SendClass::LinkControl => &mut self.link_control_queue,
            SendClass::Feedback => &mut self.feedback_queue,
            SendClass::FileData => &mut self.file_queue,
        };
        (queue, &mut self.send_scratch)
    }

    fn pace_ready(&self, now: MonoNs) -> bool {
        self.target_rate() > 0 && now >= self.ready_at()
    }

    fn poll_controller_control(&mut self, now: MonoNs) {
        let Some(body) = self.controller.poll_control(now) else {
            return;
        };
        if self.pending_tx_control.as_ref() == Some(&body) {
            return;
        }
        if self.enqueue_link_control(body.clone()).is_ok() {
            self.pending_tx_control = Some(body);
        }
    }

    fn poll_rx_control(&mut self, now: MonoNs) {
        let Some(body) = self
            .rx_controller
            .as_mut()
            .and_then(|controller| controller.poll_control(now))
        else {
            return;
        };
        if self.pending_rx_control.as_ref() == Some(&body) {
            return;
        }
        if self.enqueue_link_control(body.clone()).is_ok() {
            self.pending_rx_control = Some(body);
        }
    }

    fn select_class(&mut self, now: MonoNs) -> Option<SendClass> {
        let data_waiting = !self.file_queue.is_empty() && !self.data_blocked_by_inflight_cap(now);
        if data_waiting
            && self.consecutive_non_file >= self.config.scheduler.max_consecutive_non_file
        {
            return Some(SendClass::FileData);
        }
        let feedback_waiting = !self.feedback_queue.is_empty();
        let control_waiting = !self.link_control_queue.is_empty();
        if control_waiting {
            if feedback_waiting && self.can_piggyback(now, SendClass::Feedback) {
                return Some(SendClass::Feedback);
            }
            if data_waiting && self.can_piggyback(now, SendClass::FileData) {
                return Some(SendClass::FileData);
            }
            if self.can_send_standalone_control(now) {
                return Some(SendClass::LinkControl);
            }
        }
        if feedback_waiting {
            return Some(SendClass::Feedback);
        }
        data_waiting.then_some(SendClass::FileData)
    }

    fn data_blocked_by_inflight_cap(&self, now: MonoNs) -> bool {
        match (self.inflight_limit_bytes, self.controller.inflight_bytes()) {
            (Some(cap), Some(inflight)) => self
                .planned_frame_len(now, SendClass::FileData)
                .is_some_and(|frame_len| {
                    u64::try_from(frame_len)
                        .map_or(true, |frame_len| inflight.saturating_add(frame_len) > cap)
                }),
            _ => false,
        }
    }

    fn send_waiting(&self, now: MonoNs) -> bool {
        !self.link_control_queue.is_empty()
            || !self.feedback_queue.is_empty()
            || (!self.file_queue.is_empty() && !self.data_blocked_by_inflight_cap(now))
    }

    fn data_fits_inflight_cap(&self, frame_len: usize) -> bool {
        match (self.inflight_limit_bytes, self.controller.inflight_bytes()) {
            (Some(cap), Some(inflight)) => u64::try_from(frame_len)
                .is_ok_and(|frame_len| inflight.saturating_add(frame_len) <= cap),
            _ => true,
        }
    }

    fn can_piggyback(&self, now: MonoNs, target: SendClass) -> bool {
        let (Some((target_pkt, _)), Some((control_pkt, control))) =
            (self.queue(target).front(), self.link_control_queue.front())
        else {
            return false;
        };
        let Some(control) = control else {
            return false;
        };
        if control_pkt.len() > self.config.max_piggyback {
            return false;
        }
        let total = WIRE_HEADER_LEN
            + if target == SendClass::FileData || target == SendClass::Feedback {
                target_pkt.len()
            } else {
                0
            }
            + control.prefix_len()
            + control_pkt.len();
        total <= self.config.max_datagram
            && self.control_window.can_send_now(
                now,
                total,
                self.target_rate(),
                self.config.scheduler,
            )
    }

    fn can_send_standalone_control(&self, now: MonoNs) -> bool {
        let Some((pkt, Some(control))) = self.link_control_queue.front() else {
            return false;
        };
        let total = WIRE_HEADER_LEN + control.prefix_len() + pkt.len();
        self.control_window
            .can_send_now(now, total, self.target_rate(), self.config.scheduler)
    }

    fn prospective_cc_bytes(&self, class: SendClass, piggyback: bool) -> Option<OpaqueBytes> {
        if !matches!(class, SendClass::FileData | SendClass::Feedback) || piggyback {
            return None;
        }
        let (packet, control) = self.queue(class).front()?;
        if control.is_some() {
            return None;
        }
        self.controller.attach_cc().filter(|bytes| {
            encoded_entry_len(packet, class, control, None, Some(bytes.as_ref()))
                <= self.config.max_datagram
        })
    }

    fn planned_frame_len(&self, now: MonoNs, class: SendClass) -> Option<usize> {
        let (packet, control) = self.queue(class).front()?;
        let piggyback = matches!(class, SendClass::FileData | SendClass::Feedback)
            && self.can_piggyback(now, class);
        let attached = if piggyback {
            let (attached_packet, attached_control) = self.link_control_queue.front()?;
            Some((attached_packet, attached_control))
        } else {
            None
        };
        let cc_bytes = self.prospective_cc_bytes(class, piggyback);
        Some(encoded_entry_len(
            packet,
            class,
            control,
            attached,
            cc_bytes.as_deref(),
        ))
    }

    fn send_one(&mut self, now: MonoNs, class: SendClass, report: &mut DriveReport) -> SendStep {
        let piggyback = if class == SendClass::FileData || class == SendClass::Feedback {
            self.can_piggyback(now, class)
        } else {
            false
        };

        let candidate_seq = self.next_link_seq;
        let attached = if piggyback {
            self.link_control_queue
                .front()
                .map(|(packet, control)| (packet.fanout(), control))
        } else {
            None
        };
        let cc_bytes = self.prospective_cc_bytes(class, piggyback);
        let sent_cc = cc_bytes.clone();
        let sent_link_control = if piggyback || class == SendClass::LinkControl {
            self.link_control_queue.front().and_then(|(packet, spec)| {
                matches!(spec, Some(ControlSpec::Cc { .. }))
                    .then(|| OpaqueBytes::copy_from_slice(packet.payload_bytes()))
            })
        } else {
            None
        };
        let (_front_control, encode_result, encoded_allocation) = {
            let (queue, scratch) = self.queue_and_send_scratch_mut(class);
            let (header, control) = queue
                .front_header_mut()
                .expect("selected class must have a front packet");
            write_transmit_fields(header, candidate_seq);
            let packet = queue
                .front()
                .expect("selected class must have a front packet")
                .0;
            let attached_ref = attached
                .as_ref()
                .map(|(packet, control)| (packet, *control));
            let capacity = scratch.capacity();
            let result = encode_entry_into(packet, class, control, attached_ref, cc_bytes, scratch);
            (control, result, scratch.capacity() != capacity)
        };
        let Ok(()) = encode_result else {
            let queue = self.queue_mut(class);
            if let Some((header, _)) = queue.front_header_mut() {
                write_transmit_fields(header, 0);
            }
            self.record_drop("serialize_failed");
            report.send_outcome = Some(LocalSendOutcome::Fatal);
            return SendStep::Failed;
        };
        self.wire_io.copies = self.wire_io.copies.saturating_add(1);
        if encoded_allocation {
            self.wire_io.allocations = self.wire_io.allocations.saturating_add(1);
        }
        let frame_len = self.send_scratch.len();
        if class == SendClass::FileData && !self.data_fits_inflight_cap(frame_len) {
            let queue = self.queue_mut(class);
            if let Some((header, _)) = queue.front_header_mut() {
                write_transmit_fields(header, 0);
            }
            return SendStep::CapBlocked;
        }

        match self
            .transport
            .send_batch(now, &[self.send_scratch.as_slice()], &mut self.wire_io)
        {
            Ok(1) => {
                let sent_class = class;
                let _packet = self
                    .queue_mut(class)
                    .pop()
                    .expect("front existed before successful send");
                if piggyback {
                    let _ = self.link_control_queue.pop();
                    self.control_window
                        .record(now, frame_len, self.config.scheduler);
                } else if class == SendClass::LinkControl {
                    self.control_window
                        .record(now, frame_len, self.config.scheduler);
                }
                if class.is_non_file() {
                    self.consecutive_non_file = self.consecutive_non_file.saturating_add(1);
                } else {
                    self.consecutive_non_file = 0;
                }
                self.next_link_seq = self.next_link_seq.wrapping_add(1);
                conet_core::RatePacer::on_sent(&mut self.pacer, now, frame_len as u64);
                if let Some(body) = sent_cc.as_ref() {
                    self.controller.on_cc_sent(body);
                }
                if let Some(body) = sent_link_control.as_ref() {
                    if self.pending_tx_control.as_ref() == Some(body) {
                        self.controller.on_cc_sent(body);
                        self.pending_tx_control = None;
                    }
                    if self.pending_rx_control.as_ref() == Some(body) {
                        if let Some(controller) = self.rx_controller.as_mut() {
                            controller.on_control_sent(body);
                        }
                        self.pending_rx_control = None;
                    }
                }
                if matches!(class, SendClass::FileData | SendClass::Feedback) {
                    self.controller.on_packet_sent(
                        now,
                        u16::try_from(frame_len).unwrap_or(u16::MAX),
                        Some(candidate_seq as u64),
                    );
                }
                self.sent.push(SentDatagram {
                    at: now,
                    bytes: frame_len,
                    class: sent_class,
                    link_seq: candidate_seq,
                    ready_at: self.ready_at(),
                });
                // A newly due controller body may be offered immediately.
                self.poll_rx_control(now);
                report.send_outcome = Some(LocalSendOutcome::Accepted);
                SendStep::Sent
            }
            Ok(_) => {
                let queue = self.queue_mut(class);
                if let Some((header, _)) = queue.front_header_mut() {
                    write_transmit_fields(header, 0);
                }
                self.record_drop("sendto_failed");
                report.send_failed = true;
                report.send_outcome = Some(LocalSendOutcome::Fatal);
                SendStep::Failed
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let queue = self.queue_mut(class);
                if let Some((header, _)) = queue.front_header_mut() {
                    write_transmit_fields(header, 0);
                }
                report.send_failed = true;
                report.send_would_block = true;
                report.send_outcome = Some(LocalSendOutcome::WouldBlock);
                SendStep::WouldBlock
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                let queue = self.queue_mut(class);
                if let Some((header, _)) = queue.front_header_mut() {
                    write_transmit_fields(header, 0);
                }
                report.send_failed = true;
                report.send_outcome = Some(LocalSendOutcome::Interrupted);
                SendStep::Interrupted
            }
            Err(error) if is_transient_send_error(error.kind()) => {
                let queue = self.queue_mut(class);
                if let Some((header, _)) = queue.front_header_mut() {
                    write_transmit_fields(header, 0);
                }
                self.drop_after_local_send_failure(class, piggyback);
                self.record_drop("sendto_transient");
                report.send_failed = true;
                report.send_outcome = Some(LocalSendOutcome::TransientDrop);
                SendStep::TransientDrop
            }
            Err(_) => {
                let queue = self.queue_mut(class);
                if let Some((header, _)) = queue.front_header_mut() {
                    write_transmit_fields(header, 0);
                }
                self.record_drop("sendto_failed");
                report.send_failed = true;
                report.send_outcome = Some(LocalSendOutcome::Fatal);
                SendStep::Failed
            }
        }
    }

    fn drop_after_local_send_failure(&mut self, class: SendClass, piggyback: bool) {
        let _ = self.queue_mut(class).pop();
        if piggyback {
            let _ = self.link_control_queue.pop();
        }
    }

    fn enqueue_user_class(
        &mut self,
        class: SendClass,
        mut pkt: PacketHandle,
        control: Option<ControlSpec>,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        let user_len = pkt.len();
        let total = WIRE_HEADER_LEN + user_len;
        if total > self.config.max_datagram {
            return Err(ProfileEnqueueError::DatagramTooLarge {
                pkt,
                len: total,
                max: self.config.max_datagram,
            });
        }
        self.initialize_header(&mut pkt, qos_class(class), Some(user_len));
        self.queue_mut(class)
            .enqueue(pkt, control)
            .map_err(ProfileEnqueueError::Queue)
    }

    fn enqueue_cc_body(
        &mut self,
        class: SendClass,
        ctrl_type: ControlType,
        body: OpaqueBytes,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        if !self.association.is_ready() {
            return Err(ProfileEnqueueError::Closed {
                pkt: bytes_packet(body, WIRE_HEADER_LEN),
            });
        }
        if body.len() > self.config.max_control_body {
            return Err(ProfileEnqueueError::ControlBodyTooLarge {
                pkt: bytes_packet(body.clone(), WIRE_HEADER_LEN),
                len: body.len(),
                max: self.config.max_control_body,
            });
        }
        let total = WIRE_HEADER_LEN + CC_PREFIX_LEN + body.len();
        if total > self.config.max_datagram {
            return Err(ProfileEnqueueError::DatagramTooLarge {
                pkt: bytes_packet(body, WIRE_HEADER_LEN),
                len: total,
                max: self.config.max_datagram,
            });
        }
        let mut pkt = bytes_packet(body, WIRE_HEADER_LEN);
        self.initialize_header(&mut pkt, QosClass::Control, Some(0));
        self.queue_mut(class)
            .enqueue(pkt, Some(ControlSpec::Cc { ctrl_type }))
            .map_err(ProfileEnqueueError::Queue)
    }

    fn initialize_header(&self, pkt: &mut PacketHandle, qos: QosClass, payload_len: Option<usize>) {
        let header = pkt.header_mut();
        if header.len() != WIRE_HEADER_LEN {
            header.resize(WIRE_HEADER_LEN, 0);
        }
        let bytes = header.as_mut_bytes();
        bytes.fill(0);
        bytes[0..2].copy_from_slice(&conet_core::REFERENCE_WIRE_MAGIC.to_be_bytes());
        bytes[2] = conet_core::REFERENCE_WIRE_VERSION;
        bytes[3] = qos.wire_value();
        let payload_len = payload_len.unwrap_or(0);
        bytes[8..10].copy_from_slice(&(payload_len as u16).to_be_bytes());
        bytes[10..12].copy_from_slice(&self.epoch.to_be_bytes());
    }

    fn receive_datagram(&mut self, now: MonoNs, datagram: InboundDatagram) -> bool {
        let boundary_len = datagram.bytes.len();
        debug_assert_eq!(datagram.meta.len, boundary_len);
        let (bytes, io_lease) = datagram.bytes.into_shared().into_parts();
        let parsed = match self.wire.parse(bytes) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.record_drop(error.drop_reason());
                return false;
            }
        };
        drop(io_lease);
        let (packet, header, mut control) = parsed.into_parts();
        if self.association.is_closed() {
            self.record_drop("closed");
            return false;
        }
        if let Some(message) = &control {
            match message.ctrl_type {
                ControlType::Open | ControlType::Accept => {
                    // Legacy setup types are inert. They neither establish
                    // state nor gate any datagram, so a peer that still emits
                    // them cannot delay an unreliable path.
                    control = None;
                }
                ControlType::Close | ControlType::CloseAck => {
                    if !self
                        .control_admissible(datagram.authenticated, "unauthenticated_association")
                    {
                        return false;
                    }
                    if header.epoch < self.epoch {
                        self.record_drop("stale_epoch");
                        return false;
                    }
                    if header.epoch > self.epoch {
                        self.record_drop("future_epoch");
                        return false;
                    }
                    self.association = AssociationState::Closed;
                    self.cancel_profile_queues();
                    return true;
                }
                ControlType::CcOpaque => {}
                ControlType::Cc => {}
            }
        }

        if header.epoch < self.epoch {
            self.record_drop("stale_epoch");
            return false;
        }
        if header.epoch > self.epoch {
            self.record_drop("future_epoch");
            return false;
        }
        if control
            .as_ref()
            .is_some_and(|control| control.ctrl_type == ControlType::CcOpaque)
        {
            if !self.cc_admissible(datagram.authenticated, "unauthenticated_cc") {
                if header.payload_len == 0 {
                    return false;
                }
                // A rejected controller sidecar must not discard a co-resident
                // reliability/user body. Standalone controls remain drop-only.
                control = None;
            } else {
                // Authentication admits the body. Its private codec owns any
                // message identity and replay policy.
            }
        }

        let mut cc_bytes = None;
        if control
            .as_ref()
            .is_some_and(|control| control.ctrl_type == ControlType::Cc)
        {
            if self.cc_admissible(datagram.authenticated, "unauthenticated_cc_trailer") {
                cc_bytes = control.as_ref().map(|control| control.body.clone());
            } else if header.payload_len == 0 {
                return false;
            }
            control = None;
        }

        self.accept_valid_datagram(
            now,
            datagram.authenticated,
            boundary_len,
            packet,
            header,
            control,
            cc_bytes,
        );
        true
    }

    fn accept_valid_datagram(
        &mut self,
        now: MonoNs,
        _authenticated: bool,
        boundary_len: usize,
        packet: PacketHandle,
        header: WireHeader,
        control: Option<ControlMessage>,
        cc_bytes: Option<OpaqueBytes>,
    ) {
        let mut observation =
            Observation::new(now, u16::try_from(boundary_len).unwrap_or(u16::MAX));
        observation.payload_len = header.payload_len;
        observation.seq = Some(u64::from(header.link_seq));
        observation.cc_bytes = cc_bytes.clone();
        self.observations.push(observation.clone());
        if let Some(controller) = self.rx_controller.as_mut() {
            controller.on_observed(observation);
        }
        if let Some(body) = cc_bytes.as_ref() {
            self.handle_cc_opaque(now, body);
        }

        if let Some(message) = control.as_ref() {
            if message.ctrl_type == ControlType::CcOpaque {
                self.handle_cc_opaque(now, &message.body);
            }
        }

        self.received.push_back(ReceivedDatagram {
            recv_ts: now,
            boundary_len,
            class: header.flags.qos,
            packet,
            header,
            control,
        });
    }

    fn control_admissible(
        &mut self,
        authenticated: bool,
        unauthenticated_reason: &'static str,
    ) -> bool {
        if !authenticated && !self.config.allow_unauthenticated_cc {
            self.record_drop(unauthenticated_reason);
            return false;
        }
        true
    }

    fn cc_admissible(&mut self, authenticated: bool, unauthenticated_reason: &'static str) -> bool {
        if !authenticated {
            self.record_drop(unauthenticated_reason);
            return false;
        }
        self.control_admissible(authenticated, unauthenticated_reason)
    }

    fn handle_cc_opaque(&mut self, now: MonoNs, body: &OpaqueBytes) -> ControlDisposition {
        let disposition = self.controller.on_peer_control(now, body.clone());
        if disposition == ControlDisposition::Usable {
            self.apply_controller_pace(RateControlPolicy::authenticated());
        }
        disposition
    }

    fn apply_controller_pace(&mut self, policy: RateControlPolicy) -> AppliedDecision {
        conet_core::apply_controller_decision(
            &mut self.pacer,
            &mut self.inflight_limit_bytes,
            self.controller.pace(),
            policy,
        )
    }

    fn record_drop(&mut self, reason: &'static str) {
        *self.drops.entry(reason).or_insert(0) += 1;
    }
}

fn qos_class(class: SendClass) -> QosClass {
    match class {
        SendClass::FileData => QosClass::Bulk,
        SendClass::Feedback => QosClass::Feedback,
        SendClass::LinkControl => QosClass::Control,
    }
}

fn write_transmit_fields(header: &mut conet_core::HeaderBuf, link_seq: u32) {
    if header.len() != WIRE_HEADER_LEN {
        header.resize(WIRE_HEADER_LEN, 0);
    }
    let bytes = header.as_mut_bytes();
    bytes[4..8].copy_from_slice(&link_seq.to_be_bytes());
}

fn is_transient_send_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

fn encoded_entry_len(
    packet: &PacketHandle,
    class: SendClass,
    control: Option<ControlSpec>,
    attached: Option<(&PacketHandle, Option<ControlSpec>)>,
    cc_bytes: Option<&[u8]>,
) -> usize {
    let body_len = if class == SendClass::LinkControl {
        0
    } else {
        packet.payload_bytes().len()
    };
    WIRE_HEADER_LEN
        + body_len
        + control.map_or(0, ControlSpec::prefix_len)
        + attached
            .and_then(|(_, spec)| spec)
            .map_or(0, ControlSpec::prefix_len)
        + attached.map_or(0, |(attached_packet, _)| attached_packet.len())
        + cc_bytes.map_or(0, |bytes| CC_PREFIX_LEN + bytes.len())
}

#[cfg(test)]
fn encode_entry(
    packet: &PacketHandle,
    class: SendClass,
    control: Option<ControlSpec>,
    attached: Option<(&PacketHandle, Option<ControlSpec>)>,
    cc_bytes: Option<OpaqueBytes>,
) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::with_capacity(encoded_entry_len(
        packet,
        class,
        control,
        attached,
        cc_bytes.as_deref(),
    ));
    encode_entry_into(packet, class, control, attached, cc_bytes, &mut bytes)?;
    Ok(bytes)
}

fn encode_entry_into(
    packet: &PacketHandle,
    class: SendClass,
    control: Option<ControlSpec>,
    attached: Option<(&PacketHandle, Option<ControlSpec>)>,
    cc_bytes: Option<OpaqueBytes>,
    bytes: &mut Vec<u8>,
) -> Result<(), WireError> {
    let body = if class == SendClass::LinkControl {
        &[][..]
    } else {
        packet.payload_bytes()
    };
    let required = encoded_entry_len(packet, class, control, attached, cc_bytes.as_deref());
    bytes.clear();
    bytes.reserve(required.saturating_sub(bytes.capacity()));
    let header = packet.header().as_bytes();
    if header.len() != WIRE_HEADER_LEN {
        return Err(WireError::HeaderMismatch);
    }
    bytes.extend_from_slice(header);
    bytes[8..10].copy_from_slice(
        &(u16::try_from(body.len()).map_err(|_| WireError::PayloadTooLarge { len: body.len() })?)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(body);

    if let Some((control_pkt, Some(spec))) = attached {
        write_control_prefix(bytes, spec);
        bytes.extend_from_slice(control_pkt.payload_bytes());
    } else if let Some(spec) = control {
        write_control_prefix(bytes, spec);
        bytes.extend_from_slice(packet.payload_bytes());
    } else if let Some(cc_bytes) = cc_bytes {
        bytes.push(ControlType::Cc.wire_value());
        bytes.extend_from_slice(&cc_bytes);
    }
    Ok(())
}

fn write_control_prefix(bytes: &mut Vec<u8>, spec: ControlSpec) {
    bytes.push(spec.ctrl_type().wire_value());
}

fn bytes_packet(bytes: OpaqueBytes, headroom: usize) -> PacketHandle {
    PacketBuilder::from_payload(bytes, headroom).freeze()
}

fn earliest(left: Option<MonoNs>, right: Option<MonoNs>) -> Option<MonoNs> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

/// Convert a plain user payload into an owned handle without interpreting it.
pub fn payload_packet(payload: impl AsRef<[u8]>) -> PacketHandle {
    bytes_packet(
        OpaqueBytes::copy_from_slice(payload.as_ref()),
        WIRE_HEADER_LEN,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Role, SimNetwork};
    use conet_core::{BlockId, Feedback};

    #[test]
    fn local_close_and_reset_cancel_queues_without_setup_packets() {
        let network = SimNetwork::new();
        let old_id = 0x91_c0_ffee;
        let old_epoch = 7;
        let mut endpoint = UdpLiEndpoint::new(
            network.transport(0),
            EndpointConfig::new(Role::Initiator, u64::MAX),
        );
        endpoint.association_id = Some(old_id);
        endpoint.epoch = old_epoch;
        endpoint
            .enqueue_file_data(payload_packet(b"queued-file"))
            .unwrap();
        endpoint
            .enqueue_feedback_value(Feedback::ack(BlockId::new(3)))
            .unwrap();
        endpoint
            .enqueue_link_control(OpaqueBytes::from_static(b"queued-control"))
            .unwrap();

        endpoint.close().unwrap();
        assert_eq!(endpoint.cancelled_packets(), 3);
        assert_eq!(endpoint.queued(SendClass::FileData), 0);
        assert_eq!(endpoint.queued(SendClass::Feedback), 0);
        assert_eq!(endpoint.queued(SendClass::LinkControl), 0);
        endpoint.drive(MonoNs::new(1_000_000));
        assert!(network.frames_from(0).is_empty());

        endpoint.start_association().unwrap();
        let new_id = endpoint.association_id().unwrap();
        assert_ne!(new_id, old_id);
        assert_eq!(endpoint.cancelled_packets(), 3);
        assert_eq!(endpoint.queued(SendClass::FileData), 0);
        assert_eq!(endpoint.queued(SendClass::Feedback), 0);
        assert_eq!(endpoint.queued(SendClass::LinkControl), 0);
        endpoint.drive(MonoNs::new(1_000_000));
        endpoint.drive(MonoNs::new(2_000_000));
        assert_eq!(endpoint.state(), AssociationState::Ready);
        assert_eq!(endpoint.epoch(), 1);
        assert!(network.frames_from(0).is_empty());
    }

    #[test]
    fn encode_entry_into_matches_the_allocating_reference() {
        let packet = payload_packet(b"payload");
        let attached_packet = payload_packet(b"attached");
        let attached_control = ControlSpec::Cc {
            ctrl_type: ControlType::CcOpaque,
        };

        let cases = [
            (SendClass::FileData, None, None, None),
            (
                SendClass::Feedback,
                Some(ControlSpec::Cc {
                    ctrl_type: ControlType::CcOpaque,
                }),
                None,
                None,
            ),
            (
                SendClass::FileData,
                None,
                Some((&attached_packet, Some(attached_control))),
                None,
            ),
            (
                SendClass::FileData,
                None,
                None,
                Some(OpaqueBytes::from_static(b"cc-body")),
            ),
            (
                SendClass::LinkControl,
                Some(ControlSpec::Cc {
                    ctrl_type: ControlType::CcOpaque,
                }),
                None,
                None,
            ),
        ];

        let mut scratch = Vec::with_capacity(1);
        for (class, control, attached, cc_bytes) in cases {
            let reference =
                encode_entry(&packet, class, control, attached, cc_bytes.clone()).unwrap();
            encode_entry_into(&packet, class, control, attached, cc_bytes, &mut scratch).unwrap();
            assert_eq!(scratch, reference);

            let allocated_at = scratch.as_ptr();
            encode_entry_into(&packet, class, control, attached, None, &mut scratch).unwrap();
            assert_eq!(scratch.as_ptr(), allocated_at);
        }
    }
}
