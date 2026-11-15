//! UDP-LI endpoint: association, profile queues, scheduling, and demux.

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

use crate::OpenState;
use crate::association::{
    AssociationError, AssociationState, HandshakePolicy, OpenStateBody, Role, UDP_LI_PROFILE_ID,
    make_open_state,
};
use crate::scheduler::{ControlWindow, SchedulerConfig, SendClass};
use crate::transport::{DatagramTransport, InboundDatagram, WireIoStats};

const WIRE_HEADER_LEN: usize = conet_core::REFERENCE_WIRE_HEADER_LEN;
const LINK_CONTROL_PREFIX_LEN: usize = 5;
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
    pub handshake: HandshakePolicy,
    pub scheduler: SchedulerConfig,
    pub association_limits: QueueLimits,
    pub link_control_limits: QueueLimits,
    pub feedback_limits: QueueLimits,
    pub file_data_limits: QueueLimits,
    pub inbound_limit: usize,
    /// Local accounting/nonce seed for new handshakes; never serialized.
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
            handshake: HandshakePolicy::default(),
            scheduler: SchedulerConfig::default(),
            association_limits: QueueLimits::new(32, 32 * 1024, 32 * 1024)
                .with_max_packet_bytes(packet_max),
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

/// User payload or feedback attempted before the association reached
/// `Established`.
#[derive(Debug)]
pub struct EnqueueBeforeEstablished {
    pub pkt: PacketHandle,
    pub state: AssociationState,
}

/// Profile enqueue/admission error. Every variant retains the caller's handle.
#[derive(Debug)]
pub enum ProfileEnqueueError {
    EnqueueBeforeEstablished(EnqueueBeforeEstablished),
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
    pub fn stage_established(&self) -> Option<AssociationState> {
        match self {
            Self::EnqueueBeforeEstablished(error) => Some(error.state),
            _ => None,
        }
    }

    pub fn kind(&self) -> ProfileEnqueueErrorKind {
        match self {
            Self::EnqueueBeforeEstablished(_) => ProfileEnqueueErrorKind::EnqueueBeforeEstablished,
            Self::Queue(error) => ProfileEnqueueErrorKind::Queue(error.kind()),
            Self::DatagramTooLarge { .. } => ProfileEnqueueErrorKind::DatagramTooLarge,
            Self::ControlBodyTooLarge { .. } => ProfileEnqueueErrorKind::ControlBodyTooLarge,
        }
    }

    pub fn packet(&self) -> &PacketHandle {
        match self {
            Self::EnqueueBeforeEstablished(error) => &error.pkt,
            Self::Queue(error) => error.packet(),
            Self::DatagramTooLarge { pkt, .. } | Self::ControlBodyTooLarge { pkt, .. } => pkt,
        }
    }

    pub fn into_packet(self) -> PacketHandle {
        match self {
            Self::EnqueueBeforeEstablished(error) => error.pkt,
            Self::Queue(error) => error.into_packet(),
            Self::DatagramTooLarge { pkt, .. } | Self::ControlBodyTooLarge { pkt, .. } => pkt,
        }
    }
}

/// Non-owning failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileEnqueueErrorKind {
    EnqueueBeforeEstablished,
    Queue(EnqueueErrorKind),
    DatagramTooLarge,
    ControlBodyTooLarge,
}

impl std::fmt::Display for ProfileEnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnqueueBeforeEstablished(error) => {
                write!(
                    f,
                    "user payload or feedback is not admitted before Established (state {:?})",
                    error.state
                )
            }
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
    pub send_failed: bool,
    pub association_failed: bool,
    pub clock_discontinuity: bool,
    /// Transport-near counters observed when this drive completed.
    pub wire_io: WireIoStats,
    /// The TX controller's next hook deadline after this drive completed.
    pub next_wakeup: Option<MonoNs>,
}

#[derive(Clone, Copy, Debug)]
enum ControlSpec {
    Link {
        ctrl_type: ControlType,
        ctrl_seq: u32,
    },
    Cc {
        ctrl_type: ControlType,
    },
}

impl ControlSpec {
    const fn ctrl_type(self) -> ControlType {
        match self {
            Self::Link { ctrl_type, .. } | Self::Cc { ctrl_type } => ctrl_type,
        }
    }

    const fn prefix_len(self) -> usize {
        match self {
            Self::Link { .. } => LINK_CONTROL_PREFIX_LEN,
            Self::Cc { .. } => CC_PREFIX_LEN,
        }
    }
}

const CONTROL_REPLAY_WINDOW_BITS: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlSeqDisposition {
    Accepted,
    Duplicate,
    TooOld,
}

#[derive(Clone, Copy, Debug, Default)]
struct ControlReplayWindow {
    max_seq: u32,
    seen: u64,
    initialized: bool,
}

impl ControlReplayWindow {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn inspect(&self, seq: u32) -> ControlSeqDisposition {
        if !self.initialized {
            return ControlSeqDisposition::Accepted;
        }
        let ahead = seq.wrapping_sub(self.max_seq);
        if ahead == 0 {
            return ControlSeqDisposition::Duplicate;
        }
        if ahead & (1 << 31) == 0 {
            return ControlSeqDisposition::Accepted;
        }
        let behind = self.max_seq.wrapping_sub(seq);
        if behind >= CONTROL_REPLAY_WINDOW_BITS {
            return ControlSeqDisposition::TooOld;
        }
        if self.seen & (1_u64 << behind) != 0 {
            ControlSeqDisposition::Duplicate
        } else {
            ControlSeqDisposition::Accepted
        }
    }

    /// Record a control sequence and report whether this is its first arrival.
    ///
    /// A 64-entry sliding bitmap admits bounded reordering and retains no
    /// unbounded per-control history.
    fn accept(&mut self, seq: u32) -> ControlSeqDisposition {
        let disposition = self.inspect(seq);
        if disposition != ControlSeqDisposition::Accepted {
            return disposition;
        }

        if !self.initialized {
            self.initialized = true;
            self.max_seq = seq;
            self.seen = 1;
            return ControlSeqDisposition::Accepted;
        }

        let ahead = seq.wrapping_sub(self.max_seq);
        if ahead & (1 << 31) == 0 {
            self.seen = if ahead >= CONTROL_REPLAY_WINDOW_BITS {
                1
            } else {
                (self.seen << ahead) | 1
            };
            self.max_seq = seq;
            return ControlSeqDisposition::Accepted;
        }

        let behind = self.max_seq.wrapping_sub(seq);
        let mask = 1_u64 << behind;
        self.seen |= mask;
        ControlSeqDisposition::Accepted
    }
}

#[cfg(test)]
mod control_replay_window_tests {
    use super::{ControlReplayWindow, ControlSeqDisposition};

    #[test]
    fn accepts_first_copy_and_rejects_an_in_window_duplicate() {
        let mut window = ControlReplayWindow::default();

        assert_eq!(window.accept(10), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(10), ControlSeqDisposition::Duplicate);
    }

    #[test]
    fn accepts_in_window_reordering_and_fills_holes_once() {
        let mut window = ControlReplayWindow::default();

        assert_eq!(window.accept(10), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(12), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(11), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(11), ControlSeqDisposition::Duplicate);
        assert_eq!(window.accept(12), ControlSeqDisposition::Duplicate);
        assert_eq!(window.accept(10), ControlSeqDisposition::Duplicate);
    }

    #[test]
    fn accepts_reordering_across_u32_wraparound() {
        let mut window = ControlReplayWindow::default();

        assert_eq!(window.accept(u32::MAX - 1), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(u32::MAX), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(0), ControlSeqDisposition::Accepted);
        assert_eq!(
            window.accept(u32::MAX - 1),
            ControlSeqDisposition::Duplicate
        );
        assert_eq!(window.accept(u32::MAX), ControlSeqDisposition::Duplicate);
        assert_eq!(window.accept(1), ControlSeqDisposition::Accepted);
    }

    #[test]
    fn classifies_a_sequence_evicted_behind_the_window_as_too_old() {
        let mut window = ControlReplayWindow::default();

        assert_eq!(window.accept(100), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(163), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(100), ControlSeqDisposition::Duplicate);
        assert_eq!(window.accept(164), ControlSeqDisposition::Accepted);
        assert_eq!(window.accept(100), ControlSeqDisposition::TooOld);
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
    next_ctrl_seq: u32,
    control_replay: ControlReplayWindow,
    open_state: Option<OpenState>,
    open_ctrl_seq: Option<u32>,
    open_sends: u8,
    handshake_due: MonoNs,
    association_queue: ProfileQueue,
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
        let wire = ReferenceWireCodec::new(conet_core::WireLimits {
            max_datagram: config.max_datagram,
            max_control_body: config.max_control_body,
        });
        let pacer = DiscreteRatePacer::new(config.target_rate);
        let send_scratch = Vec::with_capacity(config.max_datagram);
        let receive_scratch = Vec::with_capacity(config.inbound_limit);
        Self {
            transport,
            association_queue: ProfileQueue::new(config.association_limits),
            link_control_queue: ProfileQueue::new(config.link_control_limits),
            feedback_queue: ProfileQueue::new(config.feedback_limits),
            file_queue: ProfileQueue::new(config.file_data_limits),
            next_association_id: config.initial_association_id,
            config,
            wire,
            association: AssociationState::Idle,
            association_id: None,
            epoch: 0,
            next_link_seq: 0,
            next_ctrl_seq: 1,
            control_replay: ControlReplayWindow::default(),
            open_state: None,
            open_ctrl_seq: None,
            open_sends: 0,
            handshake_due: MonoNs::ZERO,
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
    /// This aggregates the TX and RX controller hooks, a waiting pacer, and
    /// an in-progress handshake. It deliberately does not alter
    /// [`Self::next_wakeup`], which remains the TX controller hook only.
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
        if self.association == AssociationState::Handshaking {
            deadline = earliest(deadline, Some(self.handshake_due));
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
        let current = now();
        let deadline = self.next_drive();
        if deadline.is_some_and(|deadline| deadline <= current) {
            return Ok(self.drive(current));
        }

        let timeout = deadline.map(|deadline| {
            let nanos = deadline.as_nanos().saturating_sub(current.as_nanos());
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        });
        let inbound_ready = self.transport.wait_readable(timeout)?;
        let drive_at = if inbound_ready {
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

    /// Begin an initiator association with a fresh local ID and epoch 1.
    pub fn start_association(&mut self) -> Result<(), AssociationError> {
        if self.config.role != Role::Initiator {
            return Err(AssociationError::WrongRole);
        }
        if !matches!(
            self.association,
            AssociationState::Idle | AssociationState::Closed | AssociationState::Failed
        ) {
            return Err(AssociationError::WrongState {
                state: self.association,
            });
        }
        self.cancel_profile_queues();
        self.association_id = Some(self.allocate_association_id());
        self.epoch = 1;
        self.next_link_seq = 0;
        self.control_replay.clear();
        self.open_sends = 0;
        self.handshake_due = MonoNs::ZERO;
        self.open_state = Some(make_open_state(
            self.config.max_datagram,
            nonce_from_id(self.association_id.unwrap_or(0)),
        ));
        self.open_ctrl_seq = Some(self.take_ctrl_seq());
        self.association = AssociationState::Handshaking;
        self.association_queue.clear();
        self.enqueue_open()
            .map_err(|_| AssociationError::WrongState {
                state: self.association,
            })?;
        Ok(())
    }

    /// Explicit test-only pre-shared association. This skips OPEN/ACCEPT and
    /// must not be used as the shipping security path.
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
        self.cancel_profile_queues();
        self.association_id = Some(association_id);
        self.epoch = epoch;
        self.next_link_seq = 0;
        self.control_replay.clear();
        self.open_sends = 0;
        self.open_ctrl_seq = None;
        self.association_queue.clear();
        self.association = AssociationState::Established;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), AssociationError> {
        if !self.association.is_established() {
            return Err(AssociationError::NotEstablished {
                state: self.association,
            });
        }
        self.cancel_profile_queues();
        self.association = AssociationState::Closing;
        self.enqueue_association_control(ControlType::Close, OpaqueBytes::new())
            .map_err(|_| AssociationError::WrongState {
                state: self.association,
            })?;
        Ok(())
    }

    /// In-place restart: bump epoch, reset this direction's link sequence,
    /// cancel queued reliability users, and retain the association binding.
    pub fn restart(&mut self) -> Result<u16, AssociationError> {
        if !self.association.is_established() {
            return Err(AssociationError::NotEstablished {
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
        self.apply_controller_pace(RateControlPolicy::authenticated());
        Ok(self.epoch)
    }

    pub fn enqueue_file_data(
        &mut self,
        pkt: PacketHandle,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        if !self.association.is_established() {
            return Err(ProfileEnqueueError::EnqueueBeforeEstablished(
                EnqueueBeforeEstablished {
                    pkt,
                    state: self.association,
                },
            ));
        }
        self.enqueue_user_class(SendClass::FileData, pkt, None)
    }

    pub fn enqueue_feedback(
        &mut self,
        pkt: PacketHandle,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        if !self.association.is_established() {
            return Err(ProfileEnqueueError::EnqueueBeforeEstablished(
                EnqueueBeforeEstablished {
                    pkt,
                    state: self.association,
                },
            ));
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

        self.controller.on_clock(now);
        self.apply_controller_pace(RateControlPolicy::authenticated());
        self.poll_controller_control(now);
        self.poll_rx_control(now);
        self.maintain_handshake(now, &mut report);

        while self.pace_ready(now) {
            let Some(class) = self.select_class(now) else {
                break;
            };
            match self.send_one(now, class, &mut report) {
                SendStep::Sent => {}
                SendStep::CapBlocked => continue,
                SendStep::Failed => break,
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
        self.maintain_handshake(now, &mut report);
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

    fn take_ctrl_seq(&mut self) -> u32 {
        let seq = self.next_ctrl_seq;
        self.next_ctrl_seq = self.next_ctrl_seq.wrapping_add(1).max(1);
        seq
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
            SendClass::Association => &self.association_queue,
            SendClass::LinkControl => &self.link_control_queue,
            SendClass::Feedback => &self.feedback_queue,
            SendClass::FileData => &self.file_queue,
        }
    }

    fn queue_mut(&mut self, class: SendClass) -> &mut ProfileQueue {
        match class {
            SendClass::Association => &mut self.association_queue,
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
            SendClass::Association => &mut self.association_queue,
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

    fn maintain_handshake(&mut self, now: MonoNs, report: &mut DriveReport) {
        if self.association != AssociationState::Handshaking {
            return;
        }
        if self.open_sends >= self.config.handshake.max_sends {
            if now >= self.handshake_due {
                self.association = AssociationState::Failed;
                self.association_queue.clear();
                self.record_drop("handshake_retry_cap");
                report.association_failed = true;
            }
            return;
        }
        if now >= self.handshake_due && self.association_queue.is_empty() {
            let _ = self.enqueue_open();
        }
    }

    fn select_class(&mut self, now: MonoNs) -> Option<SendClass> {
        if !self.association.is_established() {
            return (!self.association_queue.is_empty()).then_some(SendClass::Association);
        }
        let data_waiting = !self.file_queue.is_empty() && !self.data_blocked_by_inflight_cap(now);
        if data_waiting
            && self.consecutive_non_file >= self.config.scheduler.max_consecutive_non_file
        {
            return Some(SendClass::FileData);
        }
        if !self.association_queue.is_empty() {
            return Some(SendClass::Association);
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
        !self.association_queue.is_empty()
            || !self.link_control_queue.is_empty()
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
        let (front_control, encode_result, encoded_allocation) = {
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
                // A committed standalone body may become due for a same-event
                // retry immediately. Offer it before this drive consumes
                // inbound Status that can clear the expected effect.
                self.poll_rx_control(now);

                if class == SendClass::Association {
                    if self.association == AssociationState::Handshaking {
                        match front_control.map(ControlSpec::ctrl_type) {
                            Some(ControlType::Open) => {
                                self.open_sends = self.open_sends.saturating_add(1);
                                self.handshake_due =
                                    now.saturating_add(self.config.handshake.retry_interval);
                            }
                            Some(ControlType::Accept) => {
                                self.association = AssociationState::Established;
                            }
                            _ => {}
                        }
                    }
                }
                SendStep::Sent
            }
            Ok(_) | Err(_) => {
                let queue = self.queue_mut(class);
                if let Some((header, _)) = queue.front_header_mut() {
                    write_transmit_fields(header, 0);
                }
                self.record_drop("sendto_failed");
                report.send_failed = true;
                SendStep::Failed
            }
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

    fn enqueue_link_control_body(
        &mut self,
        class: SendClass,
        ctrl_type: ControlType,
        ctrl_seq: u32,
        body: OpaqueBytes,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        if body.len() > self.config.max_control_body {
            return Err(ProfileEnqueueError::ControlBodyTooLarge {
                pkt: bytes_packet(body.clone(), WIRE_HEADER_LEN),
                len: body.len(),
                max: self.config.max_control_body,
            });
        }
        let total = WIRE_HEADER_LEN + LINK_CONTROL_PREFIX_LEN + body.len();
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
            .enqueue(
                pkt,
                Some(ControlSpec::Link {
                    ctrl_type,
                    ctrl_seq,
                }),
            )
            .map_err(ProfileEnqueueError::Queue)
    }

    fn enqueue_cc_body(
        &mut self,
        class: SendClass,
        ctrl_type: ControlType,
        body: OpaqueBytes,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
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

    fn enqueue_open(&mut self) -> Result<UdpLiEnqueueStatus, EnqueueError> {
        let Some(open) = self.open_state else {
            return Err(EnqueueError::Closed {
                pkt: bytes_packet(OpaqueBytes::new(), WIRE_HEADER_LEN),
            });
        };
        let body = OpenStateBody {
            profile_id: open.profile_id,
            max_datagram: open.max_datagram,
            nonce: open.nonce,
        }
        .encode();
        let Some(ctrl_seq) = self.open_ctrl_seq else {
            return Err(EnqueueError::Closed {
                pkt: bytes_packet(OpaqueBytes::new(), WIRE_HEADER_LEN),
            });
        };
        let mut pkt = bytes_packet(body, WIRE_HEADER_LEN);
        self.initialize_header(&mut pkt, QosClass::Control, Some(0));
        self.association_queue.enqueue(
            pkt,
            Some(ControlSpec::Link {
                ctrl_type: ControlType::Open,
                ctrl_seq,
            }),
        )
    }

    fn enqueue_association_control(
        &mut self,
        ctrl_type: ControlType,
        body: OpaqueBytes,
    ) -> Result<UdpLiEnqueueStatus, ProfileEnqueueError> {
        let ctrl_seq = self.take_ctrl_seq();
        self.enqueue_link_control_body(SendClass::Association, ctrl_type, ctrl_seq, body)
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
        if let Some(message) = &control {
            let ctrl_type = message.ctrl_type;
            match ctrl_type {
                ControlType::Open => {
                    if !self
                        .control_admissible(datagram.authenticated, "unauthenticated_association")
                    {
                        return false;
                    }
                    return self.receive_open(
                        now,
                        datagram.authenticated,
                        boundary_len,
                        (packet, header, control),
                    );
                }
                ControlType::Accept => {
                    if !self
                        .control_admissible(datagram.authenticated, "unauthenticated_association")
                    {
                        return false;
                    }
                    return self.receive_accept(
                        now,
                        datagram.authenticated,
                        boundary_len,
                        (packet, header, control),
                    );
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
                    let ctrl_seq = control
                        .as_ref()
                        .expect("control branch has a control message")
                        .link_seq()
                        .expect("link control has a sequence");
                    let disposition = self.accept_control_seq(ctrl_seq);
                    if disposition != ControlSeqDisposition::Accepted {
                        return self.handle_rejected_control(
                            now,
                            datagram.authenticated,
                            boundary_len,
                            packet,
                            header,
                            disposition,
                        );
                    }
                    self.accept_valid_datagram(
                        now,
                        datagram.authenticated,
                        boundary_len,
                        packet,
                        header,
                        control,
                        None,
                    );
                    if ctrl_type == ControlType::CloseAck {
                        if self.association == AssociationState::Closing {
                            self.association = AssociationState::Closed;
                            self.cancel_profile_queues();
                        }
                    } else {
                        let _ = self
                            .enqueue_association_control(ControlType::CloseAck, OpaqueBytes::new());
                        self.association = AssociationState::Closed;
                        self.cancel_profile_queues();
                    }
                    return true;
                }
                ControlType::CcOpaque => {}
                ControlType::Cc => {}
            }
        }

        if !self.association.is_established() {
            self.record_drop("not_established");
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

    fn receive_open(
        &mut self,
        now: MonoNs,
        authenticated: bool,
        boundary_len: usize,
        parsed: (PacketHandle, WireHeader, Option<ControlMessage>),
    ) -> bool {
        if self.config.role != Role::Responder {
            self.record_drop("unexpected_open");
            return false;
        }
        let (packet, header, control) = parsed;
        let Some(body) = control
            .as_ref()
            .and_then(|message| OpenStateBody::decode(&message.body))
        else {
            self.record_drop("malformed_open");
            return false;
        };
        if body.profile_id != UDP_LI_PROFILE_ID
            || body.max_datagram as usize > self.config.max_datagram
        {
            self.record_drop("open_profile_mismatch");
            return false;
        }

        let starts_new_association = matches!(
            self.association,
            AssociationState::Idle | AssociationState::Failed | AssociationState::Closed
        );
        let ctrl_seq = control
            .as_ref()
            .expect("Open branch has a control message")
            .link_seq()
            .expect("Open has a link sequence");
        match self.association {
            AssociationState::Idle | AssociationState::Failed | AssociationState::Closed => {}
            AssociationState::Established | AssociationState::Handshaking => {
                if header.epoch != self.epoch
                    || self.open_state.map(|open| open.nonce) != Some(body.nonce)
                {
                    self.record_drop("association_mismatch");
                    return false;
                }
            }
            AssociationState::Closing => {
                let disposition = self.control_replay.inspect(ctrl_seq);
                if disposition != ControlSeqDisposition::Accepted {
                    return self.handle_rejected_control(
                        now,
                        authenticated,
                        boundary_len,
                        packet,
                        header,
                        disposition,
                    );
                }
                self.record_drop("association_closing");
                return false;
            }
        }

        if starts_new_association {
            self.control_replay.clear();
        }
        let disposition = self.accept_control_seq(ctrl_seq);
        if disposition != ControlSeqDisposition::Accepted {
            return self.handle_rejected_control(
                now,
                authenticated,
                boundary_len,
                packet,
                header,
                disposition,
            );
        }

        if starts_new_association {
            self.cancel_profile_queues();
            self.epoch = header.epoch;
            self.next_link_seq = 0;
            self.open_state = Some(OpenState {
                profile_id: body.profile_id,
                max_datagram: body.max_datagram,
                nonce: body.nonce,
            });
            self.association = AssociationState::Handshaking;
        }

        let Some(open) = self.open_state else {
            self.record_drop("malformed_open");
            return false;
        };
        let accept_body = OpenStateBody {
            profile_id: open.profile_id,
            max_datagram: open.max_datagram,
            nonce: open.nonce,
        }
        .encode();
        let _ = self.enqueue_association_control(ControlType::Accept, accept_body);
        self.accept_valid_datagram(
            now,
            authenticated,
            boundary_len,
            packet,
            header,
            control,
            None,
        );
        true
    }

    fn receive_accept(
        &mut self,
        now: MonoNs,
        authenticated: bool,
        boundary_len: usize,
        parsed: (PacketHandle, WireHeader, Option<ControlMessage>),
    ) -> bool {
        if self.config.role != Role::Initiator || parsed.1.epoch != self.epoch {
            self.record_drop("invalid_accept");
            return false;
        }
        let Some(body) = parsed
            .2
            .as_ref()
            .and_then(|message| OpenStateBody::decode(&message.body))
        else {
            self.record_drop("malformed_accept");
            return false;
        };
        if body.profile_id != UDP_LI_PROFILE_ID
            || Some(body.nonce) != self.open_state.map(|open| open.nonce)
        {
            self.record_drop("accept_profile_mismatch");
            return false;
        }
        let ctrl_seq = parsed
            .2
            .as_ref()
            .expect("Accept branch has a control message")
            .link_seq()
            .expect("Accept has a link sequence");
        let disposition = self.control_replay.inspect(ctrl_seq);
        if disposition != ControlSeqDisposition::Accepted {
            return self.handle_rejected_control(
                now,
                authenticated,
                boundary_len,
                parsed.0,
                parsed.1,
                disposition,
            );
        }
        if self.association != AssociationState::Handshaking {
            self.record_drop("invalid_accept");
            return false;
        }
        let disposition = self.accept_control_seq(ctrl_seq);
        if disposition != ControlSeqDisposition::Accepted {
            return self.handle_rejected_control(
                now,
                authenticated,
                boundary_len,
                parsed.0,
                parsed.1,
                disposition,
            );
        }
        self.association = AssociationState::Established;
        self.accept_valid_datagram(
            now,
            authenticated,
            boundary_len,
            parsed.0,
            parsed.1,
            parsed.2,
            None,
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

        if control.as_ref().is_some_and(|control| {
            matches!(control.ctrl_type, ControlType::Open | ControlType::Accept)
        }) {
            return;
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

    fn handle_rejected_control(
        &mut self,
        now: MonoNs,
        authenticated: bool,
        boundary_len: usize,
        packet: PacketHandle,
        header: WireHeader,
        disposition: ControlSeqDisposition,
    ) -> bool {
        if header.payload_len == 0 {
            let reason = match disposition {
                ControlSeqDisposition::Duplicate => "replayed_control",
                ControlSeqDisposition::TooOld => "old_control",
                ControlSeqDisposition::Accepted => {
                    unreachable!("accepted control reached rejection handler")
                }
            };
            self.record_drop(reason);
            return false;
        }
        // First-copy-wins applies only to the control effect. Piggybacked user
        // data remains independent and is still delivered exactly as before.
        self.accept_valid_datagram(now, authenticated, boundary_len, packet, header, None, None);
        true
    }

    fn accept_control_seq(&mut self, ctrl_seq: u32) -> ControlSeqDisposition {
        self.control_replay.accept(ctrl_seq)
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
        SendClass::Association | SendClass::LinkControl => QosClass::Control,
    }
}

fn write_transmit_fields(header: &mut conet_core::HeaderBuf, link_seq: u32) {
    if header.len() != WIRE_HEADER_LEN {
        header.resize(WIRE_HEADER_LEN, 0);
    }
    let bytes = header.as_mut_bytes();
    bytes[4..8].copy_from_slice(&link_seq.to_be_bytes());
}

fn encoded_entry_len(
    packet: &PacketHandle,
    class: SendClass,
    control: Option<ControlSpec>,
    attached: Option<(&PacketHandle, Option<ControlSpec>)>,
    cc_bytes: Option<&[u8]>,
) -> usize {
    let body_len = if matches!(class, SendClass::Association | SendClass::LinkControl) {
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
    let body = if class == SendClass::Association || class == SendClass::LinkControl {
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
    if let ControlSpec::Link { ctrl_seq, .. } = spec {
        bytes.extend_from_slice(&ctrl_seq.to_be_bytes());
    }
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

fn nonce_from_id(id: u32) -> u64 {
    0x554c_4900_0000_0000 | u64::from(id)
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
    use crate::{Role, SimNetwork, SimTransport};
    use conet_core::{BlockId, Feedback};

    fn enqueue_stale_profile_items(endpoint: &mut UdpLiEndpoint<SimTransport>) {
        let mut file = bytes_packet(OpaqueBytes::from_static(b"stale-file"), WIRE_HEADER_LEN);
        endpoint.initialize_header(&mut file, QosClass::Bulk, Some(10));
        endpoint.file_queue.enqueue(file, None).unwrap();

        let mut feedback = bytes_packet(
            conet_core::encode_reliability_feedback(Feedback::ack(BlockId::new(9))).into(),
            WIRE_HEADER_LEN,
        );
        let feedback_len = feedback.len();
        endpoint.initialize_header(&mut feedback, QosClass::Feedback, Some(feedback_len));
        endpoint.feedback_queue.enqueue(feedback, None).unwrap();

        let mut control = bytes_packet(OpaqueBytes::from_static(b"stale-control"), WIRE_HEADER_LEN);
        endpoint.initialize_header(&mut control, QosClass::Control, Some(0));
        endpoint
            .link_control_queue
            .enqueue(
                control,
                Some(ControlSpec::Cc {
                    ctrl_type: ControlType::CcOpaque,
                }),
            )
            .unwrap();
    }

    #[test]
    fn close_and_fresh_start_cancel_leftover_profile_queues() {
        let network = SimNetwork::new();
        let old_id = 0x91_c0_ffee;
        let old_epoch = 7;
        let mut endpoint = UdpLiEndpoint::new(
            network.transport(0),
            EndpointConfig::new(Role::Initiator, u64::MAX),
        );
        endpoint.establish_for_test(old_id, old_epoch).unwrap();
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

        let close_frames = network.frames_from(0);
        assert_eq!(close_frames.len(), 1);
        let close = ReferenceWireCodec::default()
            .parse(OpaqueBytes::copy_from_slice(&close_frames[0].bytes))
            .unwrap();
        assert_eq!(close.header().flags.qos, QosClass::Control);
        assert_eq!(close.packet().header().len(), 12);
        assert_eq!(close.header().epoch, old_epoch);
        assert!(close.packet().payload_bytes().is_empty());
        assert_eq!(
            close.control().map(|control| control.ctrl_type),
            Some(ControlType::Close)
        );

        endpoint.association = AssociationState::Closed;
        enqueue_stale_profile_items(&mut endpoint);
        assert_eq!(endpoint.queued(SendClass::FileData), 1);
        assert_eq!(endpoint.queued(SendClass::Feedback), 1);
        assert_eq!(endpoint.queued(SendClass::LinkControl), 1);
        endpoint.drive(MonoNs::ZERO);
        assert_eq!(network.frames_from(0).len(), 1);

        endpoint.start_association().unwrap();
        let new_id = endpoint.association_id().unwrap();
        assert_ne!(new_id, old_id);
        assert_eq!(endpoint.cancelled_packets(), 6);
        assert_eq!(endpoint.queued(SendClass::FileData), 0);
        assert_eq!(endpoint.queued(SendClass::Feedback), 0);
        assert_eq!(endpoint.queued(SendClass::LinkControl), 0);
        endpoint.drive(MonoNs::new(1_000_000));
        endpoint.drive(MonoNs::new(2_000_000));

        let frames = network.frames_from(0);
        assert_eq!(frames.len(), 2);
        let open = ReferenceWireCodec::default()
            .parse(OpaqueBytes::copy_from_slice(&frames[1].bytes))
            .unwrap();
        assert_eq!(open.header().flags.qos, QosClass::Control);
        assert_eq!(open.packet().header().len(), 12);
        assert_eq!(open.header().epoch, 1);
        assert_eq!(
            open.control().map(|control| control.ctrl_type),
            Some(ControlType::Open)
        );
    }

    #[test]
    fn encode_entry_into_matches_the_allocating_reference() {
        let packet = payload_packet(b"payload");
        let attached_packet = payload_packet(b"attached");
        let attached_control = ControlSpec::Link {
            ctrl_type: ControlType::Close,
            ctrl_seq: 0x0102_0304,
        };

        let cases = [
            (SendClass::FileData, None, None, None),
            (
                SendClass::Feedback,
                Some(ControlSpec::Link {
                    ctrl_type: ControlType::Accept,
                    ctrl_seq: 7,
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
