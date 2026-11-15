//! Paced in-process datagram links.
//!
//! The link owns the queue and applies a [`RatePacer`]. A producer enqueues an
//! owned handle; [`Drive`] advances virtual time and moves ready handles to the
//! sink without changing payload backing. [`PacketClass`] is only a minimal
//! scheduler/accounting tag: all classes debit the same pacer budget.

use std::collections::VecDeque;

use crate::clock::{Drive, MonoNs};
use crate::control::{
    AppliedDecision, OpaqueBytes, Pace, RateControlPolicy, TxController, apply_controller_decision,
};
use crate::link::{IdentityReceiver, IdentitySender, LinkSender, identity_link};
use crate::pacing::{ByteRate, DiscreteRatePacer, RatePacer};
use crate::packet::{BackingId, PacketHandle};
use crate::queue::{EnqueueError, EnqueueStatus, Occupancy, PacketQueue, QueueLimits};

/// Capabilities exposed by an in-process link implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkCaps {
    pub lossy_datagram: bool,
    pub integrity_assured: bool,
    pub paced: bool,
    pub observations: bool,
}

impl LinkCaps {
    /// The S4 identity pipe: datagrams stay in-process and no pacer is applied.
    pub const UNPACED_IN_PROCESS: Self = Self {
        lossy_datagram: true,
        integrity_assured: true,
        paced: false,
        observations: false,
    };

    /// The S5 paced simulator/device-stub links.
    pub const PACED_IN_PROCESS: Self = Self {
        lossy_datagram: true,
        integrity_assured: true,
        paced: true,
        observations: false,
    };
}

/// Minimal class tag used to demonstrate one shared pacing budget.
///
/// This is deliberately not a policy hierarchy. Future profiles may map their
/// own scheduler classes onto these or a richer profile-local tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketClass {
    Data,
    Control,
}

/// One successful grant and transfer to the downstream sink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendRecord {
    pub at: MonoNs,
    pub bytes: u64,
    pub class: PacketClass,
    pub backing_id: BackingId,
    /// Pacer deadline after this grant was charged.
    pub ready_at: MonoNs,
}

/// Paced in-process sender used as the simulator link in S5.
///
/// The queue stores class tags separately from the owned packet handles. A
/// successful drive step moves the original handle to the sink, so the payload
/// backing and in-process copy count are unchanged.
pub struct PacedIdentitySender {
    output: IdentitySender,
    queue: PacketQueue,
    classes: VecDeque<PacketClass>,
    pacer: Box<dyn RatePacer>,
    inflight_limit_bytes: Option<u64>,
    sent: Vec<SendRecord>,
}

impl PacedIdentitySender {
    pub const fn caps(&self) -> LinkCaps {
        LinkCaps::PACED_IN_PROCESS
    }

    /// Enqueue a handle with an explicit minimal class tag.
    pub fn enqueue_class(
        &mut self,
        class: PacketClass,
        pkt: PacketHandle,
    ) -> Result<EnqueueStatus, EnqueueError> {
        if !self.output.is_open() {
            return Err(EnqueueError::Closed { pkt });
        }
        let status = self.queue.enqueue(pkt)?;
        self.classes.push_back(class);
        Ok(status)
    }

    pub fn would_accept(&self, pkt: &PacketHandle) -> Result<(), crate::queue::EnqueueErrorKind> {
        if !self.output.is_open() {
            return Err(crate::queue::EnqueueErrorKind::Closed);
        }
        self.queue.would_accept(pkt)
    }

    pub fn occupancy(&self) -> Occupancy {
        self.queue.occupancy()
    }

    pub fn target_rate(&self) -> ByteRate {
        self.pacer.target_rate()
    }

    pub fn ready_at(&self) -> MonoNs {
        self.pacer.ready_at()
    }

    /// The pacer deadline when at least one send is waiting.
    pub fn next_drive(&self) -> Option<MonoNs> {
        (!self.queue.is_empty()).then(|| self.pacer.ready_at())
    }

    /// This transport has no controller hook deadline of its own.
    pub const fn next_wakeup(&self) -> Option<MonoNs> {
        None
    }

    pub fn set_target_rate(&mut self, bytes_per_sec: ByteRate) {
        self.pacer.set_target_rate(bytes_per_sec);
    }

    /// The accepted controller inflight/window cap.
    ///
    /// The in-process link exposes this port but does not yet maintain an ACK
    /// ledger, so it cannot enforce inflight admission in this slice.
    pub const fn inflight_limit_bytes(&self) -> Option<u64> {
        self.inflight_limit_bytes
    }

    /// Records returned by successful drive steps, oldest first.
    pub fn sent(&self) -> &[SendRecord] {
        &self.sent
    }

    /// Apply a controller pace through the profile security rule.
    pub fn apply_pace(&mut self, pace: Pace, policy: RateControlPolicy) -> AppliedDecision {
        apply_controller_decision(
            self.pacer.as_mut(),
            &mut self.inflight_limit_bytes,
            pace,
            policy,
        )
    }

    /// Deliver an admitted opaque control body and read the resulting pace.
    pub fn handle_peer_control(
        &mut self,
        controller: &mut dyn TxController,
        now: MonoNs,
        body: OpaqueBytes,
        policy: RateControlPolicy,
    ) -> AppliedDecision {
        controller.on_peer_control(now, body);
        self.apply_pace(controller.pace(), policy)
    }

    /// Run the controller's single clock entry and apply its pace.
    pub fn handle_clock(
        &mut self,
        controller: &mut dyn TxController,
        now: MonoNs,
        policy: RateControlPolicy,
    ) -> AppliedDecision {
        controller.on_clock(now);
        self.apply_pace(controller.pace(), policy)
    }

    /// Move every packet that is currently ready, then stop at backpressure or
    /// the next pacer deadline.
    pub fn drive(&mut self, now: MonoNs) -> Vec<SendRecord> {
        let start = self.sent.len();
        while let Some(pkt) = self.queue.front() {
            if self.output.would_accept(pkt).is_err() {
                break;
            }
            let bytes = pkt.len() as u64;
            if !self.pacer.try_consume(now, bytes) {
                break;
            }

            let class = self
                .classes
                .pop_front()
                .expect("every queued handle has one class tag");
            let pkt = self
                .queue
                .dequeue()
                .expect("front was checked before dequeue");
            let backing_id = pkt.backing_id();
            self.output
                .enqueue(pkt)
                .expect("downstream admission was preflighted");
            self.sent.push(SendRecord {
                at: now,
                bytes,
                class,
                backing_id,
                ready_at: self.pacer.ready_at(),
            });
        }
        self.sent[start..].to_vec()
    }
}

impl LinkSender for PacedIdentitySender {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        self.enqueue_class(PacketClass::Data, pkt)
    }

    fn occupancy(&self) -> Occupancy {
        self.queue.occupancy()
    }

    fn close(&mut self) {
        self.queue.close();
        self.output.close();
    }
}

impl Drive for PacedIdentitySender {
    type Output = Vec<SendRecord>;

    fn drive(&mut self, now: MonoNs) -> Self::Output {
        PacedIdentitySender::drive(self, now)
    }

    fn next_drive(&self) -> Option<MonoNs> {
        PacedIdentitySender::next_drive(self)
    }
}

/// Second in-process link shape used by the G4 pacer-reuse composition.
///
/// It intentionally delegates to the same pacing core as the simulator link;
/// only the transport stub identity differs.
pub struct DeviceStubSender {
    inner: PacedIdentitySender,
}

impl DeviceStubSender {
    pub const fn caps(&self) -> LinkCaps {
        LinkCaps::PACED_IN_PROCESS
    }

    pub fn enqueue_class(
        &mut self,
        class: PacketClass,
        pkt: PacketHandle,
    ) -> Result<EnqueueStatus, EnqueueError> {
        self.inner.enqueue_class(class, pkt)
    }

    pub fn would_accept(&self, pkt: &PacketHandle) -> Result<(), crate::queue::EnqueueErrorKind> {
        self.inner.would_accept(pkt)
    }

    pub fn target_rate(&self) -> ByteRate {
        self.inner.target_rate()
    }

    pub fn ready_at(&self) -> MonoNs {
        self.inner.ready_at()
    }

    pub fn next_drive(&self) -> Option<MonoNs> {
        self.inner.next_drive()
    }

    pub const fn next_wakeup(&self) -> Option<MonoNs> {
        self.inner.next_wakeup()
    }

    pub fn set_target_rate(&mut self, bytes_per_sec: ByteRate) {
        self.inner.set_target_rate(bytes_per_sec);
    }

    pub const fn inflight_limit_bytes(&self) -> Option<u64> {
        self.inner.inflight_limit_bytes()
    }

    pub fn sent(&self) -> &[SendRecord] {
        self.inner.sent()
    }

    pub fn apply_pace(&mut self, pace: Pace, policy: RateControlPolicy) -> AppliedDecision {
        self.inner.apply_pace(pace, policy)
    }

    pub fn handle_peer_control(
        &mut self,
        controller: &mut dyn TxController,
        now: MonoNs,
        body: OpaqueBytes,
        policy: RateControlPolicy,
    ) -> AppliedDecision {
        self.inner
            .handle_peer_control(controller, now, body, policy)
    }

    pub fn handle_clock(
        &mut self,
        controller: &mut dyn TxController,
        now: MonoNs,
        policy: RateControlPolicy,
    ) -> AppliedDecision {
        self.inner.handle_clock(controller, now, policy)
    }

    pub fn drive(&mut self, now: MonoNs) -> Vec<SendRecord> {
        self.inner.drive(now)
    }
}

impl LinkSender for DeviceStubSender {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        self.inner.enqueue(pkt)
    }

    fn occupancy(&self) -> Occupancy {
        self.inner.occupancy()
    }

    fn close(&mut self) {
        self.inner.close();
    }
}

impl Drive for DeviceStubSender {
    type Output = Vec<SendRecord>;

    fn drive(&mut self, now: MonoNs) -> Self::Output {
        DeviceStubSender::drive(self, now)
    }

    fn next_drive(&self) -> Option<MonoNs> {
        DeviceStubSender::next_drive(self)
    }
}

/// Build a paced simulator-style in-process link with the discrete pacer.
pub fn paced_identity_link(
    limits: QueueLimits,
    bytes_per_sec: ByteRate,
) -> (PacedIdentitySender, IdentityReceiver) {
    paced_identity_link_with_pacer(limits, Box::new(DiscreteRatePacer::new(bytes_per_sec)))
}

/// Build a paced simulator link with a caller-supplied pacer implementation.
pub fn paced_identity_link_with_pacer(
    limits: QueueLimits,
    pacer: Box<dyn RatePacer>,
) -> (PacedIdentitySender, IdentityReceiver) {
    let (output, receiver) = identity_link(limits);
    (
        PacedIdentitySender {
            output,
            queue: PacketQueue::new(limits),
            classes: VecDeque::new(),
            pacer,
            inflight_limit_bytes: None,
            sent: Vec::new(),
        },
        receiver,
    )
}

/// Build the second in-process device-stub link with the same discrete pacer.
pub fn device_stub_link(
    limits: QueueLimits,
    bytes_per_sec: ByteRate,
) -> (DeviceStubSender, IdentityReceiver) {
    device_stub_link_with_pacer(limits, Box::new(DiscreteRatePacer::new(bytes_per_sec)))
}

/// Build a device-stub link with a caller-supplied pacer implementation.
pub fn device_stub_link_with_pacer(
    limits: QueueLimits,
    pacer: Box<dyn RatePacer>,
) -> (DeviceStubSender, IdentityReceiver) {
    let (inner, receiver) = paced_identity_link_with_pacer(limits, pacer);
    (DeviceStubSender { inner }, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketBuilder;

    fn packet(len: usize) -> PacketHandle {
        let mut builder = PacketBuilder::with_capacity(len, 0);
        builder.payload_mut().fill(0x5a);
        builder.freeze()
    }

    #[test]
    fn device_stub_and_simulator_share_the_same_discrete_timing() {
        let rate = 1_000;
        let (mut simulator, _sim_sink) =
            paced_identity_link(QueueLimits::new(4, 8_192, 8_192), rate);
        let (mut device, _dev_sink) = device_stub_link(QueueLimits::new(4, 8_192, 8_192), rate);
        simulator.enqueue(packet(1_000)).unwrap();
        device.enqueue(packet(1_000)).unwrap();

        assert_eq!(simulator.drive(MonoNs::ZERO).len(), 1);
        assert_eq!(device.drive(MonoNs::ZERO).len(), 1);
        assert!(simulator.drive(MonoNs::new(999_999_999)).is_empty());
        assert!(device.drive(MonoNs::new(999_999_999)).is_empty());
        assert_eq!(simulator.ready_at(), device.ready_at());
        assert_eq!(simulator.ready_at(), MonoNs::new(1_000_000_000));
    }

    #[test]
    fn paced_senders_expose_only_waiting_send_deadlines() {
        let (mut sender, _sink) = paced_identity_link(QueueLimits::new(4, 8_192, 8_192), 1_000);
        let (mut device, _device_sink) = device_stub_link(QueueLimits::new(4, 8_192, 8_192), 1_000);

        assert_eq!(sender.next_drive(), None);
        assert_eq!(device.next_drive(), None);

        sender.enqueue(packet(1_000)).unwrap();
        device.enqueue(packet(1_000)).unwrap();
        let deadline = MonoNs::new(1_000_000_000);
        assert_eq!(sender.next_drive(), Some(MonoNs::ZERO));
        assert_eq!(device.next_drive(), Some(MonoNs::ZERO));
        assert_eq!(sender.next_wakeup(), None);
        assert_eq!(device.next_wakeup(), None);

        assert_eq!(sender.drive(MonoNs::ZERO).len(), 1);
        assert_eq!(device.drive(MonoNs::ZERO).len(), 1);
        assert_eq!(sender.next_drive(), None);
        assert_eq!(device.next_drive(), None);
        assert_eq!(sender.ready_at(), deadline);
        assert_eq!(device.ready_at(), deadline);
    }
}
