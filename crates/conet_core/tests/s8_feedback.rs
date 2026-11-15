use conet_core::{
    paced_identity_link, BackingAccounting, BidirectionalAck, BlockId,
    BlockStatus, FeedbackKind, FeedbackResponderConfig, InProcessLink, LinkEndpoint, LinkReceiver,
    MonoNs, PacketHandle, PacketMetrics, PacketQueue, PayloadCopyCounter, QueueLimits,
    ReliabilityResponder, ReliabilitySender, SystematicBlockCodec,
};

const BLOCK: BlockId = BlockId::new(77);

type AckSender = ReliabilitySender<SystematicBlockCodec, BidirectionalAck>;
type AckResponder = ReliabilityResponder<SystematicBlockCodec>;

fn ms(value: i64) -> MonoNs {
    MonoNs::new(value * 1_000_000)
}

fn limits(packets: usize) -> QueueLimits {
    QueueLimits::new(packets, 8192, 8192).with_max_packet_bytes(256)
}

fn metrics(copies: &PayloadCopyCounter) -> PacketMetrics {
    PacketMetrics {
        backings: BackingAccounting::new(),
        payload_copies: copies.clone(),
    }
}

struct Harness {
    a: InProcessLink<conet_core::PacedIdentitySender, PacketQueue>,
    b: InProcessLink<conet_core::PacedIdentitySender, PacketQueue>,
    forward_out: conet_core::IdentityReceiver,
    reverse_out: conet_core::IdentityReceiver,
}

impl Harness {
    fn new() -> Self {
        let (a_out, forward_out) = paced_identity_link(limits(32), 1_000_000);
        let (b_out, reverse_out) = paced_identity_link(limits(32), 1_000_000);
        Self {
            a: InProcessLink::new(a_out, PacketQueue::new(limits(32))),
            b: InProcessLink::new(b_out, PacketQueue::new(limits(32))),
            forward_out,
            reverse_out,
        }
    }

    fn move_forward(&mut self, now: MonoNs) -> usize {
        self.a.drive(now);
        let mut moved = 0;
        while let Some(pkt) = self.forward_out.recv() {
            self.b
                .incoming_mut()
                .enqueue(pkt)
                .expect("B receive queue has capacity");
            moved += 1;
        }
        moved
    }

    fn move_reverse(&mut self, now: MonoNs) -> Vec<PacketHandle> {
        self.b.drive(now);
        let mut moved = Vec::new();
        while let Some(pkt) = self.reverse_out.recv() {
            moved.push(pkt);
        }
        moved
    }

    fn inject_feedback(&mut self, pkt: PacketHandle) {
        self.a
            .incoming_mut()
            .enqueue(pkt)
            .expect("A reverse queue has capacity");
    }

    fn inject_bad_reverse_data(&mut self, pkt: PacketHandle) {
        self.b
            .incoming_mut()
            .enqueue(pkt)
            .expect("B receive queue has capacity");
    }
}

fn make_sender(policy: BidirectionalAck, staged: usize) -> (AckSender, PayloadCopyCounter, usize) {
    let copies = PayloadCopyCounter::new();
    let mut encoder = SystematicBlockCodec::new(4, copies.clone()).unwrap();
    let shape = encoder
        .add_block(BLOCK, b"ack-drain-object".to_vec())
        .unwrap();
    let mut sender = ReliabilitySender::new(encoder, policy, limits(32), metrics(&copies));
    sender.register_block(BLOCK, MonoNs::ZERO).unwrap();
    assert_eq!(sender.stage(MonoNs::ZERO, staged).generated, staged);
    (sender, copies, shape.source_symbols as usize)
}

fn make_responder(config: FeedbackResponderConfig) -> AckResponder {
    ReliabilityResponder::new(
        SystematicBlockCodec::new(4, PayloadCopyCounter::new()).unwrap(),
        config,
        limits(32),
    )
}

fn success_config() -> FeedbackResponderConfig {
    FeedbackResponderConfig {
        ack_repeats: 3,
        ack_interval: ms(50),
        nack_interval: None,
        requested_additional: 0,
    }
}

fn send_until_recovered(
    harness: &mut Harness,
    sender: &mut AckSender,
    responder: &mut AckResponder,
    start: MonoNs,
) -> (MonoNs, Vec<PacketHandle>) {
    let mut now = start;
    for step in 0..4 {
        now = start.saturating_add(ms(step * 10));
        let pump = sender.pump_bidirectional(&mut harness.a, now, 0, 1);
        assert_eq!(pump.enqueued, 1);
        assert_eq!(harness.move_forward(now), 1);
        responder.pump(&mut harness.b, now, 16, 16);
    }
    assert!(responder.is_recovered(BLOCK));
    let acks = harness.move_reverse(now);
    assert_eq!(acks.len(), 1);
    (now, acks)
}

#[test]
fn t5_m5_ack_drains_unsent_once_and_preserves_in_flight() {
    let mut harness = Harness::new();
    let (mut sender, copies, source_symbols) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    assert_eq!(source_symbols, 4);
    let mut responder = make_responder(success_config());
    let (recovery_at, mut feedback) =
        send_until_recovered(&mut harness, &mut sender, &mut responder, MonoNs::ZERO);

    // Queue one more symbol in the link before processing the ACK. This handle
    // is already in flight and must not be recalled by the core's drain.
    let flush = sender.pump_bidirectional(&mut harness.a, recovery_at, 0, 1);
    assert_eq!(flush.enqueued, 1);
    assert_eq!(harness.a.outgoing().occupancy().count, 1);

    let ack = feedback.pop().unwrap();
    harness.inject_feedback(ack);
    let ack_report = sender.pump_bidirectional(&mut harness.a, recovery_at, 0, 0);
    assert_eq!(ack_report.acked, 1);
    assert_eq!(ack_report.cancelled, 3);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));
    assert_eq!(sender.staged_packets(), 0);
    assert_eq!(
        harness.a.outgoing().occupancy().count,
        1,
        "an in-flight link packet is not recalled"
    );

    let cancelled = sender.take_cancelled();
    assert_eq!(cancelled.len(), 3);
    let mut ids: Vec<_> = cancelled.iter().map(PacketHandle::backing_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3, "each unsent handle is returned once");
    assert!(sender.take_cancelled().is_empty());

    let in_flight_at = recovery_at.saturating_add(ms(10));
    assert_eq!(harness.move_forward(in_flight_at), 1);
    let after_ack = responder.pump(&mut harness.b, in_flight_at, 16, 16);
    assert_eq!(after_ack.duplicates, 1);
    assert_eq!(harness.a.outgoing().occupancy().count, 0);

    let no_generation = sender.stage(recovery_at.saturating_add(ms(1)), 8);
    assert_eq!(no_generation.generated, 0);
    assert_eq!(copies.count(), 8);

    let duplicate_at = recovery_at.saturating_add(ms(50));
    responder.pump(&mut harness.b, duplicate_at, 0, 16);
    let mut duplicates = harness.move_reverse(duplicate_at);
    assert_eq!(duplicates.len(), 1);
    harness.inject_feedback(duplicates.pop().unwrap());
    let duplicate_report = sender.pump_bidirectional(&mut harness.a, duplicate_at, 0, 0);
    assert_eq!(duplicate_report.duplicate_acks, 1);
    assert_eq!(duplicate_report.cancelled, 0);
    assert_eq!(duplicate_report.generated, 0);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));
    assert!(sender.take_cancelled().is_empty());

    let delivered_at = recovery_at.saturating_add(ms(2_000));
    let completion = sender.stage(delivered_at, 8);
    assert_eq!(completion.generated, 0);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Delivered));
}

#[test]
fn t6_lost_ack_repeat_stops_and_all_acks_dropped_ends_without_ack() {
    // An immediate ACK is dropped on the feedback-only path; the finite repeat
    // reaches the sender and stops generation.
    let mut harness = Harness::new();
    let (mut sender, _copies, _) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(success_config());
    let (recovery_at, _first_ack) =
        send_until_recovered(&mut harness, &mut sender, &mut responder, MonoNs::ZERO);
    // _first_ack was deliberately removed from the reverse path above.
    let repeat_at = recovery_at.saturating_add(ms(50));
    let generated = responder.pump(&mut harness.b, repeat_at, 0, 16);
    assert_eq!(generated.acks_generated, 1);
    let mut repeat = harness.move_reverse(repeat_at);
    assert_eq!(repeat.len(), 1);
    harness.inject_feedback(repeat.pop().unwrap());
    let stop = sender.pump_bidirectional(&mut harness.a, repeat_at, 0, 0);
    assert_eq!(stop.acked, 1);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));

    // A fresh transfer delivers forward data but drops every reverse ACK. The
    // sender remains responsible for finite budget-based termination.
    let mut harness = Harness::new();
    let budget = 6;
    let (mut sender, _copies, source_symbols) =
        make_sender(BidirectionalAck::new(budget, ms(2_000)), budget as usize);
    assert!(budget as usize > source_symbols);
    let mut responder = make_responder(success_config());
    let mut dropped = 0;
    let mut now = MonoNs::ZERO;
    for step in 0..source_symbols {
        now = ms(step as i64 * 10);
        sender.pump_bidirectional(&mut harness.a, now, 0, 1);
        harness.move_forward(now);
        responder.pump(&mut harness.b, now, 16, 16);
        dropped += harness.move_reverse(now).len();
    }
    assert!(responder.is_recovered(BLOCK));
    assert!(dropped >= 1);

    let linger_at = now.saturating_add(ms(1));
    let linger = sender.stage(linger_at, 4);
    assert_eq!(linger.generated, 0);
    assert_eq!(linger.cancelled, 2);
    assert_eq!(sender.take_cancelled().len(), 2);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::LingerWithoutAck));
    let stopped_at = linger_at.saturating_add(ms(2_000));
    assert_eq!(sender.stage(stopped_at, 4).generated, 0);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::StoppedWithoutAck));
}

#[test]
fn t6_ack_has_three_finite_repeats_and_no_resent_until_ack_loop() {
    let mut harness = Harness::new();
    let (mut sender, _copies, _) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(success_config());
    let (recovery_at, immediate) =
        send_until_recovered(&mut harness, &mut sender, &mut responder, MonoNs::ZERO);
    assert_eq!(immediate.len(), 1);

    let mut total = 1;
    for repeat in 1..=3 {
        let at = recovery_at.saturating_add(ms(repeat * 50));
        responder.pump(&mut harness.b, at, 0, 16);
        total += harness.move_reverse(at).len();
    }
    let after_cap = recovery_at.saturating_add(ms(200));
    let cap_report = responder.pump(&mut harness.b, after_cap, 0, 16);
    assert_eq!(cap_report.acks_generated, 0);
    assert!(harness.move_reverse(after_cap).is_empty());
    assert_eq!(total, 4, "immediate ACK plus exactly three duplicates");
}

#[test]
fn t7_duplicate_ack_does_not_double_cancel_or_reopen_block() {
    let mut harness = Harness::new();
    let (mut sender, _copies, _) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(FeedbackResponderConfig {
        ack_repeats: 2,
        ..success_config()
    });
    let (recovery_at, mut feedback) =
        send_until_recovered(&mut harness, &mut sender, &mut responder, MonoNs::ZERO);
    harness.inject_feedback(feedback.pop().unwrap());
    let first = sender.pump_bidirectional(&mut harness.a, recovery_at, 0, 0);
    assert_eq!(first.acked, 1);
    assert_eq!(first.cancelled, 4);
    assert_eq!(sender.take_cancelled().len(), 4);
    assert_eq!(sender.generated_symbols(BLOCK), Some(8));

    let duplicate_at = recovery_at.saturating_add(ms(50));
    responder.pump(&mut harness.b, duplicate_at, 0, 16);
    let mut duplicate = harness.move_reverse(duplicate_at);
    assert_eq!(duplicate.len(), 1);
    harness.inject_feedback(duplicate.pop().unwrap());
    let second = sender.pump_bidirectional(&mut harness.a, duplicate_at, 8, 8);
    assert_eq!(second.duplicate_acks, 1);
    assert_eq!(second.cancelled, 0);
    assert_eq!(second.generated, 0);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));
    assert_eq!(sender.generated_symbols(BLOCK), Some(8));
    assert!(sender.take_cancelled().is_empty());
}

#[test]
fn t18_nack_before_ack_keeps_sending_and_reordered_stale_nack_is_ignored() {
    let mut harness = Harness::new();
    let (mut sender, _copies, _) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(FeedbackResponderConfig {
        ack_repeats: 1,
        ack_interval: ms(50),
        nack_interval: Some(ms(100)),
        requested_additional: 2,
    });

    let pump = sender.pump_bidirectional(&mut harness.a, MonoNs::ZERO, 0, 1);
    assert_eq!(pump.enqueued, 1);
    assert_eq!(harness.move_forward(MonoNs::ZERO), 1);
    let response = responder.pump(&mut harness.b, MonoNs::ZERO, 16, 16);
    assert_eq!(response.nacks_generated, 1);
    let mut reverse = harness.move_reverse(MonoNs::ZERO);
    assert_eq!(reverse.len(), 1);
    let nack = reverse.pop().unwrap();
    let stale_nack = nack.fanout();
    harness.inject_feedback(nack);
    let nack_report = sender.receive_feedback(harness.a.incoming(), ms(1), 16);
    assert_eq!(nack_report.nacked, 1);
    let hint = nack_report.last_feedback.unwrap();
    assert_eq!(hint.kind, FeedbackKind::Nack);
    assert_eq!(hint.requested_additional, 2);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Sending));

    let mut now = MonoNs::ZERO;
    for step in 1..4 {
        now = ms(step * 10);
        sender.pump_bidirectional(&mut harness.a, now, 0, 1);
        harness.move_forward(now);
        responder.pump(&mut harness.b, now, 16, 16);
    }
    assert!(responder.is_recovered(BLOCK));
    let mut ack = harness.move_reverse(now);
    assert_eq!(ack.len(), 1);
    let ack_packet = ack.pop().unwrap();
    let ack_copy = ack_packet.fanout();
    harness.inject_feedback(ack_packet);
    let ack_report = sender.receive_feedback(harness.a.incoming(), now, 16);
    assert_eq!(ack_report.acked, 1);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));

    // Reordering the reverse path delivers a stale NACK after the ACK.
    harness.inject_feedback(stale_nack);
    let stale = sender.receive_feedback(harness.a.incoming(), now, 16);
    assert_eq!(stale.nacked, 0);
    assert_eq!(stale.ignored, 1);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));

    // Delivering an ACK back to the responder is not forward data and creates
    // no ACK-of-ACK.
    harness.inject_bad_reverse_data(ack_copy);
    let no_nested = responder.pump(&mut harness.b, now, 16, 0);
    assert_eq!(no_nested.received, 1);
    assert_eq!(no_nested.ignored, 1);
    assert_eq!(no_nested.acks_generated, 0);
}

