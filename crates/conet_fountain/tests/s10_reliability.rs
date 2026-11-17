use conet_core::{
    BackingAccounting, BidirectionalAck, BlockId, BlockStatus, Clock, FeedbackKind,
    FeedbackResponderConfig, IdentityReceiver, InProcessLink, LinkEndpoint, LinkReceiver, MonoNs,
    PacketHandle, PacketMetrics, PacketQueue, PayloadCopyCounter, QueueLimits,
    ReliabilityResponder, ReliabilitySender, VirtualClock, paced_identity_link,
};
use conet_fountain::{FountainBlockCodec, FountainCodecConfig};

const BLOCK: BlockId = BlockId::new(77);
const SYMBOL_LEN: usize = 8;

type AckSender = ReliabilitySender<FountainBlockCodec, BidirectionalAck>;
type AckResponder = ReliabilityResponder<FountainBlockCodec>;

fn ms(value: i64) -> MonoNs {
    MonoNs::new(value * 1_000_000)
}

fn limits(packets: usize) -> QueueLimits {
    QueueLimits::new(packets, 8192, 8192).with_max_packet_bytes(256)
}

fn codec() -> FountainBlockCodec {
    FountainBlockCodec::new(
        FountainCodecConfig {
            symbol_len: SYMBOL_LEN,
            minimum_source_symbols: 4,
        },
        PayloadCopyCounter::new(),
    )
    .unwrap()
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
    forward_out: IdentityReceiver,
    reverse_out: IdentityReceiver,
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

fn make_sender(policy: BidirectionalAck, staged: usize) -> (AckSender, PayloadCopyCounter) {
    let mut encoder = codec();
    let copies = encoder.copies().clone();
    encoder
        .add_block(BLOCK, b"raptor-ack-drain-object".to_vec())
        .unwrap();
    let mut sender = ReliabilitySender::new(encoder, policy, limits(32), metrics(&copies));
    sender.register_block(BLOCK, MonoNs::ZERO).unwrap();
    assert_eq!(sender.stage(MonoNs::ZERO, staged).generated, staged);
    (sender, copies)
}

fn make_responder(config: FeedbackResponderConfig) -> AckResponder {
    ReliabilityResponder::new(codec(), config, limits(32))
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
fn t1_one_way_with_raptor10_recovers_and_stops_on_budget() {
    let block = BlockId::new(42);
    let object = b"one-way-raptor-object-recovered".to_vec();
    let mut encoder = codec();
    let encode_copies = encoder.copies().clone();
    let shape = encoder.add_block(block, object.clone()).unwrap();
    let mut sender = ReliabilitySender::new(
        encoder,
        conet_core::OneWayBudget::new(shape.source_symbols as u64 + 2),
        limits(16),
        metrics(&encode_copies),
    );
    sender.register_block(block, MonoNs::ZERO).unwrap();

    let (mut link, mut receiver) = paced_identity_link(limits(16), 1_000);
    let mut receiver_core = conet_core::ReliabilityReceiver::new(codec());
    let clock = VirtualClock::new(MonoNs::ZERO);
    let budget = shape.source_symbols as u64 + 2;
    for tick in 0..=budget {
        clock
            .drive(MonoNs::new((tick as i64) * 10_000_000))
            .unwrap();
        sender.pump(&mut link, clock.now(), 1, 1);
        let _ = link.drive(clock.now());
        receiver_core.drain(&mut receiver);
    }

    assert_eq!(
        sender.status(block),
        Some(BlockStatus::StoppedByBudget),
        "one-way policy must not treat feedback as success"
    );
    assert!(receiver_core.is_recovered(block));
    assert_eq!(receiver_core.take_recovered_block(block).unwrap(), object);
    assert!(encode_copies.count() >= shape.source_symbols as u64);
}

#[test]
fn t5_m5_raptor10_ack_drains_unsent_once_and_preserves_in_flight() {
    let mut harness = Harness::new();
    let (mut sender, copies) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(success_config());
    let (recovery_at, mut feedback) =
        send_until_recovered(&mut harness, &mut sender, &mut responder, MonoNs::ZERO);

    let flush = sender.pump_bidirectional(&mut harness.a, recovery_at, 0, 1);
    assert_eq!(flush.enqueued, 1);
    harness.inject_feedback(feedback.pop().unwrap());
    let ack_report = sender.pump_bidirectional(&mut harness.a, recovery_at, 0, 0);
    assert_eq!(ack_report.acked, 1);
    assert_eq!(ack_report.cancelled, 3);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));
    assert_eq!(sender.staged_packets(), 0);
    assert_eq!(harness.a.outgoing().occupancy().count, 1);

    let cancelled = sender.take_cancelled();
    assert_eq!(cancelled.len(), 3);
    let mut ids: Vec<_> = cancelled.iter().map(PacketHandle::backing_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3);
    assert!(sender.take_cancelled().is_empty());

    let in_flight_at = recovery_at.saturating_add(ms(10));
    assert_eq!(harness.move_forward(in_flight_at), 1);
    let after_ack = responder.pump(&mut harness.b, in_flight_at, 16, 16);
    assert_eq!(after_ack.duplicates, 1);
    assert_eq!(harness.a.outgoing().occupancy().count, 0);
    assert_eq!(
        sender.stage(recovery_at.saturating_add(ms(1)), 8).generated,
        0
    );
    assert_eq!(copies.count(), 8);

    let delivered_at = recovery_at.saturating_add(ms(2_000));
    sender.stage(delivered_at, 8);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Delivered));
}

#[test]
fn t6_raptor10_lost_ack_repeats_and_all_acks_dropped_ends_without_ack() {
    let mut harness = Harness::new();
    let (mut sender, _) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(success_config());
    let (recovery_at, _first_ack) =
        send_until_recovered(&mut harness, &mut sender, &mut responder, MonoNs::ZERO);
    let repeat_at = recovery_at.saturating_add(ms(50));
    assert_eq!(
        responder
            .pump(&mut harness.b, repeat_at, 0, 16)
            .acks_generated,
        1
    );
    let mut repeat = harness.move_reverse(repeat_at);
    assert_eq!(repeat.len(), 1);
    harness.inject_feedback(repeat.pop().unwrap());
    assert_eq!(
        sender
            .pump_bidirectional(&mut harness.a, repeat_at, 0, 0)
            .acked,
        1
    );
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));

    let mut harness = Harness::new();
    let (mut sender, _) = make_sender(BidirectionalAck::new(6, ms(2_000)), 6);
    let mut responder = make_responder(success_config());
    let mut now = MonoNs::ZERO;
    for step in 0..4 {
        now = ms(step * 10);
        sender.pump_bidirectional(&mut harness.a, now, 0, 1);
        harness.move_forward(now);
        responder.pump(&mut harness.b, now, 16, 16);
        let _ = harness.move_reverse(now);
    }
    assert!(responder.is_recovered(BLOCK));
    let linger = sender.stage(now.saturating_add(ms(1)), 4);
    assert_eq!(linger.cancelled, 2);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::LingerWithoutAck));
    sender.stage(now.saturating_add(ms(2_001)), 4);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::StoppedWithoutAck));
}

#[test]
fn t7_duplicate_raptor10_ack_does_not_double_cancel_or_reopen() {
    let mut harness = Harness::new();
    let (mut sender, _) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(FeedbackResponderConfig {
        ack_repeats: 2,
        ..success_config()
    });
    let (recovery_at, mut feedback) =
        send_until_recovered(&mut harness, &mut sender, &mut responder, MonoNs::ZERO);
    harness.inject_feedback(feedback.pop().unwrap());
    assert_eq!(
        sender
            .pump_bidirectional(&mut harness.a, recovery_at, 0, 0)
            .cancelled,
        4
    );
    assert_eq!(sender.take_cancelled().len(), 4);

    let duplicate_at = recovery_at.saturating_add(ms(50));
    responder.pump(&mut harness.b, duplicate_at, 0, 16);
    let mut duplicate = harness.move_reverse(duplicate_at);
    harness.inject_feedback(duplicate.pop().unwrap());
    let second = sender.pump_bidirectional(&mut harness.a, duplicate_at, 8, 8);
    assert_eq!(second.duplicate_acks, 1);
    assert_eq!(second.cancelled, 0);
    assert_eq!(second.generated, 0);
    assert_eq!(sender.status(BLOCK), Some(BlockStatus::Acked));
}

#[test]
fn t18_raptor10_nack_continues_and_never_creates_ack_of_ack() {
    let mut harness = Harness::new();
    let (mut sender, _) = make_sender(BidirectionalAck::new(12, ms(2_000)), 8);
    let mut responder = make_responder(FeedbackResponderConfig {
        ack_repeats: 1,
        ack_interval: ms(50),
        nack_interval: Some(ms(100)),
        requested_additional: 2,
    });

    sender.pump_bidirectional(&mut harness.a, MonoNs::ZERO, 0, 1);
    harness.move_forward(MonoNs::ZERO);
    responder.pump(&mut harness.b, MonoNs::ZERO, 16, 16);
    let mut reverse = harness.move_reverse(MonoNs::ZERO);
    let nack = reverse.pop().unwrap();
    let stale_nack = nack.fanout();
    harness.inject_feedback(nack);
    let nack_report = sender.receive_feedback(harness.a.incoming(), ms(1), 16);
    assert_eq!(nack_report.nacked, 1);
    assert_eq!(nack_report.last_feedback.unwrap().kind, FeedbackKind::Nack);
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
    let ack_packet = ack.pop().unwrap();
    let ack_copy = ack_packet.fanout();
    harness.inject_feedback(ack_packet);
    assert_eq!(
        sender.receive_feedback(harness.a.incoming(), now, 16).acked,
        1
    );

    harness.inject_feedback(stale_nack);
    assert_eq!(
        sender
            .receive_feedback(harness.a.incoming(), now, 16)
            .nacked,
        0
    );
    harness.inject_bad_reverse_data(ack_copy);
    let no_nested = responder.pump(&mut harness.b, now, 16, 0);
    assert_eq!(no_nested.ignored, 1);
    assert_eq!(no_nested.acks_generated, 0);
}
