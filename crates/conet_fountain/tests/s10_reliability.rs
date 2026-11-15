use conet_core::{
    BackingAccounting, BidirectionalAck, BlockId, BlockStatus, Clock, FeedbackResponderConfig,
    IdentityReceiver, InProcessLink, LinkEndpoint, LinkReceiver, MonoNs,
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

