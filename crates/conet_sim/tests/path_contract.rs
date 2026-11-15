use conet_core::{
    EnqueueStatus, LinkEndpoint, LinkReceiver, LinkSender, MonoNs, PacketBuilder, PacketHandle,
};
use conet_sim::{CapacityStep, PathConfig, duplex_path, path_link};

fn ns(value: i64) -> MonoNs {
    MonoNs::new(value)
}

fn ms(value: i64) -> MonoNs {
    ns(value * 1_000_000)
}

fn packet(label: &[u8], len: usize) -> PacketHandle {
    let mut payload = vec![0; len];
    payload[..label.len()].copy_from_slice(label);
    PacketBuilder::from_payload(payload, 0).freeze()
}

fn label(pkt: &PacketHandle) -> &[u8] {
    &pkt.payload_bytes()[..3]
}

fn config(capacity_bps: u64, base_delay: MonoNs, buffer_bytes: u64) -> PathConfig {
    PathConfig {
        capacity_bps,
        base_delay,
        buffer_bytes,
        loss_prob: 0.0,
        capacity_schedule: Vec::new(),
        loss_seed: 1,
    }
}

#[test]
fn delivery_includes_serialization_and_propagation_after_send_time() {
    let mut cfg = config(8_000_000, ms(5), 100_000);
    cfg.loss_seed = 7;
    let (mut sender, mut receiver) = path_link(cfg);

    sender.drive(ms(10));
    let sent = packet(b"one", 1000);
    let sent_backing = sent.backing_id();
    sender.enqueue(sent).unwrap();

    receiver.drive(ns(15_999_999));
    assert!(receiver.recv().is_none());
    receiver.drive(ms(16));
    let received = receiver.recv().unwrap();
    assert_eq!(label(&received), b"one");
    assert_eq!(received.backing_id(), sent_backing);
    assert_eq!(receiver.stats().delivered, 1);
}

#[test]
fn drop_tail_discards_at_enqueue_without_reserving_link_time() {
    let (mut sender, mut receiver) = path_link(config(8_000_000, MonoNs::ZERO, 1500));

    sender.enqueue(packet(b"aaa", 1000)).unwrap();
    assert_eq!(
        sender.enqueue(packet(b"bbb", 1000)).unwrap(),
        EnqueueStatus::Accepted
    );
    assert_eq!(sender.stats().dropped_buffer, 1);

    sender.drive(ms(1));
    sender.enqueue(packet(b"ccc", 1000)).unwrap();
    receiver.drive(ms(1));
    assert_eq!(label(&receiver.recv().unwrap()), b"aaa");
    receiver.drive(ns(1_999_999));
    assert!(receiver.recv().is_none());
    receiver.drive(ms(2));
    assert_eq!(label(&receiver.recv().unwrap()), b"ccc");

    let stats = receiver.stats();
    assert_eq!(stats.sent, 3);
    assert_eq!(stats.queued, 2);
    assert_eq!(stats.dropped_buffer, 1);
}

#[test]
fn post_link_loss_still_consumes_bottleneck_serialization_time() {
    let mut cfg = config(8_000_000, MonoNs::ZERO, 100_000);
    cfg.loss_prob = 1.0;
    let (mut sender, mut receiver) = path_link(cfg);

    sender.enqueue(packet(b"aaa", 1000)).unwrap();
    sender.enqueue(packet(b"bbb", 1000)).unwrap();
    sender.drive(ms(1));
    assert_eq!(sender.stats().dropped_loss, 1);
    assert_eq!(sender.buffer_bytes(), 1000);

    sender.drive(ms(2));
    assert_eq!(sender.stats().dropped_loss, 2);
    assert_eq!(sender.buffer_bytes(), 0);
    receiver.drive(ms(10));
    assert!(receiver.recv().is_none());
}

#[test]
fn capacity_schedule_changes_rate_at_and_after_step_time() {
    let mut cfg = config(8_000_000, MonoNs::ZERO, 100_000);
    cfg.capacity_schedule.push(CapacityStep {
        at: ms(10),
        capacity_bps: 16_000_000,
    });
    let (mut sender, mut receiver) = path_link(cfg);

    sender.enqueue(packet(b"old", 1000)).unwrap();
    sender.drive(ms(1));
    receiver.drive(ms(1));
    assert_eq!(label(&receiver.recv().unwrap()), b"old");

    sender.drive(ms(10));
    assert_eq!(sender.capacity_bps(), 16_000_000);
    sender.enqueue(packet(b"new", 1000)).unwrap();
    receiver.drive(ns(10_499_999));
    assert!(receiver.recv().is_none());
    receiver.drive(ms(11));
    assert_eq!(label(&receiver.recv().unwrap()), b"new");
}

#[test]
fn duplex_endpoints_exchange_packets_with_independent_delays() {
    let mut path = duplex_path(
        config(8_000_000, ms(1), 100_000),
        config(8_000_000, ms(5), 100_000),
    );

    path.a.outgoing_mut().enqueue(packet(b"fwd", 1000)).unwrap();
    path.b.outgoing_mut().enqueue(packet(b"rev", 1000)).unwrap();

    path.a.drive(ms(2));
    path.b.drive(ms(2));
    assert_eq!(label(&path.b.incoming_mut().recv().unwrap()), b"fwd");
    assert!(path.a.incoming_mut().recv().is_none());

    path.a.drive(ms(6));
    path.b.drive(ms(6));
    assert_eq!(label(&path.a.incoming_mut().recv().unwrap()), b"rev");
    assert!(path.b.incoming_mut().recv().is_none());
}
