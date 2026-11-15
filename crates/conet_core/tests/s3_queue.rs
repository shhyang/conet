use conet_core::{
    BackingAccounting, CancelResult, EnqueueError, EnqueueErrorKind, InvalidReason, PacketBuilder,
    PacketHandle, PacketMetrics, PacketQueue, PayloadCopyCounter, QueueLimits,
};

fn packet_with(
    payload: &[u8],
    accounting: BackingAccounting,
    copies: PayloadCopyCounter,
) -> PacketHandle {
    let metrics = PacketMetrics {
        backings: accounting,
        payload_copies: copies,
    };
    let mut builder = PacketBuilder::with_capacity_and_metrics(payload.len(), 4, metrics);
    builder.payload_mut().copy_from_slice(payload);
    builder.freeze()
}

fn packet(payload: &[u8]) -> PacketHandle {
    packet_with(payload, BackingAccounting::new(), PayloadCopyCounter::new())
}

#[test]
fn m4_full_closed_and_invalid_enqueue_return_the_original_handle() {
    let mut queue = PacketQueue::new(QueueLimits::new(1, 1024, 1024));
    queue.enqueue(packet(b"first")).unwrap();

    let rejected = packet(b"second");
    let rejected_id = rejected.backing_id();
    let error = queue.enqueue(rejected).unwrap_err();
    assert_eq!(error.kind(), EnqueueErrorKind::Full);
    assert_eq!(error.packet().backing_id(), rejected_id);
    assert_eq!(error.packet().payload_bytes(), b"second");
    assert_eq!(queue.occupancy().count, 1);

    queue.close();
    let closed = packet(b"closed");
    let closed_id = closed.backing_id();
    let error = queue.enqueue(closed).unwrap_err();
    assert_eq!(error.kind(), EnqueueErrorKind::Closed);
    assert_eq!(error.packet().backing_id(), closed_id);

    let mut invalid_queue =
        PacketQueue::new(QueueLimits::new(4, 1024, 1024).with_max_packet_bytes(2));
    let invalid = packet(b"too-large");
    let invalid_id = invalid.backing_id();
    let error = invalid_queue.enqueue(invalid).unwrap_err();
    assert_eq!(
        error.kind(),
        EnqueueErrorKind::Invalid(InvalidReason::PacketTooLarge { len: 9, max: 2 })
    );
    assert_eq!(error.packet().backing_id(), invalid_id);
}

#[test]
fn m6_slow_consumer_cannot_grow_unique_backing_without_bound() {
    let accounting = BackingAccounting::new();
    let copies = PayloadCopyCounter::new();
    let limits = QueueLimits::new(16, 1 << 20, 4096);
    let mut queue = PacketQueue::new(limits);

    let mut accepted = 0;
    for _ in 0..16 {
        let pkt = packet_with(&[7; 1024], accounting.clone(), copies.clone());
        match queue.enqueue(pkt) {
            Ok(_) => accepted += 1,
            Err(EnqueueError::Full { pkt }) => {
                assert_eq!(pkt.payload_bytes().len(), 1024);
                break;
            }
            Err(other) => panic!("unexpected admission result: {other}"),
        }
    }
    assert_eq!(accepted, 4);
    assert_eq!(
        queue.occupancy().unique_backing_bytes,
        limits.max_unique_backing_bytes
    );
    assert!(queue.occupancy().count <= limits.max_packets);

    for _ in 0..8 {
        let pkt = packet_with(&[9; 1024], accounting.clone(), copies.clone());
        let error = queue.enqueue(pkt).unwrap_err();
        assert_eq!(error.kind(), EnqueueErrorKind::Full);
    }
    assert_eq!(queue.occupancy().unique_backing_bytes, 4096);

    drop(queue.dequeue().unwrap());
    let replacement = packet_with(&[8; 1024], accounting, copies);
    queue.enqueue(replacement).unwrap();
    assert_eq!(queue.occupancy().unique_backing_bytes, 4096);
}

#[test]
fn g2_count_visible_and_unique_bounds_are_never_exceeded() {
    let mut count_queue = PacketQueue::new(QueueLimits::new(1, 4096, 4096));
    count_queue.enqueue(packet(b"a")).unwrap();
    assert_eq!(
        count_queue.enqueue(packet(b"b")).unwrap_err().kind(),
        EnqueueErrorKind::Full
    );
    assert_eq!(count_queue.occupancy().count, 1);

    let mut visible_queue = PacketQueue::new(QueueLimits::new(8, 5, 4096));
    visible_queue.enqueue(packet(b"1234")).unwrap();
    assert_eq!(
        visible_queue.enqueue(packet(b"56")).unwrap_err().kind(),
        EnqueueErrorKind::Full
    );
    assert_eq!(visible_queue.occupancy().visible_bytes, 4);

    let accounting = BackingAccounting::new();
    let copies = PayloadCopyCounter::new();
    let mut unique_queue = PacketQueue::new(QueueLimits::new(8, 4096, 4));
    let parent = packet_with(b"1234", accounting.clone(), copies.clone());
    let first = parent.slice(0, 2).unwrap();
    let second = parent.slice(2, 2).unwrap();
    unique_queue.enqueue(first).unwrap();
    unique_queue.enqueue(second).unwrap();
    assert_eq!(unique_queue.occupancy().count, 2);
    assert_eq!(unique_queue.occupancy().visible_bytes, 4);
    assert_eq!(unique_queue.occupancy().unique_backing_bytes, 4);
    assert_eq!(unique_queue.occupancy().unique_backings, 1);
    assert_eq!(
        unique_queue
            .enqueue(packet_with(b"z", accounting, copies))
            .unwrap_err()
            .kind(),
        EnqueueErrorKind::Full
    );
}

#[test]
fn s3_composition_producer_bounded_queue_consumer() {
    let mut queue = PacketQueue::new(QueueLimits::new(2, 64, 64));
    let one = packet(b"one");
    let two = packet(b"two");
    let three = packet(b"three");

    queue.enqueue(one).unwrap();
    queue.enqueue(two).unwrap();
    let mut pending = match queue.enqueue(three).unwrap_err() {
        EnqueueError::Full { pkt } => pkt,
        other => panic!("expected Full, got {other}"),
    };

    assert_eq!(queue.dequeue().unwrap().payload_bytes(), b"one");
    queue.enqueue(pending).unwrap();
    pending = packet(b"unused");
    drop(pending);

    assert_eq!(queue.dequeue().unwrap().payload_bytes(), b"two");
    assert_eq!(queue.dequeue().unwrap().payload_bytes(), b"three");
    assert!(queue.dequeue().is_none());
}

#[test]
fn cancel_returns_each_queued_handle() {
    let mut queue = PacketQueue::new(QueueLimits::new(4, 64, 64));
    queue.enqueue(packet(b"keep")).unwrap();
    queue.enqueue(packet(b"cancel-a")).unwrap();
    queue.enqueue(packet(b"cancel-b")).unwrap();
    let cancelled = queue.cancel(|pkt| pkt.payload_bytes().starts_with(b"cancel"));
    assert_eq!(cancelled.len(), 2);
    for result in cancelled {
        match result {
            CancelResult::Cancelled { pkt } => assert!(pkt.payload_bytes().starts_with(b"cancel")),
        }
    }
    assert_eq!(queue.occupancy().count, 1);
    assert_eq!(queue.dequeue().unwrap().payload_bytes(), b"keep");
}
