use conet_core::{
    BackingAccounting, EnqueueErrorKind, FanoutSender, ForwardError, ForwardOutcome,
    IdentityForwarder, InProcessLink, LinkEndpoint, LinkReceiver, LinkSender, MonoNs,
    PacketBuilder, PacketHandle, PacketMetrics, PayloadCopyCounter, QueueLimits,
    identity_link, paced_identity_link,
};

fn limits(packets: usize) -> QueueLimits {
    QueueLimits::new(packets, 4096, 4096)
}

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
fn in_process_link_surfaces_the_pacer_deadline_only_as_next_drive() {
    let (sender, _sink) = paced_identity_link(limits(2), 1_000);
    let (_peer, receiver) = identity_link(limits(2));
    let mut link = InProcessLink::new(sender, receiver);

    assert_eq!(link.next_drive(), None);
    assert_eq!(link.next_wakeup(), None);
    link.outgoing().enqueue(packet(b"x")).unwrap();
    assert_eq!(link.next_drive(), Some(MonoNs::ZERO));
    assert_eq!(link.next_wakeup(), None);

    link.drive(MonoNs::ZERO);
    assert_eq!(link.next_drive(), None);
    assert_eq!(link.next_wakeup(), None);
}

#[test]
fn m1_and_m10_three_identity_devices_forward_same_backing_without_copy() {
    let accounting = BackingAccounting::new();
    let copies = PayloadCopyCounter::new();
    let pkt = packet_with(b"through-chain", accounting, copies.clone());
    let id = pkt.backing_id();

    let (mut source, inbound0) = identity_link(limits(1));
    let (outbound1, inbound1) = identity_link(limits(1));
    let (outbound2, inbound2) = identity_link(limits(1));
    let (outbound3, mut sink) = identity_link(limits(1));
    let mut identity1 = IdentityForwarder::new(inbound0, outbound1);
    let mut identity2 = IdentityForwarder::new(inbound1, outbound2);
    let mut identity3 = IdentityForwarder::new(inbound2, outbound3);

    source.enqueue(pkt).unwrap();
    assert_eq!(identity1.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(identity2.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(identity3.forward_once().unwrap(), ForwardOutcome::Forwarded);

    let received = sink.recv().unwrap();
    assert_eq!(received.backing_id(), id);
    assert_eq!(received.payload_bytes(), b"through-chain");
    assert_eq!(copies.count(), 0);
    assert_eq!(received.payload_copies().count(), 0);
}

#[test]
fn supported_fanout_to_two_sinks_shares_backing_and_isolates_headers() {
    let copies = PayloadCopyCounter::new();
    let mut pkt = packet_with(b"fanout-payload", BackingAccounting::new(), copies.clone());
    pkt.header_mut().resize(2, 0);
    pkt.header_mut().as_mut_bytes()[0] = 0x11;
    let id = pkt.backing_id();

    let (sink_a, mut receiver_a) = identity_link(limits(2));
    let (sink_b, mut receiver_b) = identity_link(limits(2));
    let mut fanout = FanoutSender::new(vec![sink_a, sink_b]);
    assert_eq!(fanout.enqueue_to_all(pkt).unwrap().delivered, 2);

    let mut a = receiver_a.recv().unwrap();
    let mut b = receiver_b.recv().unwrap();
    assert_eq!(a.backing_id(), id);
    assert_eq!(b.backing_id(), id);
    assert_eq!(a.payload_bytes(), b.payload_bytes());
    assert_eq!(copies.count(), 0);

    a.header_mut().as_mut_bytes()[0] = 0xaa;
    b.header_mut().as_mut_bytes()[0] = 0xbb;
    assert_ne!(a.header().as_bytes(), b.header().as_bytes());
    assert_eq!(a.payload_bytes(), b"fanout-payload");
    assert_eq!(b.payload_bytes(), b"fanout-payload");
}

#[test]
fn fanout_rejection_returns_handle_without_partial_delivery() {
    let (sink_a, mut receiver_a) = identity_link(limits(1));
    let (sink_b, mut receiver_b) = identity_link(limits(1));
    let mut fanout = FanoutSender::new(vec![sink_a, sink_b]);
    fanout.enqueue_to_all(packet(b"occupies-a")).unwrap();

    let rejected = packet(b"reject-me");
    let rejected_id = rejected.backing_id();
    let error = fanout.enqueue_to_all(rejected).unwrap_err();
    assert_eq!(error.packet().backing_id(), rejected_id);
    assert_eq!(receiver_a.recv().unwrap().payload_bytes(), b"occupies-a");
    assert_eq!(receiver_b.recv().unwrap().payload_bytes(), b"occupies-a");
}

#[test]
fn g2_backpressure_from_bounded_sink_reaches_producer_through_chain() {
    let copies = PayloadCopyCounter::new();
    let (mut source, inbound0) = identity_link(limits(1));
    let (outbound1, inbound1) = identity_link(limits(1));
    let (outbound2, mut sink) = identity_link(limits(1));
    let mut identity1 = IdentityForwarder::new(inbound0, outbound1);
    let mut identity2 = IdentityForwarder::new(inbound1, outbound2);

    let p1 = packet_with(b"p1", BackingAccounting::new(), copies.clone());
    let p1_id = p1.backing_id();
    source.enqueue(p1).unwrap();
    identity1.forward_once().unwrap();
    identity2.forward_once().unwrap();

    source
        .enqueue(packet_with(b"p2", BackingAccounting::new(), copies.clone()))
        .unwrap();
    identity1.forward_once().unwrap();
    assert!(matches!(
        identity2.forward_once(),
        Err(ForwardError::Backpressure {
            kind: EnqueueErrorKind::Full
        })
    ));

    source
        .enqueue(packet_with(b"p3", BackingAccounting::new(), copies.clone()))
        .unwrap();
    assert_eq!(identity1.forward_once().unwrap(), ForwardOutcome::Forwarded);

    let p4 = packet_with(b"p4", BackingAccounting::new(), copies.clone());
    let p4_id = p4.backing_id();
    source.enqueue(p4).unwrap();
    assert!(matches!(
        identity1.forward_once(),
        Err(ForwardError::Backpressure {
            kind: EnqueueErrorKind::Full
        })
    ));

    source
        .enqueue(packet_with(b"p5", BackingAccounting::new(), copies.clone()))
        .unwrap();
    let p6 = packet_with(b"p6", BackingAccounting::new(), copies.clone());
    let p6_id = p6.backing_id();
    let error = source.enqueue(p6).unwrap_err();
    assert_eq!(error.kind(), EnqueueErrorKind::Full);
    assert_eq!(error.packet().backing_id(), p6_id);
    assert_eq!(identity1.pending_backing_id(), Some(p4_id));
    assert!(identity2.pending_backing_id().is_some());
    assert_eq!(copies.count(), 0);

    assert_eq!(sink.recv().unwrap().backing_id(), p1_id);
    assert_eq!(identity2.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(sink.recv().unwrap().payload_bytes(), b"p2");
    assert_eq!(identity2.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(sink.recv().unwrap().payload_bytes(), b"p3");
    assert_eq!(identity1.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(identity2.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(sink.recv().unwrap().payload_bytes(), b"p4");
    assert_eq!(identity1.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(identity2.forward_once().unwrap(), ForwardOutcome::Forwarded);
    assert_eq!(sink.recv().unwrap().payload_bytes(), b"p5");
    assert_eq!(copies.count(), 0);
}

