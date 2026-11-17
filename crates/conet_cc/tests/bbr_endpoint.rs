use conet_cc::{
    AckReceiver, BbrController, FeedbackMessage, MonoNs, OpaqueBytes, RxController, TxController,
};
use conet_core::ReferenceWireCodec;
use conet_udp::{
    EndpointConfig, Role, SendClass, SimNetwork, SimTransport, UdpLiEndpoint, payload_packet,
};

type SimEndpoint = UdpLiEndpoint<SimTransport>;

fn endpoint(
    network: &SimNetwork,
    host: usize,
    role: Role,
    tx: Box<dyn TxController>,
    rx: Option<Box<dyn RxController>>,
) -> SimEndpoint {
    UdpLiEndpoint::with_controllers(
        network.transport(host),
        EndpointConfig::new(role, u64::MAX),
        tx,
        rx,
    )
}

fn ms(value: i64) -> MonoNs {
    MonoNs::new(value * 1_000_000)
}

#[test]
fn bbr_endpoint_enforces_its_cap_and_transfers_over_the_simulator() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut sender = endpoint(
        &network,
        0,
        Role::Initiator,
        Box::new(BbrController::new(MonoNs::ZERO)),
        None,
    );
    let mut receiver = endpoint(
        &network,
        1,
        Role::Responder,
        Box::new(conet_core::FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );
    for value in 0..8_u8 {
        sender
            .enqueue_file_data(payload_packet([value; 500]))
            .unwrap();
    }

    for now in [ms(0), ms(16), ms(32), ms(48)] {
        assert_eq!(sender.drive(now).sent, 1);
    }
    assert_eq!(sender.sent().len(), 4);
    assert_eq!(sender.queued(SendClass::FileData), 4);
    assert_eq!(sender.inflight_limit_bytes(), Some(2_400));
    assert_eq!(sender.drive(ms(64)).sent, 0);
    assert_eq!(sender.queued(SendClass::FileData), 4);

    for step in 1..40 {
        let now = ms(64 + step * 16);
        sender.drive(now);
        receiver.drive(now);
    }
    assert_eq!(receiver.received_len(), 8);
    assert_eq!(receiver.take_received().len(), 8);
    assert!(sender.controller_inflight_bytes().is_some());
}

#[test]
fn would_blocked_ack_control_send_reuses_the_pending_private_identity() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut sender = endpoint(
        &network,
        0,
        Role::Initiator,
        Box::new(BbrController::new(MonoNs::ZERO)),
        None,
    );
    let mut receiver = endpoint(
        &network,
        1,
        Role::Responder,
        Box::new(conet_core::FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );
    sender
        .enqueue_file_data(payload_packet(b"bbr-feedback"))
        .unwrap();

    assert_eq!(sender.drive(MonoNs::ZERO).sent, 1);
    receiver.drive(ms(1));
    assert_eq!(receiver.queued(SendClass::LinkControl), 1);
    network.fail_next_send(1);
    let failed = receiver.drive(ms(2));
    assert!(failed.send_would_block);
    assert!(failed.send_failed);
    assert_eq!(receiver.queued(SendClass::LinkControl), 1);

    let retried = receiver.drive(ms(3));
    assert_eq!(retried.sent, 1);
    assert_eq!(receiver.queued(SendClass::LinkControl), 0);
    let frames = network.frames_from(1);
    assert_eq!(frames.len(), 1);
    let parsed = ReferenceWireCodec::default()
        .parse(OpaqueBytes::copy_from_slice(&frames[0].bytes))
        .unwrap();
    let feedback =
        FeedbackMessage::decode(&parsed.control().expect("standalone feedback control").body)
            .unwrap();
    assert_eq!(feedback.control_id, Some(1));

    sender.drive(ms(4));
    assert_eq!(sender.controller_inflight_bytes(), Some(0));
}
