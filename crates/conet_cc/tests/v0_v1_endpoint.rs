use conet_cc::{
    AckReceiver, BookkeepingTestController, CubicController, FeedbackMessage, MonoNs, OpaqueBytes,
    RxController, TxController,
};
use conet_core::{ControlMessage, ControlType, ReferenceWireCodec, WireFlags, WireHeader};
use conet_udp::{EndpointConfig, Role, SimNetwork, SimTransport, UdpLiEndpoint, payload_packet};

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

fn feedback_frame(ctrl_seq: u32, body: OpaqueBytes) -> Vec<u8> {
    let codec = ReferenceWireCodec::default();
    let parsed = codec
        .build(
            WireHeader {
                flags: WireFlags::default(),
                epoch: 1,
                link_seq: 40,
                payload_len: 0,
            },
            OpaqueBytes::new(),
            Some(ControlMessage::new(ControlType::CcOpaque, ctrl_seq, body)),
        )
        .unwrap();
    codec.serialize(&parsed).unwrap()
}

#[test]
fn malformed_and_unauthenticated_feedback_do_not_clear_inflight() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut sender = endpoint(
        &network,
        0,
        Role::Initiator,
        Box::new(BookkeepingTestController::new(10_000)),
        None,
    );
    let mut receiver = endpoint(
        &network,
        1,
        Role::Responder,
        Box::new(conet_core::FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );
    sender.establish_for_test(0x5151, 1).unwrap();
    receiver.establish_for_test(0x5151, 1).unwrap();
    sender
        .enqueue_file_data(payload_packet(b"one-substrate-packet"))
        .unwrap();

    sender.drive(MonoNs::ZERO);
    receiver.drive(MonoNs::ZERO);
    let inflight = sender.controller_inflight_bytes().unwrap();
    assert!(inflight > 0);

    network.inject(
        0,
        feedback_frame(7, OpaqueBytes::from_static(b"malformed")),
        true,
    );
    sender.drive(MonoNs::new(1_000_000));
    assert_eq!(sender.controller_inflight_bytes(), Some(inflight));

    let valid_ack = FeedbackMessage::ack(0).encode().unwrap();
    network.inject(0, feedback_frame(8, valid_ack.clone()), false);
    sender.drive(MonoNs::new(2_000_000));
    assert_eq!(sender.controller_inflight_bytes(), Some(inflight));
    assert_eq!(sender.drop_count("unauthenticated_cc"), 1);

    network.inject(0, feedback_frame(9, valid_ack), true);
    sender.drive(MonoNs::new(3_000_000));
    assert_eq!(sender.controller_inflight_bytes(), Some(0));
}

#[test]
fn cubic_controller_installs_on_the_sim_hook_and_receives_opaque_acks() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut sender = endpoint(
        &network,
        0,
        Role::Initiator,
        Box::new(CubicController::new(MonoNs::ZERO)),
        None,
    );
    let mut receiver = endpoint(
        &network,
        1,
        Role::Responder,
        Box::new(conet_core::FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );
    sender.establish_for_test(0x6161, 1).unwrap();
    receiver.establish_for_test(0x6161, 1).unwrap();
    for byte in 0..3 {
        sender
            .enqueue_file_data(payload_packet([byte; 500]))
            .unwrap();
    }

    for step in 0..3 {
        let now = MonoNs::new(step * 1_000_000);
        sender.drive(now);
        receiver.drive(now);
    }
    assert_eq!(receiver.take_received().len(), 3);

    receiver.drive(MonoNs::new(3_000_000));
    sender.drive(MonoNs::new(4_000_000));
    assert_eq!(sender.controller_inflight_bytes(), Some(0));
    assert_eq!(sender.target_rate(), u64::MAX);
    assert_eq!(sender.next_wakeup(), None);
    assert!(
        sender
            .inflight_limit_bytes()
            .is_some_and(|window| window >= 12_000)
    );
}

#[test]
fn malformed_and_replayed_feedback_use_private_identity_without_link_burn() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut sender = endpoint(
        &network,
        0,
        Role::Initiator,
        Box::new(BookkeepingTestController::new(10_000)),
        None,
    );
    sender.establish_for_test(0x8181, 1).unwrap();
    for byte in 0..2 {
        sender
            .enqueue_file_data(payload_packet([byte; 100]))
            .unwrap();
    }
    sender.drive(MonoNs::ZERO);
    sender.drive(MonoNs::new(1_000_000));
    let initial_inflight = sender.controller_inflight_bytes().unwrap();
    assert!(initial_inflight > 0);

    let valid = FeedbackMessage::ack(0).with_control_id(1).encode().unwrap();
    let mut malformed = valid.to_vec();
    malformed[20] = 0xff;
    network.inject(0, feedback_frame(0, OpaqueBytes::from(malformed)), true);
    sender.drive(MonoNs::new(2_000_000));
    assert_eq!(sender.controller_inflight_bytes(), Some(initial_inflight));

    // The malformed body did not consume private ID 1, and the link did not
    // consume a ctrl_seq for either CC trailer.
    network.inject(0, feedback_frame(0, valid), true);
    sender.drive(MonoNs::new(3_000_000));
    let after_ack = sender.controller_inflight_bytes().unwrap();
    assert!(after_ack < initial_inflight);

    let noop = FeedbackMessage::ack(999)
        .with_control_id(2)
        .encode()
        .unwrap();
    network.inject(0, feedback_frame(0, noop), true);
    sender.drive(MonoNs::new(4_000_000));
    assert_eq!(sender.controller_inflight_bytes(), Some(after_ack));

    let reused_noop_id = FeedbackMessage::ack(0).with_control_id(2).encode().unwrap();
    network.inject(0, feedback_frame(0, reused_noop_id), true);
    sender.drive(MonoNs::new(5_000_000));
    assert_eq!(sender.controller_inflight_bytes(), Some(after_ack));

    let fresh = FeedbackMessage::ack(1).with_control_id(3).encode().unwrap();
    network.inject(0, feedback_frame(0, fresh), true);
    sender.drive(MonoNs::new(6_000_000));
    assert!(sender.controller_inflight_bytes().unwrap() < after_ack);
}

