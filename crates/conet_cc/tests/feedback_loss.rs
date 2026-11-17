use conet_cc::{AckReceiver, BookkeepingTestController};
use conet_core::{ControlType, MonoNs, ReferenceWireCodec};
use conet_udp::{EndpointConfig, Role, SimNetwork, UdpLiEndpoint, payload_packet};

fn ms(value: i64) -> MonoNs {
    MonoNs::new(value * 1_000_000)
}

#[test]
fn lost_feedback_is_not_retransmitted_and_a_later_ack_advances_cc() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut sender = UdpLiEndpoint::with_controllers(
        network.transport(0),
        EndpointConfig::new(Role::Initiator, u64::MAX),
        Box::new(BookkeepingTestController::new(10_000)),
        None,
    );
    let mut receiver = UdpLiEndpoint::with_controllers(
        network.transport(1),
        EndpointConfig::new(Role::Responder, u64::MAX),
        Box::new(conet_core::FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );

    for payload in [b"zero".as_slice(), b"one", b"two"] {
        sender.enqueue_file_data(payload_packet(payload)).unwrap();
    }
    for step in 0..3 {
        assert_eq!(sender.drive(ms(step)).sent, 1);
    }
    receiver.drive(ms(3));

    network.drop_next(1);
    assert_eq!(receiver.drive(ms(4)).sent, 1);
    assert!(network.frames_from(1)[0].dropped);
    sender.drive(ms(5));
    assert!(sender.controller_inflight_bytes().unwrap() > 0);

    assert_eq!(receiver.drive(ms(6)).sent, 0);
    assert_eq!(network.frames_from(1).len(), 1);

    sender.enqueue_file_data(payload_packet(b"three")).unwrap();
    assert_eq!(sender.drive(ms(7)).sent, 1);
    receiver.drive(ms(7));
    receiver.drive(ms(8));
    assert_eq!(network.frames_from(1).len(), 2);
    assert!(!network.frames_from(1)[1].dropped);

    sender.drive(ms(9));
    assert_eq!(sender.controller_inflight_bytes(), Some(0));
    let codec = ReferenceWireCodec::default();
    assert!(network.frames_from(1).iter().all(|frame| {
        codec
            .parse(conet_core::OpaqueBytes::copy_from_slice(&frame.bytes))
            .ok()
            .and_then(|datagram| datagram.control().map(|control| control.ctrl_type))
            == Some(ControlType::CcOpaque)
    }));
}
