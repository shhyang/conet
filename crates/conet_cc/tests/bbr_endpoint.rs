use conet_cc::{AckReceiver, BbrController, MonoNs, RxController, TxController};
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
    sender.establish_for_test(0xb0b0, 1).unwrap();
    receiver.establish_for_test(0xb0b0, 1).unwrap();
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

