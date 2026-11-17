//! File transfer under public `conet_cc` CUBIC- and BBR-style controllers.
//!
//! Does not path-depend from `conet_transfer` into this crate for the CLI;
//! research/dev tests wire controllers via [`UdpLiEndpoint::with_controllers`]
//! and [`conet_transfer::run_pair_transfer`].

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use conet_cc::{AckReceiver, BbrController, CubicController, MonoNs};
use conet_core::FixedRateController;
use conet_transfer::{FileTransferConfig, run_pair_transfer, transfer_endpoint_config};
use conet_udp::{LoopbackUdpTransport, Role, SimNetwork, UdpLiEndpoint};

fn cubic_sim_pair(
    config: &FileTransferConfig,
) -> (
    UdpLiEndpoint<conet_udp::SimTransport>,
    UdpLiEndpoint<conet_udp::SimTransport>,
    SimNetwork,
) {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let rate = config.target_rate;
    let sender = UdpLiEndpoint::with_controllers(
        network.transport(0),
        transfer_endpoint_config(Role::Initiator, rate),
        Box::new(CubicController::new(MonoNs::ZERO)),
        None,
    );
    let receiver = UdpLiEndpoint::with_controllers(
        network.transport(1),
        transfer_endpoint_config(Role::Responder, rate),
        Box::new(FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );
    (sender, receiver, network)
}

fn bbr_sim_pair(
    config: &FileTransferConfig,
) -> (
    UdpLiEndpoint<conet_udp::SimTransport>,
    UdpLiEndpoint<conet_udp::SimTransport>,
    SimNetwork,
) {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let rate = config.target_rate;
    let sender = UdpLiEndpoint::with_controllers(
        network.transport(0),
        transfer_endpoint_config(Role::Initiator, rate),
        Box::new(BbrController::new(MonoNs::ZERO)),
        None,
    );
    let receiver = UdpLiEndpoint::with_controllers(
        network.transport(1),
        transfer_endpoint_config(Role::Responder, rate),
        Box::new(FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );
    (sender, receiver, network)
}

#[test]
fn simulated_open_loop_recovers_under_cubic() {
    let file: Vec<u8> = (0..8_192).map(|i| (i % 251) as u8).collect();
    let config = FileTransferConfig {
        closed_loop: false,
        one_way_symbol_budget: Some(256),
        target_rate: 2_000_000,
        ..FileTransferConfig::default()
    };
    let (mut sender, mut receiver, _network) = cubic_sim_pair(&config);
    let report = run_pair_transfer(
        &mut sender,
        &mut receiver,
        "cubic-ol.bin",
        &file,
        config,
        false,
    )
    .expect("CUBIC open-loop transfer");
    assert_eq!(report.recovered_file, file);
}

#[test]
fn simulated_closed_loop_delivers_under_cubic() {
    let file: Vec<u8> = (0..4_096).map(|i| ((i * 3) % 251) as u8).collect();
    let config = FileTransferConfig {
        closed_loop: true,
        one_way_symbol_budget: Some(256),
        target_rate: 2_000_000,
        ..FileTransferConfig::default()
    };
    let (mut sender, mut receiver, _network) = cubic_sim_pair(&config);
    let report = run_pair_transfer(
        &mut sender,
        &mut receiver,
        "cubic-cl.bin",
        &file,
        config,
        false,
    )
    .expect("CUBIC closed-loop transfer");
    assert_eq!(report.recovered_file, file);
    assert_eq!(report.sender_status, conet_core::BlockStatus::Delivered);
    assert!(report.acks_received >= 1);
}

#[test]
fn simulated_open_loop_recovers_under_bbr() {
    let file: Vec<u8> = (0..8_192).map(|i| ((i * 5) % 251) as u8).collect();
    let config = FileTransferConfig {
        closed_loop: false,
        one_way_symbol_budget: Some(256),
        target_rate: 2_000_000,
        ..FileTransferConfig::default()
    };
    let (mut sender, mut receiver, _network) = bbr_sim_pair(&config);
    let report = run_pair_transfer(
        &mut sender,
        &mut receiver,
        "bbr-ol.bin",
        &file,
        config,
        false,
    )
    .expect("BBR open-loop transfer");
    assert_eq!(report.recovered_file, file);
}

#[test]
fn simulated_closed_loop_delivers_under_bbr() {
    let file: Vec<u8> = (0..4_096).map(|i| ((i * 11) % 251) as u8).collect();
    let config = FileTransferConfig {
        closed_loop: true,
        one_way_symbol_budget: Some(256),
        target_rate: 2_000_000,
        ..FileTransferConfig::default()
    };
    let (mut sender, mut receiver, _network) = bbr_sim_pair(&config);
    let report = run_pair_transfer(
        &mut sender,
        &mut receiver,
        "bbr-cl.bin",
        &file,
        config,
        false,
    )
    .expect("BBR closed-loop transfer");
    assert_eq!(report.recovered_file, file);
    assert_eq!(report.sender_status, conet_core::BlockStatus::Delivered);
    assert!(report.acks_received >= 1);
}

fn loopback_closed_loop_with_tx(
    label: &str,
    tx: Box<dyn conet_cc::TxController>,
) {
    let file: Vec<u8> = (0..6_144).map(|i| ((i * 7) % 251) as u8).collect();
    let config = FileTransferConfig {
        closed_loop: true,
        one_way_symbol_budget: Some(512),
        target_rate: 2_000_000,
        linger: MonoNs::new(1_000_000_000),
        ..FileTransferConfig::default()
    };

    let socket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    let transport_a = LoopbackUdpTransport::from_socket(socket_a, addr_b).unwrap();
    let transport_b = LoopbackUdpTransport::from_socket(socket_b, addr_a).unwrap();
    let rate = config.target_rate;

    let mut sender = UdpLiEndpoint::with_controllers(
        transport_a,
        transfer_endpoint_config(Role::Initiator, rate).test_open(),
        tx,
        None,
    );
    let mut receiver = UdpLiEndpoint::with_controllers(
        transport_b,
        transfer_endpoint_config(Role::Responder, rate).test_open(),
        Box::new(FixedRateController::new(u64::MAX)),
        Some(Box::new(AckReceiver::new())),
    );

    let started = Instant::now();
    let report = run_pair_transfer(
        &mut sender,
        &mut receiver,
        &format!("{label}-loopback.bin"),
        &file,
        config,
        true,
    )
    .unwrap_or_else(|error| panic!("{label} loopback transfer failed: {error}"));
    assert!(started.elapsed() < Duration::from_secs(20), "{label} too slow");
    assert_eq!(report.recovered_file, file, "{label}");
    assert_eq!(
        report.sender_status,
        conet_core::BlockStatus::Delivered,
        "{label}"
    );
}

#[test]
fn loopback_udp_delivers_under_cubic() {
    loopback_closed_loop_with_tx("cubic", Box::new(CubicController::new(MonoNs::ZERO)));
}

#[test]
fn loopback_udp_delivers_under_bbr() {
    // Default BBR_INITIAL_BANDWIDTH (12 KiB/s) is too tight for this fountain
    // burst on real loopback and can trip a fatal send; seed a lab-rate start.
    loopback_closed_loop_with_tx(
        "bbr",
        Box::new(BbrController::with_initial_bandwidth(2_000_000)),
    );
}
