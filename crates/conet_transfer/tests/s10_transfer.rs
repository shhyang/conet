use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conet_transfer::{
    FileTransferConfig, SimulatorImpairment, TransferError, run_simulated_transfer,
    run_udp_receiver, run_udp_sender,
};

fn object() -> Vec<u8> {
    (0..=255).cycle().take(8_193).collect()
}

#[test]
fn one_way_is_default_and_recovers_under_stated_simulated_loss_budget() {
    let source = object();
    let config = FileTransferConfig::default();
    assert!(
        !config.closed_loop,
        "the CLI/library default must be one-way"
    );
    let report = run_simulated_transfer(
        "lossy.bin",
        &source,
        config,
        SimulatorImpairment {
            forward_loss_every: Some(5),
            reverse_loss_every: None,
        },
    )
    .unwrap();

    assert_eq!(report.recovered_file, source);
    assert_eq!(report.file_name, "lossy.bin");
    assert!(!report.closed_loop);
    assert_eq!(
        report.stated_symbol_budget,
        u64::from(report.source_symbols) * 3 + 16
    );
    assert_eq!(report.acks_received, 0);
    assert_eq!(report.feedback_datagrams_sent, 0);
    assert!(report.generated_symbols <= report.stated_symbol_budget);
}

#[test]
fn closed_loop_is_opt_in_and_recovers_with_reverse_user_feedback() {
    let source = object();
    let report = run_simulated_transfer(
        "closed-loop.bin",
        &source,
        FileTransferConfig {
            closed_loop: true,
            ..FileTransferConfig::default()
        },
        SimulatorImpairment {
            forward_loss_every: Some(7),
            reverse_loss_every: Some(4),
        },
    )
    .unwrap();

    assert_eq!(report.recovered_file, source);
    assert!(report.closed_loop);
    assert!(report.feedback_datagrams_sent >= 1);
    assert!(report.acks_received >= 1);
    assert_eq!(report.sender_status, conet_core::BlockStatus::Delivered);
}

#[test]
fn insufficient_one_way_budget_fails_without_claiming_recovery() {
    let source = object();
    let error = run_simulated_transfer(
        "insufficient.bin",
        &source,
        FileTransferConfig {
            one_way_symbol_budget: Some(2),
            ..FileTransferConfig::default()
        },
        SimulatorImpairment::default(),
    )
    .unwrap_err();
    assert!(matches!(error, TransferError::NotRecovered { .. }));
}

#[test]
fn cli_help_documents_explicit_udp_pair_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_conet_transfer"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let usage = String::from_utf8(output.stdout).unwrap();
    assert!(usage.contains("conet_transfer send INPUT --listen LOCAL_ADDR --peer PEER_ADDR"));
    assert!(usage.contains("conet_transfer recv --listen LOCAL_ADDR --peer PEER_ADDR"));
    assert!(usage.contains("reflexive-probe"));
    assert!(usage.contains("do not fill --peer from an HTTP public-IP lookup"));
}

#[test]
fn two_process_cli_transfer_recovers_a_file_over_explicit_udp_addresses() {
    let source = object();
    let sender_addr = unused_udp_addr();
    let receiver_addr = unused_udp_addr();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "conet-transfer-two-process-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("two-host.bin");
    let output = directory.join("received.bin");
    std::fs::write(&input, &source).unwrap();

    let binary = env!("CARGO_BIN_EXE_conet_transfer");
    let mut receiver = Command::new(binary)
        .args([
            "recv",
            "--listen",
            &receiver_addr.to_string(),
            "--peer",
            &sender_addr.to_string(),
            "--output",
            output.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    let mut sender = Command::new(binary)
        .args([
            "send",
            input.to_str().unwrap(),
            "--listen",
            &sender_addr.to_string(),
            "--peer",
            &receiver_addr.to_string(),
        ])
        .spawn()
        .unwrap();

    let sender_output = wait_for_child(&mut sender, Duration::from_secs(15));
    if sender_output
        .as_ref()
        .is_none_or(|output| !output.status.success())
    {
        let _ = receiver.kill();
        let _ = receiver.wait();
        panic!(
            "sender failed: {}",
            sender_output.map_or_else(
                || "timed out".to_owned(),
                |output| String::from_utf8_lossy(&output.stderr).into_owned()
            )
        );
    }
    let receiver_output = wait_for_child(&mut receiver, Duration::from_secs(15));
    let receiver_output = receiver_output.expect("receiver timed out");
    assert!(
        receiver_output.status.success(),
        "receiver failed: {}",
        String::from_utf8_lossy(&receiver_output.stderr)
    );
    assert_eq!(std::fs::read(&output).unwrap(), source);

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn udp_transfer_learns_a_responder_supplied_source_port_when_nat_maps_it() {
    let source = object();
    let sender_addr = unused_udp_addr();
    let receiver_addr = unused_udp_addr();
    let mut configured_source = unused_udp_addr();
    while configured_source.port() == sender_addr.port() {
        configured_source = unused_udp_addr();
    }
    let configured_source = SocketAddr::new(sender_addr.ip(), configured_source.port());

    let receiver = std::thread::spawn(move || {
        run_udp_receiver(
            receiver_addr,
            configured_source,
            FileTransferConfig::default(),
        )
    });
    let sent = run_udp_sender(
        sender_addr,
        receiver_addr,
        "nat-mapped.bin",
        &source,
        FileTransferConfig::default(),
    )
    .unwrap();
    let received = receiver.join().unwrap().unwrap();

    assert!(sent.data_datagrams_sent > 0);
    assert_eq!(received.recovered_file, source);
    assert_eq!(received.file_name, "nat-mapped.bin");
}

fn unused_udp_addr() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> Option<Output> {
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Some(Output {
        status,
        stdout: read_pipe(child.stdout.as_mut()),
        stderr: read_pipe(child.stderr.as_mut()),
    })
}

fn read_pipe(pipe: Option<&mut impl Read>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(pipe) = pipe {
        pipe.read_to_end(&mut bytes).unwrap();
    }
    bytes
}

#[test]
#[ignore = "gated loopback conformance; both sockets are restricted to 127.0.0.1"]
fn loopback_one_way_recovers_a_file() {
    let source = object();
    let report = run_simulated_transfer(
        "loopback-control.bin",
        &source,
        FileTransferConfig::default(),
        SimulatorImpairment::default(),
    )
    .unwrap();
    assert_eq!(report.recovered_file, source);

    let report = conet_transfer::run_loopback_transfer(
        "loopback.bin",
        &source,
        FileTransferConfig::default(),
    )
    .unwrap();
    assert_eq!(report.recovered_file, source);
    assert_eq!(report.file_name, "loopback.bin");
}
