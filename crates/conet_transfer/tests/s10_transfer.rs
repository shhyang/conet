use conet_transfer::{
    FileTransferConfig, SimulatorImpairment, TransferError, run_simulated_transfer,
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
