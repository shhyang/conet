use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use conet_transfer::{
    FileTransferConfig, SimulatorImpairment, run_loopback_transfer, run_reflexive_helper,
    run_reflexive_probe, run_simulated_transfer, run_udp_receiver, run_udp_sender,
};

const USAGE: &str = "usage:\n  \
conet_transfer simulate INPUT [--output PATH] [--loss-every N] [--budget N] [--closed-loop]\n  \
conet_transfer loopback INPUT [--output PATH] [--budget N] [--closed-loop]\n  \
conet_transfer send INPUT --listen LOCAL_ADDR --peer PEER_ADDR [--budget N] [--closed-loop] [--lab-observe-ip]\n  \
conet_transfer recv --listen LOCAL_ADDR --peer PEER_ADDR --output PATH [--budget N] [--closed-loop] [--lab-observe-ip]\n  \
conet_transfer reflexive-probe --listen LOCAL_ADDR --helper HELPER_ADDR [--timeout-ms N]\n  \
conet_transfer reflexive-helper --listen LOCAL_ADDR [--duration-ms N]\n\n\
default policy: one-way/open-loop; closed loop is opt-in\n\
loopback is restricted to 127.0.0.1 by the transport adapter\n\
send/recv use one nonblocking UDP socket per process, learn the observed peer source port, and then accept only that one peer\n\
--peer must be the peer's UDP address (use reflexive-probe on the same socket); do not fill --peer from an HTTP public-IP lookup\n\
--lab-observe-ip is a lab bridge that admits the first Conet source IP when it disagrees with --peer\n\
reflexive-* is the UL-6 same-socket helper (not STUN/ICE; not path validation)\n\
open-loop (default): stop on symbol budget; closed-loop: ACK/NACK feedback (pass --closed-loop on both ends)\n\
see docs/user/conet-transfer.md for LAN, NAT, and peer rules";

fn main() {
    if let Err(error) = run() {
        eprintln!("conet_transfer: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        return usage();
    };
    if mode == "--help" || mode == "-h" {
        return print_usage();
    }
    match mode.as_str() {
        "simulate" | "loopback" => return run_file_mode(&mode, args),
        "send" | "recv" => return run_udp_mode(&mode, args),
        "reflexive-probe" => return run_reflexive_probe_mode(args),
        "reflexive-helper" => return run_reflexive_helper_mode(args),
        _ => return usage(),
    }
}

fn run_file_mode(
    mode: &str,
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(input) = args.next() else {
        return usage();
    };
    if input == "--help" || input == "-h" {
        return print_usage();
    }
    let mut config = FileTransferConfig::default();
    let mut impairment = SimulatorImpairment::default();
    let mut output = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--closed-loop" => config.closed_loop = true,
            "--loss-every" => {
                impairment.forward_loss_every = Some(
                    args.next()
                        .ok_or("--loss-every requires a positive integer")?
                        .parse()?,
                );
            }
            "--budget" => {
                config.one_way_symbol_budget = Some(
                    args.next()
                        .ok_or("--budget requires a symbol count")?
                        .parse()?,
                );
            }
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ));
            }
            _ => return Err(format!("unknown option {arg}").into()),
        }
    }

    let input = PathBuf::from(input);
    let file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("input path has no UTF-8 file name")?;
    let file = std::fs::read(&input)?;
    let report = match mode {
        "simulate" => run_simulated_transfer(file_name, &file, config, impairment)?,
        "loopback" => {
            if impairment.forward_loss_every.is_some() || impairment.reverse_loss_every.is_some() {
                return Err("loopback is lossless and does not accept --loss-every".into());
            }
            run_loopback_transfer(file_name, &file, config)?
        }
        _ => return usage(),
    };

    if let Some(output) = output {
        std::fs::write(output, &report.recovered_file)?;
    }
    println!(
        "recovered={} file={} bytes={} k={} budget={} generated={} status={:?} closed_loop={} data_packets={} feedback_packets={} acks={} nacks={}",
        report.recovered_file == file,
        report.file_name,
        report.file_len,
        report.source_symbols,
        report.stated_symbol_budget,
        report.generated_symbols,
        report.sender_status,
        report.closed_loop,
        report.data_datagrams_sent,
        report.feedback_datagrams_sent,
        report.acks_received,
        report.nacks_received,
    );
    Ok(())
}

fn run_udp_mode(
    mode: &str,
    args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut args = args.peekable();
    if args
        .peek()
        .is_some_and(|arg| arg == "--help" || arg == "-h")
        && mode == "send"
    {
        return print_usage();
    }
    let input = if mode == "send" {
        Some(PathBuf::from(
            args.next().ok_or("send requires an input path")?,
        ))
    } else {
        None
    };
    let mut config = FileTransferConfig::default();
    let mut listen = None;
    let mut peer = None;
    let mut output = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return print_usage(),
            "--closed-loop" => config.closed_loop = true,
            "--lab-observe-ip" => config.lab_observe_ip = true,
            "--budget" => {
                config.one_way_symbol_budget = Some(
                    args.next()
                        .ok_or("--budget requires a symbol count")?
                        .parse()?,
                );
            }
            "--listen" => {
                listen = Some(
                    args.next()
                        .ok_or("--listen requires a local SocketAddr")?
                        .parse::<SocketAddr>()?,
                );
            }
            "--peer" => {
                peer = Some(
                    args.next()
                        .ok_or("--peer requires a peer SocketAddr")?
                        .parse::<SocketAddr>()?,
                );
            }
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ));
            }
            _ => return Err(format!("unknown option {arg}").into()),
        }
    }
    let listen = listen.ok_or("UDP transfer requires --listen LOCAL_ADDR")?;
    let peer = peer.ok_or("UDP transfer requires --peer PEER_ADDR")?;

    if mode == "send" {
        if output.is_some() {
            return Err("send does not accept --output".into());
        }
        let input = input.expect("send input was parsed above");
        let file_name = input
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("input path has no UTF-8 file name")?;
        let file = std::fs::read(&input)?;
        let report = run_udp_sender(listen, peer, file_name, &file, config)?;
        println!(
            "sent file={} bytes={} k={} budget={} generated={} status={:?} closed_loop={} data_packets={} feedback_packets={} acks={} nacks={}",
            report.file_name,
            report.file_len,
            report.source_symbols,
            report.stated_symbol_budget,
            report.generated_symbols,
            report.sender_status,
            report.closed_loop,
            report.data_datagrams_sent,
            report.feedback_datagrams_sent,
            report.acks_received,
            report.nacks_received,
        );
        return Ok(());
    }

    let output = output.ok_or("recv requires --output PATH")?;
    let report = run_udp_receiver(listen, peer, config)?;
    std::fs::write(&output, &report.recovered_file)?;
    println!(
        "recovered=true file={} bytes={} k={} data_packets={} manifests={} feedback_packets={} output={}",
        report.file_name,
        report.file_len,
        report.source_symbols,
        report.data_datagrams_received,
        report.manifests_received,
        report.feedback_datagrams_sent,
        output.display(),
    );
    Ok(())
}

fn run_reflexive_probe_mode(
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut listen = None;
    let mut helper = None;
    let mut timeout_ms = 1_000_u64;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return print_usage(),
            "--listen" => {
                listen = Some(
                    args.next()
                        .ok_or("--listen requires a local SocketAddr")?
                        .parse::<SocketAddr>()?,
                );
            }
            "--helper" => {
                helper = Some(
                    args.next()
                        .ok_or("--helper requires a SocketAddr")?
                        .parse::<SocketAddr>()?,
                );
            }
            "--timeout-ms" => {
                timeout_ms = args
                    .next()
                    .ok_or("--timeout-ms requires an integer")?
                    .parse()?;
            }
            _ => return Err(format!("unknown option {arg}").into()),
        }
    }
    let listen = listen.ok_or("reflexive-probe requires --listen LOCAL_ADDR")?;
    let helper = helper.ok_or("reflexive-probe requires --helper HELPER_ADDR")?;
    let report = run_reflexive_probe(listen, helper, Duration::from_millis(timeout_ms))?;
    println!(
        "reflexive={} helper={} note=candidate-only-not-validated",
        report.reflexive, report.helper
    );
    Ok(())
}

fn run_reflexive_helper_mode(
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut listen = None;
    let mut duration_ms = 30_000_u64;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return print_usage(),
            "--listen" => {
                listen = Some(
                    args.next()
                        .ok_or("--listen requires a local SocketAddr")?
                        .parse::<SocketAddr>()?,
                );
            }
            "--duration-ms" => {
                duration_ms = args
                    .next()
                    .ok_or("--duration-ms requires an integer")?
                    .parse()?;
            }
            _ => return Err(format!("unknown option {arg}").into()),
        }
    }
    let listen = listen.ok_or("reflexive-helper requires --listen LOCAL_ADDR")?;
    let answered = run_reflexive_helper(listen, Duration::from_millis(duration_ms))?;
    println!("reflexive_helper_answered={answered} listen={listen}");
    Ok(())
}

fn usage<T>() -> Result<T, Box<dyn std::error::Error>> {
    eprintln!("{USAGE}");
    Err("missing or invalid arguments".into())
}

fn print_usage() -> Result<(), Box<dyn std::error::Error>> {
    println!("{USAGE}");
    Ok(())
}
