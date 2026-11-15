use std::path::PathBuf;

use conet_transfer::{
    FileTransferConfig, SimulatorImpairment, run_loopback_transfer, run_simulated_transfer,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("conet_transfer: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(mode) = args.next() else {
        return usage_error();
    };
    if mode == "--help" || mode == "-h" {
        print_usage();
        return Ok(());
    }
    let Some(input) = args.next() else {
        return usage_error();
    };
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
    let report = match mode.as_str() {
        "simulate" => run_simulated_transfer(file_name, &file, config, impairment)?,
        "loopback" => {
            if impairment.forward_loss_every.is_some() || impairment.reverse_loss_every.is_some() {
                return Err("loopback is lossless and does not accept --loss-every".into());
            }
            run_loopback_transfer(file_name, &file, config)?
        }
        _ => return usage_error(),
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

fn print_usage() {
    println!(
        "usage:\n  conet_transfer simulate INPUT [--output PATH] [--loss-every N] [--budget N] [--closed-loop]\n  conet_transfer loopback INPUT [--output PATH] [--budget N] [--closed-loop]\n\ndefault policy: one-way/open-loop; closed loop is opt-in\nloopback is restricted to 127.0.0.1 by the transport adapter"
    );
}

fn usage_error<T>() -> Result<T, Box<dyn std::error::Error>> {
    print_usage();
    Err("missing or invalid arguments".into())
}
