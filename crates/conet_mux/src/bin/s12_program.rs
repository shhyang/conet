use std::env;
use std::process::ExitCode;
use std::time::Duration;

use conet_core::{HeaderBuf, LinkEndpoint, PacketBuilder};
use conet_mux::{ProgramMuxEndpoint, UserId};

fn main() -> ExitCode {
    let args: Vec<_> = env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: s12_program <local-socket> <mux-socket> <user-id> <payload>");
        return ExitCode::from(2);
    }
    let Ok(user_id) = args[3].parse::<UserId>() else {
        return ExitCode::from(2);
    };
    let payload = args[4].as_bytes();
    let Ok(mut endpoint) = ProgramMuxEndpoint::connect(&args[1], &args[2], user_id) else {
        return ExitCode::FAILURE;
    };
    endpoint.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let mut builder = PacketBuilder::with_capacity(payload.len(), 16);
    builder.payload_mut().copy_from_slice(payload);
    *builder.header_mut() = HeaderBuf::zeroed(16);
    if endpoint.outgoing().enqueue(builder.freeze()).is_err() {
        return ExitCode::FAILURE;
    }

    match endpoint.incoming().recv() {
        Some(reply) if reply.payload_bytes() == payload => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
