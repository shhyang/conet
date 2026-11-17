//! Same-socket reflexive address discovery (UL-6).
//!
//! A minimal Conet lab helper (`CULR`) that reflects the observed UDP source
//! address back to the probing socket. This is **not** STUN/ICE/TURN and must
//! not be treated as authenticated path validation (that is UL-3 / S2-6).
//!
//! Use the result as an out-of-band candidate for `--peer` (or rendezvous).
//! Do **not** fill `--peer` from an HTTP “what is my IP” service—field WAN
//! probes showed HTTP and UDP egress can disagree.

use core::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Wire magic for Conet UDP-LI Reflexive helper frames (`CULR`).
pub const REFLEXIVE_MAGIC: [u8; 4] = *b"CULR";
pub const REFLEXIVE_VERSION: u8 = 1;
pub const REFLEXIVE_TYPE_REQUEST: u8 = 1;
pub const REFLEXIVE_TYPE_RESPONSE: u8 = 2;

const HEADER_LEN: usize = 14; // magic(4) + ver(1) + type(1) + txn(8)
const MAX_FRAME: usize = HEADER_LEN + 1 + 2 + 16;

/// Result of a same-socket reflexive probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReflexiveReport {
    /// Address the helper observed as this socket's UDP source.
    pub reflexive: SocketAddr,
    /// Helper that answered.
    pub helper: SocketAddr,
}

/// Errors from encoding, decoding, or probing.
#[derive(Debug)]
pub enum ReflexiveError {
    Io(io::Error),
    Truncated,
    BadMagic,
    BadVersion { version: u8 },
    BadType { typ: u8 },
    TxnMismatch,
    TimedOut,
    UnsupportedFamily { family: u8 },
}

impl fmt::Display for ReflexiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "reflexive I/O: {error}"),
            Self::Truncated => write!(f, "reflexive frame truncated"),
            Self::BadMagic => write!(f, "reflexive frame bad magic"),
            Self::BadVersion { version } => write!(f, "reflexive unsupported version {version}"),
            Self::BadType { typ } => write!(f, "reflexive unexpected type {typ}"),
            Self::TxnMismatch => write!(f, "reflexive transaction id mismatch"),
            Self::TimedOut => write!(f, "reflexive probe timed out"),
            Self::UnsupportedFamily { family } => {
                write!(f, "reflexive unsupported address family {family}")
            }
        }
    }
}

impl std::error::Error for ReflexiveError {}

impl From<io::Error> for ReflexiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Encode a reflexive request with the given transaction id.
pub fn encode_request(txn: [u8; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN);
    bytes.extend_from_slice(&REFLEXIVE_MAGIC);
    bytes.push(REFLEXIVE_VERSION);
    bytes.push(REFLEXIVE_TYPE_REQUEST);
    bytes.extend_from_slice(&txn);
    bytes
}

/// Encode a reflexive response reflecting `observed`.
pub fn encode_response(txn: [u8; 8], observed: SocketAddr) -> Result<Vec<u8>, ReflexiveError> {
    let mut bytes = Vec::with_capacity(MAX_FRAME);
    bytes.extend_from_slice(&REFLEXIVE_MAGIC);
    bytes.push(REFLEXIVE_VERSION);
    bytes.push(REFLEXIVE_TYPE_RESPONSE);
    bytes.extend_from_slice(&txn);
    match observed {
        SocketAddr::V4(addr) => {
            bytes.push(4);
            bytes.extend_from_slice(&addr.port().to_be_bytes());
            bytes.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            bytes.push(6);
            bytes.extend_from_slice(&addr.port().to_be_bytes());
            bytes.extend_from_slice(&addr.ip().octets());
        }
    }
    Ok(bytes)
}

/// Parse a reflexive response; returns `(txn, reflected)`.
pub fn decode_response(bytes: &[u8]) -> Result<([u8; 8], SocketAddr), ReflexiveError> {
    if bytes.len() < HEADER_LEN + 1 + 2 {
        return Err(ReflexiveError::Truncated);
    }
    if bytes[0..4] != REFLEXIVE_MAGIC {
        return Err(ReflexiveError::BadMagic);
    }
    if bytes[4] != REFLEXIVE_VERSION {
        return Err(ReflexiveError::BadVersion { version: bytes[4] });
    }
    if bytes[5] != REFLEXIVE_TYPE_RESPONSE {
        return Err(ReflexiveError::BadType { typ: bytes[5] });
    }
    let mut txn = [0_u8; 8];
    txn.copy_from_slice(&bytes[6..14]);
    let family = bytes[14];
    let port = u16::from_be_bytes([bytes[15], bytes[16]]);
    let addr = match family {
        4 => {
            if bytes.len() < HEADER_LEN + 1 + 2 + 4 {
                return Err(ReflexiveError::Truncated);
            }
            let ip = Ipv4Addr::new(bytes[17], bytes[18], bytes[19], bytes[20]);
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        6 => {
            if bytes.len() < HEADER_LEN + 1 + 2 + 16 {
                return Err(ReflexiveError::Truncated);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[17..33]);
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
        other => return Err(ReflexiveError::UnsupportedFamily { family: other }),
    };
    Ok((txn, addr))
}

fn decode_request(bytes: &[u8]) -> Result<[u8; 8], ReflexiveError> {
    if bytes.len() < HEADER_LEN {
        return Err(ReflexiveError::Truncated);
    }
    if bytes[0..4] != REFLEXIVE_MAGIC {
        return Err(ReflexiveError::BadMagic);
    }
    if bytes[4] != REFLEXIVE_VERSION {
        return Err(ReflexiveError::BadVersion { version: bytes[4] });
    }
    if bytes[5] != REFLEXIVE_TYPE_REQUEST {
        return Err(ReflexiveError::BadType { typ: bytes[5] });
    }
    let mut txn = [0_u8; 8];
    txn.copy_from_slice(&bytes[6..14]);
    Ok(txn)
}

fn fresh_txn() -> [u8; 8] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xA24B_AED4_96E5_7B05);
    mixed.to_le_bytes()
}

/// Probe `helper` from an already-bound UDP socket (same socket as the association).
///
/// The returned address is a **candidate only**. Do not treat it as a validated
/// path identity without UL-3 / authentication.
pub fn discover_reflexive(
    socket: &UdpSocket,
    helper: SocketAddr,
    timeout: Duration,
) -> Result<ReflexiveReport, ReflexiveError> {
    let txn = fresh_txn();
    let request = encode_request(txn);
    let started = Instant::now();
    let previous_timeout = socket.read_timeout()?;
    socket.send_to(&request, helper)?;

    // Blocking reads with a short timeout; restore nonblocking afterward.
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(timeout.min(Duration::from_millis(250))))?;

    let mut buf = [0_u8; MAX_FRAME];
    let result = loop {
        if started.elapsed() >= timeout {
            break Err(ReflexiveError::TimedOut);
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        let slice = remaining.min(Duration::from_millis(250)).max(Duration::from_millis(1));
        let _ = socket.set_read_timeout(Some(slice));
        match socket.recv_from(&mut buf) {
            Ok((len, source)) => match decode_response(&buf[..len]) {
                Ok((got_txn, reflexive)) if got_txn == txn => {
                    break Ok(ReflexiveReport {
                        reflexive,
                        helper: source,
                    });
                }
                Ok(_) => continue, // wrong txn or unrelated
                Err(ReflexiveError::BadMagic) | Err(ReflexiveError::BadType { .. }) => continue,
                Err(error) => break Err(error),
            },
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => break Err(ReflexiveError::Io(error)),
        }
    };

    let _ = socket.set_read_timeout(previous_timeout);
    let _ = socket.set_nonblocking(true);
    result
}

/// Reflect one inbound request: reply to `source` with the observed address.
pub fn reflect_request(socket: &UdpSocket, request: &[u8], source: SocketAddr) -> Result<(), ReflexiveError> {
    let txn = decode_request(request)?;
    let response = encode_response(txn, source)?;
    socket.send_to(&response, source)?;
    Ok(())
}

/// Serve reflexive requests until `deadline`, answering every valid request.
pub fn serve_reflexive_until(
    socket: &UdpSocket,
    deadline: Instant,
) -> Result<u64, ReflexiveError> {
    let previous_timeout = socket.read_timeout()?;
    socket.set_nonblocking(false)?;
    let mut answered = 0_u64;
    let mut buf = [0_u8; MAX_FRAME];
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = socket.set_read_timeout(Some(remaining.min(Duration::from_millis(500))));
        match socket.recv_from(&mut buf) {
            Ok((len, source)) => {
                if reflect_request(socket, &buf[..len], source).is_ok() {
                    answered = answered.saturating_add(1);
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                let _ = socket.set_read_timeout(previous_timeout);
                let _ = socket.set_nonblocking(true);
                return Err(ReflexiveError::Io(error));
            }
        }
    }
    let _ = socket.set_read_timeout(previous_timeout);
    let _ = socket.set_nonblocking(true);
    Ok(answered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_v4_codec() {
        let txn = [1, 2, 3, 4, 5, 6, 7, 8];
        let observed: SocketAddr = "203.0.113.10:19002".parse().unwrap();
        let bytes = encode_response(txn, observed).unwrap();
        let (got_txn, got) = decode_response(&bytes).unwrap();
        assert_eq!(got_txn, txn);
        assert_eq!(got, observed);
    }

    #[test]
    fn same_socket_probe_against_local_helper() {
        let helper = UdpSocket::bind("127.0.0.1:0").unwrap();
        let helper_addr = helper.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();

        let helper_thread = std::thread::spawn(move || {
            serve_reflexive_until(&helper, Instant::now() + Duration::from_secs(2)).unwrap()
        });

        let report =
            discover_reflexive(&client, helper_addr, Duration::from_secs(1)).expect("probe");
        assert_eq!(report.reflexive, client_addr);
        assert_eq!(report.helper, helper_addr);
        assert!(helper_thread.join().unwrap() >= 1);
    }
}
