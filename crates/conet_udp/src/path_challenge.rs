//! Path challenge / response for peer validation (UL-3).
//!
//! Minimal Conet lab frames (`CULP`) exchanged on the association UDP socket.
//! A matching response promotes an observed or candidate peer to
//! `Validated`/`Locked`. This is **not** S2-6 authentication; the optional
//! token is a shared test secret until a real MAC profile exists.
//!
//! Challenge datagrams are not fountain-protected and are not Conet wire
//! layout tag-5 frames (distinct magic), so they are ignored by the Conet
//! parser and counted as non-Conet unless handled here first.

use core::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Wire magic for Conet UDP-LI Path challenge frames (`CULP`).
pub const PATH_CHALLENGE_MAGIC: [u8; 4] = *b"CULP";
pub const PATH_CHALLENGE_VERSION: u8 = 1;
pub const PATH_CHALLENGE_TYPE: u8 = 1;
pub const PATH_RESPONSE_TYPE: u8 = 2;

const HEADER_LEN: usize = 14; // magic4 + ver1 + type1 + txn8
const MAX_TOKEN: usize = 32;
const MAX_FRAME: usize = HEADER_LEN + MAX_TOKEN;

/// One in-flight path challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPathChallenge {
    pub candidate: SocketAddr,
    pub txn: [u8; 8],
    pub token: [u8; 16],
    pub sent_at: Instant,
    pub attempts: u8,
    pub max_attempts: u8,
    pub per_attempt: Duration,
}

impl PendingPathChallenge {
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.sent_at) >= self.per_attempt
    }

    pub fn retries_exhausted(&self) -> bool {
        self.attempts >= self.max_attempts
    }

    /// Delay until the next retransmit or timeout decision.
    pub fn next_retransmit_in(&self, now: Instant) -> Duration {
        (self.sent_at + self.per_attempt).saturating_duration_since(now)
    }
}

/// Outcome of driving a pending challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathChallengePoll {
    /// Still waiting for a response.
    Pending,
    /// Matching response received; caller should promote the candidate.
    Validated { candidate: SocketAddr },
    /// Timed out after retries; fail closed.
    TimedOut { candidate: SocketAddr },
}

#[derive(Debug)]
pub enum PathChallengeError {
    Io(io::Error),
    Truncated,
    BadMagic,
    BadVersion { version: u8 },
    BadType { typ: u8 },
    TokenMismatch,
    Busy,
    NoCandidate,
}

impl fmt::Display for PathChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "path challenge I/O: {error}"),
            Self::Truncated => write!(f, "path challenge frame truncated"),
            Self::BadMagic => write!(f, "path challenge bad magic"),
            Self::BadVersion { version } => {
                write!(f, "path challenge unsupported version {version}")
            }
            Self::BadType { typ } => write!(f, "path challenge unexpected type {typ}"),
            Self::TokenMismatch => write!(f, "path challenge token mismatch"),
            Self::Busy => write!(f, "path challenge already in flight"),
            Self::NoCandidate => write!(f, "path challenge has no candidate"),
        }
    }
}

impl std::error::Error for PathChallengeError {}

impl From<io::Error> for PathChallengeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn fresh_txn() -> [u8; 8] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos
        .wrapping_mul(0xD1B5_4A32_D192_ED03)
        .wrapping_add(0x9E37_79B9_7F4A_7C15)
        .to_le_bytes()
}

fn fresh_token() -> [u8; 16] {
    let a = fresh_txn();
    let b = fresh_txn();
    let mut token = [0_u8; 16];
    token[..8].copy_from_slice(&a);
    token[8..].copy_from_slice(&b);
    token
}

/// Encode a path-challenge frame.
pub fn encode_challenge(txn: [u8; 8], token: &[u8]) -> Result<Vec<u8>, PathChallengeError> {
    if token.len() > MAX_TOKEN {
        return Err(PathChallengeError::Truncated);
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN + token.len());
    bytes.extend_from_slice(&PATH_CHALLENGE_MAGIC);
    bytes.push(PATH_CHALLENGE_VERSION);
    bytes.push(PATH_CHALLENGE_TYPE);
    bytes.extend_from_slice(&txn);
    bytes.extend_from_slice(token);
    Ok(bytes)
}

/// Encode a path-response echoing the challenge token.
pub fn encode_response(txn: [u8; 8], token: &[u8]) -> Result<Vec<u8>, PathChallengeError> {
    if token.len() > MAX_TOKEN {
        return Err(PathChallengeError::Truncated);
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN + token.len());
    bytes.extend_from_slice(&PATH_CHALLENGE_MAGIC);
    bytes.push(PATH_CHALLENGE_VERSION);
    bytes.push(PATH_RESPONSE_TYPE);
    bytes.extend_from_slice(&txn);
    bytes.extend_from_slice(token);
    Ok(bytes)
}

fn parse_header(bytes: &[u8]) -> Result<(u8, [u8; 8], &[u8]), PathChallengeError> {
    if bytes.len() < HEADER_LEN {
        return Err(PathChallengeError::Truncated);
    }
    if bytes[0..4] != PATH_CHALLENGE_MAGIC {
        return Err(PathChallengeError::BadMagic);
    }
    if bytes[4] != PATH_CHALLENGE_VERSION {
        return Err(PathChallengeError::BadVersion { version: bytes[4] });
    }
    let typ = bytes[5];
    let mut txn = [0_u8; 8];
    txn.copy_from_slice(&bytes[6..14]);
    Ok((typ, txn, &bytes[14..]))
}

/// Decode a challenge; returns `(txn, token)`.
pub fn decode_challenge(bytes: &[u8]) -> Result<([u8; 8], &[u8]), PathChallengeError> {
    let (typ, txn, token) = parse_header(bytes)?;
    if typ != PATH_CHALLENGE_TYPE {
        return Err(PathChallengeError::BadType { typ });
    }
    Ok((txn, token))
}

/// Decode a response; returns `(txn, token)`.
pub fn decode_response(bytes: &[u8]) -> Result<([u8; 8], &[u8]), PathChallengeError> {
    let (typ, txn, token) = parse_header(bytes)?;
    if typ != PATH_RESPONSE_TYPE {
        return Err(PathChallengeError::BadType { typ });
    }
    Ok((txn, token))
}

/// True when `bytes` look like a CULP frame (challenge or response).
pub fn is_path_challenge_frame(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN && bytes[0..4] == PATH_CHALLENGE_MAGIC
}

/// Reply to a challenge from `source` on `socket`.
pub fn respond_to_challenge(
    socket: &UdpSocket,
    request: &[u8],
    source: SocketAddr,
) -> Result<(), PathChallengeError> {
    let (txn, token) = decode_challenge(request)?;
    let response = encode_response(txn, token)?;
    socket.send_to(&response, source)?;
    Ok(())
}

/// Build a new pending challenge and transmit the first attempt.
pub fn start_challenge(
    socket: &UdpSocket,
    candidate: SocketAddr,
    max_attempts: u8,
    per_attempt: Duration,
) -> Result<PendingPathChallenge, PathChallengeError> {
    let txn = fresh_txn();
    let token = fresh_token();
    let frame = encode_challenge(txn, &token)?;
    socket.send_to(&frame, candidate)?;
    Ok(PendingPathChallenge {
        candidate,
        txn,
        token,
        sent_at: Instant::now(),
        attempts: 1,
        max_attempts: max_attempts.max(1),
        per_attempt,
    })
}

/// Retransmit if the per-attempt timer expired; otherwise leave pending.
pub fn maybe_retransmit(
    socket: &UdpSocket,
    pending: &mut PendingPathChallenge,
    now: Instant,
) -> Result<PathChallengePoll, PathChallengeError> {
    if !pending.is_expired(now) {
        return Ok(PathChallengePoll::Pending);
    }
    if pending.retries_exhausted() {
        return Ok(PathChallengePoll::TimedOut {
            candidate: pending.candidate,
        });
    }
    let frame = encode_challenge(pending.txn, &pending.token)?;
    socket.send_to(&frame, pending.candidate)?;
    pending.attempts = pending.attempts.saturating_add(1);
    pending.sent_at = now;
    Ok(PathChallengePoll::Pending)
}

/// If `bytes` is a matching response from `source`, return Validated.
pub fn match_response(
    pending: &PendingPathChallenge,
    source: SocketAddr,
    bytes: &[u8],
) -> Result<Option<PathChallengePoll>, PathChallengeError> {
    if source != pending.candidate {
        return Ok(None);
    }
    let (txn, token) = decode_response(bytes)?;
    if txn != pending.txn {
        return Ok(None);
    }
    if token != pending.token {
        return Err(PathChallengeError::TokenMismatch);
    }
    Ok(Some(PathChallengePoll::Validated {
        candidate: pending.candidate,
    }))
}

/// Maximum CULP frame size used by the transport receive scratch.
pub const fn max_frame_len() -> usize {
    MAX_FRAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_response_round_trip() {
        let txn = [9, 8, 7, 6, 5, 4, 3, 2];
        let token = [1_u8; 16];
        let challenge = encode_challenge(txn, &token).unwrap();
        let (got_txn, got_token) = decode_challenge(&challenge).unwrap();
        assert_eq!(got_txn, txn);
        assert_eq!(got_token, token);
        let response = encode_response(txn, token.as_slice()).unwrap();
        let (r_txn, r_token) = decode_response(&response).unwrap();
        assert_eq!(r_txn, txn);
        assert_eq!(r_token, token);
    }
}
