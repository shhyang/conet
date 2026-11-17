//! Idle keepalive for NAT mapping refresh (UL-4).
//!
//! Lightweight `CULK` pings are sent on the association UDP socket toward the
//! **trusted** peer when the path has been idle. They sit outside the Conet
//! link-control scheduler and therefore do **not** consume the 10% control
//! byte budget.
//!
//! Proposed profile defaults (not frozen standards): idle after **15 s**,
//! repeat every **10 s** while still idle. Tests may use shorter durations.

use core::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Wire magic for Conet UDP-LI Keepalive frames (`CULK`).
pub const KEEPALIVE_MAGIC: [u8; 4] = *b"CULK";
pub const KEEPALIVE_VERSION: u8 = 1;
pub const KEEPALIVE_TYPE_PING: u8 = 1;
pub const KEEPALIVE_TYPE_PONG: u8 = 2;

const FRAME_LEN: usize = 6; // magic4 + ver1 + type1

/// Proposed production cadence (author-tunable; not a wire standard).
pub const PROPOSED_IDLE_AFTER: Duration = Duration::from_secs(15);
pub const PROPOSED_INTERVAL: Duration = Duration::from_secs(10);

/// Keepalive enablement and cadence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepaliveConfig {
    pub enabled: bool,
    /// Send the first ping after the path has been idle this long.
    pub idle_after: Duration,
    /// Minimum spacing between keepalives while still idle.
    pub interval: Duration,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_after: PROPOSED_IDLE_AFTER,
            interval: PROPOSED_INTERVAL,
        }
    }
}

impl KeepaliveConfig {
    /// Opt-in with the Proposed 15 s / 10 s cadence.
    pub const fn proposed() -> Self {
        Self {
            enabled: true,
            idle_after: PROPOSED_IDLE_AFTER,
            interval: PROPOSED_INTERVAL,
        }
    }

    /// Short cadence for deterministic tests.
    pub const fn for_test(idle_after: Duration, interval: Duration) -> Self {
        Self {
            enabled: true,
            idle_after,
            interval,
        }
    }
}

/// Observable keepalive counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeepaliveStats {
    pub sent: u64,
    pub received: u64,
    pub pongs_sent: u64,
}

#[derive(Debug)]
pub enum KeepaliveError {
    Io(io::Error),
    Truncated,
    BadMagic,
    BadVersion { version: u8 },
    BadType { typ: u8 },
    NoTrustedPeer,
}

impl fmt::Display for KeepaliveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "keepalive I/O: {error}"),
            Self::Truncated => write!(f, "keepalive frame truncated"),
            Self::BadMagic => write!(f, "keepalive bad magic"),
            Self::BadVersion { version } => {
                write!(f, "keepalive unsupported version {version}")
            }
            Self::BadType { typ } => write!(f, "keepalive unexpected type {typ}"),
            Self::NoTrustedPeer => write!(f, "keepalive requires a validated peer"),
        }
    }
}

impl std::error::Error for KeepaliveError {}

impl From<io::Error> for KeepaliveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Encode a keepalive ping.
pub fn encode_ping() -> [u8; FRAME_LEN] {
    let mut bytes = [0_u8; FRAME_LEN];
    bytes[0..4].copy_from_slice(&KEEPALIVE_MAGIC);
    bytes[4] = KEEPALIVE_VERSION;
    bytes[5] = KEEPALIVE_TYPE_PING;
    bytes
}

/// Encode a keepalive pong.
pub fn encode_pong() -> [u8; FRAME_LEN] {
    let mut bytes = [0_u8; FRAME_LEN];
    bytes[0..4].copy_from_slice(&KEEPALIVE_MAGIC);
    bytes[4] = KEEPALIVE_VERSION;
    bytes[5] = KEEPALIVE_TYPE_PONG;
    bytes
}

/// True when `bytes` look like a CULK frame.
pub fn is_keepalive_frame(bytes: &[u8]) -> bool {
    bytes.len() >= FRAME_LEN && bytes[0..4] == KEEPALIVE_MAGIC
}

/// Parse keepalive type (`PING` / `PONG`).
pub fn decode_keepalive(bytes: &[u8]) -> Result<u8, KeepaliveError> {
    if bytes.len() < FRAME_LEN {
        return Err(KeepaliveError::Truncated);
    }
    if bytes[0..4] != KEEPALIVE_MAGIC {
        return Err(KeepaliveError::BadMagic);
    }
    if bytes[4] != KEEPALIVE_VERSION {
        return Err(KeepaliveError::BadVersion { version: bytes[4] });
    }
    match bytes[5] {
        KEEPALIVE_TYPE_PING | KEEPALIVE_TYPE_PONG => Ok(bytes[5]),
        typ => Err(KeepaliveError::BadType { typ }),
    }
}

/// Send a ping toward `peer`.
pub fn send_ping(socket: &UdpSocket, peer: SocketAddr) -> Result<(), KeepaliveError> {
    socket.send_to(&encode_ping(), peer)?;
    Ok(())
}

/// Reply with a pong toward `peer`.
pub fn send_pong(socket: &UdpSocket, peer: SocketAddr) -> Result<(), KeepaliveError> {
    socket.send_to(&encode_pong(), peer)?;
    Ok(())
}

/// Mutable keepalive runtime state owned by the transport.
#[derive(Debug)]
pub struct KeepaliveState {
    pub config: KeepaliveConfig,
    pub stats: KeepaliveStats,
    last_activity: Instant,
    last_sent: Option<Instant>,
}

impl KeepaliveState {
    pub fn new(config: KeepaliveConfig) -> Self {
        Self {
            config,
            stats: KeepaliveStats::default(),
            last_activity: Instant::now(),
            last_sent: None,
        }
    }

    pub fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Returns true when a ping should be emitted now.
    pub fn should_send(&self, now: Instant) -> bool {
        matches!(self.next_due_in(now), Some(duration) if duration.is_zero())
    }

    /// Delay until the next idle ping should be sent, if keepalives are enabled.
    pub fn next_due_in(&self, now: Instant) -> Option<Duration> {
        if !self.config.enabled {
            return None;
        }
        let idle_at = self.last_activity + self.config.idle_after;
        let due = match self.last_sent {
            None => idle_at,
            Some(sent) => idle_at.max(sent + self.config.interval),
        };
        Some(due.saturating_duration_since(now))
    }

    pub fn mark_sent(&mut self, now: Instant) {
        self.last_sent = Some(now);
        self.stats.sent = self.stats.sent.saturating_add(1);
        // Sending is activity from the local NAT's perspective, but we keep
        // `last_activity` tied to useful traffic so idle cadence continues
        // until real data resumes.
    }

    pub fn mark_received(&mut self) {
        self.stats.received = self.stats.received.saturating_add(1);
        self.note_activity();
    }

    pub fn mark_pong_sent(&mut self) {
        self.stats.pongs_sent = self.stats.pongs_sent.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_round_trip() {
        assert_eq!(decode_keepalive(&encode_ping()).unwrap(), KEEPALIVE_TYPE_PING);
        assert_eq!(decode_keepalive(&encode_pong()).unwrap(), KEEPALIVE_TYPE_PONG);
        assert!(is_keepalive_frame(&encode_ping()));
    }

    #[test]
    fn idle_gate_respects_activity() {
        let mut state = KeepaliveState::new(KeepaliveConfig::for_test(
            Duration::from_millis(50),
            Duration::from_millis(20),
        ));
        let now = Instant::now();
        assert!(!state.should_send(now));
        assert!(state.should_send(now + Duration::from_millis(60)));
        state.mark_sent(now + Duration::from_millis(60));
        assert!(!state.should_send(now + Duration::from_millis(70)));
        assert!(state.should_send(now + Duration::from_millis(90)));
        state.note_activity();
        assert!(!state.should_send(Instant::now()));
    }
}
