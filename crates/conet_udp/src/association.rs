//! UDP-LI association state and bounded OPEN duplication.

use core::fmt;

use conet_core::{MonoNs, OpaqueBytes};

use crate::OpenState;

/// Fixed profile identifier carried by OPEN and ACCEPT.
pub const UDP_LI_PROFILE_ID: u16 = 1;
/// OPEN/ACCEPT body length: profile id, max datagram, and nonce.
pub const ASSOCIATION_BODY_LEN: usize = 12;

/// Endpoint role in one association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Observable lifecycle of one UDP-LI association.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AssociationState {
    #[default]
    Idle,
    Handshaking,
    Established,
    Closing,
    Closed,
    Failed,
}

impl AssociationState {
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }
}

/// Bounded OPEN duplication policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakePolicy {
    pub retry_interval: MonoNs,
    pub max_sends: u8,
}

impl Default for HandshakePolicy {
    fn default() -> Self {
        Self {
            retry_interval: MonoNs::new(200_000_000),
            max_sends: 5,
        }
    }
}

/// Errors from association lifecycle operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssociationError {
    WrongRole,
    WrongState { state: AssociationState },
    NotEstablished { state: AssociationState },
}

impl fmt::Display for AssociationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRole => f.write_str("only an initiator may start an association"),
            Self::WrongState { state } => write!(f, "association is in state {state:?}"),
            Self::NotEstablished { state } => {
                write!(f, "association is not established (state {state:?})")
            }
        }
    }
}

impl std::error::Error for AssociationError {}

/// OPEN/ACCEPT body. Its nonce is profile-local and opaque to controllers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenStateBody {
    pub profile_id: u16,
    pub max_datagram: u16,
    pub nonce: u64,
}

impl OpenStateBody {
    pub fn encode(&self) -> OpaqueBytes {
        let mut bytes = Vec::with_capacity(ASSOCIATION_BODY_LEN);
        bytes.extend_from_slice(&self.profile_id.to_be_bytes());
        bytes.extend_from_slice(&self.max_datagram.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        OpaqueBytes::from(bytes)
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != ASSOCIATION_BODY_LEN {
            return None;
        }
        Some(Self {
            profile_id: u16::from_be_bytes([body[0], body[1]]),
            max_datagram: u16::from_be_bytes([body[2], body[3]]),
            nonce: u64::from_be_bytes(body[4..12].try_into().ok()?),
        })
    }
}

pub(crate) fn make_open_state(max_datagram: usize, nonce: u64) -> OpenState {
    OpenState {
        profile_id: UDP_LI_PROFILE_ID,
        max_datagram: u16::try_from(max_datagram).unwrap_or(u16::MAX),
        nonce,
    }
}
