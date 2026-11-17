//! Lightweight UDP-LI lifecycle (UL-1).
//!
//! The datagram path is usable as soon as an endpoint owns its socket binding.
//! There is no OPEN/ACCEPT state machine and no association deadline. Soft
//! OPEN/ACCEPT types on the wire remain inert diagnostics.
//!
//! `Closed` is local: enqueue and transmit stop; inbound datagrams are dropped
//! with reason `closed`. An initiator may call `start_association` again to
//! reopen without a peer handshake.

use core::fmt;

/// Endpoint role retained for compatibility with the reference profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Observable UDP-LI lifecycle.
///
/// `Ready` means ordinary datagrams may be sent and received immediately.
/// `Closed` is a local shutdown state; it does not imply a peer handshake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AssociationState {
    #[default]
    Ready,
    Closed,
}

impl AssociationState {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Errors from local lifecycle operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssociationError {
    WrongState { state: AssociationState },
}

impl fmt::Display for AssociationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongState { state } => write!(f, "UDP-LI endpoint is in state {state:?}"),
        }
    }
}

impl std::error::Error for AssociationError {}
