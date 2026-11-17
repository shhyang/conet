//! S9 UDP-LI reference-profile adapter.
//!
//! The adapter owns a datagram transport and all profile queues. Generic packet,
//! queue, pacing, clock, wire, and controller contracts remain in `conet_core`;
//! this crate adds association policy, scheduling, and UDP boundaries.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod association;
pub mod endpoint;
pub mod keepalive;
#[cfg(target_os = "linux")]
mod linux;
pub mod path_challenge;
pub mod reflexive;
pub mod scheduler;
pub mod sim;
pub mod transport;

pub use association::{AssociationError, AssociationState, Role};
pub use endpoint::{
    DriveReport, EndpointConfig, LocalSendOutcome, ProfileEnqueueError, ProfileEnqueueErrorKind,
    ReceivedDatagram, SentDatagram, UdpLiEndpoint, UdpLiEnqueueStatus, payload_packet,
};
pub use scheduler::{ControlWindow, SchedulerConfig, SendClass, choose_class};
pub use sim::{SimFrame, SimNetwork, SimTransport};
#[cfg(target_os = "linux")]
pub use transport::LinuxOffloadCapabilities;
pub use keepalive::{
    KEEPALIVE_MAGIC, KEEPALIVE_VERSION, KeepaliveConfig, KeepaliveError, KeepaliveStats,
    PROPOSED_IDLE_AFTER, PROPOSED_INTERVAL,
};
pub use path_challenge::{
    PATH_CHALLENGE_MAGIC, PATH_CHALLENGE_VERSION, PathChallengeError, PathChallengePoll,
    PendingPathChallenge,
};
pub use reflexive::{
    ReflexiveError, ReflexiveReport, REFLEXIVE_MAGIC, REFLEXIVE_VERSION, decode_response,
    discover_reflexive, encode_request, encode_response, reflect_request, serve_reflexive_until,
};
pub use transport::{
    ConnectedUdpTransport, DatagramTransport, EcnCodepoint, InboundDatagram, LeasedWire,
    LoopbackError, LoopbackUdpTransport, PeerAdmitPolicy, PeerBindingState, PeerRejectStats,
    RecvMeta, WireBuf, WireBufPool, WireIoCounters, WireIoStats, WireLease,
};
