//! S9 UDP-LI reference-profile adapter.
//!
//! The adapter owns a datagram transport and all profile queues. Generic packet,
//! queue, pacing, clock, wire, and controller contracts remain in `conet_core`;
//! this crate adds association policy, scheduling, and UDP boundaries.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod association;
pub mod endpoint;
#[cfg(target_os = "linux")]
mod linux;
pub mod scheduler;
pub mod sim;
pub mod transport;

pub use association::{
    ASSOCIATION_BODY_LEN, AssociationError, AssociationState, HandshakePolicy, OpenStateBody, Role,
    UDP_LI_PROFILE_ID,
};
pub use endpoint::{
    DriveReport, EndpointConfig, EnqueueBeforeEstablished, ProfileEnqueueError,
    ProfileEnqueueErrorKind, ReceivedDatagram, SentDatagram, UdpLiEndpoint, UdpLiEnqueueStatus,
    payload_packet,
};
pub use scheduler::{ControlWindow, SchedulerConfig, SendClass, choose_class};
pub use sim::{SimFrame, SimNetwork, SimTransport};
#[cfg(target_os = "linux")]
pub use transport::LinuxOffloadCapabilities;
pub use transport::{
    DatagramTransport, EcnCodepoint, InboundDatagram, LeasedWire, LoopbackError,
    LoopbackUdpTransport, RecvMeta, WireBuf, WireBufPool, WireIoCounters, WireIoStats, WireLease,
};

/// OPEN/ACCEPT fields initialized at packetization and kept locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenState {
    pub profile_id: u16,
    pub max_datagram: u16,
    pub nonce: u64,
}
