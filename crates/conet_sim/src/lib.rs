//! Deterministic in-process network paths for Conet link contracts.
//!
//! Each directed path models a router output queue with serialization,
//! drop-tail buffering, propagation delay, and post-link Bernoulli loss. The
//! path owns [`conet_core::PacketHandle`]s directly and uses only caller-driven
//! logical time.

#![forbid(unsafe_code)]

mod path;

pub use path::{
    CapacityStep, DuplexPath, PathConfig, PathEndpoint, PathReceiver, PathSender, PathStats,
    duplex_path, path_link,
};
