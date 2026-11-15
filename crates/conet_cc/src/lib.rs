//! Format-agnostic congestion-control hook for Conet.
//!
//! This crate is only a public facade over the controller ports in
//! `conet_core`. A controller may attach arbitrary opaque bytes to datagram
//! trailers, exchange standalone opaque feedback messages, and propose an
//! independent pacing rate and inflight/window cap.
//!
//! Implementations such as window-only TCP-style control, pacing-based BBR, or
//! profile-specific research algorithms can use the same [`TxController`] and
//! [`RxController`] traits. The transport never interprets controller bodies.

#![forbid(unsafe_code)]

mod ledger;

pub mod bbr;
pub mod bookkeeping;
pub mod cubic;
pub mod feedback;

pub use bbr::{
    BBR_CWND_GAIN, BBR_DRAIN_PACING_GAIN, BBR_FULL_BW_GROWTH, BBR_FULL_BW_ROUNDS,
    BBR_INITIAL_BANDWIDTH, BBR_INITIAL_RTT, BBR_LOSS_HEADROOM, BBR_MSS_BYTES,
    BBR_PROBE_ACKS_PER_GAIN, BBR_STARTUP_PACING_GAIN, BbrController, BbrMode,
};
pub use bookkeeping::BookkeepingTestController;
pub use cubic::{
    CUBIC_BETA, CUBIC_C, CUBIC_GROWTH_TICK, CubicController, DEFAULT_MSS_BYTES,
    INITIAL_WINDOW_SEGMENTS, MIN_WINDOW_SEGMENTS,
};
pub use feedback::{
    AckReceiver, FEEDBACK_RESEND_INTERVAL, FeedbackEvent, FeedbackMessage, MAX_FEEDBACK_EVENTS,
    MAX_FEEDBACK_RESENDS,
};
pub use ledger::{InflightLedger, SentPacket};

pub use conet_core::{
    AppliedDecision, ByteRate, ControlDisposition, Delivery, FixedRateController, MonoNs,
    Observation, OpaqueBytes, Pace, RateControlPolicy, RxController, TxController,
    apply_controller_decision,
};
