//! Generic, runtime-neutral contracts for owned datagram packets.
//!
//! This crate is deliberately independent of UDP, sockets, and application
//! policy. It provides the deterministic harness, shared immutable payload
//! handles, bounded queues, in-process identity links, reusable rate
//! pacing/controller contracts, and a profile-local wire container without
//! adding transport or typed controller bodies.

#![forbid(unsafe_code)]

pub mod accounting;
pub mod clock;
pub mod control;
pub mod endpoint;
pub mod link;
pub mod paced;
pub mod pacing;
pub mod packet;
pub mod queue;
pub mod reliability;
pub mod scheduler;
pub mod wire;

pub use accounting::{BackingAccounting, BackingStats, PacketMetrics, PayloadCopyCounter};
pub use clock::{Clock, ClockError, Drive, MonoNs, VirtualClock};
pub use control::{
    AppliedDecision, ControlDisposition, Delivery, FixedRateController, Observation, OpaqueBytes,
    Pace, RateControlPolicy, RxController, TxController, apply_controller_decision,
};
pub use endpoint::{EndpointError, StubEndpoint};
pub use link::{
    FanoutError, FanoutSender, FanoutStatus, ForwardError, ForwardOutcome, IdentityForwarder,
    IdentityReceiver, IdentitySender, LinkReceiver, LinkSender, identity_link,
};
pub use paced::{
    DeviceStubSender, LinkCaps, PacedIdentitySender, PacketClass, SendRecord, device_stub_link,
    device_stub_link_with_pacer, paced_identity_link, paced_identity_link_with_pacer,
};
pub use pacing::{ByteRate, DiscreteRatePacer, RatePacer};
pub use packet::{BackingId, HeaderBuf, PacketBuilder, PacketHandle, PayloadRef, SliceError};
pub use queue::{
    CancelResult, EnqueueError, EnqueueErrorKind, EnqueueStatus, InvalidReason, Occupancy,
    PacketQueue, QueueLimits,
};
pub use reliability::{
    BidirectionalAck, BlockCodec, BlockId, BlockShape, BlockSnapshot, BlockStatus, CodecError,
    DecodeStatus, Feedback, FeedbackDisposition, FeedbackKind, FeedbackReport,
    FeedbackResponderConfig, FlushReport, InProcessLink, LinkEndpoint, OneWayBudget,
    PolicyCompletion, PolicyPoll, ReceiveReport, RelCodecError, ReliabilityPolicy,
    ReliabilityReceiver, ReliabilityResponder, ReliabilitySender, ResponderPump, SenderPump,
    StageReport, SymbolId, SymbolMeta, SystematicBlockCodec, parse_reliability_data_header,
    reliability_feedback_packet,
};
pub use scheduler::{DriveEvent, ScheduleError, ScheduleId, SeededScheduler};
pub use wire::{
    ControlMessage, ControlType, QosClass, REFERENCE_WIRE_HEADER_LEN, REFERENCE_WIRE_MAGIC,
    REFERENCE_WIRE_VERSION, RELIABILITY_DATA_PREFIX_LEN, RELIABILITY_FEEDBACK_LEN,
    ReferenceWireCodec, ReliabilityContentError, ReliabilityDataContent, WireDatagram, WireError,
    WireFlags, WireHeader, WireLimits, decode_reliability_data, decode_reliability_feedback,
    encode_reliability_data, encode_reliability_feedback,
};
