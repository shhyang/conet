//! Observation/decision controller ports and the fixed-rate policy.
//!
//! A controller consumes observations and injected-time events. It exposes a
//! [`Pace`] but never owns a socket, queue, or payload. A paced link applies
//! controller pacing only when its profile's [`RateControlPolicy`] permits it.

use crate::clock::MonoNs;
use crate::pacing::{ByteRate, RatePacer};

/// Profile- or companion-defined opaque control bytes.
pub type OpaqueBytes = bytes::Bytes;

/// Whether a controller understood an opaque peer body.
///
/// A well-formed no-op is usable: the private codec accepted the body even if
/// its effect was already known. The link never interprets the body or reaches
/// into a controller-specific error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlDisposition {
    Usable,
    Unusable,
}

/// One receiver-side observation about a delivered datagram.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    pub recv_ts: MonoNs,
    pub len: u16,
    /// Application/user payload bytes carried by this datagram.
    ///
    /// Standalone link-control datagrams report zero. Controllers use this
    /// field to avoid acknowledging feedback-only datagrams.
    pub payload_len: u16,
    pub seq: Option<u64>,
    /// Opaque CC bytes accepted from an admissible datagram trailer.
    ///
    /// The link does not parse this body. The receiving controller owns its
    /// format and may ignore malformed bytes.
    pub cc_bytes: Option<OpaqueBytes>,
}

impl Observation {
    pub fn new(recv_ts: MonoNs, len: u16) -> Self {
        Self {
            recv_ts,
            len,
            payload_len: len,
            ..Self::default()
        }
    }
}

/// Delivery information for a future ACK/loss-aware sender controller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    pub seq: Option<u64>,
    pub bytes: u16,
    pub acked: bool,
    pub lost: bool,
    /// Round-trip time as nanoseconds when the link can measure one.
    pub rtt_ns: Option<u64>,
}

/// A controller's independent pacing outputs.
///
/// Rate and inflight fields are independent. A window-only controller sets
/// only `inflight_limit_bytes`; a rate-plus-cap controller sets both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pace {
    target_rate: Option<ByteRate>,
    inflight_limit_bytes: Option<u64>,
}

impl Pace {
    pub const NOOP: Self = Self {
        target_rate: None,
        inflight_limit_bytes: None,
    };

    pub const fn set_target_rate(bytes_per_sec: ByteRate) -> Self {
        Self {
            target_rate: Some(bytes_per_sec),
            inflight_limit_bytes: None,
        }
    }

    pub const fn set_inflight_limit(bytes: u64) -> Self {
        Self {
            target_rate: None,
            inflight_limit_bytes: Some(bytes),
        }
    }

    pub const fn set_rate_and_inflight(bytes_per_sec: ByteRate, inflight_limit_bytes: u64) -> Self {
        Self {
            target_rate: Some(bytes_per_sec),
            inflight_limit_bytes: Some(inflight_limit_bytes),
        }
    }

    pub const fn target_rate(self) -> Option<ByteRate> {
        self.target_rate
    }

    pub const fn inflight_limit_bytes(self) -> Option<u64> {
        self.inflight_limit_bytes
    }

    pub const fn is_noop(self) -> bool {
        self.target_rate.is_none() && self.inflight_limit_bytes.is_none()
    }
}

/// Sender-side controller port.
///
/// The methods deliberately carry no transport or socket handle. A link owns
/// transport state and independently decides whether to apply the exposed pace.
pub trait TxController {
    /// Reset controller state for a new association epoch.
    fn restart(&mut self) {}

    /// The link's single clock entry point.
    fn on_clock(&mut self, now: MonoNs);

    /// An admitted opaque peer body.
    fn on_peer_control(&mut self, now: MonoNs, body: OpaqueBytes) -> ControlDisposition;

    /// One successfully emitted payload-bearing datagram.
    ///
    /// The reference UDP profile reports file-data and reliability-feedback
    /// classes. Association and standalone controller-control datagrams are
    /// excluded so a data window cannot deadlock its own ACK path.
    fn on_packet_sent(&mut self, _now: MonoNs, _bytes: u16, _seq: Option<u64>) {}

    fn on_delivery(&mut self, _now: MonoNs, _delivery: Delivery) {}

    /// Bytes currently believed to be in flight by this controller.
    ///
    /// Window-aware controllers report a ledger sample so a link can enforce
    /// their [`Pace::inflight_limit_bytes`]. The default preserves today's
    /// send behavior for rate-only controllers.
    fn inflight_bytes(&self) -> Option<u64> {
        None
    }

    /// The sender's current independent rate and inflight proposals.
    fn pace(&self) -> Pace;

    /// Next locally armed controller wakeup, if any.
    fn next_wakeup(&self) -> Option<MonoNs> {
        None
    }

    /// Opaque control the sender may emit at `now`. The default is none.
    fn poll_control(&mut self, _now: MonoNs) -> Option<OpaqueBytes> {
        None
    }

    /// Opaque CC bytes to attach to the next eligible user datagram.
    ///
    /// A controller may use trailers, standalone control messages, both, or
    /// neither. The transport treats the returned bytes as an opaque body.
    fn attach_cc(&self) -> Option<OpaqueBytes> {
        None
    }

    /// Commit that an opaque control proposal was emitted.
    ///
    /// This covers bodies returned by both [`Self::attach_cc`] and
    /// [`Self::poll_control`]. Controllers allocate a fresh private identity
    /// only here, so planning probes, inflight-cap blocks, failed enqueues, and
    /// failed sends do not burn an identity.
    fn on_cc_sent(&mut self, _body: &OpaqueBytes) {}
}

/// Receiver-side controller port. Control bytes remain opaque at this layer.
pub trait RxController {
    /// Reset receiver state for a new association epoch.
    fn restart(&mut self) {}

    /// Process one observation.
    ///
    /// When `obs.cc_bytes` is present, `Usable` means the receiver's private
    /// codec accepted that body. Implementations that do not understand CC
    /// observations must return [`ControlDisposition::Unusable`].
    fn on_observed(&mut self, obs: Observation) -> ControlDisposition;

    /// Propose a standalone opaque control body.
    ///
    /// A controller that assigns private identity to this proposal should keep
    /// returning the same body until [`Self::on_control_sent`] confirms that it
    /// left the transport. This lets queue admission and send failures retry
    /// without consuming an identity.
    fn poll_control(&mut self, now: MonoNs) -> Option<OpaqueBytes>;

    /// Commit that an opaque standalone control body was emitted.
    ///
    /// The transport calls this only after a successful datagram send.
    fn on_control_sent(&mut self, _body: &OpaqueBytes) {}

    /// Next locally armed controller wakeup, if any.
    fn next_wakeup(&self) -> Option<MonoNs> {
        None
    }
}

/// Core-usable controller that holds one configured rate.
///
/// Opaque peer bodies are accepted as input but deliberately not interpreted,
/// so they can never change this controller's rate. A controller has no socket
/// parameter; the following shape does not compile:
///
/// ```compile_fail
/// use conet_core::FixedRateController;
/// struct SocketHandle;
/// let _controller = FixedRateController::new(1_000, SocketHandle);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedRateController {
    bytes_per_sec: ByteRate,
}

impl FixedRateController {
    pub const fn new(bytes_per_sec: ByteRate) -> Self {
        Self { bytes_per_sec }
    }
}

impl TxController for FixedRateController {
    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn pace(&self) -> Pace {
        Pace::set_target_rate(self.bytes_per_sec)
    }
}

/// Profile rule for whether control-driven rate changes are trusted.
///
/// The default is fail-closed: neither an unauthenticated test link nor an
/// unauthenticated controller body may change the applied rate. Setting
/// `link_authenticated` represents a profile that has authenticated the link;
/// `allow_unauthenticated_cc` is an explicit test-only override and defaults to
/// `false`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateControlPolicy {
    pub link_authenticated: bool,
    pub allow_unauthenticated_cc: bool,
}

impl RateControlPolicy {
    pub const fn authenticated() -> Self {
        Self {
            link_authenticated: true,
            allow_unauthenticated_cc: false,
        }
    }

    pub const fn test_allow_unauthenticated_cc() -> Self {
        Self {
            link_authenticated: false,
            allow_unauthenticated_cc: true,
        }
    }

    pub const fn permits_rate_control(self) -> bool {
        self.link_authenticated || self.allow_unauthenticated_cc
    }
}

/// What a link did with a controller pace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppliedDecision {
    NoChange,
    Applied {
        bytes_per_sec: Option<ByteRate>,
        inflight_limit_bytes: Option<u64>,
    },
    RejectedUnauthenticated {
        bytes_per_sec: Option<ByteRate>,
        inflight_limit_bytes: Option<u64>,
    },
}

/// Apply all controller pacing outputs under a profile security rule.
pub fn apply_controller_decision(
    pacer: &mut dyn RatePacer,
    inflight_limit_bytes: &mut Option<u64>,
    pace: Pace,
    policy: RateControlPolicy,
) -> AppliedDecision {
    if pace.is_noop() {
        return AppliedDecision::NoChange;
    }
    let target_rate = pace.target_rate();
    let requested_inflight_limit_bytes = pace.inflight_limit_bytes();
    if !policy.permits_rate_control() {
        return AppliedDecision::RejectedUnauthenticated {
            bytes_per_sec: target_rate,
            inflight_limit_bytes: requested_inflight_limit_bytes,
        };
    }
    if let Some(bytes_per_sec) = target_rate {
        pacer.set_target_rate(bytes_per_sec);
    }
    if let Some(bytes) = requested_inflight_limit_bytes {
        *inflight_limit_bytes = Some(bytes);
    }
    AppliedDecision::Applied {
        bytes_per_sec: target_rate,
        inflight_limit_bytes: requested_inflight_limit_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pacing::DiscreteRatePacer;
    use std::collections::VecDeque;

    #[test]
    fn fixed_rate_controller_ignores_opaque_peer_bodies() {
        let mut controller = FixedRateController::new(1_500);
        let body = OpaqueBytes::from_static(b"pretend rate: 999999999");
        assert_eq!(
            controller.on_peer_control(MonoNs::ZERO, body),
            ControlDisposition::Unusable
        );
        assert_eq!(controller.pace(), Pace::set_target_rate(1_500));
    }

    #[test]
    fn rate_control_is_fail_closed_by_default() {
        let mut pacer = DiscreteRatePacer::new(1_000);
        let denied = apply_controller_decision(
            &mut pacer,
            &mut None,
            Pace::set_target_rate(8_000),
            RateControlPolicy::default(),
        );
        assert_eq!(
            denied,
            AppliedDecision::RejectedUnauthenticated {
                bytes_per_sec: Some(8_000),
                inflight_limit_bytes: None,
            }
        );
        assert_eq!(pacer.target_rate(), 1_000);

        let applied = apply_controller_decision(
            &mut pacer,
            &mut None,
            Pace::set_target_rate(8_000),
            RateControlPolicy::test_allow_unauthenticated_cc(),
        );
        assert_eq!(
            applied,
            AppliedDecision::Applied {
                bytes_per_sec: Some(8_000),
                inflight_limit_bytes: None,
            }
        );
        assert_eq!(pacer.target_rate(), 8_000);
    }

    #[test]
    fn rx_controller_accepts_observations_and_returns_opaque_control() {
        #[derive(Default)]
        struct TestRx {
            observed: Vec<Observation>,
            pending: VecDeque<OpaqueBytes>,
        }

        impl RxController for TestRx {
            fn on_observed(&mut self, obs: Observation) -> ControlDisposition {
                self.observed.push(obs);
                ControlDisposition::Usable
            }

            fn poll_control(&mut self, _now: MonoNs) -> Option<OpaqueBytes> {
                self.pending.pop_front()
            }
        }

        let body = OpaqueBytes::from_static(b"opaque-control");
        let mut controller = TestRx {
            observed: Vec::new(),
            pending: VecDeque::from([body.clone()]),
        };
        let mut obs = Observation::new(MonoNs::new(17), 1_200);
        obs.seq = Some(4);
        assert_eq!(
            controller.on_observed(obs.clone()),
            ControlDisposition::Usable
        );

        assert_eq!(controller.observed, vec![obs]);
        assert_eq!(controller.poll_control(MonoNs::new(18)), Some(body));
        assert_eq!(controller.poll_control(MonoNs::new(19)), None);
    }
}
