//! Reusable discrete rate-pacing arithmetic.
//!
//! Pacing is intentionally separate from link composition: a link owns its
//! queue and asks a [`RatePacer`] when the next counted byte may leave. The
//! arithmetic here is transport-neutral and uses only injected [`MonoNs`].

use crate::clock::MonoNs;

/// Integer bytes per second.
pub type ByteRate = u64;

/// The pacing capability applied by a paced link.
///
/// Mutating operations take `&mut self`; this is the Rust ownership form of
/// the design's controller-facing pacing interface. Implementations never own
/// a socket, queue, or packet payload.
pub trait RatePacer {
    /// Change the target rate. Bytes already charged retain their prior
    /// deadline; subsequent counted bytes use the new rate.
    fn set_target_rate(&mut self, bytes_per_sec: ByteRate);

    /// Current configured target rate.
    fn target_rate(&self) -> ByteRate;

    /// Account for bytes that departed at `now` without checking readiness.
    ///
    /// A link that uses [`RatePacer::try_consume`] must not also call this for
    /// the same departure, because `try_consume` performs the accounting.
    fn on_sent(&mut self, now: MonoNs, bytes: u64);

    /// Earliest time at which the next non-empty transmission is allowed.
    fn ready_at(&self) -> MonoNs;

    /// Atomically check readiness and charge `bytes` when allowed.
    ///
    /// Returns `false` without changing state when `now` is before
    /// [`RatePacer::ready_at`]. A zero-byte consume succeeds without changing
    /// state. A zero target rate blocks every non-empty consume.
    fn try_consume(&mut self, now: MonoNs, bytes: u64) -> bool;
}

/// Single-budget, one-transmission-at-a-time pacing arithmetic.
///
/// The discrete rule is: for counted length `L` bytes and target rate `R`
/// bytes per second, the next opportunity is at least
/// `ceil(L * 1_000_000_000 / R)` nanoseconds after the current opportunity or
/// the actual send time, whichever is later. Ceiling division means the pacer
/// never permits a rate above the configured integer rate. An idle sender may
/// send immediately, but an idle gap does not create a credit burst.
///
/// The first non-empty transmission after construction is immediately ready at
/// or after [`MonoNs::ZERO`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscreteRatePacer {
    target_rate: ByteRate,
    ready_at: MonoNs,
}

impl DiscreteRatePacer {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;

    /// Construct a pacer with `bytes_per_sec` as its initial target rate.
    pub fn new(bytes_per_sec: ByteRate) -> Self {
        Self {
            target_rate: bytes_per_sec,
            ready_at: MonoNs::ZERO,
        }
    }

    /// The one-quantum delay for `bytes` at the current target rate.
    pub fn quantum_for(&self, bytes: u64) -> MonoNs {
        duration_for(bytes, self.target_rate)
    }
}

impl RatePacer for DiscreteRatePacer {
    fn set_target_rate(&mut self, bytes_per_sec: ByteRate) {
        self.target_rate = bytes_per_sec;
    }

    fn target_rate(&self) -> ByteRate {
        self.target_rate
    }

    fn on_sent(&mut self, now: MonoNs, bytes: u64) {
        if bytes == 0 || self.target_rate == 0 {
            return;
        }
        let base = self.ready_at.max(now);
        self.ready_at = base.saturating_add(self.quantum_for(bytes));
    }

    fn ready_at(&self) -> MonoNs {
        self.ready_at
    }

    fn try_consume(&mut self, now: MonoNs, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        if self.target_rate == 0 || now < self.ready_at {
            return false;
        }
        self.on_sent(now, bytes);
        true
    }
}

fn duration_for(bytes: u64, bytes_per_sec: ByteRate) -> MonoNs {
    if bytes == 0 {
        return MonoNs::ZERO;
    }
    if bytes_per_sec == 0 {
        return MonoNs::new(i64::MAX);
    }

    let numerator = (bytes as u128).saturating_mul(DiscreteRatePacer::NANOS_PER_SECOND);
    let denominator = bytes_per_sec as u128;
    let nanos = numerator
        .saturating_add(denominator - 1)
        .checked_div(denominator)
        .unwrap_or(i64::MAX as u128)
        .min(i64::MAX as u128) as i64;
    MonoNs::new(nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_uses_ceiling_nanosecond_rounding() {
        let mut pacer = DiscreteRatePacer::new(3);
        assert_eq!(pacer.quantum_for(1), MonoNs::new(333_333_334));
        assert!(pacer.try_consume(MonoNs::ZERO, 1));
        assert_eq!(pacer.ready_at(), MonoNs::new(333_333_334));
        assert!(!pacer.try_consume(MonoNs::new(333_333_333), 1));
        assert!(pacer.try_consume(MonoNs::new(333_333_334), 1));
    }

    #[test]
    fn a_shared_budget_serializes_counted_bytes() {
        let mut pacer = DiscreteRatePacer::new(1_000);
        assert!(pacer.try_consume(MonoNs::ZERO, 1_000));
        assert!(!pacer.try_consume(MonoNs::new(999_999_999), 500));
        assert!(pacer.try_consume(MonoNs::new(1_000_000_000), 500));
        assert_eq!(pacer.ready_at(), MonoNs::new(1_500_000_000));
    }

    #[test]
    fn rate_change_sets_the_next_quantum_without_releasing_old_charge() {
        let mut pacer = DiscreteRatePacer::new(1_000);
        assert!(pacer.try_consume(MonoNs::ZERO, 1_000));
        pacer.set_target_rate(2_000);
        assert_eq!(pacer.target_rate(), 2_000);
        assert!(pacer.try_consume(MonoNs::new(1_000_000_000), 1_000));
        assert_eq!(pacer.ready_at(), MonoNs::new(1_500_000_000));
    }

    #[test]
    fn idle_time_does_not_accumulate_a_burst() {
        let mut pacer = DiscreteRatePacer::new(1_000);
        assert!(pacer.try_consume(MonoNs::ZERO, 1_000));
        assert!(pacer.try_consume(MonoNs::new(10_000_000_000), 1_000));
        assert_eq!(pacer.ready_at(), MonoNs::new(11_000_000_000));
    }
}
