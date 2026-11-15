//! Explicit, injected monotonic time.

use core::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

/// Monotonic time in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoNs(i64);

impl MonoNs {
    pub const ZERO: Self = Self(0);

    pub const fn new(nanos: i64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl fmt::Display for MonoNs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The only source of time available to a timed module.
pub trait Clock {
    fn now(&self) -> MonoNs;
}

/// A module that can be advanced explicitly with caller-supplied time.
pub trait Drive {
    type Output;

    fn drive(&mut self, now: MonoNs) -> Self::Output;

    /// Earliest time this module may have useful drive work.
    ///
    /// This is an aggregate scheduling hint, not a controller hook deadline.
    fn next_drive(&self) -> Option<MonoNs> {
        None
    }
}

/// An error returned when a virtual clock is driven backwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockError {
    pub requested: MonoNs,
    pub current: MonoNs,
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "virtual clock cannot move backwards from {} to {}",
            self.current, self.requested
        )
    }
}

impl std::error::Error for ClockError {}

/// Test clock whose value changes only through [`VirtualClock::drive`].
#[derive(Clone, Debug)]
pub struct VirtualClock {
    now: Arc<AtomicI64>,
}

impl VirtualClock {
    pub fn new(start: MonoNs) -> Self {
        Self {
            now: Arc::new(AtomicI64::new(start.as_nanos())),
        }
    }

    pub fn drive(&self, now: MonoNs) -> Result<(), ClockError> {
        let current = self.now();
        if now < current {
            return Err(ClockError {
                requested: now,
                current,
            });
        }
        self.now.store(now.as_nanos(), Ordering::SeqCst);
        Ok(())
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new(MonoNs::ZERO)
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> MonoNs {
        MonoNs::new(self.now.load(Ordering::SeqCst))
    }
}
