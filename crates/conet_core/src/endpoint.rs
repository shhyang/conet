//! A minimal driveable stub used by the first harness slice.

use crate::clock::{Clock, ClockError, Drive, MonoNs, VirtualClock};
use crate::scheduler::{DriveEvent, ScheduleError, SeededScheduler};

/// Failure while driving the stub endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointError {
    Clock(ClockError),
    Schedule(ScheduleError),
}

impl From<ClockError> for EndpointError {
    fn from(value: ClockError) -> Self {
        Self::Clock(value)
    }
}

impl From<ScheduleError> for EndpointError {
    fn from(value: ScheduleError) -> Self {
        Self::Schedule(value)
    }
}

impl core::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Clock(error) => error.fmt(f),
            Self::Schedule(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for EndpointError {}

/// A driveable test endpoint that records explicitly scheduled events.
///
/// Construction never reads wall-clock time. Work becomes visible only after a
/// caller supplies `now` to [`StubEndpoint::drive`].
#[derive(Debug)]
pub struct StubEndpoint {
    clock: VirtualClock,
    scheduler: SeededScheduler<u64>,
    observed: Vec<DriveEvent<u64>>,
}

impl StubEndpoint {
    pub fn new(start: MonoNs, seed: u64) -> Self {
        Self {
            clock: VirtualClock::new(start),
            scheduler: SeededScheduler::new(seed),
            observed: Vec::new(),
        }
    }

    pub fn seed(&self) -> u64 {
        self.scheduler.seed()
    }

    pub fn schedule_after(&mut self, delay: MonoNs, event: u64) -> Result<(), EndpointError> {
        let at = self.clock.now().saturating_add(delay);
        self.scheduler.schedule(at, event)?;
        Ok(())
    }

    pub fn drive_to(&mut self, now: MonoNs) -> Result<Vec<DriveEvent<u64>>, EndpointError> {
        self.clock.drive(now)?;
        let due = self.scheduler.drive_until(now)?;
        self.observed.extend(due.iter().cloned());
        Ok(due)
    }

    pub fn observed(&self) -> &[DriveEvent<u64>] {
        &self.observed
    }
}

impl Drive for StubEndpoint {
    type Output = Result<Vec<DriveEvent<u64>>, EndpointError>;

    fn drive(&mut self, now: MonoNs) -> Self::Output {
        self.drive_to(now)
    }
}

impl Clock for StubEndpoint {
    fn now(&self) -> MonoNs {
        self.clock.now()
    }
}
