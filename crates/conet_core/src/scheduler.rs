//! A small seeded, single-threaded event scheduler.

use core::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::clock::MonoNs;

/// Stable identifier for an inserted event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScheduleId(u64);

impl ScheduleId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A due event with its deterministic insertion order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveEvent<T> {
    pub at: MonoNs,
    pub order: u64,
    pub event: T,
}

/// Scheduling failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    InThePast { requested: MonoNs, current: MonoNs },
}

impl core::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InThePast { requested, current } => write!(
                f,
                "cannot schedule event at {requested}; scheduler is already at {current}"
            ),
        }
    }
}

impl std::error::Error for ScheduleError {}

#[derive(Clone, Debug)]
struct Scheduled<T> {
    at: MonoNs,
    order: u64,
    event: T,
}

impl<T> PartialEq for Scheduled<T> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.order == other.order
    }
}

impl<T> Eq for Scheduled<T> {}

impl<T> PartialOrd for Scheduled<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Scheduled<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.at
            .cmp(&other.at)
            .then_with(|| self.order.cmp(&other.order))
    }
}

/// Deterministic event queue ordered by `(due time, insertion sequence)`.
///
/// Time moves only when [`SeededScheduler::drive_until`] is called. Equal due
/// times are resolved by insertion sequence, so a fixed script replays in the
/// same order. The seed is retained as trace/configuration state for seeded
/// scripts and future randomized compositions; it never reads wall-clock time.
#[derive(Debug)]
pub struct SeededScheduler<T> {
    seed: u64,
    next_order: u64,
    current: Option<MonoNs>,
    queue: BinaryHeap<Reverse<Scheduled<T>>>,
}

impl<T> SeededScheduler<T> {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            next_order: 0,
            current: None,
            queue: BinaryHeap::new(),
        }
    }

    pub const fn seed(&self) -> u64 {
        self.seed
    }

    pub fn current(&self) -> Option<MonoNs> {
        self.current
    }

    pub fn schedule(&mut self, at: MonoNs, event: T) -> Result<ScheduleId, ScheduleError> {
        if let Some(current) = self.current
            && at < current
        {
            return Err(ScheduleError::InThePast {
                requested: at,
                current,
            });
        }

        let order = self.next_order;
        self.next_order = self.next_order.wrapping_add(1);
        self.queue.push(Reverse(Scheduled { at, order, event }));
        Ok(ScheduleId(order))
    }

    pub fn next_deadline(&self) -> Option<MonoNs> {
        self.queue.peek().map(|entry| entry.0.at)
    }

    /// Advance to `now`, returning events whose due time is at most `now`.
    pub fn drive_until(&mut self, now: MonoNs) -> Result<Vec<DriveEvent<T>>, ScheduleError> {
        if let Some(current) = self.current
            && now < current
        {
            return Err(ScheduleError::InThePast {
                requested: now,
                current,
            });
        }

        self.current = Some(now);
        let mut due = Vec::new();
        while let Some(entry) = self.queue.peek() {
            if entry.0.at > now {
                break;
            }
            let Reverse(scheduled) = self.queue.pop().expect("peeked event exists");
            due.push(DriveEvent {
                at: scheduled.at,
                order: scheduled.order,
                event: scheduled.event,
            });
        }
        Ok(due)
    }
}
