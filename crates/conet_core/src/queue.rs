//! Bounded FIFO ownership queues for owned packet handles.

use core::fmt;
use std::collections::{HashMap, VecDeque};

use crate::packet::{BackingId, HeaderBuf, PacketHandle};

/// Compile-time queue bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueLimits {
    pub max_packets: usize,
    pub max_visible_bytes: usize,
    pub max_unique_backing_bytes: usize,
    pub max_packet_bytes: usize,
}

impl QueueLimits {
    pub const fn new(
        max_packets: usize,
        max_visible_bytes: usize,
        max_unique_backing_bytes: usize,
    ) -> Self {
        Self {
            max_packets,
            max_visible_bytes,
            max_unique_backing_bytes,
            max_packet_bytes: usize::MAX,
        }
    }

    pub const fn with_max_packet_bytes(mut self, max_packet_bytes: usize) -> Self {
        self.max_packet_bytes = max_packet_bytes;
        self
    }
}

/// Current queue occupancy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Occupancy {
    pub count: usize,
    /// Sum of visible slice lengths. Shared fan-out descriptors count once each.
    pub visible_bytes: usize,
    /// Sum of unique live backing allocations retained by this queue.
    pub unique_backing_bytes: usize,
    pub unique_backings: usize,
}

/// Why a handle is invalid for this queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    PacketTooLarge { len: usize, max: usize },
}

impl fmt::Display for InvalidReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooLarge { len, max } => {
                write!(f, "packet length {len} exceeds queue packet maximum {max}")
            }
        }
    }
}

/// Admission failure kind without taking ownership of the handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueErrorKind {
    Full,
    Closed,
    Invalid(InvalidReason),
}

/// Admission failure that always returns the rejected handle.
#[derive(Debug)]
pub enum EnqueueError {
    Full {
        pkt: PacketHandle,
    },
    Closed {
        pkt: PacketHandle,
    },
    Invalid {
        pkt: PacketHandle,
        reason: InvalidReason,
    },
}

impl EnqueueError {
    pub fn kind(&self) -> EnqueueErrorKind {
        match self {
            Self::Full { .. } => EnqueueErrorKind::Full,
            Self::Closed { .. } => EnqueueErrorKind::Closed,
            Self::Invalid { reason, .. } => EnqueueErrorKind::Invalid(*reason),
        }
    }

    pub fn packet(&self) -> &PacketHandle {
        match self {
            Self::Full { pkt } | Self::Closed { pkt } | Self::Invalid { pkt, .. } => pkt,
        }
    }

    pub fn into_packet(self) -> PacketHandle {
        match self {
            Self::Full { pkt } | Self::Closed { pkt } | Self::Invalid { pkt, .. } => pkt,
        }
    }
}

impl fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { .. } => f.write_str("queue is full"),
            Self::Closed { .. } => f.write_str("queue is closed"),
            Self::Invalid { reason, .. } => reason.fmt(f),
        }
    }
}

impl std::error::Error for EnqueueError {}

/// Successful transfer of ownership into a queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueStatus {
    Accepted,
}

/// Result of cancelling one queued, unsent handle.
#[derive(Debug)]
pub enum CancelResult {
    Cancelled { pkt: PacketHandle },
}

#[derive(Clone, Copy, Debug)]
struct BackingUse {
    handles: usize,
    charged_bytes: usize,
}

/// Bounded FIFO queue owning `PacketHandle`s until dequeue or cancel.
#[derive(Debug)]
pub struct PacketQueue {
    items: VecDeque<PacketHandle>,
    limits: QueueLimits,
    closed: bool,
    occupancy: Occupancy,
    backings: HashMap<BackingId, BackingUse>,
}

impl PacketQueue {
    pub fn new(limits: QueueLimits) -> Self {
        Self {
            items: VecDeque::new(),
            limits,
            closed: false,
            occupancy: Occupancy::default(),
            backings: HashMap::new(),
        }
    }

    pub const fn limits(&self) -> QueueLimits {
        self.limits
    }

    pub const fn occupancy(&self) -> Occupancy {
        self.occupancy
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Borrow the oldest queued handle without transferring ownership.
    pub fn front(&self) -> Option<&PacketHandle> {
        self.items.front()
    }

    /// Mutate only the exclusive header of the oldest queued handle.
    ///
    /// Transmit-time profile fields are written here immediately before a
    /// send attempt. Queue occupancy does not depend on header contents.
    pub fn front_header_mut(&mut self) -> Option<&mut HeaderBuf> {
        self.items.front_mut().map(PacketHandle::header_mut)
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Check admission without moving the handle.
    pub fn would_accept(&self, pkt: &PacketHandle) -> Result<(), EnqueueErrorKind> {
        if self.closed {
            return Err(EnqueueErrorKind::Closed);
        }
        if pkt.len() > self.limits.max_packet_bytes {
            return Err(EnqueueErrorKind::Invalid(InvalidReason::PacketTooLarge {
                len: pkt.len(),
                max: self.limits.max_packet_bytes,
            }));
        }
        if self.next_limits_exceeded(pkt) {
            return Err(EnqueueErrorKind::Full);
        }
        Ok(())
    }

    /// Transfer ownership into the queue; every failure returns the handle.
    pub fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        match self.would_accept(&pkt) {
            Ok(()) => {}
            Err(EnqueueErrorKind::Full) => return Err(EnqueueError::Full { pkt }),
            Err(EnqueueErrorKind::Closed) => return Err(EnqueueError::Closed { pkt }),
            Err(EnqueueErrorKind::Invalid(reason)) => {
                return Err(EnqueueError::Invalid { pkt, reason });
            }
        }

        let backing_id = pkt.backing_id();
        let charged_bytes = pkt.charged_backing_bytes();
        self.occupancy.count += 1;
        self.occupancy.visible_bytes += pkt.len();
        let entry = self.backings.entry(backing_id).or_insert(BackingUse {
            handles: 0,
            charged_bytes,
        });
        if entry.handles == 0 {
            self.occupancy.unique_backings += 1;
            self.occupancy.unique_backing_bytes += charged_bytes;
        }
        entry.handles += 1;
        self.items.push_back(pkt);
        Ok(EnqueueStatus::Accepted)
    }

    /// Remove and return the oldest handle.
    pub fn dequeue(&mut self) -> Option<PacketHandle> {
        let pkt = self.items.pop_front()?;
        self.release_accounting(&pkt);
        Some(pkt)
    }

    /// Cancel all queued, unsent handles matching `predicate`.
    pub fn cancel<F>(&mut self, mut predicate: F) -> Vec<CancelResult>
    where
        F: FnMut(&PacketHandle) -> bool,
    {
        let old = core::mem::take(&mut self.items);
        let mut kept = VecDeque::with_capacity(old.len());
        let mut cancelled = Vec::new();
        for pkt in old {
            if predicate(&pkt) {
                cancelled.push(CancelResult::Cancelled { pkt });
            } else {
                kept.push_back(pkt);
            }
        }
        self.items = kept;
        self.recompute_occupancy();
        cancelled
    }

    fn next_limits_exceeded(&self, pkt: &PacketHandle) -> bool {
        let count = self.occupancy.count.saturating_add(1);
        let visible = self.occupancy.visible_bytes.saturating_add(pkt.len());
        let unique = if self.backings.contains_key(&pkt.backing_id()) {
            self.occupancy.unique_backing_bytes
        } else {
            self.occupancy
                .unique_backing_bytes
                .saturating_add(pkt.charged_backing_bytes())
        };
        count > self.limits.max_packets
            || visible > self.limits.max_visible_bytes
            || unique > self.limits.max_unique_backing_bytes
    }

    fn release_accounting(&mut self, pkt: &PacketHandle) {
        self.occupancy.count = self.occupancy.count.saturating_sub(1);
        self.occupancy.visible_bytes = self.occupancy.visible_bytes.saturating_sub(pkt.len());
        if let Some(entry) = self.backings.get_mut(&pkt.backing_id()) {
            entry.handles = entry.handles.saturating_sub(1);
            if entry.handles == 0 {
                let charged = entry.charged_bytes;
                self.backings.remove(&pkt.backing_id());
                self.occupancy.unique_backings = self.occupancy.unique_backings.saturating_sub(1);
                self.occupancy.unique_backing_bytes =
                    self.occupancy.unique_backing_bytes.saturating_sub(charged);
            }
        }
    }

    fn recompute_occupancy(&mut self) {
        self.occupancy = Occupancy::default();
        self.backings.clear();
        for pkt in &self.items {
            self.occupancy.count += 1;
            self.occupancy.visible_bytes += pkt.len();
            let entry = self.backings.entry(pkt.backing_id()).or_insert(BackingUse {
                handles: 0,
                charged_bytes: pkt.charged_backing_bytes(),
            });
            if entry.handles == 0 {
                self.occupancy.unique_backings += 1;
                self.occupancy.unique_backing_bytes += entry.charged_bytes;
            }
            entry.handles += 1;
        }
    }
}
