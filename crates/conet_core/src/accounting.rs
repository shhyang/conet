//! Instrumentation hooks for ownership tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A point-in-time view of live unique payload backings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackingStats {
    pub live_count: u64,
    pub live_bytes: u64,
    pub peak_count: u64,
    pub peak_bytes: u64,
}

#[derive(Debug, Default)]
struct BackingState {
    live_count: u64,
    live_bytes: u64,
    peak_count: u64,
    peak_bytes: u64,
}

/// Test/accounting hook that tracks unique live payload allocations.
///
/// Clones share the same tracker. It is deliberately not a pool and does not
/// recycle storage.
#[derive(Clone, Debug, Default)]
pub struct BackingAccounting {
    state: Arc<Mutex<BackingState>>,
}

impl BackingAccounting {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> BackingStats {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        BackingStats {
            live_count: state.live_count,
            live_bytes: state.live_bytes,
            peak_count: state.peak_count,
            peak_bytes: state.peak_bytes,
        }
    }

    pub(crate) fn record_alloc(&self, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.live_count = state.live_count.saturating_add(1);
        state.live_bytes = state.live_bytes.saturating_add(bytes as u64);
        state.peak_count = state.peak_count.max(state.live_count);
        state.peak_bytes = state.peak_bytes.max(state.live_bytes);
    }

    pub(crate) fn record_free(&self, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.live_count = state.live_count.saturating_sub(1);
        state.live_bytes = state.live_bytes.saturating_sub(bytes as u64);
    }
}

/// In-process payload-copy counter.
///
/// Pure forwarding, fan-out, and slicing must leave this unchanged. A later
/// transformation or physical-edge coalescing operation calls
/// [`PayloadCopyCounter::record_copy`] explicitly.
#[derive(Clone, Debug, Default)]
pub struct PayloadCopyCounter {
    count: Arc<AtomicU64>,
}

impl PayloadCopyCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }

    pub fn reset(&self) {
        self.count.store(0, Ordering::SeqCst);
    }

    pub fn record_copy(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

/// Instrumentation carried by a builder and its handles.
#[derive(Clone, Debug, Default)]
pub struct PacketMetrics {
    pub backings: BackingAccounting,
    pub payload_copies: PayloadCopyCounter,
}
