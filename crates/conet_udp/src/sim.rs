//! Deterministic simulated-loss pipe between two logical hosts.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use conet_core::MonoNs;

use crate::transport::{
    DatagramTransport, InboundDatagram, RecvMeta, WireBufPool, WireIoCounters, WireIoStats,
};

/// One successful simulator send attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimFrame {
    pub from: usize,
    pub order: u64,
    pub at: MonoNs,
    pub bytes: Vec<u8>,
    pub dropped: bool,
}

#[derive(Clone, Debug)]
struct Delivery {
    at: MonoNs,
    order: u64,
    bytes: Vec<u8>,
    authenticated: bool,
}

#[derive(Debug, Default)]
struct HostPath {
    deliveries: VecDeque<Delivery>,
    fail_next_sends: usize,
    loss_pattern: VecDeque<bool>,
    latency_pattern: VecDeque<MonoNs>,
}

#[derive(Debug)]
struct SimState {
    paths: [HostPath; 2],
    authenticated: bool,
    next_order: u64,
    frames: Vec<SimFrame>,
}

/// Two-host simulator network. Host 0 sends to host 1 and vice versa.
#[derive(Clone, Debug)]
pub struct SimNetwork {
    shared: Arc<Mutex<SimState>>,
}

impl Default for SimNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl SimNetwork {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(SimState {
                paths: [HostPath::default(), HostPath::default()],
                authenticated: false,
                next_order: 1,
                frames: Vec::new(),
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SimState> {
        self.shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn transport(&self, from: usize) -> SimTransport {
        assert!(from < 2, "simulator host index must be 0 or 1");
        SimTransport {
            shared: Arc::clone(&self.shared),
            from,
            counters: WireIoCounters::default(),
            receive_pool: WireBufPool::new(32, 2_048),
        }
    }

    /// Mark simulator-delivered datagrams as authenticated. The default is
    /// false so controller trust remains fail-closed.
    pub fn set_authenticated(&self, authenticated: bool) {
        self.lock().authenticated = authenticated;
    }

    pub fn fail_next_send(&self, from: usize) {
        self.lock().paths[from].fail_next_sends += 1;
    }

    /// Replace the deterministic loss pattern for datagrams from `from`.
    pub fn set_loss_pattern(&self, from: usize, pattern: impl IntoIterator<Item = bool>) {
        self.lock().paths[from].loss_pattern = pattern.into_iter().collect();
    }

    pub fn drop_next(&self, from: usize) {
        self.lock().paths[from].loss_pattern.push_back(true);
    }

    /// Replace the deterministic delivery-delay pattern for datagrams from
    /// `from`. Reordering is produced by a later datagram having less delay.
    pub fn set_latency_pattern(&self, from: usize, pattern: impl IntoIterator<Item = MonoNs>) {
        self.lock().paths[from].latency_pattern = pattern.into_iter().collect();
    }

    /// Inject a raw payload into `to`, bypassing a sender-side socket attempt.
    pub fn inject(&self, to: usize, bytes: Vec<u8>, authenticated: bool) {
        let mut state = self.lock();
        let order = state.next_order;
        state.next_order += 1;
        state.paths[to].deliveries.push_back(Delivery {
            at: MonoNs::ZERO,
            order,
            bytes,
            authenticated,
        });
    }

    pub fn frames(&self) -> Vec<SimFrame> {
        self.lock().frames.clone()
    }

    pub fn frames_from(&self, from: usize) -> Vec<SimFrame> {
        self.lock()
            .frames
            .iter()
            .filter(|frame| frame.from == from)
            .cloned()
            .collect()
    }

    pub fn pending(&self, host: usize) -> usize {
        self.lock().paths[host].deliveries.len()
    }
}

/// One host's endpoint into [`SimNetwork`].
#[derive(Clone, Debug)]
pub struct SimTransport {
    shared: Arc<Mutex<SimState>>,
    from: usize,
    counters: WireIoCounters,
    receive_pool: WireBufPool,
}

impl SimTransport {
    pub const fn host(&self) -> usize {
        self.from
    }

    fn lock(&self) -> MutexGuard<'_, SimState> {
        self.shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl DatagramTransport for SimTransport {
    fn send_datagram(&mut self, now: MonoNs, bytes: &[u8]) -> io::Result<()> {
        self.counters.record_syscall();
        let mut state = self.lock();
        let path = &mut state.paths[self.from];
        if path.fail_next_sends > 0 {
            path.fail_next_sends -= 1;
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "injected simulator sendto failure",
            ));
        }

        let to = 1 - self.from;
        let dropped = path.loss_pattern.pop_front().unwrap_or(false);
        let delay = path.latency_pattern.pop_front().unwrap_or(MonoNs::ZERO);
        let order = state.next_order;
        state.next_order += 1;
        state.frames.push(SimFrame {
            from: self.from,
            order,
            at: now,
            bytes: bytes.to_vec(),
            dropped,
        });
        self.counters.record_allocation();
        self.counters.record_copy();
        if !dropped {
            let authenticated = state.authenticated;
            state.paths[to].deliveries.push_back(Delivery {
                at: now.saturating_add(delay),
                order,
                bytes: bytes.to_vec(),
                authenticated,
            });
            self.counters.record_allocation();
            self.counters.record_copy();
        }
        Ok(())
    }

    fn recv_datagram(&mut self, now: MonoNs) -> io::Result<Option<InboundDatagram>> {
        self.counters.record_syscall();
        let mut state = self.lock();
        let deliveries = &mut state.paths[self.from].deliveries;
        let index = deliveries
            .iter()
            .enumerate()
            .filter(|(_, delivery)| delivery.at <= now)
            .min_by_key(|(_, delivery)| (delivery.at, delivery.order))
            .map(|(index, _)| index);
        let Some(index) = index else {
            return Ok(None);
        };
        let delivery = deliveries
            .remove(index)
            .expect("index came from this deque");
        let len = delivery.bytes.len();
        let mut bytes = self.receive_pool.checkout(len)?;
        bytes.as_mut_slice().copy_from_slice(&delivery.bytes);
        self.counters.record_copy();
        Ok(Some(InboundDatagram {
            bytes,
            authenticated: delivery.authenticated,
            meta: RecvMeta::new(len, None),
        }))
    }

    fn io_stats(&self) -> WireIoStats {
        self.counters.snapshot().merge(self.receive_pool.stats())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulator_counters_move_on_batched_scalar_fallback() {
        let network = SimNetwork::new();
        let mut sender = network.transport(0);
        let mut receiver = network.transport(1);
        let mut stats = WireIoStats::default();

        assert_eq!(
            sender
                .send_batch(MonoNs::ZERO, &[b"counter"], &mut stats)
                .unwrap(),
            1
        );
        assert_eq!(stats.fallbacks, 1);

        let mut output = Vec::with_capacity(1);
        assert_eq!(
            receiver
                .recv_batch(MonoNs::ZERO, &mut output, 1, &mut stats)
                .unwrap(),
            1
        );
        assert_eq!(output[0].bytes.as_slice(), b"counter");

        let sender_stats = sender.io_stats();
        assert_eq!(sender_stats.syscalls, 1);
        assert!(sender_stats.allocations >= 2);
        assert!(sender_stats.copies >= 2);
        let receiver_stats = receiver.io_stats();
        assert_eq!(receiver_stats.syscalls, 1);
        assert_eq!(stats.fallbacks, 2);
    }
}
