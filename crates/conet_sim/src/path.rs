//! Mahimahi-style one-way path adapted to the Conet datagram link contracts.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use conet_core::{
    BackingId, Drive, EnqueueError, EnqueueStatus, LinkEndpoint, LinkReceiver, LinkSender, MonoNs,
    Occupancy, PacketHandle,
};

/// One absolute capacity change in simulated time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityStep {
    pub at: MonoNs,
    pub capacity_bps: u64,
}

/// Bottleneck and propagation parameters for one directed path.
#[derive(Clone, Debug, PartialEq)]
pub struct PathConfig {
    /// Bottleneck capacity in bits per second.
    pub capacity_bps: u64,
    /// Fixed one-way propagation delay after serialization.
    pub base_delay: MonoNs,
    /// Drop-tail limit for waiting and currently serializing bytes.
    pub buffer_bytes: u64,
    /// Bernoulli erasure probability applied after serialization.
    pub loss_prob: f64,
    /// Optional capacity changes, normalized by increasing `at` on creation.
    pub capacity_schedule: Vec<CapacityStep>,
    /// Seed for the deterministic post-link loss stream.
    pub loss_seed: u64,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            capacity_bps: 10_000_000,
            base_delay: MonoNs::new(10_000_000),
            buffer_bytes: 25_000,
            loss_prob: 0.0,
            capacity_schedule: Vec::new(),
            loss_seed: 1,
        }
    }
}

impl PathConfig {
    pub fn capacity_bytes_per_sec(&self) -> u64 {
        self.capacity_bps / 8
    }

    /// Bytes in flight for one bandwidth-delay product.
    pub fn bdp_bytes_for_rtt(&self, rtt: MonoNs) -> u64 {
        let bytes_per_sec = self.capacity_bytes_per_sec();
        let rtt_ns = rtt.as_nanos().max(0) as u64;
        bytes_per_sec.saturating_mul(rtt_ns) / 1_000_000_000
    }
}

/// Cumulative one-way path counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathStats {
    /// Enqueue calls admitted to the path model.
    pub sent: u64,
    /// Packets that fit in the bottleneck buffer.
    pub queued: u64,
    /// Enqueue-time drop-tail discards.
    pub dropped_buffer: u64,
    /// Post-link Bernoulli erasures.
    pub dropped_loss: u64,
    /// Packets released to the receiving endpoint.
    pub delivered: u64,
    /// Visible payload bytes released to the receiving endpoint.
    pub delivered_bytes: u64,
    /// Bytes currently held in the bottleneck buffer.
    pub queue_bytes: u64,
}

impl PathStats {
    pub const fn dropped(self) -> u64 {
        self.dropped_buffer.saturating_add(self.dropped_loss)
    }
}

#[derive(Debug)]
struct BufferedPacket {
    depart_at: MonoNs,
    deliver_at: MonoNs,
    pkt: PacketHandle,
}

#[derive(Debug)]
struct WiredPacket {
    deliver_at: MonoNs,
    pkt: PacketHandle,
}

#[derive(Debug)]
struct PathState {
    config: PathConfig,
    capacity_bps: u64,
    schedule_idx: usize,
    buffer: VecDeque<BufferedPacket>,
    wire: VecDeque<WiredPacket>,
    ready: VecDeque<PacketHandle>,
    queue_bytes: u64,
    link_free_at: MonoNs,
    now: MonoNs,
    closed: bool,
    rng: Lcg,
    stats: PathStats,
}

impl PathState {
    fn new(config: PathConfig) -> Self {
        let mut config = config;
        config.capacity_schedule.sort_by_key(|step| step.at);
        let capacity_bps = config.capacity_bps;
        let loss_seed = config.loss_seed;
        Self {
            config,
            capacity_bps,
            schedule_idx: 0,
            buffer: VecDeque::new(),
            wire: VecDeque::new(),
            ready: VecDeque::new(),
            queue_bytes: 0,
            link_free_at: MonoNs::ZERO,
            now: MonoNs::ZERO,
            closed: false,
            rng: Lcg::new(loss_seed),
            stats: PathStats::default(),
        }
    }

    fn drive(&mut self, now: MonoNs) {
        assert!(
            now >= self.now,
            "simulated path cannot move backwards from {} to {}",
            self.now,
            now
        );
        self.now = now;
        self.apply_schedule(now);
        self.flush_departs(now);
        self.release_due(now);
    }

    fn apply_schedule(&mut self, now: MonoNs) {
        while let Some(step) = self.config.capacity_schedule.get(self.schedule_idx) {
            if step.at > now {
                break;
            }
            self.capacity_bps = step.capacity_bps;
            self.schedule_idx += 1;
        }
    }

    fn flush_departs(&mut self, now: MonoNs) {
        while let Some(front) = self.buffer.front() {
            if front.depart_at > now {
                break;
            }
            let pkt = self.buffer.pop_front().expect("front packet was present");
            self.queue_bytes = self.queue_bytes.saturating_sub(pkt.pkt.len() as u64);
            if self.rng.bernoulli(self.config.loss_prob) {
                self.stats.dropped_loss = self.stats.dropped_loss.saturating_add(1);
            } else {
                self.wire.push_back(WiredPacket {
                    deliver_at: pkt.deliver_at,
                    pkt: pkt.pkt,
                });
            }
        }
    }

    fn release_due(&mut self, now: MonoNs) {
        while let Some(front) = self.wire.front() {
            if front.deliver_at > now {
                break;
            }
            let pkt = self.wire.pop_front().expect("front packet was present");
            self.stats.delivered = self.stats.delivered.saturating_add(1);
            self.stats.delivered_bytes = self
                .stats
                .delivered_bytes
                .saturating_add(pkt.pkt.len() as u64);
            self.ready.push_back(pkt.pkt);
        }
    }

    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        if self.closed {
            return Err(EnqueueError::Closed { pkt });
        }

        self.flush_departs(self.now);
        self.stats.sent = self.stats.sent.saturating_add(1);
        let size = pkt.len() as u64;
        if self.queue_bytes.saturating_add(size) > self.config.buffer_bytes {
            self.stats.dropped_buffer = self.stats.dropped_buffer.saturating_add(1);
            return Ok(EnqueueStatus::Accepted);
        }

        let start = self.now.max(self.link_free_at);
        let depart_at = start.saturating_add(self.serialization_delay(pkt.len()));
        let deliver_at = depart_at.saturating_add(self.config.base_delay);
        self.link_free_at = depart_at;
        self.queue_bytes = self.queue_bytes.saturating_add(size);
        self.stats.queued = self.stats.queued.saturating_add(1);
        self.buffer.push_back(BufferedPacket {
            depart_at,
            deliver_at,
            pkt,
        });
        Ok(EnqueueStatus::Accepted)
    }

    fn serialization_delay(&self, size: usize) -> MonoNs {
        let bits = size as u128;
        let nanos = bits.saturating_mul(8).saturating_mul(1_000_000_000)
            / u128::from(self.capacity_bps.max(1));
        MonoNs::new(i64::try_from(nanos).unwrap_or(i64::MAX))
    }

    fn stats(&self) -> PathStats {
        PathStats {
            queue_bytes: self.queue_bytes,
            ..self.stats
        }
    }

    fn next_delivery_at(&self) -> Option<MonoNs> {
        self.wire
            .front()
            .map(|pkt| pkt.deliver_at)
            .or_else(|| self.buffer.front().map(|pkt| pkt.deliver_at))
    }

    fn buffer_occupancy(&self) -> Occupancy {
        occupancy(self.buffer.iter().map(|entry| &entry.pkt))
    }

    fn ready_occupancy(&self) -> Occupancy {
        occupancy(self.ready.iter())
    }
}

fn occupancy<'a>(packets: impl Iterator<Item = &'a PacketHandle>) -> Occupancy {
    let mut occupancy = Occupancy::default();
    let mut backings = HashMap::<BackingId, usize>::new();
    for pkt in packets {
        occupancy.count += 1;
        occupancy.visible_bytes += pkt.len();
        backings.entry(pkt.backing_id()).or_insert_with(|| {
            occupancy.unique_backings += 1;
            occupancy.unique_backing_bytes += pkt.charged_backing_bytes();
            pkt.charged_backing_bytes()
        });
    }
    occupancy
}

#[derive(Debug)]
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.state
    }

    fn bernoulli(&mut self, probability: f64) -> bool {
        if probability <= 0.0 {
            return false;
        }
        if probability >= 1.0 {
            return true;
        }
        let sample = (self.next_u64() >> 11) as f64 / (1_u64 << 53) as f64;
        sample < probability
    }
}

#[derive(Debug)]
struct SharedPath {
    state: Mutex<PathState>,
}

impl SharedPath {
    fn new(config: PathConfig) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(PathState::new(config)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, PathState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Sending end of one simulated directed path.
#[derive(Debug)]
pub struct PathSender {
    shared: Arc<SharedPath>,
}

/// Receiving end of one simulated directed path.
#[derive(Debug)]
pub struct PathReceiver {
    shared: Arc<SharedPath>,
}

/// Construct one directed simulated path using Conet's datagram link traits.
pub fn path_link(config: PathConfig) -> (PathSender, PathReceiver) {
    let shared = SharedPath::new(config);
    (
        PathSender {
            shared: Arc::clone(&shared),
        },
        PathReceiver { shared },
    )
}

impl PathSender {
    /// Advance the path to an absolute injected time.
    pub fn drive(&mut self, now: MonoNs) {
        self.shared.lock().drive(now);
    }

    pub fn config(&self) -> PathConfig {
        self.shared.lock().config.clone()
    }

    pub fn capacity_bps(&self) -> u64 {
        self.shared.lock().capacity_bps
    }

    pub fn buffer_bytes(&self) -> u64 {
        self.shared.lock().queue_bytes
    }

    pub fn stats(&self) -> PathStats {
        self.shared.lock().stats()
    }

    pub fn next_delivery_at(&self) -> Option<MonoNs> {
        self.shared.lock().next_delivery_at()
    }

    pub fn is_closed(&self) -> bool {
        self.shared.lock().closed
    }
}

impl LinkSender for PathSender {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        self.shared.lock().enqueue(pkt)
    }

    fn occupancy(&self) -> Occupancy {
        self.shared.lock().buffer_occupancy()
    }

    fn close(&mut self) {
        self.shared.lock().closed = true;
    }
}

impl Drive for PathSender {
    type Output = ();

    fn drive(&mut self, now: MonoNs) {
        PathSender::drive(self, now);
    }
}

impl PathReceiver {
    /// Advance the path to an absolute injected time and release all due arrivals.
    pub fn drive(&mut self, now: MonoNs) {
        self.shared.lock().drive(now);
    }

    pub fn config(&self) -> PathConfig {
        self.shared.lock().config.clone()
    }

    pub fn capacity_bps(&self) -> u64 {
        self.shared.lock().capacity_bps
    }

    pub fn stats(&self) -> PathStats {
        self.shared.lock().stats()
    }

    pub fn next_delivery_at(&self) -> Option<MonoNs> {
        self.shared.lock().next_delivery_at()
    }
}

impl LinkReceiver for PathReceiver {
    fn recv(&mut self) -> Option<PacketHandle> {
        self.shared.lock().ready.pop_front()
    }

    fn occupancy(&self) -> Occupancy {
        self.shared.lock().ready_occupancy()
    }
}

impl Drive for PathReceiver {
    type Output = ();

    fn drive(&mut self, now: MonoNs) {
        PathReceiver::drive(self, now);
    }
}

/// One endpoint of a two-endpoint simulated duplex path.
#[derive(Debug)]
pub struct PathEndpoint {
    outgoing: PathSender,
    incoming: PathReceiver,
}

impl PathEndpoint {
    pub const fn new(outgoing: PathSender, incoming: PathReceiver) -> Self {
        Self { outgoing, incoming }
    }

    pub fn outgoing_mut(&mut self) -> &mut PathSender {
        &mut self.outgoing
    }

    pub fn incoming_mut(&mut self) -> &mut PathReceiver {
        &mut self.incoming
    }
}

impl LinkEndpoint for PathEndpoint {
    fn outgoing(&mut self) -> &mut dyn LinkSender {
        &mut self.outgoing
    }

    fn incoming(&mut self) -> &mut dyn LinkReceiver {
        &mut self.incoming
    }

    fn drive(&mut self, now: MonoNs) {
        self.outgoing.drive(now);
        self.incoming.drive(now);
    }
}

/// Pair of endpoints connected by independently configured one-way paths.
#[derive(Debug)]
pub struct DuplexPath {
    pub a: PathEndpoint,
    pub b: PathEndpoint,
}

/// Build two endpoints whose forward and reverse directions are independent.
pub fn duplex_path(forward: PathConfig, reverse: PathConfig) -> DuplexPath {
    let (forward_sender, forward_receiver) = path_link(forward);
    let (reverse_sender, reverse_receiver) = path_link(reverse);
    DuplexPath {
        a: PathEndpoint::new(forward_sender, reverse_receiver),
        b: PathEndpoint::new(reverse_sender, forward_receiver),
    }
}
