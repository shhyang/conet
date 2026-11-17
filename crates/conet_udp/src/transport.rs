//! Injected-time datagram boundaries used by the simulator and UDP socket.

use core::fmt;
#[cfg(target_os = "linux")]
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use conet_core::{MonoNs, OpaqueBytes, ReferenceWireCodec, WireLimits};

use crate::keepalive::{
    KeepaliveConfig, KeepaliveState, KeepaliveStats, decode_keepalive, is_keepalive_frame,
    send_ping, send_pong, KEEPALIVE_TYPE_PING,
};
use crate::path_challenge::{
    PathChallengeError, PathChallengePoll, PendingPathChallenge, is_path_challenge_frame,
    match_response, maybe_retransmit, respond_to_challenge, start_challenge,
};
use crate::reflexive::{ReflexiveError, ReflexiveReport, discover_reflexive};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

/// Transport and wire-near accounting shared by diagnostics and tests.
///
/// These counters are deliberately outside the congestion-control API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireIoStats {
    /// Transport I/O calls recorded by adapter-local counters.
    pub syscalls: u64,
    /// Wire-buffer or temporary-output allocations.
    pub allocations: u64,
    /// Explicit byte-copy operations at a transport/encode boundary.
    pub copies: u64,
    /// Scalar calls made by a default batch implementation.
    pub fallbacks: u64,
}

impl WireIoStats {
    pub fn merge(self, other: Self) -> Self {
        Self {
            syscalls: self.syscalls.saturating_add(other.syscalls),
            allocations: self.allocations.saturating_add(other.allocations),
            copies: self.copies.saturating_add(other.copies),
            fallbacks: self.fallbacks.saturating_add(other.fallbacks),
        }
    }
}

#[derive(Debug, Default)]
struct WireIoAtomic {
    syscalls: AtomicU64,
    allocations: AtomicU64,
    copies: AtomicU64,
    fallbacks: AtomicU64,
}

/// Cloneable counter handle for a simulator or socket adapter.
#[derive(Clone, Debug, Default)]
pub struct WireIoCounters {
    shared: Arc<WireIoAtomic>,
}

impl WireIoCounters {
    pub fn record_syscall(&self) {
        self.shared.syscalls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_allocation(&self) {
        self.shared.allocations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_copy(&self) {
        self.shared.copies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fallback(&self) {
        self.shared.fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> WireIoStats {
        WireIoStats {
            syscalls: self.shared.syscalls.load(Ordering::Relaxed),
            allocations: self.shared.allocations.load(Ordering::Relaxed),
            copies: self.shared.copies.load(Ordering::Relaxed),
            fallbacks: self.shared.fallbacks.load(Ordering::Relaxed),
        }
    }
}

/// Per-datagram receive metadata retained at the transport boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecvMeta {
    /// Bytes occupied by this datagram.
    pub len: usize,
    /// Stride between datagrams when a later backend reports a batch.
    pub stride: usize,
    /// Source address when the backend has one.
    pub source: Option<SocketAddr>,
    /// Local destination address reported by PKTINFO, when available.
    pub destination: Option<IpAddr>,
    /// Local interface index reported by PKTINFO, when available.
    pub interface_index: Option<u32>,
    /// Number of transport segments represented by this entry.
    pub segments: u16,
    /// Explicit-congestion-notification codepoint, when the socket reported it.
    pub ecn: Option<EcnCodepoint>,
}

impl RecvMeta {
    pub const fn new(len: usize, source: Option<SocketAddr>) -> Self {
        Self {
            len,
            stride: len,
            source,
            destination: None,
            interface_index: None,
            segments: 1,
            ecn: None,
        }
    }

    #[cfg(target_os = "linux")]
    const fn from_linux(
        len: usize,
        source: Option<SocketAddr>,
        destination: Option<IpAddr>,
        interface_index: Option<u32>,
        segments: u16,
        stride: usize,
        ecn: Option<u8>,
    ) -> Self {
        Self {
            len,
            stride,
            source,
            destination,
            interface_index,
            segments,
            ecn: match ecn {
                Some(bits) => Some(EcnCodepoint::from_bits(bits)),
                None => None,
            },
        }
    }
}

/// The two ECN capability bits carried by an IP traffic-class field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum EcnCodepoint {
    #[default]
    NotEct = 0,
    Ect1 = 1,
    Ect0 = 2,
    Ce = 3,
}

impl EcnCodepoint {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NotEct,
            1 => Self::Ect1,
            2 => Self::Ect0,
            3 => Self::Ce,
            _ => unreachable!(),
        }
    }

    pub const fn bits(self) -> u8 {
        self as u8
    }
}

#[derive(Debug)]
struct WireBufPoolInner {
    free: Mutex<Vec<Vec<u8>>>,
    max_buffers: usize,
    buffer_size: usize,
    created: AtomicU64,
    counters: WireIoCounters,
}

/// Bounded recycler for mutable transport receive buffers.
///
/// A buffer moves into a reference-counted frozen owner when converted to
/// [`LeasedWire`]. It cannot return to the free list until the last `Bytes`
/// handle and the explicit I/O lease are both gone.
#[derive(Clone, Debug)]
pub struct WireBufPool {
    inner: Arc<WireBufPoolInner>,
}

impl WireBufPool {
    pub fn new(max_buffers: usize, buffer_size: usize) -> Self {
        Self {
            inner: Arc::new(WireBufPoolInner {
                free: Mutex::new(Vec::new()),
                max_buffers: max_buffers.max(1),
                buffer_size,
                created: AtomicU64::new(0),
                counters: WireIoCounters::default(),
            }),
        }
    }

    pub fn checkout(&self, len: usize) -> io::Result<WireBuf> {
        if len > self.inner.buffer_size {
            return Ok(self.unpooled(len));
        }
        let reusable = self.lock_free().pop();
        let storage = match reusable {
            Some(storage) => storage,
            None => match self.inner.created.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |created| (created < self.inner.max_buffers as u64).then_some(created + 1),
            ) {
                Ok(_) => {
                    self.inner.counters.record_allocation();
                    vec![0_u8; self.inner.buffer_size]
                }
                Err(_) => return Ok(self.unpooled(len)),
            },
        };
        Ok(WireBuf {
            storage: Some(storage),
            len,
            recycler: Some(Arc::clone(&self.inner)),
        })
    }

    pub fn available(&self) -> usize {
        self.lock_free().len()
    }

    pub fn created(&self) -> u64 {
        self.inner.created.load(Ordering::Relaxed)
    }

    pub fn max_buffers(&self) -> usize {
        self.inner.max_buffers
    }

    pub fn buffer_size(&self) -> usize {
        self.inner.buffer_size
    }

    pub fn stats(&self) -> WireIoStats {
        self.inner.counters.snapshot()
    }

    fn lock_free(&self) -> MutexGuard<'_, Vec<Vec<u8>>> {
        self.inner
            .free
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn unpooled(&self, len: usize) -> WireBuf {
        self.inner.counters.record_allocation();
        WireBuf::from_vec(vec![0_u8; len])
    }
}

/// Mutable transport buffer checked out from a [`WireBufPool`].
///
/// The buffer is exclusive while mutable. Converting it to shared wire bytes
/// creates a [`WireLease`] that keeps the allocation out of the pool.
#[derive(Debug)]
pub struct WireBuf {
    storage: Option<Vec<u8>>,
    len: usize,
    recycler: Option<Arc<WireBufPoolInner>>,
}

impl WireBuf {
    /// Wrap an already-owned datagram buffer without introducing a pool.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            storage: Some(bytes),
            len,
            recycler: None,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage_ref()[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.storage_mut()[..len]
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Set the used prefix after receiving directly into the pooled storage.
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= self.storage_ref().len());
        self.len = len;
    }

    /// Restore the full writable backing before the next `recv` into this buffer.
    ///
    /// [`Self::as_mut_slice`] exposes only the used prefix. After a short
    /// control datagram shrinks that prefix, the next receive must widen it
    /// again or later datagrams are silently truncated.
    pub fn prepare_recv(&mut self) {
        let capacity = self.storage_ref().len();
        self.len = capacity;
    }

    /// Freeze this buffer and retain an explicit lease over its backing.
    pub fn into_shared(mut self) -> LeasedWire {
        let storage = self
            .storage
            .take()
            .expect("wire buffer storage is present until conversion");
        let owner = WireBufOwner {
            storage: Some(storage),
            len: self.len,
            recycler: self.recycler.take(),
        };
        let bytes = OpaqueBytes::from_owner(owner);
        LeasedWire {
            lease: WireLease {
                bytes: bytes.clone(),
            },
            bytes,
        }
    }

    /// Run a mutable preparation hook before freezing this buffer.
    ///
    /// The hook runs exactly once while the buffer is still exclusively owned.
    /// It receives the full backing storage and the current used length, so it
    /// may edit the used prefix, write into spare checkout capacity, and update
    /// the used length before the immutable lease is frozen. Returning an error
    /// produces no lease; setting the length beyond the backing storage returns
    /// [`io::ErrorKind::InvalidInput`].
    ///
    /// This is a buffer-lifecycle hook only. It does not implement
    /// authentication, encryption, or a wire format.
    pub fn into_shared_with<F>(mut self, prepare: F) -> io::Result<LeasedWire>
    where
        F: FnOnce(&mut [u8], &mut usize) -> io::Result<()>,
    {
        let storage_len = self.storage_ref().len();
        let mut used = self.len;
        prepare(self.storage_mut(), &mut used)?;
        if used > storage_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prepared wire length exceeds backing storage",
            ));
        }
        self.len = used;
        Ok(self.into_shared())
    }

    fn storage_ref(&self) -> &[u8] {
        self.storage
            .as_deref()
            .expect("wire buffer storage is present while borrowed")
    }

    fn storage_mut(&mut self) -> &mut [u8] {
        self.storage
            .as_deref_mut()
            .expect("wire buffer storage is present while mutably borrowed")
    }
}

impl Drop for WireBuf {
    fn drop(&mut self) {
        let Some(storage) = self.storage.take() else {
            return;
        };
        if let Some(recycler) = self.recycler.take() {
            recycle(&recycler, storage);
        }
    }
}

#[derive(Debug)]
struct WireBufOwner {
    storage: Option<Vec<u8>>,
    len: usize,
    recycler: Option<Arc<WireBufPoolInner>>,
}

impl AsRef<[u8]> for WireBufOwner {
    fn as_ref(&self) -> &[u8] {
        &self
            .storage
            .as_deref()
            .expect("wire buffer owner retains storage")[..self.len]
    }
}

impl Drop for WireBufOwner {
    fn drop(&mut self) {
        let Some(storage) = self.storage.take() else {
            return;
        };
        if let Some(recycler) = self.recycler.take() {
            recycle(&recycler, storage);
        }
    }
}

fn recycle(pool: &Arc<WireBufPoolInner>, mut storage: Vec<u8>) {
    storage.resize(pool.buffer_size, 0);
    let mut free = pool
        .free
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if free.len() < pool.max_buffers {
        free.push(storage);
    }
}

/// Explicit I/O-reference lease over a frozen wire buffer.
///
/// Dropping this lease releases one backing reference. It intentionally owns
/// a `Bytes` clone so pool reuse follows the same lifetime as packet payload
/// slices.
#[derive(Clone, Debug)]
pub struct WireLease {
    bytes: OpaqueBytes,
}

impl WireLease {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// A frozen wire buffer plus the explicit lease held by the I/O path.
#[derive(Debug)]
pub struct LeasedWire {
    bytes: OpaqueBytes,
    lease: WireLease,
}

impl LeasedWire {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn lease(&self) -> WireLease {
        self.lease.clone()
    }

    pub fn into_parts(self) -> (OpaqueBytes, WireLease) {
        (self.bytes, self.lease)
    }
}

/// One received UDP payload plus profile-boundary authentication metadata.
#[derive(Debug)]
pub struct InboundDatagram {
    pub bytes: WireBuf,
    /// A link profile verified integrity/MAC for this datagram.
    pub authenticated: bool,
    pub meta: RecvMeta,
}

impl InboundDatagram {
    pub fn from_vec(bytes: Vec<u8>, authenticated: bool) -> Self {
        let meta = RecvMeta::new(bytes.len(), None);
        Self {
            bytes: WireBuf::from_vec(bytes),
            authenticated,
            meta,
        }
    }
}

/// A datagram transport boundary. Time is injected; no wall-clock loop lives
/// inside the endpoint or these transports.
pub trait DatagramTransport {
    fn send_datagram(&mut self, now: MonoNs, bytes: &[u8]) -> io::Result<()>;
    fn recv_datagram(&mut self, now: MonoNs) -> io::Result<Option<InboundDatagram>>;

    /// UL-4: emit idle keepalives if the concrete transport supports them.
    ///
    /// Returns the number of keepalive datagrams sent. The default is a no-op
    /// so simulators and loopback adapters stay unchanged.
    fn drive_keepalive(&mut self) -> io::Result<u32> {
        Ok(0)
    }

    /// Enable or disable emission of transport controls (keepalive / challenge).
    ///
    /// Closed associations should disable emission so receive-side processing
    /// cannot reply after [`crate::UdpLiEndpoint::close`]. Default is a no-op.
    fn set_emit_controls(&mut self, _enabled: bool) {}

    /// Clear in-flight path-challenge state on association restart.
    ///
    /// Validated peer bindings may survive; pending challenges must not.
    /// Default is a no-op.
    fn on_association_restart(&mut self) {}

    /// Wall-clock delay until the next transport control action (keepalive or
    /// challenge retransmit), if any. `Some(Duration::ZERO)` means due now.
    /// Used by [`crate::UdpLiEndpoint::drive_when_ready_with_timeout`].
    fn next_io_wake(&self) -> Option<Duration> {
        None
    }

    /// Wait for socket readability or the supplied timeout.
    ///
    /// `None` waits until readability. The default is a sleep-based permanent
    /// fallback for transports without a wakeable socket. It never busy-polls,
    /// but it cannot interrupt a wait early when a datagram arrives.
    fn wait_readable(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        let Some(timeout) = timeout else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transport has no indefinitely waitable readiness source",
            ));
        };
        if !timeout.is_zero() {
            std::thread::sleep(timeout);
        }
        Ok(false)
    }

    /// Receive up to `max` datagrams into caller-owned storage.
    ///
    /// The default executes the scalar reference path. `stats` records each
    /// scalar fallback and any growth of `out`.
    fn recv_batch(
        &mut self,
        now: MonoNs,
        out: &mut Vec<InboundDatagram>,
        max: usize,
        stats: &mut WireIoStats,
    ) -> io::Result<usize> {
        let mut received = 0;
        while received < max {
            stats.fallbacks = stats.fallbacks.saturating_add(1);
            match self.recv_datagram(now) {
                Ok(Some(datagram)) => {
                    let capacity = out.capacity();
                    out.push(datagram);
                    if out.capacity() != capacity {
                        stats.allocations = stats.allocations.saturating_add(1);
                    }
                    received += 1;
                }
                Ok(None) => break,
                Err(error) if received > 0 && error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(received)
    }

    /// Send several datagrams, stopping at the first error.
    ///
    /// The default delegates each datagram to [`Self::send_datagram`].
    fn send_batch(
        &mut self,
        now: MonoNs,
        datagrams: &[&[u8]],
        stats: &mut WireIoStats,
    ) -> io::Result<usize> {
        for datagram in datagrams {
            stats.fallbacks = stats.fallbacks.saturating_add(1);
            self.send_datagram(now, datagram)?;
        }
        Ok(datagrams.len())
    }

    /// Send one datagram assembled from vectored parts.
    ///
    /// The default coalesces into a temporary contiguous buffer because the
    /// scalar reference sends exactly one datagram.
    fn send_vectored(
        &mut self,
        now: MonoNs,
        parts: &[io::IoSlice<'_>],
        stats: &mut WireIoStats,
    ) -> io::Result<()> {
        let len = parts.iter().map(|part| part.len()).sum();
        let mut bytes = Vec::with_capacity(len);
        stats.allocations = stats.allocations.saturating_add(1);
        for part in parts {
            bytes.extend_from_slice(part);
            stats.copies = stats.copies.saturating_add(1);
        }
        stats.fallbacks = stats.fallbacks.saturating_add(1);
        self.send_datagram(now, &bytes)
    }

    /// Adapter-local counters. Transports without diagnostics return zeroes.
    fn io_stats(&self) -> WireIoStats {
        WireIoStats::default()
    }
}

/// Invalid loopback configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopbackError {
    NonLoopbackLocal { addr: SocketAddr },
    NonLoopbackPeer { addr: SocketAddr },
}

impl fmt::Display for LoopbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackLocal { addr } => {
                write!(f, "loopback UDP driver refuses local address {addr}")
            }
            Self::NonLoopbackPeer { addr } => {
                write!(f, "loopback UDP driver refuses peer address {addr}")
            }
        }
    }
}

impl std::error::Error for LoopbackError {}

/// Peer binding lifecycle for one UDP-LI association (UL-2).
///
/// Default shipping behavior stays fail-closed on IP mismatch. A lab
/// `observe_ip` policy may accept the first Conet source IP when the
/// configured peer was only a guess (WAN HTTP vs UDP egress split).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PeerBindingState {
    /// Only the configured destination is known.
    #[default]
    Configured,
    /// A Conet source was seen but is not yet trusted for send.
    Observed,
    /// Path is trusted for send (auto-validate until UL-3, or explicit promote).
    Validated,
    /// Optional pin after validation; conflicting sources are rejected.
    Locked,
}

/// Admission policy for [`ConnectedUdpTransport`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAdmitPolicy {
    /// Allow the first admissible Conet datagram to rewrite the peer IP.
    pub observe_ip: bool,
    /// Promote `Observed` to `Validated` immediately (legacy NAT port learning).
    pub auto_validate: bool,
    /// After validation, pin the peer (`Locked`) so a second source is rejected.
    pub lock_on_validate: bool,
    /// When observing without `auto_validate`, immediately emit a UL-3 path challenge.
    pub auto_challenge: bool,
}

impl Default for PeerAdmitPolicy {
    fn default() -> Self {
        Self {
            observe_ip: false,
            auto_validate: true,
            lock_on_validate: true,
            auto_challenge: false,
        }
    }
}

impl PeerAdmitPolicy {
    /// Lab bridge for WAN probes where HTTP public IP may disagree with UDP egress.
    pub const fn lab_observe_ip() -> Self {
        Self {
            observe_ip: true,
            auto_validate: true,
            lock_on_validate: true,
            auto_challenge: false,
        }
    }

    /// Shipping-shaped admit: observe then UL-3 challenge before trusted send.
    pub const fn require_path_challenge() -> Self {
        Self {
            observe_ip: false,
            auto_validate: false,
            lock_on_validate: true,
            auto_challenge: true,
        }
    }
}

/// Reject / filter counters for peer admission (observable on WAN silence).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerRejectStats {
    pub wrong_ip: u64,
    pub locked_conflict: u64,
    pub non_conet: u64,
    pub challenge_timeout: u64,
    pub challenge_fail: u64,
}

/// Real UDP over one local/peer address pair.
///
/// Unlike [`LoopbackUdpTransport`], this adapter does not restrict either
/// address family to loopback. The configured peer is the initial destination
/// and, by default, an IP-address filter. The first admissible datagram may
/// learn the observed source port (and, under [`PeerAdmitPolicy::observe_ip`],
/// the source IP). Trusted send follows validation rules (UL-2).
#[derive(Debug)]
pub struct ConnectedUdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
    learned_peer: Option<SocketAddr>,
    binding: PeerBindingState,
    policy: PeerAdmitPolicy,
    rejects: PeerRejectStats,
    pending_challenge: Option<PendingPathChallenge>,
    keepalive: KeepaliveState,
    /// When false, consume control frames without emitting replies or probes.
    emit_controls: bool,
    receive_pool: WireBufPool,
    counters: WireIoCounters,
}

impl ConnectedUdpTransport {
    pub fn bind(local: SocketAddr, peer: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        Self::with_socket(socket, peer, PeerAdmitPolicy::default())
    }

    /// Wrap an already-bound UDP socket for one explicit peer.
    pub fn from_socket(socket: UdpSocket, peer: SocketAddr) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Self::with_socket(socket, peer, PeerAdmitPolicy::default())
    }

    /// Bind with an explicit peer-admission policy (UL-2 lab / shipping profiles).
    pub fn bind_with_policy(
        local: SocketAddr,
        peer: SocketAddr,
        policy: PeerAdmitPolicy,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        Self::with_socket(socket, peer, policy)
    }

    pub fn from_socket_with_policy(
        socket: UdpSocket,
        peer: SocketAddr,
        policy: PeerAdmitPolicy,
    ) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Self::with_socket(socket, peer, policy)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The observed peer endpoint after the first admissible datagram.
    pub const fn learned_peer_addr(&self) -> Option<SocketAddr> {
        self.learned_peer
    }

    pub const fn peer_binding_state(&self) -> PeerBindingState {
        self.binding
    }

    pub const fn peer_admit_policy(&self) -> PeerAdmitPolicy {
        self.policy
    }

    pub const fn peer_reject_stats(&self) -> PeerRejectStats {
        self.rejects
    }

    /// Promote `Observed` → `Validated` (and optionally `Locked`).
    ///
    /// No-op success if already validated/locked. Fails if still `Configured`.
    pub fn validate_observed_peer(&mut self) -> bool {
        match self.binding {
            PeerBindingState::Observed => {
                self.promote_validated();
                true
            }
            PeerBindingState::Validated | PeerBindingState::Locked => true,
            PeerBindingState::Configured => false,
        }
    }

    /// UL-6: discover this socket's reflexive address via a helper on the
    /// **same** UDP socket used for the association.
    ///
    /// The result is a candidate only—it does not change peer binding or trust.
    pub fn probe_reflexive(
        &self,
        helper: SocketAddr,
        timeout: Duration,
    ) -> Result<ReflexiveReport, ReflexiveError> {
        discover_reflexive(&self.socket, helper, timeout)
    }

    /// Replace the keepalive policy (UL-4). Disabled by default.
    pub fn set_keepalive_config(&mut self, config: KeepaliveConfig) {
        let stats = self.keepalive.stats;
        self.keepalive = KeepaliveState::new(config);
        self.keepalive.stats = stats;
    }

    pub const fn keepalive_config(&self) -> KeepaliveConfig {
        self.keepalive.config
    }

    pub const fn keepalive_stats(&self) -> KeepaliveStats {
        self.keepalive.stats
    }

    /// In-flight path challenge, if any.
    pub fn pending_path_challenge(&self) -> Option<&PendingPathChallenge> {
        self.pending_challenge.as_ref()
    }

    /// UL-3: challenge `candidate` before trusting it for send.
    ///
    /// If the association is already locked to another peer, a successful
    /// challenge replaces the learned peer. Fails if a challenge is already
    /// in flight.
    pub fn challenge_candidate(
        &mut self,
        candidate: SocketAddr,
    ) -> Result<(), PathChallengeError> {
        if self.pending_challenge.is_some() {
            return Err(PathChallengeError::Busy);
        }
        self.pending_challenge = Some(start_challenge(
            &self.socket,
            candidate,
            3,
            Duration::from_millis(200),
        )?);
        Ok(())
    }

    /// Retransmit or time out the pending UL-3 challenge.
    pub fn drive_path_challenge(&mut self) -> Result<PathChallengePoll, PathChallengeError> {
        if !self.emit_controls {
            return Ok(PathChallengePoll::Pending);
        }
        let Some(pending) = self.pending_challenge.as_mut() else {
            return Ok(PathChallengePoll::Pending);
        };
        let poll = maybe_retransmit(&self.socket, pending, Instant::now())?;
        match poll {
            PathChallengePoll::TimedOut { candidate } => {
                self.fail_challenge(candidate);
                Ok(PathChallengePoll::TimedOut { candidate })
            }
            PathChallengePoll::Validated { candidate } => {
                self.complete_challenge(candidate);
                Ok(PathChallengePoll::Validated { candidate })
            }
            PathChallengePoll::Pending => Ok(PathChallengePoll::Pending),
        }
    }

    /// Drop any in-flight challenge without changing a validated binding.
    ///
    /// Association restart must call this so a delayed response from a prior
    /// epoch cannot promote a stale candidate onto the new epoch.
    pub fn invalidate_pending_challenge(&mut self) {
        self.pending_challenge = None;
    }

    /// Destination used for trusted send.
    ///
    /// Until the peer is validated, this stays on the configured address so an
    /// unvalidated observe cannot redirect bulk traffic.
    fn selected_peer(&self) -> SocketAddr {
        match self.binding {
            PeerBindingState::Validated | PeerBindingState::Locked => {
                self.learned_peer.unwrap_or(self.peer)
            }
            PeerBindingState::Configured | PeerBindingState::Observed => self.peer,
        }
    }

    fn promote_validated(&mut self) {
        self.binding = if self.policy.lock_on_validate {
            PeerBindingState::Locked
        } else {
            PeerBindingState::Validated
        };
    }

    fn complete_challenge(&mut self, candidate: SocketAddr) {
        self.learned_peer = Some(candidate);
        self.pending_challenge = None;
        self.promote_validated();
        self.note_path_activity();
    }

    fn fail_challenge(&mut self, _candidate: SocketAddr) {
        self.pending_challenge = None;
        self.rejects.challenge_timeout = self.rejects.challenge_timeout.saturating_add(1);
        // First-path challenge failure returns to Configured. A locked prior
        // path is kept so remaps cannot steal the association without success.
        if !matches!(
            self.binding,
            PeerBindingState::Validated | PeerBindingState::Locked
        ) {
            self.learned_peer = None;
            self.binding = PeerBindingState::Configured;
        }
    }

    fn launch_challenge(&mut self, candidate: SocketAddr) {
        if self.pending_challenge.is_some() {
            return;
        }
        match start_challenge(&self.socket, candidate, 3, Duration::from_millis(200)) {
            Ok(pending) => self.pending_challenge = Some(pending),
            Err(_) => {
                self.rejects.challenge_fail = self.rejects.challenge_fail.saturating_add(1);
            }
        }
    }

    fn accept_source(&mut self, source: SocketAddr) -> bool {
        if let Some(learned) = self.learned_peer {
            if learned == source {
                return true;
            }
            // Allow a challenge toward a new candidate while keeping the old path.
            if self.pending_challenge.as_ref().is_some_and(|p| p.candidate == source) {
                return false;
            }
            self.rejects.locked_conflict = self.rejects.locked_conflict.saturating_add(1);
            return false;
        }

        if !self.policy.observe_ip && source.ip() != self.peer.ip() {
            self.rejects.wrong_ip = self.rejects.wrong_ip.saturating_add(1);
            return false;
        }

        self.learned_peer = Some(source);
        self.binding = PeerBindingState::Observed;
        if self.policy.auto_validate {
            self.promote_validated();
        } else if self.policy.auto_challenge {
            self.launch_challenge(source);
        }
        true
    }

    fn handle_path_frame(&mut self, source: SocketAddr, bytes: &[u8]) -> bool {
        if !self.emit_controls {
            // Swallow CULP while closed / controls disabled; do not reply.
            return true;
        }
        // Dispatch by control type first. An incoming challenge must be answered
        // even while we await our own response; treating it as a response yields
        // BadType and both peers can exhaust retries.
        if respond_to_challenge(&self.socket, bytes, source).is_ok() {
            return true;
        }
        let Some(pending) = self.pending_challenge.as_ref() else {
            return false;
        };
        match match_response(pending, source, bytes) {
            Ok(Some(PathChallengePoll::Validated { candidate })) => {
                self.complete_challenge(candidate);
                true
            }
            Ok(Some(PathChallengePoll::TimedOut { candidate })) => {
                self.fail_challenge(candidate);
                true
            }
            Ok(Some(PathChallengePoll::Pending)) | Ok(None) => false,
            Err(_) => {
                self.rejects.challenge_fail = self.rejects.challenge_fail.saturating_add(1);
                true
            }
        }
    }

    fn is_admitted_keepalive_source(&self, source: SocketAddr) -> bool {
        match self.learned_peer {
            Some(learned) => learned == source,
            None => self.policy.observe_ip || source.ip() == self.peer.ip(),
        }
    }

    fn trusted_send_peer(&self) -> Option<SocketAddr> {
        match self.binding {
            PeerBindingState::Validated | PeerBindingState::Locked => {
                Some(self.learned_peer.unwrap_or(self.peer))
            }
            PeerBindingState::Configured | PeerBindingState::Observed => None,
        }
    }

    fn note_path_activity(&mut self) {
        self.keepalive.note_activity();
    }

    fn handle_keepalive_frame(&mut self, source: SocketAddr, bytes: &[u8]) -> bool {
        if !self.is_admitted_keepalive_source(source) {
            self.rejects.wrong_ip = self.rejects.wrong_ip.saturating_add(1);
            return true;
        }
        if !self.emit_controls || !self.keepalive.config.enabled {
            // Admitted but disabled / closed: consume without activity or pong.
            return true;
        }
        match decode_keepalive(bytes) {
            Ok(KEEPALIVE_TYPE_PING) => {
                self.keepalive.mark_received();
                if send_pong(&self.socket, source).is_ok() {
                    self.keepalive.mark_pong_sent();
                }
                true
            }
            Ok(_) => {
                self.keepalive.mark_received();
                true
            }
            Err(_) => false,
        }
    }

    fn with_socket(
        socket: UdpSocket,
        peer: SocketAddr,
        policy: PeerAdmitPolicy,
    ) -> io::Result<Self> {
        Ok(Self {
            socket,
            peer,
            learned_peer: None,
            binding: PeerBindingState::Configured,
            policy,
            rejects: PeerRejectStats::default(),
            pending_challenge: None,
            keepalive: KeepaliveState::new(KeepaliveConfig::default()),
            emit_controls: true,
            receive_pool: WireBufPool::new(32, 65_535),
            counters: WireIoCounters::default(),
        })
    }
}

impl DatagramTransport for ConnectedUdpTransport {
    fn send_datagram(&mut self, _now: MonoNs, bytes: &[u8]) -> io::Result<()> {
        self.counters.record_syscall();
        match self.socket.send_to(bytes, self.selected_peer()) {
            Ok(sent) if sent == bytes.len() => {
                self.note_path_activity();
                Ok(())
            }
            Ok(sent) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("UDP send wrote {sent} of {} bytes", bytes.len()),
            )),
            Err(error) => Err(error),
        }
    }

    fn set_emit_controls(&mut self, enabled: bool) {
        self.emit_controls = enabled;
    }

    fn on_association_restart(&mut self) {
        // Validated / locked bindings survive restart; pending challenges do not.
        self.invalidate_pending_challenge();
    }

    fn next_io_wake(&self) -> Option<Duration> {
        if !self.emit_controls {
            return None;
        }
        let now = Instant::now();
        let mut wake = self.keepalive.next_due_in(now);
        if self.pending_challenge.is_some() {
            let challenge = self
                .pending_challenge
                .as_ref()
                .map(|pending| pending.next_retransmit_in(now))
                .unwrap_or(Duration::ZERO);
            wake = Some(wake.map_or(challenge, |wait| wait.min(challenge)));
        }
        wake
    }

    fn drive_keepalive(&mut self) -> io::Result<u32> {
        if !self.emit_controls {
            return Ok(0);
        }
        let now = Instant::now();
        if !self.keepalive.should_send(now) {
            return Ok(0);
        }
        let Some(peer) = self.trusted_send_peer() else {
            return Ok(0);
        };
        self.counters.record_syscall();
        match send_ping(&self.socket, peer) {
            Ok(()) => {
                self.keepalive.mark_sent(now);
                Ok(1)
            }
            Err(error) => Err(io::Error::other(error.to_string())),
        }
    }

    fn recv_datagram(&mut self, _now: MonoNs) -> io::Result<Option<InboundDatagram>> {
        let _ = self.drive_path_challenge();
        let _ = self.drive_keepalive();
        let mut bytes = self
            .receive_pool
            .checkout(self.receive_pool.buffer_size())?;
        loop {
            // Short control frames shrink the used prefix; restore full capacity
            // before every recv so the next datagram is not truncated.
            bytes.prepare_recv();
            self.counters.record_syscall();
            match self.socket.recv_from(bytes.as_mut_slice()) {
                Ok((len, source)) => {
                    bytes.set_len(len);
                    if is_path_challenge_frame(bytes.as_slice()) {
                        let _ = self.handle_path_frame(source, bytes.as_slice());
                        continue;
                    }
                    if is_keepalive_frame(bytes.as_slice()) {
                        let _ = self.handle_keepalive_frame(source, bytes.as_slice());
                        continue;
                    }
                    if !is_parseable_conet_datagram(bytes.as_slice()) {
                        self.rejects.non_conet = self.rejects.non_conet.saturating_add(1);
                        continue;
                    }
                    if !self.accept_source(source) {
                        continue;
                    }
                    self.note_path_activity();
                    return Ok(Some(InboundDatagram {
                        bytes,
                        // Address filtering does not provide a MAC. Security
                        // profiles remain outside this transport slice.
                        authenticated: false,
                        meta: RecvMeta::new(len, Some(source)),
                    }));
                }
                Err(error) if is_retryable_udp_io(error.kind()) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    }

    fn wait_readable(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            self.counters.record_syscall();
            return match self.socket.peek_from(&mut [0_u8; 1]) {
                Ok(_) => Ok(true),
                Err(error) if is_retryable_udp_io(error.kind()) => Ok(false),
                Err(error) => Err(error),
            };
        }

        self.socket.set_nonblocking(false)?;
        let mut byte = [0_u8; 1];
        let ready = self.socket.set_read_timeout(timeout).and_then(|()| {
            self.counters.record_syscall();
            self.socket
                .peek_from(&mut byte)
                .map(|_| true)
                .or_else(|error| {
                    if is_retryable_udp_io(error.kind()) {
                        Ok(false)
                    } else {
                        Err(error)
                    }
                })
        });

        let timeout_cleared = self.socket.set_read_timeout(None);
        let nonblocking = self.socket.set_nonblocking(true);
        if nonblocking.is_err() {
            let _ = self.socket.set_read_timeout(Some(Duration::ZERO));
        }
        if timeout_cleared.is_err() {
            let _ = self.socket.set_read_timeout(Some(Duration::ZERO));
        }
        nonblocking?;
        timeout_cleared?;
        ready
    }

    fn io_stats(&self) -> WireIoStats {
        self.counters.snapshot().merge(self.receive_pool.stats())
    }
}

fn is_parseable_conet_datagram(bytes: &[u8]) -> bool {
    let codec = ReferenceWireCodec::new(WireLimits {
        max_datagram: u16::MAX as usize,
        max_control_body: u16::MAX as usize,
    });
    codec.parse(OpaqueBytes::copy_from_slice(bytes)).is_ok()
}

fn is_retryable_udp_io(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

/// Real UDP on loopback only, for gated conformance runs.
///
/// The socket is owned by this adapter. The profile never reads wall-clock
/// time; `send_datagram` receives the caller's injected timestamp.
#[derive(Debug)]
pub struct LoopbackUdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
    receive_pool: WireBufPool,
    counters: WireIoCounters,
    #[cfg(target_os = "linux")]
    linux_batch: LinuxBatchState,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxBatchState {
    mmsg_enabled: bool,
    recvmsg_enabled: bool,
    gso_enabled: bool,
    gro_enabled: bool,
    ecn_enabled: bool,
    pktinfo_enabled: bool,
    txtime_supported: bool,
    txtime_enabled: bool,
    pending: VecDeque<InboundDatagram>,
}

#[cfg(target_os = "linux")]
impl Default for LinuxBatchState {
    fn default() -> Self {
        Self {
            mmsg_enabled: true,
            recvmsg_enabled: true,
            gso_enabled: false,
            gro_enabled: false,
            ecn_enabled: false,
            pktinfo_enabled: false,
            txtime_supported: false,
            txtime_enabled: false,
            pending: VecDeque::new(),
        }
    }
}

/// Linux feature probes reported by a loopback transport.
///
/// These are capabilities, not a request to use an offload. The default batch
/// sender still uses one UDP datagram per `mmsghdr`, and unsupported features
/// permanently fall back to the portable scalar path.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinuxOffloadCapabilities {
    pub batch_mmsg: bool,
    pub send_gso: bool,
    pub receive_gro: bool,
    pub receive_ecn: bool,
    pub receive_pktinfo: bool,
    pub send_txtime: bool,
}

impl LoopbackUdpTransport {
    pub fn bind(local: SocketAddr, peer: SocketAddr) -> io::Result<Self> {
        validate_loopback(local, peer)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let socket = UdpSocket::bind(local)?;
        socket.set_nonblocking(true)?;
        Self::with_socket(socket, peer)
    }

    /// Wrap an already-bound UDP socket for loopback-only conformance tests.
    pub fn from_socket(socket: UdpSocket, peer: SocketAddr) -> io::Result<Self> {
        let local = socket.local_addr()?;
        validate_loopback(local, peer)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        socket.set_nonblocking(true)?;
        Self::with_socket(socket, peer)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn with_socket(socket: UdpSocket, peer: SocketAddr) -> io::Result<Self> {
        // The association has one known peer. Connecting the socket moves
        // peer filtering into the kernel and enables connected send/recv.
        socket.connect(peer)?;
        #[cfg(target_os = "linux")]
        let linux_batch = {
            let probe = crate::linux::probe(socket.as_raw_fd(), peer.is_ipv4());
            let gro_enabled = probe.gro && crate::linux::set_gro(socket.as_raw_fd(), true).is_ok();
            LinuxBatchState {
                mmsg_enabled: true,
                recvmsg_enabled: true,
                gso_enabled: probe.gso,
                gro_enabled,
                ecn_enabled: probe.ecn,
                pktinfo_enabled: probe.pktinfo,
                txtime_supported: probe.txtime,
                txtime_enabled: false,
                pending: VecDeque::new(),
            }
        };
        Ok(Self {
            socket,
            peer,
            receive_pool: WireBufPool::new(32, 65_535),
            counters: WireIoCounters::default(),
            #[cfg(target_os = "linux")]
            linux_batch,
        })
    }

    /// Return the feature probes made when this socket was connected.
    #[cfg(target_os = "linux")]
    pub fn linux_offload_capabilities(&self) -> LinuxOffloadCapabilities {
        LinuxOffloadCapabilities {
            batch_mmsg: self.linux_batch.mmsg_enabled,
            send_gso: self.linux_batch.gso_enabled,
            receive_gro: self.linux_batch.gro_enabled,
            receive_ecn: self.linux_batch.ecn_enabled,
            receive_pktinfo: self.linux_batch.pktinfo_enabled,
            send_txtime: self.linux_batch.txtime_supported,
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_scalar_batch(
        &mut self,
        now: MonoNs,
        out: &mut Vec<InboundDatagram>,
        max: usize,
        stats: &mut WireIoStats,
    ) -> io::Result<usize> {
        let mut received = 0;
        while received < max {
            stats.fallbacks = stats.fallbacks.saturating_add(1);
            match self.recv_datagram(now) {
                Ok(Some(datagram)) => {
                    let capacity = out.capacity();
                    out.push(datagram);
                    if out.capacity() != capacity {
                        stats.allocations = stats.allocations.saturating_add(1);
                    }
                    received += 1;
                }
                Ok(None) => break,
                Err(error) if received > 0 && error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(received)
    }

    #[cfg(target_os = "linux")]
    fn send_scalar_batch(
        &mut self,
        now: MonoNs,
        datagrams: &[&[u8]],
        stats: &mut WireIoStats,
    ) -> io::Result<usize> {
        for (sent, datagram) in datagrams.iter().enumerate() {
            stats.fallbacks = stats.fallbacks.saturating_add(1);
            match self.send_datagram(now, datagram) {
                Ok(()) => {}
                Err(_) if sent > 0 => return Ok(sent),
                Err(error) => return Err(error),
            }
        }
        Ok(datagrams.len())
    }

    /// Optional Linux GSO batch. GSO is used only when non-final datagrams are
    /// all exactly one segment long; the kernel then emits one UDP datagram per
    /// segment. Unsupported kernels permanently fall back to scalar sends.
    #[cfg(target_os = "linux")]
    pub fn send_gso_batch(&mut self, now: MonoNs, datagrams: &[&[u8]]) -> io::Result<usize> {
        if !self.linux_batch.gso_enabled {
            return self.send_scalar_batch(now, datagrams, &mut WireIoStats::default());
        }
        self.counters.record_syscall();
        match crate::linux::send_gso(self.socket.as_raw_fd(), datagrams) {
            Ok(sent) => Ok(sent),
            Err(error) if linux_offload_unsupported(&error) => {
                self.linux_batch.gso_enabled = false;
                self.counters.record_fallback();
                self.send_scalar_batch(now, datagrams, &mut WireIoStats::default())
            }
            Err(error) => Err(error),
        }
    }

    /// Optionally attach an absolute Linux `SO_TXTIME` release time to one
    /// send. `release_at` is converted directly with [`MonoNs::as_nanos`] and
    /// the socket is configured for Linux `CLOCK_MONOTONIC`.
    ///
    /// [`MonoNs`] is Conet's injected protocol clock and is not guaranteed to
    /// use Linux `CLOCK_MONOTONIC`'s epoch. This hook performs no clock-domain
    /// translation, so a caller may use it only with a release timestamp that
    /// is already expressed in the socket's `CLOCK_MONOTONIC` domain. The
    /// userspace pacer remains the authority for when to send; endpoint pacing
    /// does not call this hook. `None` uses the ordinary scalar send path.
    #[cfg(target_os = "linux")]
    pub fn send_datagram_at(
        &mut self,
        now: MonoNs,
        release_at: Option<MonoNs>,
        bytes: &[u8],
    ) -> io::Result<()> {
        let Some(release_at) = release_at.filter(|_| self.linux_batch.txtime_supported) else {
            return self.send_datagram(now, bytes);
        };
        let release_ns = u64::try_from(release_at.as_nanos()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "SO_TXTIME release time must be non-negative",
            )
        })?;
        if !self.linux_batch.txtime_enabled {
            match crate::linux::enable_txtime(self.socket.as_raw_fd()) {
                Ok(()) => self.linux_batch.txtime_enabled = true,
                Err(error) if linux_offload_unsupported(&error) => {
                    self.linux_batch.txtime_supported = false;
                    self.counters.record_fallback();
                    return self.send_datagram(now, bytes);
                }
                Err(error) => return Err(error),
            }
        }
        self.counters.record_syscall();
        match crate::linux::send_txtime(self.socket.as_raw_fd(), bytes, release_ns) {
            Ok(()) => Ok(()),
            Err(error) if linux_offload_unsupported(&error) => {
                self.linux_batch.txtime_supported = false;
                self.counters.record_fallback();
                self.send_datagram(now, bytes)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(target_os = "linux")]
    fn drain_pending(&mut self, out: &mut Vec<InboundDatagram>, max: usize) -> usize {
        let mut delivered = 0;
        while delivered < max {
            let Some(datagram) = self.linux_batch.pending.pop_front() else {
                break;
            };
            out.push(datagram);
            delivered += 1;
        }
        delivered
    }

    #[cfg(target_os = "linux")]
    fn enqueue_received(
        &mut self,
        buffer: WireBuf,
        info: crate::linux::ReceivedInfo,
    ) -> io::Result<()> {
        let segment = info
            .gso_size
            .filter(|segment| *segment > 0 && *segment < info.len);
        let Some(segment) = segment else {
            self.linux_batch.pending.push_back(InboundDatagram {
                bytes: buffer,
                authenticated: false,
                meta: RecvMeta::from_linux(
                    info.len,
                    Some(self.peer),
                    info.destination,
                    info.interface_index,
                    1,
                    info.len,
                    info.ecn,
                ),
            });
            return Ok(());
        };

        let segments = info.len.div_ceil(segment).min(u16::MAX as usize);
        let mut split = Vec::with_capacity(segments);
        let mut offset = 0;
        while offset < info.len {
            let len = segment.min(info.len - offset);
            let mut bytes = self.receive_pool.checkout(len)?;
            bytes
                .as_mut_slice()
                .copy_from_slice(&buffer.as_slice()[offset..offset + len]);
            split.push(InboundDatagram {
                bytes,
                authenticated: false,
                meta: RecvMeta::from_linux(
                    len,
                    Some(self.peer),
                    info.destination,
                    info.interface_index,
                    segments as u16,
                    segment,
                    info.ecn,
                ),
            });
            offset += len;
        }
        self.linux_batch.pending.extend(split);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn recv_ordinary(&mut self, mut bytes: WireBuf) -> io::Result<Option<InboundDatagram>> {
        self.counters.record_syscall();
        match self.socket.recv(bytes.as_mut_slice()) {
            Ok(len) => {
                bytes.set_len(len);
                Ok(Some(InboundDatagram {
                    bytes,
                    authenticated: false,
                    meta: RecvMeta::new(len, Some(self.peer)),
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_linux_one(&mut self, now: MonoNs) -> io::Result<Option<InboundDatagram>> {
        if let Some(datagram) = self.linux_batch.pending.pop_front() {
            return Ok(Some(datagram));
        }
        let mut bytes = self
            .receive_pool
            .checkout(self.receive_pool.buffer_size())?;
        if !self.linux_batch.recvmsg_enabled {
            return self.recv_ordinary(bytes);
        }
        self.counters.record_syscall();
        let info = match crate::linux::recv_one(self.socket.as_raw_fd(), &mut bytes) {
            Ok(info) => info,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) if linux_offload_unsupported(&error) => {
                self.linux_batch.recvmsg_enabled = false;
                self.linux_batch.gro_enabled = false;
                self.linux_batch.ecn_enabled = false;
                self.linux_batch.pktinfo_enabled = false;
                self.counters.record_fallback();
                let _ = crate::linux::set_gro(self.socket.as_raw_fd(), false);
                return self.recv_ordinary(bytes);
            }
            Err(error) => return Err(error),
        };
        self.enqueue_received(bytes, info)?;
        let _ = now;
        Ok(self.linux_batch.pending.pop_front())
    }
}

fn validate_loopback(local: SocketAddr, peer: SocketAddr) -> Result<(), LoopbackError> {
    if !is_loopback(local.ip()) {
        return Err(LoopbackError::NonLoopbackLocal { addr: local });
    }
    if !is_loopback(peer.ip()) {
        return Err(LoopbackError::NonLoopbackPeer { addr: peer });
    }
    Ok(())
}

fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

impl DatagramTransport for LoopbackUdpTransport {
    fn send_datagram(&mut self, _now: MonoNs, bytes: &[u8]) -> io::Result<()> {
        self.counters.record_syscall();
        self.socket.send(bytes).map(|_| ())
    }

    fn recv_datagram(&mut self, _now: MonoNs) -> io::Result<Option<InboundDatagram>> {
        #[cfg(target_os = "linux")]
        {
            return self.recv_linux_one(_now);
        }

        #[cfg(not(target_os = "linux"))]
        {
            let mut bytes = self
                .receive_pool
                .checkout(self.receive_pool.buffer_size())?;
            self.counters.record_syscall();
            match self.socket.recv(bytes.as_mut_slice()) {
                Ok(len) => {
                    bytes.set_len(len);
                    Ok(Some(InboundDatagram {
                        bytes,
                        // Merely arriving from the configured loopback peer is
                        // not a MAC. CC trust remains fail-closed on this adapter.
                        authenticated: false,
                        meta: RecvMeta::new(len, Some(self.peer)),
                    }))
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_batch(
        &mut self,
        now: MonoNs,
        out: &mut Vec<InboundDatagram>,
        max: usize,
        stats: &mut WireIoStats,
    ) -> io::Result<usize> {
        if max == 0 {
            return Ok(0);
        }
        let delivered = self.drain_pending(out, max);
        if delivered == max {
            return Ok(delivered);
        }
        let remaining = max - delivered;
        if !self.linux_batch.mmsg_enabled {
            return Ok(delivered + self.recv_scalar_batch(now, out, remaining, stats)?);
        }
        let mut buffers = Vec::with_capacity(remaining);
        for _ in 0..remaining {
            buffers.push(
                self.receive_pool
                    .checkout(self.receive_pool.buffer_size())?,
            );
        }
        let mut infos = vec![crate::linux::ReceivedInfo::default(); remaining];
        self.counters.record_syscall();
        let received =
            match crate::linux::recvmmsg(self.socket.as_raw_fd(), &mut buffers, &mut infos) {
                Ok(received) => received,
                Err(error) if linux_offload_unsupported(&error) => {
                    self.linux_batch.mmsg_enabled = false;
                    self.counters.record_fallback();
                    return Ok(delivered + self.recv_scalar_batch(now, out, remaining, stats)?);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(delivered),
                Err(error) => return Err(error),
            };
        let capacity = out.capacity();
        for (buffer, info) in buffers.into_iter().zip(infos).take(received) {
            self.enqueue_received(buffer, info)?;
        }
        let appended = self.drain_pending(out, remaining);
        if out.capacity() != capacity {
            stats.allocations = stats.allocations.saturating_add(1);
        }
        Ok(delivered + appended)
    }

    #[cfg(target_os = "linux")]
    fn send_batch(
        &mut self,
        now: MonoNs,
        datagrams: &[&[u8]],
        stats: &mut WireIoStats,
    ) -> io::Result<usize> {
        if !self.linux_batch.mmsg_enabled || datagrams.len() < 2 {
            return self.send_scalar_batch(now, datagrams, stats);
        }
        self.counters.record_syscall();
        match retry_partial_batches(datagrams.len(), |offset, remaining| {
            crate::linux::sendmmsg(
                self.socket.as_raw_fd(),
                &datagrams[offset..offset + remaining],
            )
        }) {
            Ok(sent) => Ok(sent),
            Err(error) if linux_offload_unsupported(&error.error) => {
                self.linux_batch.mmsg_enabled = false;
                self.counters.record_fallback();
                let remaining = self.send_scalar_batch(now, &datagrams[error.sent..], stats)?;
                Ok(error.sent + remaining)
            }
            Err(error) if error.sent > 0 => Ok(error.sent),
            Err(error) => Err(error.error),
        }
    }

    fn wait_readable(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            self.counters.record_syscall();
            return match self.socket.peek_from(&mut [0_u8; 1]) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error),
            };
        }

        self.socket.set_nonblocking(false)?;
        let mut byte = [0_u8; 1];
        let ready = self.socket.set_read_timeout(timeout).and_then(|()| {
            self.counters.record_syscall();
            self.socket
                .peek_from(&mut byte)
                .map(|_| true)
                .or_else(|error| {
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) {
                        Ok(false)
                    } else {
                        Err(error)
                    }
                })
        });

        // `SO_RCVTIMEO` persists across mode changes. Always clear it and
        // restore nonblocking mode, including when setting up the wait or the
        // readability probe failed.
        let timeout_cleared = self.socket.set_read_timeout(None);
        let nonblocking = self.socket.set_nonblocking(true);
        if nonblocking.is_err() {
            // A valid UDP descriptor should always restore successfully. If it
            // does not, retain bounded blocking behavior instead of allowing a
            // later receive to wait forever.
            let _ = self.socket.set_read_timeout(Some(Duration::ZERO));
        }
        if timeout_cleared.is_err() {
            // Keep even a failed timeout clear bounded on platforms that
            // reject `None`; the socket is still private to this adapter.
            let _ = self.socket.set_read_timeout(Some(Duration::ZERO));
        }
        nonblocking?;
        timeout_cleared?;
        ready
    }

    fn io_stats(&self) -> WireIoStats {
        self.counters.snapshot().merge(self.receive_pool.stats())
    }
}

#[cfg(target_os = "linux")]
fn linux_offload_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS)
            | Some(libc::EINVAL)
            | Some(libc::EOPNOTSUPP)
            | Some(libc::EPROTONOSUPPORT)
    )
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
struct PartialBatchError {
    sent: usize,
    error: io::Error,
}

#[cfg(any(target_os = "linux", test))]
fn retry_partial_batches(
    total: usize,
    mut send: impl FnMut(usize, usize) -> io::Result<usize>,
) -> Result<usize, PartialBatchError> {
    let mut sent = 0;
    while sent < total {
        match send(sent, total - sent) {
            Ok(0) => break,
            Ok(count) if count <= total - sent => sent += count,
            Ok(_) => {
                return Err(PartialBatchError {
                    sent,
                    error: io::Error::new(
                        io::ErrorKind::InvalidData,
                        "batch send reported more datagrams than remained",
                    ),
                });
            }
            Err(error) if sent > 0 && error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(PartialBatchError { sent, error }),
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Instant;

    use super::*;

    fn conet_datagram(payload: &[u8]) -> Vec<u8> {
        let codec = ReferenceWireCodec::default();
        let datagram = codec
            .build(
                conet_core::WireHeader {
                    flags: conet_core::WireFlags::default(),
                    epoch: 1,
                    link_seq: 10,
                    payload_len: 0,
                },
                OpaqueBytes::copy_from_slice(payload),
                None,
            )
            .unwrap();
        codec.serialize(&datagram).unwrap()
    }

    #[derive(Debug, Default)]
    struct ScalarTransport {
        sent: Vec<Vec<u8>>,
        inbound: VecDeque<InboundDatagram>,
    }

    impl ScalarTransport {
        fn with_inbound(datagrams: impl IntoIterator<Item = &'static [u8]>) -> Self {
            Self {
                sent: Vec::new(),
                inbound: datagrams
                    .into_iter()
                    .map(|bytes| InboundDatagram::from_vec(bytes.to_vec(), true))
                    .collect(),
            }
        }
    }

    impl DatagramTransport for ScalarTransport {
        fn send_datagram(&mut self, _now: MonoNs, bytes: &[u8]) -> io::Result<()> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        fn recv_datagram(&mut self, _now: MonoNs) -> io::Result<Option<InboundDatagram>> {
            Ok(self.inbound.pop_front())
        }
    }

    fn recv_connected(
        transport: &mut ConnectedUdpTransport,
        timeout: Duration,
    ) -> Option<InboundDatagram> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(datagram) = transport.recv_datagram(MonoNs::ZERO).unwrap() {
                return Some(datagram);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline.saturating_duration_since(now);
            transport
                .wait_readable(Some(remaining.min(Duration::from_millis(25))))
                .unwrap();
        }
    }

    #[test]
    fn default_batch_methods_fall_back_and_match_scalar_datagrams() {
        let datagrams: &[&[u8]] = &[b"first", b"second"];

        let mut scalar = ScalarTransport::default();
        for datagram in datagrams {
            scalar.send_datagram(MonoNs::ZERO, datagram).unwrap();
        }
        scalar
            .send_vectored(
                MonoNs::ZERO,
                &[io::IoSlice::new(b"vec"), io::IoSlice::new(b"tored")],
                &mut WireIoStats::default(),
            )
            .unwrap();

        let mut batched = ScalarTransport::default();
        let mut send_stats = WireIoStats::default();
        assert_eq!(
            batched
                .send_batch(MonoNs::ZERO, datagrams, &mut send_stats)
                .unwrap(),
            2
        );
        let mut vector_stats = WireIoStats::default();
        batched
            .send_vectored(
                MonoNs::ZERO,
                &[io::IoSlice::new(b"vec"), io::IoSlice::new(b"tored")],
                &mut vector_stats,
            )
            .unwrap();

        assert_eq!(batched.sent, scalar.sent);
        assert_eq!(send_stats.fallbacks, 2);
        assert_eq!(send_stats.allocations, 0);
        assert_eq!(vector_stats.fallbacks, 1);
        assert_eq!(vector_stats.allocations, 1);
        assert_eq!(vector_stats.copies, 2);

        let mut scalar_receive =
            ScalarTransport::with_inbound([b"one".as_slice(), b"two".as_slice()]);
        let mut reference = Vec::new();
        while let Some(datagram) = scalar_receive.recv_datagram(MonoNs::ZERO).unwrap() {
            reference.push(datagram.bytes.as_slice().to_vec());
        }

        let mut batched_receive =
            ScalarTransport::with_inbound([b"one".as_slice(), b"two".as_slice()]);
        let mut output = Vec::with_capacity(2);
        let mut receive_stats = WireIoStats::default();
        assert_eq!(
            batched_receive
                .recv_batch(MonoNs::ZERO, &mut output, 2, &mut receive_stats,)
                .unwrap(),
            2
        );
        let observed: Vec<_> = output
            .iter()
            .map(|datagram| datagram.bytes.as_slice().to_vec())
            .collect();
        assert_eq!(observed, reference);
        assert_eq!(receive_stats.fallbacks, 2);
        assert_eq!(receive_stats.allocations, 0);
    }

    #[test]
    fn partial_batch_retry_advances_without_repeating_a_sequence() {
        let link_seq = [10_u32, 11, 12, 13];
        let mut attempts = 0;
        let mut observed = Vec::new();
        let sent = retry_partial_batches(link_seq.len(), |offset, remaining| {
            attempts += 1;
            let count = match attempts {
                1 => 2,
                2 => 1,
                _ => 1,
            };
            assert!(count <= remaining);
            observed.extend_from_slice(&link_seq[offset..offset + count]);
            Ok(count)
        })
        .unwrap();

        assert_eq!(sent, link_seq.len());
        assert_eq!(observed, link_seq);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn partial_batch_failure_reports_the_committed_prefix() {
        let link_seq = [20_u32, 21, 22];
        let mut observed = Vec::new();
        let error = retry_partial_batches(link_seq.len(), |offset, remaining| {
            if offset == 0 {
                observed.extend_from_slice(&link_seq[..2]);
                Ok(2)
            } else {
                assert_eq!(remaining, 1);
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
        })
        .unwrap_err();

        assert_eq!(error.sent, 2);
        assert_eq!(error.error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(observed, [20, 21]);
    }

    #[test]
    fn connected_loopback_scalar_and_batch_paths_preserve_datagrams() {
        fn receive_datagrams(
            receiver: &mut LoopbackUdpTransport,
            expected: usize,
        ) -> Vec<InboundDatagram> {
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut output = Vec::with_capacity(expected);
            while output.len() < expected && Instant::now() < deadline {
                let remaining = Duration::from_millis(10).min(deadline - Instant::now());
                let _ = receiver.wait_readable(Some(remaining)).unwrap();
                let max = expected - output.len();
                receiver
                    .recv_batch(MonoNs::ZERO, &mut output, max, &mut WireIoStats::default())
                    .unwrap();
            }
            assert_eq!(output.len(), expected);
            output
        }

        let expected: &[&[u8]] = &[b"first", b"second", b"third"];

        let scalar_server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let scalar_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let scalar_server_addr = scalar_server.local_addr().unwrap();
        let scalar_client_addr = scalar_client.local_addr().unwrap();
        let mut scalar_sender =
            LoopbackUdpTransport::from_socket(scalar_client, scalar_server_addr).unwrap();
        let mut scalar_receiver =
            LoopbackUdpTransport::from_socket(scalar_server, scalar_client_addr).unwrap();
        for datagram in expected {
            scalar_sender.send_datagram(MonoNs::ZERO, datagram).unwrap();
        }
        let scalar = receive_datagrams(&mut scalar_receiver, expected.len());

        let batch_server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let batch_client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let batch_server_addr = batch_server.local_addr().unwrap();
        let batch_client_addr = batch_client.local_addr().unwrap();
        let mut batch_sender =
            LoopbackUdpTransport::from_socket(batch_client, batch_server_addr).unwrap();
        let mut batch_receiver =
            LoopbackUdpTransport::from_socket(batch_server, batch_client_addr).unwrap();
        let mut batch_stats = WireIoStats::default();
        assert_eq!(
            batch_sender
                .send_batch(MonoNs::ZERO, expected, &mut batch_stats)
                .unwrap(),
            expected.len()
        );
        let batch = receive_datagrams(&mut batch_receiver, expected.len());

        let scalar: Vec<_> = scalar
            .iter()
            .map(|datagram| datagram.bytes.as_slice())
            .collect();
        let batch: Vec<_> = batch
            .iter()
            .map(|datagram| datagram.bytes.as_slice())
            .collect();
        assert_eq!(batch, scalar);
        assert_eq!(batch, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_gso_and_gro_preserve_individual_datagrams() {
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let sender_addr = sender_socket.local_addr().unwrap();
        let mut receiver = LoopbackUdpTransport::from_socket(receiver_socket, sender_addr).unwrap();
        let mut sender = LoopbackUdpTransport::from_socket(sender_socket, receiver_addr).unwrap();
        let expected: &[&[u8]] = &[b"one!", b"two!", b"end"];
        assert_eq!(
            sender.send_gso_batch(MonoNs::ZERO, expected).unwrap(),
            expected.len()
        );

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut received = Vec::new();
        while received.len() < expected.len() && Instant::now() < deadline {
            let _ = receiver.wait_readable(Some(Duration::from_millis(10)));
            let remaining = expected.len() - received.len();
            receiver
                .recv_batch(
                    MonoNs::ZERO,
                    &mut received,
                    remaining,
                    &mut WireIoStats::default(),
                )
                .unwrap();
        }
        let observed: Vec<_> = received
            .iter()
            .map(|datagram| datagram.bytes.as_slice())
            .collect();
        assert_eq!(observed, expected);
        for datagram in received
            .iter()
            .filter(|datagram| datagram.meta.segments > 1)
        {
            assert_eq!(datagram.meta.stride, 4);
            assert!((2..=expected.len()).contains(&usize::from(datagram.meta.segments)));
        }
    }

    #[test]
    fn loopback_wait_clears_read_timeout_and_restores_nonblocking_mode() {
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let mut receiver = LoopbackUdpTransport::from_socket(receiver_socket, sender_addr).unwrap();

        assert!(!receiver.wait_readable(Some(Duration::ZERO)).unwrap());
        assert!(
            !receiver
                .wait_readable(Some(Duration::from_millis(10)))
                .unwrap()
        );
        assert_eq!(receiver.socket.read_timeout().unwrap(), None);
        assert!(receiver.recv_datagram(MonoNs::ZERO).unwrap().is_none());

        sender.send_to(b"ready", receiver_addr).unwrap();
        assert!(
            receiver
                .wait_readable(Some(Duration::from_secs(1)))
                .unwrap()
        );
        assert_eq!(receiver.socket.read_timeout().unwrap(), None);
        let datagram = receiver
            .recv_datagram(MonoNs::ZERO)
            .unwrap()
            .expect("readable datagram");
        assert_eq!(datagram.bytes.as_slice(), b"ready");
    }

    #[test]
    fn connected_udp_accepts_non_loopback_peer_but_loopback_adapter_refuses_it() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let non_loopback_peer: SocketAddr = "192.0.2.1:7878".parse().unwrap();
        let transport = ConnectedUdpTransport::from_socket(socket, non_loopback_peer).unwrap();
        assert_eq!(transport.peer_addr(), non_loopback_peer);
        assert!(!transport.peer_addr().ip().is_loopback());

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(LoopbackUdpTransport::from_socket(socket, non_loopback_peer).is_err());
    }

    #[test]
    fn connected_udp_learns_nat_mapped_source_and_replies_to_it() {
        let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender_socket.local_addr().unwrap();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        // Hold this port so the receiver's configured source is definitely
        // different from the sender's observed source.
        let wrong_source = UdpSocket::bind("127.0.0.1:0").unwrap();
        let configured_source =
            SocketAddr::new(sender_addr.ip(), wrong_source.local_addr().unwrap().port());

        let mut sender = ConnectedUdpTransport::from_socket(sender_socket, receiver_addr).unwrap();
        let mut receiver =
            ConnectedUdpTransport::from_socket(receiver_socket, configured_source).unwrap();

        wrong_source.send_to(b"not-conet", receiver_addr).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            receiver
                .recv_datagram(MonoNs::ZERO)
                .expect("non-Conet is not fatal")
                .is_none()
        );
        assert_eq!(receiver.learned_peer_addr(), None);
        assert_eq!(receiver.peer_binding_state(), PeerBindingState::Configured);
        assert_eq!(receiver.peer_reject_stats().non_conet, 1);
        let request_bytes = conet_datagram(b"request");
        sender.send_datagram(MonoNs::ZERO, &request_bytes).unwrap();
        let request =
            recv_connected(&mut receiver, Duration::from_secs(1)).expect("NAT-mapped request");
        assert_eq!(request.bytes.as_slice(), request_bytes);
        assert_eq!(request.meta.source, Some(sender_addr));
        assert_eq!(receiver.learned_peer_addr(), Some(sender_addr));
        assert_eq!(receiver.peer_binding_state(), PeerBindingState::Locked);

        let reply_bytes = conet_datagram(b"reply");
        receiver.send_datagram(MonoNs::ZERO, &reply_bytes).unwrap();
        let reply =
            recv_connected(&mut sender, Duration::from_secs(1)).expect("reply to observed source");
        assert_eq!(reply.bytes.as_slice(), reply_bytes);
        assert_eq!(reply.meta.source, Some(receiver_addr));
        assert_eq!(sender.learned_peer_addr(), Some(receiver_addr));
    }

    #[test]
    fn connected_udp_counts_wrong_ip_and_stays_configured() {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender.local_addr().unwrap();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        // Configure a different loopback-mapped IP filter that will not match
        // 127.0.0.1 — use an alternate 127.0.0.0/8 address when available via
        // binding, otherwise skip-style assert on reject counter alone.
        let mut receiver = ConnectedUdpTransport::from_socket(
            receiver_socket,
            "127.0.0.2:9".parse().unwrap(),
        )
        .unwrap();

        sender
            .send_to(&conet_datagram(b"wan-mismatch"), receiver_addr)
            .unwrap();
        assert!(
            recv_connected(&mut receiver, Duration::from_millis(200)).is_none(),
            "wrong configured IP must not deliver"
        );
        assert_eq!(receiver.learned_peer_addr(), None);
        assert_eq!(receiver.peer_binding_state(), PeerBindingState::Configured);
        assert!(receiver.peer_reject_stats().wrong_ip >= 1);
        let _ = sender_addr;
    }

    #[test]
    fn lab_observe_ip_accepts_first_conet_source_despite_wrong_configured_ip() {
        let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender_socket.local_addr().unwrap();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let mut sender = ConnectedUdpTransport::from_socket(sender_socket, receiver_addr).unwrap();
        let mut receiver = ConnectedUdpTransport::from_socket_with_policy(
            receiver_socket,
            "127.0.0.2:9".parse().unwrap(),
            PeerAdmitPolicy::lab_observe_ip(),
        )
        .unwrap();

        let request_bytes = conet_datagram(b"observed-ip");
        sender.send_datagram(MonoNs::ZERO, &request_bytes).unwrap();
        let request =
            recv_connected(&mut receiver, Duration::from_secs(1)).expect("observe_ip accepts");
        assert_eq!(request.bytes.as_slice(), request_bytes);
        assert_eq!(receiver.learned_peer_addr(), Some(sender_addr));
        assert_eq!(receiver.peer_binding_state(), PeerBindingState::Locked);
        assert_eq!(receiver.peer_reject_stats().wrong_ip, 0);

        let reply_bytes = conet_datagram(b"reply-observed");
        receiver.send_datagram(MonoNs::ZERO, &reply_bytes).unwrap();
        let reply = recv_connected(&mut sender, Duration::from_secs(1)).expect("reply to learned");
        assert_eq!(reply.bytes.as_slice(), reply_bytes);
    }

    #[test]
    fn observed_peer_does_not_redirect_send_until_validated() {
        let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = sender_socket.local_addr().unwrap();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let policy = PeerAdmitPolicy {
            observe_ip: false,
            auto_validate: false,
            lock_on_validate: false,
            auto_challenge: false,
        };
        let mut receiver =
            ConnectedUdpTransport::from_socket_with_policy(receiver_socket, sender_addr, policy)
                .unwrap();

        sender_socket
            .send_to(&conet_datagram(b"observe-only"), receiver_addr)
            .unwrap();
        let _ = recv_connected(&mut receiver, Duration::from_secs(1)).expect("observed");
        assert_eq!(receiver.peer_binding_state(), PeerBindingState::Observed);
        assert_eq!(receiver.learned_peer_addr(), Some(sender_addr));
        // Trusted send stays on the configured peer until explicit validate.
        assert!(receiver.validate_observed_peer());
        assert_eq!(receiver.peer_binding_state(), PeerBindingState::Validated);
    }

    #[test]
    fn connected_udp_treats_icmp_refusal_as_retryable() {
        let dead_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_peer = dead_socket.local_addr().unwrap();
        drop(dead_socket);

        let mut transport =
            ConnectedUdpTransport::bind("127.0.0.1:0".parse().unwrap(), dead_peer).unwrap();
        for _ in 0..3 {
            transport
                .send_datagram(MonoNs::ZERO, b"unbound")
                .expect("ICMP refusal must not make send fatal");
            std::thread::sleep(Duration::from_millis(10));
            transport
                .wait_readable(Some(Duration::from_millis(25)))
                .expect("ICMP refusal must not make readiness fatal");
            assert!(
                transport
                    .recv_datagram(MonoNs::ZERO)
                    .expect("ICMP refusal must not make receive fatal")
                    .is_none()
            );
        }
        assert!(is_retryable_udp_io(io::ErrorKind::ConnectionRefused));
        assert!(is_retryable_udp_io(io::ErrorKind::ConnectionReset));
    }

    #[test]
    fn connected_udp_locks_to_the_first_observed_peer() {
        let expected = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender_addr = expected.local_addr().unwrap();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let intruder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver =
            ConnectedUdpTransport::from_socket(receiver_socket, sender_addr).unwrap();

        let first_bytes = conet_datagram(b"first");
        expected.send_to(&first_bytes, receiver_addr).unwrap();
        let first = recv_connected(&mut receiver, Duration::from_secs(1)).expect("expected peer");
        assert_eq!(first.bytes.as_slice(), first_bytes);
        assert_eq!(receiver.learned_peer_addr(), Some(sender_addr));

        intruder
            .send_to(&conet_datagram(b"intruder"), receiver_addr)
            .unwrap();
        let second_bytes = conet_datagram(b"second");
        expected.send_to(&second_bytes, receiver_addr).unwrap();
        let second = recv_connected(&mut receiver, Duration::from_secs(1))
            .expect("expected peer after intruder");
        assert_eq!(second.bytes.as_slice(), second_bytes);
        assert_eq!(second.meta.source, Some(sender_addr));
        assert_eq!(receiver.learned_peer_addr(), Some(sender_addr));
        assert!(receiver.peer_reject_stats().locked_conflict >= 1);
        assert_eq!(receiver.peer_binding_state(), PeerBindingState::Locked);
    }

    #[test]
    fn pooled_buffer_waits_for_the_last_handle_and_io_lease() {
        let pool = WireBufPool::new(1, 8);
        let mut buffer = pool.checkout(4).unwrap();
        buffer.as_mut_slice().copy_from_slice(b"data");
        assert_eq!(buffer.as_slice(), b"data");

        let (bytes, lease) = buffer.into_shared().into_parts();
        let handle = bytes.slice(1..3);
        drop(bytes);
        assert_eq!(pool.available(), 0);
        drop(lease);
        assert_eq!(pool.available(), 0);
        assert_eq!(&handle[..], b"at");
        drop(handle);

        assert_eq!(pool.available(), 1);
        assert_eq!(pool.created(), 1);
        assert_eq!(pool.stats().allocations, 1);

        let reused = pool.checkout(3).unwrap();
        assert_eq!(reused.len(), 3);
        drop(reused);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn mutable_preparation_hook_runs_before_lease_freeze() {
        let pool = WireBufPool::new(1, 8);
        let mut buffer = pool.checkout(4).unwrap();
        buffer.as_mut_slice().copy_from_slice(b"data");

        let leased = buffer
            .into_shared_with(|bytes, len| {
                assert_eq!(bytes.len(), pool.buffer_size());
                assert_eq!(*len, 4);
                bytes[0] = b'D';
                bytes[3] = b'A';
                bytes[4..8].copy_from_slice(b"Tail");
                *len = 8;
                Ok(())
            })
            .unwrap();
        assert_eq!(leased.as_slice(), b"DatATail");
        let (bytes, lease) = leased.into_parts();
        let handle = bytes.slice(4..8);
        drop(bytes);
        drop(lease);
        assert_eq!(pool.available(), 0);
        assert_eq!(&handle[..], b"Tail");
        drop(handle);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn pool_does_not_grow_past_max_buffers_when_the_free_list_is_empty() {
        let pool = WireBufPool::new(2, 8);
        let first = pool.checkout(8).unwrap();
        let second = pool.checkout(8).unwrap();
        let fallback = pool.checkout(4).unwrap();
        assert_eq!(fallback.as_slice().len(), 4);
        assert_eq!(pool.created(), 2);
        assert_eq!(pool.max_buffers(), 2);

        drop(fallback);
        assert_eq!(pool.available(), 0);
        drop(first);
        drop(second);
        assert_eq!(pool.available(), 2);

        let _reused_first = pool.checkout(8).unwrap();
        let _reused_second = pool.checkout(8).unwrap();
        assert_eq!(pool.created(), 2);
    }
}
