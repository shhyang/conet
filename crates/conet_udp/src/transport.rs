//! Injected-time datagram boundaries used by the simulator and UDP socket.

use core::fmt;
#[cfg(target_os = "linux")]
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use conet_core::{MonoNs, OpaqueBytes};

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
