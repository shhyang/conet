//! Datagram-only link contracts and lossless in-process identity links.

use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::paced::LinkCaps;
use crate::packet::PacketHandle;
use crate::queue::{
    EnqueueError, EnqueueErrorKind, EnqueueStatus, Occupancy, PacketQueue, QueueLimits,
};

/// Sends complete owned datagram handles.
///
/// A successful enqueue moves the handle. A failed enqueue returns it. There is
/// intentionally no byte-stream surface:
///
/// ```compile_fail
/// use conet_core::link::LinkSender;
/// fn stream_write<S: LinkSender>(sender: &mut S) {
///     sender.write_all(b"not a datagram");
/// }
/// ```
pub trait LinkSender {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError>;
    fn occupancy(&self) -> Occupancy;
    fn close(&mut self);
}

/// Receives complete owned datagram handles, or nothing.
///
/// There is intentionally no byte-stream read API:
///
/// ```compile_fail
/// use conet_core::link::LinkReceiver;
/// fn stream_read<R: LinkReceiver>(receiver: &mut R) {
///     let _ = receiver.read_exact(&mut [0_u8; 8]);
/// }
/// ```
pub trait LinkReceiver {
    fn recv(&mut self) -> Option<PacketHandle>;
    fn occupancy(&self) -> Occupancy;
}

impl LinkSender for PacketQueue {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        PacketQueue::enqueue(self, pkt)
    }

    fn occupancy(&self) -> Occupancy {
        PacketQueue::occupancy(self)
    }

    fn close(&mut self) {
        PacketQueue::close(self);
    }
}

impl LinkReceiver for PacketQueue {
    fn recv(&mut self) -> Option<PacketHandle> {
        self.dequeue()
    }

    fn occupancy(&self) -> Occupancy {
        PacketQueue::occupancy(self)
    }
}

#[derive(Debug)]
struct SharedLink {
    queue: PacketQueue,
    receiver_open: bool,
    sender_open: bool,
}

/// Sending end of an in-process, lossless identity link.
#[derive(Debug)]
pub struct IdentitySender {
    shared: Arc<Mutex<SharedLink>>,
}

/// Receiving end of an in-process, lossless identity link.
#[derive(Debug)]
pub struct IdentityReceiver {
    shared: Arc<Mutex<SharedLink>>,
}

/// Create one directed lossless identity link with a bounded queue.
pub fn identity_link(limits: QueueLimits) -> (IdentitySender, IdentityReceiver) {
    let shared = Arc::new(Mutex::new(SharedLink {
        queue: PacketQueue::new(limits),
        receiver_open: true,
        sender_open: true,
    }));
    (
        IdentitySender {
            shared: Arc::clone(&shared),
        },
        IdentityReceiver { shared },
    )
}

impl IdentitySender {
    fn lock(&self) -> MutexGuard<'_, SharedLink> {
        self.shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn would_accept(&self, pkt: &PacketHandle) -> Result<(), EnqueueErrorKind> {
        let shared = self.lock();
        if !shared.receiver_open {
            return Err(EnqueueErrorKind::Closed);
        }
        shared.queue.would_accept(pkt)
    }

    pub fn is_open(&self) -> bool {
        let shared = self.lock();
        shared.receiver_open && shared.sender_open && !shared.queue.is_closed()
    }

    pub const fn caps(&self) -> LinkCaps {
        LinkCaps::UNPACED_IN_PROCESS
    }
}

impl LinkSender for IdentitySender {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        let mut shared = self.lock();
        if !shared.receiver_open {
            return Err(EnqueueError::Closed { pkt });
        }
        shared.queue.enqueue(pkt)
    }

    fn occupancy(&self) -> Occupancy {
        self.lock().queue.occupancy()
    }

    fn close(&mut self) {
        self.lock().queue.close();
    }
}

impl Drop for IdentitySender {
    fn drop(&mut self) {
        self.lock().sender_open = false;
    }
}

impl IdentityReceiver {
    fn lock(&self) -> MutexGuard<'_, SharedLink> {
        self.shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub fn is_open(&self) -> bool {
        let shared = self.lock();
        shared.sender_open && shared.receiver_open
    }
}

impl LinkReceiver for IdentityReceiver {
    fn recv(&mut self) -> Option<PacketHandle> {
        self.lock().queue.dequeue()
    }

    fn occupancy(&self) -> Occupancy {
        self.lock().queue.occupancy()
    }
}

impl Drop for IdentityReceiver {
    fn drop(&mut self) {
        self.lock().receiver_open = false;
    }
}

/// Successful fan-out delivery count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FanoutStatus {
    pub delivered: usize,
}

/// Fan-out admission failure. No sink accepted the packet on failure.
#[derive(Debug)]
pub enum FanoutError {
    NoSinks {
        pkt: PacketHandle,
    },
    DuplicateSink {
        pkt: PacketHandle,
        sink_index: usize,
    },
    Rejected {
        pkt: PacketHandle,
        sink_index: usize,
        kind: EnqueueErrorKind,
    },
}

impl FanoutError {
    pub fn packet(&self) -> &PacketHandle {
        match self {
            Self::NoSinks { pkt }
            | Self::DuplicateSink { pkt, .. }
            | Self::Rejected { pkt, .. } => pkt,
        }
    }

    pub fn into_packet(self) -> PacketHandle {
        match self {
            Self::NoSinks { pkt }
            | Self::DuplicateSink { pkt, .. }
            | Self::Rejected { pkt, .. } => pkt,
        }
    }
}

impl fmt::Display for FanoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSinks { .. } => f.write_str("fan-out has no sinks"),
            Self::DuplicateSink { sink_index, .. } => {
                write!(f, "fan-out sink {sink_index} is attached more than once")
            }
            Self::Rejected {
                sink_index, kind, ..
            } => write!(f, "fan-out sink {sink_index} rejected packet: {kind:?}"),
        }
    }
}

impl std::error::Error for FanoutError {}

/// Supported fan-out to two or more identity-link sinks.
///
/// This is replication, not a merge. Admission is checked on every sink while
/// all sink queues are locked; a rejected packet is returned before any sink is
/// mutated.
#[derive(Debug)]
pub struct FanoutSender {
    sinks: Vec<IdentitySender>,
}

impl FanoutSender {
    pub fn new(sinks: Vec<IdentitySender>) -> Self {
        Self { sinks }
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Fan out one shared payload into an independent handle per sink.
    pub fn enqueue_to_all(&mut self, pkt: PacketHandle) -> Result<FanoutStatus, FanoutError> {
        if self.sinks.is_empty() {
            return Err(FanoutError::NoSinks { pkt });
        }
        for left in 0..self.sinks.len() {
            for right in (left + 1)..self.sinks.len() {
                if Arc::ptr_eq(&self.sinks[left].shared, &self.sinks[right].shared) {
                    return Err(FanoutError::DuplicateSink {
                        pkt,
                        sink_index: right,
                    });
                }
            }
        }

        let mut guards = Vec::with_capacity(self.sinks.len());
        for sink in &self.sinks {
            guards.push(sink.lock());
        }

        for (sink_index, shared) in guards.iter().enumerate() {
            if !shared.receiver_open {
                return Err(FanoutError::Rejected {
                    pkt,
                    sink_index,
                    kind: EnqueueErrorKind::Closed,
                });
            }
            if let Err(kind) = shared.queue.would_accept(&pkt) {
                return Err(FanoutError::Rejected {
                    pkt,
                    sink_index,
                    kind,
                });
            }
        }

        let sink_count = guards.len();
        let mut original = Some(pkt);
        for (sink_index, shared) in guards.iter_mut().enumerate() {
            let handle = if sink_index + 1 == sink_count {
                original.take().expect("original handle is used once")
            } else {
                original
                    .as_ref()
                    .expect("original handle remains until final sink")
                    .fanout()
            };
            shared
                .queue
                .enqueue(handle)
                .expect("fan-out admission was preflighted under the same lock");
        }

        Ok(FanoutStatus {
            delivered: sink_count,
        })
    }
}

/// One forwarding step between two identity links.
#[derive(Debug)]
pub struct IdentityForwarder {
    inbound: IdentityReceiver,
    outbound: IdentitySender,
    pending: Option<PacketHandle>,
}

impl IdentityForwarder {
    pub fn new(inbound: IdentityReceiver, outbound: IdentitySender) -> Self {
        Self {
            inbound,
            outbound,
            pending: None,
        }
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn pending_backing_id(&self) -> Option<crate::packet::BackingId> {
        self.pending.as_ref().map(PacketHandle::backing_id)
    }

    /// Move or retain one handle while applying downstream backpressure.
    pub fn forward_once(&mut self) -> Result<ForwardOutcome, ForwardError> {
        let pkt = match self.pending.take() {
            Some(pkt) => pkt,
            None => match self.inbound.recv() {
                Some(pkt) => pkt,
                None => return Ok(ForwardOutcome::Idle),
            },
        };

        match self.outbound.enqueue(pkt) {
            Ok(_) => Ok(ForwardOutcome::Forwarded),
            Err(error) => {
                let kind = error.kind();
                self.pending = Some(error.into_packet());
                Err(ForwardError::Backpressure { kind })
            }
        }
    }
}

/// Outcome of a forwarding step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardOutcome {
    Idle,
    Forwarded,
}

/// A forwarding step that could not move its retained handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardError {
    Backpressure { kind: EnqueueErrorKind },
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backpressure { kind } => write!(f, "forward backpressure: {kind:?}"),
        }
    }
}

impl std::error::Error for ForwardError {}
