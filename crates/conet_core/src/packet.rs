//! Shared immutable payloads with exclusive per-output headers.

use core::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Bytes, BytesMut};

use crate::accounting::{BackingAccounting, PacketMetrics, PayloadCopyCounter};

static NEXT_BACKING_ID: AtomicU64 = AtomicU64::new(1);

/// Identity of one unique frozen payload allocation.
///
/// This is an in-process accounting identity, never a wire identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackingId(u64);

impl BackingId {
    pub const fn get(self) -> u64 {
        self.0
    }

    fn allocate() -> Self {
        Self(NEXT_BACKING_ID.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for BackingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
struct Backing {
    id: BackingId,
    bytes: Bytes,
    charged_bytes: usize,
    accounting: BackingAccounting,
}

impl Backing {
    fn new(bytes: Bytes, charged_bytes: usize, accounting: BackingAccounting) -> Self {
        accounting.record_alloc(charged_bytes);
        Self {
            id: BackingId::allocate(),
            bytes,
            charged_bytes,
            accounting,
        }
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        self.accounting.record_free(self.charged_bytes);
    }
}

/// A descriptor into a shared immutable payload backing.
#[derive(Clone, Debug)]
pub struct PayloadRef {
    backing: Arc<Backing>,
    offset: usize,
    len: usize,
}

impl PayloadRef {
    pub fn backing_id(&self) -> BackingId {
        self.backing.id
    }

    /// Absolute `(offset, length)` within the unique backing.
    pub const fn range(&self) -> (usize, usize) {
        (self.offset, self.len)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrowed synchronous view; not a byte-stream API.
    pub fn bytes(&self) -> &[u8] {
        let end = self.offset + self.len;
        &self.backing.bytes[self.offset..end]
    }

    /// Unique allocated backing size, not the visible slice length.
    pub fn charged_backing_bytes(&self) -> usize {
        self.backing.charged_bytes
    }
}

/// Exclusively owned per-output metadata and optional wire headroom.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderBuf {
    bytes: Vec<u8>,
}

impl HeaderBuf {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0; len],
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn resize(&mut self, len: usize, value: u8) {
        self.bytes.resize(len, value);
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Exclusive pre-freeze builder for one payload backing and one header.
#[derive(Debug)]
pub struct PacketBuilder {
    payload: BytesMut,
    header: HeaderBuf,
    metrics: PacketMetrics,
}

impl PacketBuilder {
    /// Allocate `payload_cap` zero-initialized payload bytes and header headroom.
    pub fn with_capacity(payload_cap: usize, headroom: usize) -> Self {
        Self::with_capacity_and_metrics(payload_cap, headroom, PacketMetrics::default())
    }

    pub fn with_capacity_and_metrics(
        payload_cap: usize,
        headroom: usize,
        metrics: PacketMetrics,
    ) -> Self {
        let mut payload = BytesMut::with_capacity(payload_cap);
        payload.resize(payload_cap, 0);
        Self {
            payload,
            header: HeaderBuf::zeroed(headroom),
            metrics,
        }
    }

    /// Take ownership of an exclusive payload buffer.
    pub fn from_bytes_mut(payload: BytesMut, headroom: usize) -> Self {
        Self::from_bytes_mut_and_metrics(payload, headroom, PacketMetrics::default())
    }

    pub fn from_bytes_mut_and_metrics(
        payload: BytesMut,
        headroom: usize,
        metrics: PacketMetrics,
    ) -> Self {
        Self {
            payload,
            header: HeaderBuf::zeroed(headroom),
            metrics,
        }
    }

    pub fn from_payload(payload: impl AsRef<[u8]>, headroom: usize) -> Self {
        Self::from_bytes_mut(BytesMut::from(payload.as_ref()), headroom)
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.payload
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn truncate_payload(&mut self, len: usize) {
        self.payload.truncate(len);
    }

    pub fn header(&self) -> &HeaderBuf {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut HeaderBuf {
        &mut self.header
    }

    pub fn metrics(&self) -> &PacketMetrics {
        &self.metrics
    }

    /// Make the payload immutable and shareable; the header remains exclusive.
    pub fn freeze(self) -> PacketHandle {
        let charged_bytes = self.payload.capacity();
        let bytes = self.payload.freeze();
        let metrics = self.metrics;
        let backing = Arc::new(Backing::new(bytes, charged_bytes, metrics.backings.clone()));
        PacketHandle {
            payload: PayloadRef {
                offset: 0,
                len: backing.bytes.len(),
                backing,
            },
            header: self.header,
            payload_copies: metrics.payload_copies,
        }
    }
}

/// An owned datagram handle: shared immutable payload plus exclusive header.
#[derive(Debug)]
pub struct PacketHandle {
    payload: PayloadRef,
    header: HeaderBuf,
    payload_copies: PayloadCopyCounter,
}

impl PacketHandle {
    /// Build a handle from bytes that are already immutable and validated.
    ///
    /// The wire profile uses this hook after successful receive validation so
    /// that the accepted payload can be sliced from the receive backing without
    /// copying it.
    pub(crate) fn from_shared_payload(
        payload: Bytes,
        charged_bytes: usize,
        header: HeaderBuf,
        metrics: PacketMetrics,
    ) -> Self {
        let backing = Arc::new(Backing::new(
            payload,
            charged_bytes,
            metrics.backings.clone(),
        ));
        Self {
            payload: PayloadRef {
                offset: 0,
                len: backing.bytes.len(),
                backing,
            },
            header,
            payload_copies: metrics.payload_copies,
        }
    }

    pub fn payload(&self) -> &PayloadRef {
        &self.payload
    }

    pub fn payload_bytes(&self) -> &[u8] {
        self.payload.bytes()
    }

    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    pub fn header(&self) -> &HeaderBuf {
        &self.header
    }

    pub fn header_mut(&mut self) -> &mut HeaderBuf {
        &mut self.header
    }

    /// Independent descriptor and header over the same immutable payload.
    pub fn fanout(&self) -> Self {
        Self {
            payload: self.payload.clone(),
            header: self.header.clone(),
            payload_copies: self.payload_copies.clone(),
        }
    }

    /// A new descriptor at `rel_off..rel_off+len` within the current range.
    pub fn slice(&self, rel_off: usize, len: usize) -> Result<Self, SliceError> {
        let end = rel_off.checked_add(len).ok_or(SliceError::OutOfBounds {
            offset: rel_off,
            len,
            parent_len: self.len(),
        })?;
        if end > self.len() {
            return Err(SliceError::OutOfBounds {
                offset: rel_off,
                len,
                parent_len: self.len(),
            });
        }

        Ok(Self {
            payload: PayloadRef {
                backing: self.payload.backing.clone(),
                offset: self.payload.offset + rel_off,
                len,
            },
            header: self.header.clone(),
            payload_copies: self.payload_copies.clone(),
        })
    }

    pub fn backing_id(&self) -> BackingId {
        self.payload.backing_id()
    }

    pub fn charged_backing_bytes(&self) -> usize {
        self.payload.charged_backing_bytes()
    }

    pub fn payload_copies(&self) -> &PayloadCopyCounter {
        &self.payload_copies
    }
}

/// Invalid slice range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliceError {
    OutOfBounds {
        offset: usize,
        len: usize,
        parent_len: usize,
    },
}

impl fmt::Display for SliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds {
                offset,
                len,
                parent_len,
            } => write!(
                f,
                "slice {offset}..{} exceeds payload length {parent_len}",
                offset.saturating_add(*len)
            ),
        }
    }
}

impl std::error::Error for SliceError {}
