//! Transport-neutral reliability core, systematic codec, and stop policies.
//!
//! The core owns block identity and symbol generation. It stages encoded
//! symbols until a caller-provided [`LinkSender`] accepts them, preserving
//! returned ownership under backpressure. Timing and stop policy live in a
//! [`ReliabilityPolicy`], not in the core or link.

use core::fmt;
use std::collections::{BTreeMap, HashMap};

use crate::accounting::{PacketMetrics, PayloadCopyCounter};
use crate::clock::{Drive, MonoNs};
use crate::link::{LinkReceiver, LinkSender};
use crate::packet::{PacketBuilder, PacketHandle};
use crate::queue::{PacketQueue, QueueLimits};

const LOCAL_MAGIC: [u8; 4] = *b"OCNR";
const LOCAL_VERSION: u8 = 1;
const DATA_HEADER_LEN: usize = 48;
const DATA_KIND: u8 = 1;
const FEEDBACK_MESSAGE_LEN: usize = 32;
const ACK_KIND: u8 = 2;
const NACK_KIND: u8 = 3;

/// One endpoint's view of an in-process bidirectional datagram transport.
///
/// `outgoing` is the local user toward the peer and `incoming` is the peer's
/// reverse user toward this endpoint. ACK/NACK are ordinary datagrams on
/// `outgoing`; they are not link-control messages.
pub trait LinkEndpoint {
    fn outgoing(&mut self) -> &mut dyn LinkSender;
    fn incoming(&mut self) -> &mut dyn LinkReceiver;
    fn drive(&mut self, now: MonoNs);

    /// The lower endpoint's currently armed controller hook wakeup, if any.
    fn next_wakeup(&self) -> Option<MonoNs> {
        None
    }

    /// Earliest time this endpoint may have useful drive work.
    ///
    /// Unlike [`LinkEndpoint::next_wakeup`], this aggregate hint may include
    /// pacer and protocol timers.
    fn next_drive(&self) -> Option<MonoNs> {
        self.next_wakeup()
    }
}

/// A `LinkEndpoint` composed from one directed sender and receiver.
pub struct InProcessLink<S, R> {
    outgoing: S,
    incoming: R,
}

impl<S, R> InProcessLink<S, R> {
    pub const fn new(outgoing: S, incoming: R) -> Self {
        Self { outgoing, incoming }
    }

    pub fn outgoing_mut(&mut self) -> &mut S {
        &mut self.outgoing
    }

    pub fn incoming_mut(&mut self) -> &mut R {
        &mut self.incoming
    }
}

impl<S, R> LinkEndpoint for InProcessLink<S, R>
where
    S: LinkSender + Drive,
    R: LinkReceiver,
{
    fn outgoing(&mut self) -> &mut dyn LinkSender {
        &mut self.outgoing
    }

    fn incoming(&mut self) -> &mut dyn LinkReceiver {
        &mut self.incoming
    }

    fn drive(&mut self, now: MonoNs) {
        let _ = Drive::drive(&mut self.outgoing, now);
    }

    fn next_drive(&self) -> Option<MonoNs> {
        self.outgoing.next_drive()
    }
}

/// Stable identity of one reliability block within a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(u64);

impl BlockId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Monotonic symbol identity within a block.
///
/// A systematic codec may repeat a source slice for distinct symbol ids. The
/// codec, not the core, decides that mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(u64);

impl SymbolId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Shape needed to decode one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockShape {
    pub source_symbols: u32,
    pub symbol_len: usize,
    pub block_len: usize,
}

impl BlockShape {
    pub fn new(
        source_symbols: u32,
        symbol_len: usize,
        block_len: usize,
    ) -> Result<Self, CodecError> {
        if source_symbols == 0 {
            return Err(CodecError::InvalidSourceSymbols);
        }
        if symbol_len == 0 {
            return Err(CodecError::InvalidSymbolLength);
        }
        Ok(Self {
            source_symbols,
            symbol_len,
            block_len,
        })
    }
}

/// Codec metadata carried with one symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolMeta {
    pub block_id: BlockId,
    pub symbol_id: SymbolId,
    pub shape: BlockShape,
}

/// Decoder progress for one symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeStatus {
    NeedMore,
    Duplicate,
    BlockRecovered,
}

/// Codec/configuration errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    UnknownBlock(BlockId),
    DuplicateBlock(BlockId),
    InvalidSourceSymbols,
    InvalidSymbolLength,
    WrongOutputLength { expected: usize, actual: usize },
    WrongSymbolLength { expected: usize, actual: usize },
    BlockShapeMismatch,
    BlockTooLarge,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBlock(id) => write!(f, "unknown reliability block {id}"),
            Self::DuplicateBlock(id) => write!(f, "block {id} is already registered"),
            Self::InvalidSourceSymbols => f.write_str("source symbol count must be non-zero"),
            Self::InvalidSymbolLength => f.write_str("symbol length must be non-zero"),
            Self::WrongOutputLength { expected, actual } => {
                write!(f, "encode output length {actual}, expected {expected}")
            }
            Self::WrongSymbolLength { expected, actual } => {
                write!(f, "received symbol length {actual}, expected {expected}")
            }
            Self::BlockShapeMismatch => f.write_str("received block shape does not match"),
            Self::BlockTooLarge => f.write_str("block metadata exceeds local encoding limits"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Block encode/decode port used by the reliability core.
///
/// Encoding writes a new output buffer and is therefore an explicit
/// transformation. Implementations account that write in their copy counter.
pub trait BlockCodec {
    fn block_shape(&self, block_id: BlockId) -> Option<BlockShape>;
    fn encode(
        &mut self,
        block_id: BlockId,
        symbol_id: SymbolId,
        out: &mut [u8],
    ) -> Result<usize, CodecError>;
    fn accumulate(&mut self, meta: SymbolMeta, symbol: &[u8]) -> Result<DecodeStatus, CodecError>;
    fn take_recovered_block(&mut self, block_id: BlockId) -> Option<Vec<u8>>;
}

#[derive(Debug)]
struct SourceBlock {
    shape: BlockShape,
    padded: Vec<u8>,
}

#[derive(Debug)]
struct DecodeBlock {
    shape: BlockShape,
    symbols: Vec<Option<Vec<u8>>>,
    unique_symbols: usize,
    recovered: bool,
}

/// Minimal systematic codec used by S7/S8.
///
/// Symbol `n` is source slice `n % source_symbols`. The final source symbol is
/// zero-padded to `symbol_len`; `block_len` trims that padding on recovery.
/// Every encode and every accepted decode write increments the explicit copy
/// counter.
#[derive(Debug)]
pub struct SystematicBlockCodec {
    symbol_len: usize,
    sources: HashMap<BlockId, SourceBlock>,
    decoders: HashMap<BlockId, DecodeBlock>,
    copies: PayloadCopyCounter,
}

impl SystematicBlockCodec {
    pub fn new(symbol_len: usize, copies: PayloadCopyCounter) -> Result<Self, CodecError> {
        if symbol_len == 0 {
            return Err(CodecError::InvalidSymbolLength);
        }
        Ok(Self {
            symbol_len,
            sources: HashMap::new(),
            decoders: HashMap::new(),
            copies,
        })
    }

    /// Register a source block by moving its bytes into the codec.
    pub fn add_block(
        &mut self,
        block_id: BlockId,
        data: Vec<u8>,
    ) -> Result<BlockShape, CodecError> {
        if self.sources.contains_key(&block_id) {
            return Err(CodecError::DuplicateBlock(block_id));
        }
        let block_len = data.len();
        let source_symbols = block_len.div_ceil(self.symbol_len);
        let source_symbols =
            u32::try_from(source_symbols).map_err(|_| CodecError::BlockTooLarge)?;
        if source_symbols == 0 {
            return Err(CodecError::InvalidSourceSymbols);
        }
        let padded_len = (source_symbols as usize)
            .checked_mul(self.symbol_len)
            .ok_or(CodecError::BlockTooLarge)?;
        let mut padded = data;
        padded.resize(padded_len, 0);
        let shape = BlockShape::new(source_symbols, self.symbol_len, block_len)?;
        self.sources.insert(block_id, SourceBlock { shape, padded });
        Ok(shape)
    }

    pub fn copies(&self) -> &PayloadCopyCounter {
        &self.copies
    }
}

impl BlockCodec for SystematicBlockCodec {
    fn block_shape(&self, block_id: BlockId) -> Option<BlockShape> {
        self.sources.get(&block_id).map(|block| block.shape)
    }

    fn encode(
        &mut self,
        block_id: BlockId,
        symbol_id: SymbolId,
        out: &mut [u8],
    ) -> Result<usize, CodecError> {
        let block = self
            .sources
            .get(&block_id)
            .ok_or(CodecError::UnknownBlock(block_id))?;
        if out.len() != block.shape.symbol_len {
            return Err(CodecError::WrongOutputLength {
                expected: block.shape.symbol_len,
                actual: out.len(),
            });
        }
        let index = (symbol_id.get() % block.shape.source_symbols as u64) as usize;
        let start = index * block.shape.symbol_len;
        out.copy_from_slice(&block.padded[start..start + block.shape.symbol_len]);
        self.copies.record_copy();
        Ok(block.shape.symbol_len)
    }

    fn accumulate(&mut self, meta: SymbolMeta, symbol: &[u8]) -> Result<DecodeStatus, CodecError> {
        if symbol.len() != meta.shape.symbol_len {
            return Err(CodecError::WrongSymbolLength {
                expected: meta.shape.symbol_len,
                actual: symbol.len(),
            });
        }

        let block = self
            .decoders
            .entry(meta.block_id)
            .or_insert_with(|| DecodeBlock {
                shape: meta.shape,
                symbols: vec![None; meta.shape.source_symbols as usize],
                unique_symbols: 0,
                recovered: false,
            });
        if block.shape != meta.shape {
            return Err(CodecError::BlockShapeMismatch);
        }
        if block.recovered {
            return Ok(DecodeStatus::Duplicate);
        }

        let index = (meta.symbol_id.get() % meta.shape.source_symbols as u64) as usize;
        if block.symbols[index].is_some() {
            return Ok(DecodeStatus::Duplicate);
        }

        let mut owned = vec![0; meta.shape.symbol_len];
        owned.copy_from_slice(symbol);
        self.copies.record_copy();
        block.symbols[index] = Some(owned);
        block.unique_symbols += 1;
        if block.unique_symbols == block.shape.source_symbols as usize {
            block.recovered = true;
            Ok(DecodeStatus::BlockRecovered)
        } else {
            Ok(DecodeStatus::NeedMore)
        }
    }

    fn take_recovered_block(&mut self, block_id: BlockId) -> Option<Vec<u8>> {
        let block = self.decoders.get(&block_id)?;
        if !block.recovered {
            return None;
        }

        let mut recovered =
            Vec::with_capacity(block.shape.source_symbols as usize * block.shape.symbol_len);
        for symbol in &block.symbols {
            recovered.extend_from_slice(symbol.as_deref().expect("recovered block is complete"));
        }
        recovered.truncate(block.shape.block_len);
        self.copies.record_copy();
        Some(recovered)
    }
}

/// State of one block as seen by a reliability policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    Sending,
    Acked,
    LingerWithoutAck,
    Delivered,
    StoppedByBudget,
    StoppedWithoutAck,
}

/// Policy-visible immutable block progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSnapshot {
    pub status: BlockStatus,
    pub started_at: MonoNs,
    pub phase_started_at: MonoNs,
    pub generated_symbols: u64,
    pub first_ack_at: Option<MonoNs>,
}

/// One policy polling decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyPoll {
    Emit,
    Wait,
    BeginLingerWithoutAck,
    Finish(PolicyCompletion),
}

/// Terminal block result selected by a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyCompletion {
    Delivered,
    StoppedByBudget,
    StoppedWithoutAck,
}

/// Reliability feedback carried by a reverse user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feedback {
    pub block_id: BlockId,
    pub kind: FeedbackKind,
    /// Advisory count; zero means unspecified.
    pub packets_received_count: u32,
    /// Advisory request; zero means unspecified.
    pub requested_additional: u32,
}

impl Feedback {
    pub const fn ack(block_id: BlockId) -> Self {
        Self {
            block_id,
            kind: FeedbackKind::Ack,
            packets_received_count: 0,
            requested_additional: 0,
        }
    }

    pub const fn nack(
        block_id: BlockId,
        packets_received_count: u32,
        requested_additional: u32,
    ) -> Self {
        Self {
            block_id,
            kind: FeedbackKind::Nack,
            packets_received_count,
            requested_additional,
        }
    }
}

/// ACK or NACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackKind {
    Ack,
    Nack,
}

/// Result of offering feedback to a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackDisposition {
    Ignore,
    Acked,
    NackAccepted,
}

/// Replaceable reliability behavior over one shared core.
pub trait ReliabilityPolicy {
    fn on_block_start(&mut self, block_id: BlockId, now: MonoNs);
    fn poll(&mut self, block_id: BlockId, snapshot: BlockSnapshot, now: MonoNs) -> PolicyPoll;
    fn on_feedback(
        &mut self,
        block_id: BlockId,
        feedback: Feedback,
        snapshot: BlockSnapshot,
        now: MonoNs,
    ) -> FeedbackDisposition;
    fn cancel_unsent_on_ack(&self) -> bool;

    /// Maximum number of blocks in `Sending` at once, or `None` for no
    /// reliability-level block window.
    fn block_window(&self) -> Option<usize> {
        None
    }
}

/// One-way policy: emit until a symbol counter or local timer budget is spent.
///
/// It never consumes ACK as a success signal. This object supplies no window,
/// UDP user number, or wire-header rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneWayBudget {
    symbol_budget: u64,
    time_budget: Option<MonoNs>,
}

impl OneWayBudget {
    pub const fn new(symbol_budget: u64) -> Self {
        Self {
            symbol_budget,
            time_budget: None,
        }
    }

    pub const fn with_time_budget(mut self, duration: MonoNs) -> Self {
        self.time_budget = Some(duration);
        self
    }

    pub const fn symbol_budget(&self) -> u64 {
        self.symbol_budget
    }
}

impl ReliabilityPolicy for OneWayBudget {
    fn on_block_start(&mut self, _block_id: BlockId, _now: MonoNs) {}

    fn poll(&mut self, _block_id: BlockId, snapshot: BlockSnapshot, now: MonoNs) -> PolicyPoll {
        if snapshot.status != BlockStatus::Sending {
            return PolicyPoll::Wait;
        }
        let time_expired = self.time_budget.is_some_and(|budget| {
            now.as_nanos()
                >= snapshot
                    .started_at
                    .as_nanos()
                    .saturating_add(budget.as_nanos())
        });
        if snapshot.generated_symbols >= self.symbol_budget || time_expired {
            PolicyPoll::Finish(PolicyCompletion::StoppedByBudget)
        } else {
            PolicyPoll::Emit
        }
    }

    fn on_feedback(
        &mut self,
        _block_id: BlockId,
        _feedback: Feedback,
        _snapshot: BlockSnapshot,
        _now: MonoNs,
    ) -> FeedbackDisposition {
        FeedbackDisposition::Ignore
    }

    fn cancel_unsent_on_ack(&self) -> bool {
        false
    }
}

/// Bidirectional policy with drain-on-ACK, finite-budget fallback, and linger.
///
/// The policy is independent of the wire profile and user numbering. NACK is
/// advisory: it never stops the block and never starts a nested reliability
/// session. The local symbol/time budget still controls termination. NACK hints
/// are accepted as advisory metadata but are not allowed to extend the local
/// budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BidirectionalAck {
    symbol_budget: u64,
    time_budget: Option<MonoNs>,
    linger: MonoNs,
    block_window: usize,
}

impl BidirectionalAck {
    pub const fn new(symbol_budget: u64, linger: MonoNs) -> Self {
        Self {
            symbol_budget,
            time_budget: None,
            linger,
            block_window: 1,
        }
    }

    pub const fn with_time_budget(mut self, duration: MonoNs) -> Self {
        self.time_budget = Some(duration);
        self
    }

    pub const fn with_block_window(mut self, block_window: usize) -> Self {
        self.block_window = if block_window == 0 { 1 } else { block_window };
        self
    }

    pub const fn linger(&self) -> MonoNs {
        self.linger
    }

    pub const fn symbol_budget(&self) -> u64 {
        self.symbol_budget
    }

    pub const fn configured_block_window(&self) -> usize {
        self.block_window
    }

    fn elapsed(&self, snapshot: BlockSnapshot, now: MonoNs, budget: MonoNs) -> bool {
        now.as_nanos()
            >= snapshot
                .phase_started_at
                .as_nanos()
                .saturating_add(budget.as_nanos())
    }
}

impl ReliabilityPolicy for BidirectionalAck {
    fn on_block_start(&mut self, _block_id: BlockId, _now: MonoNs) {}

    fn poll(&mut self, _block_id: BlockId, snapshot: BlockSnapshot, now: MonoNs) -> PolicyPoll {
        match snapshot.status {
            BlockStatus::Sending => {
                let time_expired = self.time_budget.is_some_and(|budget| {
                    now.as_nanos()
                        >= snapshot
                            .started_at
                            .as_nanos()
                            .saturating_add(budget.as_nanos())
                });
                if snapshot.generated_symbols >= self.symbol_budget || time_expired {
                    PolicyPoll::BeginLingerWithoutAck
                } else {
                    PolicyPoll::Emit
                }
            }
            BlockStatus::Acked => {
                if self.elapsed(snapshot, now, self.linger) {
                    PolicyPoll::Finish(PolicyCompletion::Delivered)
                } else {
                    PolicyPoll::Wait
                }
            }
            BlockStatus::LingerWithoutAck => {
                if self.elapsed(snapshot, now, self.linger) {
                    PolicyPoll::Finish(PolicyCompletion::StoppedWithoutAck)
                } else {
                    PolicyPoll::Wait
                }
            }
            BlockStatus::Delivered
            | BlockStatus::StoppedByBudget
            | BlockStatus::StoppedWithoutAck => PolicyPoll::Wait,
        }
    }

    fn on_feedback(
        &mut self,
        _block_id: BlockId,
        feedback: Feedback,
        snapshot: BlockSnapshot,
        _now: MonoNs,
    ) -> FeedbackDisposition {
        match feedback.kind {
            FeedbackKind::Ack => {
                if snapshot.first_ack_at.is_none()
                    && matches!(
                        snapshot.status,
                        BlockStatus::Sending | BlockStatus::LingerWithoutAck
                    )
                {
                    FeedbackDisposition::Acked
                } else {
                    FeedbackDisposition::Ignore
                }
            }
            FeedbackKind::Nack => {
                if snapshot.status == BlockStatus::Sending && snapshot.first_ack_at.is_none() {
                    FeedbackDisposition::NackAccepted
                } else {
                    FeedbackDisposition::Ignore
                }
            }
        }
    }

    fn cancel_unsent_on_ack(&self) -> bool {
        true
    }

    fn block_window(&self) -> Option<usize> {
        Some(self.block_window)
    }
}

#[derive(Debug)]
struct SenderBlock {
    shape: BlockShape,
    status: BlockStatus,
    started_at: MonoNs,
    phase_started_at: MonoNs,
    generated_symbols: u64,
    enqueued_symbols: u64,
    first_ack_at: Option<MonoNs>,
}

impl SenderBlock {
    fn snapshot(&self) -> BlockSnapshot {
        BlockSnapshot {
            status: self.status,
            started_at: self.started_at,
            phase_started_at: self.phase_started_at,
            generated_symbols: self.generated_symbols,
            first_ack_at: self.first_ack_at,
        }
    }
}

/// Symbol staging result for one policy poll.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StageReport {
    pub generated: usize,
    pub cancelled: usize,
}

/// Symbol movement result for one link-admission pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub enqueued: usize,
    pub backpressured: bool,
}

/// Reverse-user feedback processed by the sender core.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedbackReport {
    pub received: usize,
    pub acked: usize,
    pub nacked: usize,
    pub duplicate_acks: usize,
    pub ignored: usize,
    pub cancelled: usize,
    pub last_feedback: Option<Feedback>,
}

/// Combined core pump result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SenderPump {
    pub generated: usize,
    pub enqueued: usize,
    pub cancelled: usize,
    pub acked: usize,
    pub nacked: usize,
    pub duplicate_acks: usize,
    pub backpressured: bool,
}

/// Reliability sender core parameterized by codec and policy.
///
/// The same type and methods implement one-way and ACK-driven behavior; only
/// the injected policy and feedback path differ.
pub struct ReliabilitySender<C: BlockCodec, P: ReliabilityPolicy> {
    codec: C,
    policy: P,
    blocks: BTreeMap<BlockId, SenderBlock>,
    unsent: PacketQueue,
    staging_limit: usize,
    metrics: PacketMetrics,
    cancelled: Vec<PacketHandle>,
}

impl<C: BlockCodec, P: ReliabilityPolicy> ReliabilitySender<C, P> {
    pub fn new(codec: C, policy: P, staging_limits: QueueLimits, metrics: PacketMetrics) -> Self {
        let staging_limit = staging_limits.max_packets;
        Self {
            codec,
            policy,
            blocks: BTreeMap::new(),
            unsent: PacketQueue::new(staging_limits),
            staging_limit,
            metrics,
            cancelled: Vec::new(),
        }
    }

    pub fn register_block(&mut self, block_id: BlockId, now: MonoNs) -> Result<(), RelCodecError> {
        if self.blocks.contains_key(&block_id) {
            return Err(RelCodecError::Codec(CodecError::DuplicateBlock(block_id)));
        }
        let shape = self
            .codec
            .block_shape(block_id)
            .ok_or(RelCodecError::Codec(CodecError::UnknownBlock(block_id)))?;
        self.policy.on_block_start(block_id, now);
        self.blocks.insert(
            block_id,
            SenderBlock {
                shape,
                status: BlockStatus::Sending,
                started_at: now,
                phase_started_at: now,
                generated_symbols: 0,
                enqueued_symbols: 0,
                first_ack_at: None,
            },
        );
        Ok(())
    }

    pub fn status(&self, block_id: BlockId) -> Option<BlockStatus> {
        self.blocks.get(&block_id).map(|block| block.status)
    }

    pub fn generated_symbols(&self, block_id: BlockId) -> Option<u64> {
        self.blocks
            .get(&block_id)
            .map(|block| block.generated_symbols)
    }

    pub fn enqueued_symbols(&self, block_id: BlockId) -> Option<u64> {
        self.blocks
            .get(&block_id)
            .map(|block| block.enqueued_symbols)
    }

    pub fn staged_packets(&self) -> usize {
        self.unsent.len()
    }

    /// Remove and return handles cancelled as unsent repair.
    pub fn take_cancelled(&mut self) -> Vec<PacketHandle> {
        core::mem::take(&mut self.cancelled)
    }

    /// Poll policy and stage up to `max_symbols` new encoded symbols.
    pub fn stage(&mut self, now: MonoNs, max_symbols: usize) -> StageReport {
        let mut report = StageReport::default();
        let cancelled_before = self.cancelled.len();
        if max_symbols == 0 {
            return report;
        }

        let block_ids: Vec<_> = self.blocks.keys().copied().collect();
        let block_window = self.policy.block_window();
        'rounds: for _ in 0..max_symbols {
            let mut made_progress = false;
            let mut sending_blocks = 0;
            for block_id in &block_ids {
                let block_status = self
                    .blocks
                    .get(block_id)
                    .expect("block id came from the block map")
                    .status;
                if block_status == BlockStatus::Sending {
                    if block_window.is_some_and(|window| sending_blocks >= window) {
                        continue;
                    }
                    sending_blocks += 1;
                }
                let decision = {
                    let block = self
                        .blocks
                        .get(block_id)
                        .expect("block id came from the block map");
                    self.policy.poll(*block_id, block.snapshot(), now)
                };
                match decision {
                    PolicyPoll::Emit => {
                        if self.unsent.len() >= self.staging_limit {
                            break 'rounds;
                        }
                        if self.encode_and_stage(*block_id).is_err() {
                            break 'rounds;
                        }
                        made_progress = true;
                        report.generated += 1;
                        if report.generated >= max_symbols {
                            break 'rounds;
                        }
                    }
                    PolicyPoll::Wait => {}
                    PolicyPoll::BeginLingerWithoutAck => {
                        let block = self
                            .blocks
                            .get_mut(block_id)
                            .expect("block id came from the block map");
                        block.status = BlockStatus::LingerWithoutAck;
                        block.phase_started_at = now;
                        self.cancel_unsent(*block_id);
                    }
                    PolicyPoll::Finish(completion) => {
                        let status = match completion {
                            PolicyCompletion::Delivered => BlockStatus::Delivered,
                            PolicyCompletion::StoppedByBudget => BlockStatus::StoppedByBudget,
                            PolicyCompletion::StoppedWithoutAck => BlockStatus::StoppedWithoutAck,
                        };
                        let block = self
                            .blocks
                            .get_mut(block_id)
                            .expect("block id came from the block map");
                        block.status = status;
                        block.phase_started_at = now;
                        self.cancel_unsent(*block_id);
                    }
                }
            }
            if !made_progress {
                break;
            }
        }
        report.cancelled = self.cancelled.len().saturating_sub(cancelled_before);
        report
    }

    /// Move up to `max_packets` staged handles into the supplied link.
    ///
    /// A rejected handle is returned to the core's staging queue immediately.
    pub fn flush(&mut self, link: &mut dyn LinkSender, max_packets: usize) -> FlushReport {
        let mut report = FlushReport::default();
        for _ in 0..max_packets {
            let Some(pkt) = self.unsent.dequeue() else {
                break;
            };
            let block_id =
                parse_reliability_data_header(pkt.header().as_bytes()).map(|meta| meta.block_id);
            match link.enqueue(pkt) {
                Ok(_) => {
                    report.enqueued += 1;
                    if let Some(block_id) = block_id
                        && let Some(block) = self.blocks.get_mut(&block_id)
                    {
                        block.enqueued_symbols += 1;
                    }
                }
                Err(error) => {
                    report.backpressured = true;
                    let pkt = error.into_packet();
                    self.unsent
                        .enqueue(pkt)
                        .expect("a dequeued staging slot is available");
                    break;
                }
            }
        }
        report
    }

    pub fn pump(
        &mut self,
        link: &mut dyn LinkSender,
        now: MonoNs,
        max_new_symbols: usize,
        max_link_packets: usize,
    ) -> SenderPump {
        let stage = self.stage(now, max_new_symbols);
        let flush = self.flush(link, max_link_packets);
        SenderPump {
            generated: stage.generated,
            enqueued: flush.enqueued,
            cancelled: stage.cancelled,
            acked: 0,
            nacked: 0,
            duplicate_acks: 0,
            backpressured: flush.backpressured,
        }
    }

    /// Process reverse-user ACK/NACK datagrams without generating feedback.
    ///
    /// Receiving feedback can only affect this sender's local state. It never
    /// creates an ACK-of-ACK or another reverse reliability session.
    pub fn receive_feedback(
        &mut self,
        receiver: &mut dyn LinkReceiver,
        now: MonoNs,
        max_feedback: usize,
    ) -> FeedbackReport {
        let mut report = FeedbackReport::default();
        let cancelled_before = self.cancelled.len();
        for _ in 0..max_feedback {
            let Some(pkt) = receiver.recv() else {
                break;
            };
            report.received += 1;
            let Some(feedback) = parse_feedback_message(pkt.payload_bytes()) else {
                report.ignored += 1;
                continue;
            };
            let Some(block) = self.blocks.get(&feedback.block_id) else {
                report.ignored += 1;
                continue;
            };
            if feedback.kind == FeedbackKind::Ack && block.first_ack_at.is_some() {
                report.duplicate_acks += 1;
                report.last_feedback = Some(feedback);
                continue;
            }

            let snapshot = block.snapshot();
            match self
                .policy
                .on_feedback(feedback.block_id, feedback, snapshot, now)
            {
                FeedbackDisposition::Acked => {
                    let cancel_unsent = self.policy.cancel_unsent_on_ack();
                    let block = self
                        .blocks
                        .get_mut(&feedback.block_id)
                        .expect("feedback block lookup succeeded");
                    block.status = BlockStatus::Acked;
                    block.phase_started_at = now;
                    block.first_ack_at = Some(now);
                    if cancel_unsent {
                        self.cancel_unsent(feedback.block_id);
                    }
                    report.acked += 1;
                }
                FeedbackDisposition::NackAccepted => report.nacked += 1,
                FeedbackDisposition::Ignore => report.ignored += 1,
            }
            report.last_feedback = Some(feedback);
            report.cancelled = self.cancelled.len().saturating_sub(cancelled_before);
        }
        report
    }

    /// Process feedback, then poll policy and move at most one new symbol.
    pub fn pump_bidirectional(
        &mut self,
        link: &mut dyn LinkEndpoint,
        now: MonoNs,
        max_new_symbols: usize,
        max_link_packets: usize,
    ) -> SenderPump {
        let feedback = self.receive_feedback(link.incoming(), now, max_new_symbols.max(16));
        let stage = self.stage(now, max_new_symbols);
        let flush = self.flush(link.outgoing(), max_link_packets);
        SenderPump {
            generated: stage.generated,
            enqueued: flush.enqueued,
            cancelled: feedback.cancelled.saturating_add(stage.cancelled),
            acked: feedback.acked,
            nacked: feedback.nacked,
            duplicate_acks: feedback.duplicate_acks,
            backpressured: flush.backpressured,
        }
    }

    fn encode_and_stage(&mut self, block_id: BlockId) -> Result<(), RelCodecError> {
        let (symbol_id, shape) = {
            let block = self
                .blocks
                .get(&block_id)
                .expect("block id came from the block map");
            (SymbolId::new(block.generated_symbols), block.shape)
        };
        let mut builder = PacketBuilder::with_capacity_and_metrics(
            shape.symbol_len,
            DATA_HEADER_LEN,
            self.metrics.clone(),
        );
        let written = self
            .codec
            .encode(block_id, symbol_id, builder.payload_mut())?;
        if written != shape.symbol_len {
            return Err(RelCodecError::Codec(CodecError::WrongOutputLength {
                expected: shape.symbol_len,
                actual: written,
            }));
        }
        *builder.header_mut() = crate::packet::HeaderBuf::from_bytes(data_header(SymbolMeta {
            block_id,
            symbol_id,
            shape,
        }));
        let pkt = builder.freeze();
        self.unsent
            .enqueue(pkt)
            .map_err(|_| RelCodecError::StagingFull)?;
        let block = self
            .blocks
            .get_mut(&block_id)
            .expect("block id came from the block map");
        block.generated_symbols += 1;
        Ok(())
    }

    fn cancel_unsent(&mut self, block_id: BlockId) {
        let cancelled = self.unsent.cancel(|pkt| {
            parse_reliability_data_header(pkt.header().as_bytes())
                .is_some_and(|meta| meta.block_id == block_id)
        });
        self.cancelled
            .extend(cancelled.into_iter().map(|result| match result {
                crate::queue::CancelResult::Cancelled { pkt } => pkt,
            }));
    }
}

/// Receive-side reliability core for one or more blocks.
pub struct ReliabilityReceiver<C: BlockCodec> {
    codec: C,
    recovered: Vec<BlockId>,
    invalid_packets: u64,
}

impl<C: BlockCodec> ReliabilityReceiver<C> {
    pub fn new(codec: C) -> Self {
        Self {
            codec,
            recovered: Vec::new(),
            invalid_packets: 0,
        }
    }

    /// Receive available datagrams and feed valid data symbols to the codec.
    ///
    /// Packets without this local reliability envelope are ignored, so a
    /// reverse-user ACK can never be mistaken for forward data.
    pub fn drain(&mut self, receiver: &mut dyn LinkReceiver) -> ReceiveReport {
        let mut report = ReceiveReport::default();
        while let Some(pkt) = receiver.recv() {
            report.received += 1;
            let Some(meta) = parse_reliability_data_header(pkt.header().as_bytes()) else {
                report.ignored += 1;
                continue;
            };
            if pkt.payload_bytes().len() != meta.shape.symbol_len {
                self.invalid_packets += 1;
                report.invalid += 1;
                continue;
            }
            match self.codec.accumulate(meta, pkt.payload_bytes()) {
                Ok(DecodeStatus::NeedMore) => {}
                Ok(DecodeStatus::Duplicate) => report.duplicates += 1,
                Ok(DecodeStatus::BlockRecovered) => {
                    report.recovered += 1;
                    self.recovered.push(meta.block_id);
                }
                Err(_) => {
                    self.invalid_packets += 1;
                    report.invalid += 1;
                }
            }
        }
        report
    }

    pub fn is_recovered(&self, block_id: BlockId) -> bool {
        self.recovered.contains(&block_id)
    }

    pub fn take_recovered_block(&mut self, block_id: BlockId) -> Option<Vec<u8>> {
        self.codec.take_recovered_block(block_id)
    }

    pub fn invalid_packets(&self) -> u64 {
        self.invalid_packets
    }
}

/// Receive-side drain report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiveReport {
    pub received: usize,
    pub ignored: usize,
    pub invalid: usize,
    pub duplicates: usize,
    pub recovered: usize,
}

/// Responder timing and advisory-hint configuration.
///
/// `ack_repeats` counts additional finite duplicates after the immediate ACK.
/// `None` for `nack_interval` disables advisory NACK generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedbackResponderConfig {
    pub ack_repeats: u32,
    pub ack_interval: MonoNs,
    pub nack_interval: Option<MonoNs>,
    pub requested_additional: u32,
}

impl Default for FeedbackResponderConfig {
    fn default() -> Self {
        Self {
            ack_repeats: 3,
            ack_interval: MonoNs::new(50_000_000),
            nack_interval: Some(MonoNs::new(100_000_000)),
            requested_additional: 0,
        }
    }
}

/// Sender core plus reverse-user ACK/NACK responder behavior.
///
/// This is the receive-side reliability core. It emits feedback only when the
/// local decoder recovers a block or remains incomplete. An incoming feedback
/// datagram is ignored and can never trigger ACK-of-ACK.
pub struct ReliabilityResponder<C: BlockCodec> {
    codec: C,
    config: FeedbackResponderConfig,
    pending: PacketQueue,
    pending_limit: usize,
    blocks: BTreeMap<BlockId, ResponderBlock>,
    invalid_packets: u64,
}

#[derive(Debug, Default)]
struct ResponderBlock {
    received_packets: u32,
    recovered: bool,
    next_nack_at: Option<MonoNs>,
    ack_schedule: Option<AckSchedule>,
}

#[derive(Clone, Copy, Debug)]
struct AckSchedule {
    repeats_left: u32,
    next_at: MonoNs,
}

/// One responder pump report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResponderPump {
    pub received: usize,
    pub ignored: usize,
    pub invalid: usize,
    pub duplicates: usize,
    pub recovered: usize,
    pub acks_generated: usize,
    pub nacks_generated: usize,
    pub feedback_admitted: usize,
    pub backpressured: bool,
}

impl<C: BlockCodec> ReliabilityResponder<C> {
    pub fn new(codec: C, config: FeedbackResponderConfig, pending_limits: QueueLimits) -> Self {
        let pending_limit = pending_limits.max_packets;
        Self {
            codec,
            config,
            pending: PacketQueue::new(pending_limits),
            pending_limit,
            blocks: BTreeMap::new(),
            invalid_packets: 0,
        }
    }

    /// Receive forward data, schedule feedback, and admit feedback to the
    /// reverse user of `link`.
    pub fn pump(
        &mut self,
        link: &mut dyn LinkEndpoint,
        now: MonoNs,
        max_in: usize,
        max_out: usize,
    ) -> ResponderPump {
        let mut report = ResponderPump::default();
        self.drain_forward(link.incoming(), now, max_in, &mut report);
        self.enqueue_due_ack_repeats(now, &mut report);
        self.flush_feedback(link.outgoing(), max_out, &mut report);
        report
    }

    /// Receive forward data from a unidirectional receiver without sending.
    pub fn drain(&mut self, receiver: &mut dyn LinkReceiver, now: MonoNs) -> ResponderPump {
        let mut report = ResponderPump::default();
        while receiver.occupancy().count > 0 {
            self.drain_forward(receiver, now, 1, &mut report);
        }
        report
    }

    /// Move pending feedback to a reverse sender.
    pub fn flush_feedback(
        &mut self,
        sender: &mut dyn LinkSender,
        max_packets: usize,
        report: &mut ResponderPump,
    ) {
        for _ in 0..max_packets {
            let Some(pkt) = self.pending.dequeue() else {
                break;
            };
            match sender.enqueue(pkt) {
                Ok(_) => report.feedback_admitted += 1,
                Err(error) => {
                    report.backpressured = true;
                    self.pending
                        .enqueue(error.into_packet())
                        .expect("dequeued feedback slot is available again");
                    break;
                }
            }
        }
    }

    pub fn is_recovered(&self, block_id: BlockId) -> bool {
        self.blocks
            .get(&block_id)
            .is_some_and(|block| block.recovered)
    }

    pub fn received_packets(&self, block_id: BlockId) -> u32 {
        self.blocks
            .get(&block_id)
            .map_or(0, |block| block.received_packets)
    }

    pub fn pending_feedback(&self) -> usize {
        self.pending.len()
    }

    pub fn invalid_packets(&self) -> u64 {
        self.invalid_packets
    }

    pub fn take_recovered_block(&mut self, block_id: BlockId) -> Option<Vec<u8>> {
        self.codec.take_recovered_block(block_id)
    }

    fn drain_forward(
        &mut self,
        receiver: &mut dyn LinkReceiver,
        now: MonoNs,
        max_in: usize,
        report: &mut ResponderPump,
    ) {
        for _ in 0..max_in {
            let Some(pkt) = receiver.recv() else {
                break;
            };
            report.received += 1;
            let Some(meta) = parse_reliability_data_header(pkt.header().as_bytes()) else {
                report.ignored += 1;
                continue;
            };
            if self
                .blocks
                .get(&meta.block_id)
                .is_some_and(|block| block.recovered)
            {
                report.duplicates += 1;
                continue;
            }
            if pkt.payload_bytes().len() != meta.shape.symbol_len {
                self.invalid_packets += 1;
                report.invalid += 1;
                continue;
            }

            let status = match self.codec.accumulate(meta, pkt.payload_bytes()) {
                Ok(status) => status,
                Err(_) => {
                    self.invalid_packets += 1;
                    report.invalid += 1;
                    continue;
                }
            };
            let block = self.blocks.entry(meta.block_id).or_default();
            match status {
                DecodeStatus::NeedMore => {
                    block.received_packets = block.received_packets.saturating_add(1);
                }
                DecodeStatus::Duplicate => {
                    block.received_packets = block.received_packets.saturating_add(1);
                    report.duplicates += 1;
                }
                DecodeStatus::BlockRecovered => {
                    block.received_packets = block.received_packets.saturating_add(1);
                    block.recovered = true;
                    block.next_nack_at = None;
                    block.ack_schedule = Some(AckSchedule {
                        repeats_left: self.config.ack_repeats,
                        next_at: now.saturating_add(self.config.ack_interval),
                    });
                    if self.enqueue_feedback(Feedback::ack(meta.block_id)) {
                        report.acks_generated += 1;
                    }
                    report.recovered += 1;
                }
            }

            if status == DecodeStatus::NeedMore {
                self.maybe_enqueue_nack(meta.block_id, now, report);
            }
        }
    }

    fn maybe_enqueue_nack(&mut self, block_id: BlockId, now: MonoNs, report: &mut ResponderPump) {
        let Some(interval) = self.config.nack_interval else {
            return;
        };
        let Some(block) = self.blocks.get_mut(&block_id) else {
            return;
        };
        if block.recovered || block.next_nack_at.is_some_and(|next_at| now < next_at) {
            return;
        }
        block.next_nack_at = Some(now.saturating_add(interval));
        let received = block.received_packets;
        if self.enqueue_feedback(Feedback::nack(
            block_id,
            received,
            self.config.requested_additional,
        )) {
            report.nacks_generated += 1;
        }
    }

    fn enqueue_due_ack_repeats(&mut self, now: MonoNs, report: &mut ResponderPump) {
        let mut due = Vec::new();
        for (block_id, block) in &mut self.blocks {
            let Some(schedule) = block.ack_schedule.as_mut() else {
                continue;
            };
            if schedule.repeats_left > 0 && now >= schedule.next_at {
                schedule.repeats_left -= 1;
                schedule.next_at = schedule.next_at.saturating_add(self.config.ack_interval);
                due.push(*block_id);
            }
        }
        for block_id in due {
            if self.enqueue_feedback(Feedback::ack(block_id)) {
                report.acks_generated += 1;
            }
        }
    }

    fn enqueue_feedback(&mut self, feedback: Feedback) -> bool {
        if self.pending.len() >= self.pending_limit {
            return false;
        }
        let mut builder = PacketBuilder::with_capacity(FEEDBACK_MESSAGE_LEN, 0);
        builder
            .payload_mut()
            .copy_from_slice(&feedback_message(feedback));
        self.pending.enqueue(builder.freeze()).is_ok()
    }
}

/// Errors while building a reliability sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelCodecError {
    Codec(CodecError),
    StagingFull,
}

impl From<CodecError> for RelCodecError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl fmt::Display for RelCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::StagingFull => f.write_str("reliability symbol staging queue is full"),
        }
    }
}

impl std::error::Error for RelCodecError {}

fn data_header(meta: SymbolMeta) -> Vec<u8> {
    let mut header = vec![0; DATA_HEADER_LEN];
    header[0..4].copy_from_slice(&LOCAL_MAGIC);
    header[4] = DATA_KIND;
    header[5] = LOCAL_VERSION;
    header[8..16].copy_from_slice(&meta.block_id.get().to_be_bytes());
    header[16..24].copy_from_slice(&meta.symbol_id.get().to_be_bytes());
    header[24..28].copy_from_slice(&meta.shape.source_symbols.to_be_bytes());
    header[28..32].copy_from_slice(&(meta.shape.symbol_len as u32).to_be_bytes());
    header[32..40].copy_from_slice(&(meta.shape.block_len as u64).to_be_bytes());
    header
}

/// Parse the local reliability DATA header used by [`ReliabilitySender`].
///
/// Profile adapters use this only to translate a staged symbol into their
/// user-content encoding; the header itself is not carried by UDP-LI.
pub fn parse_reliability_data_header(header: &[u8]) -> Option<SymbolMeta> {
    if header.len() != DATA_HEADER_LEN
        || header[0..4] != LOCAL_MAGIC
        || header[4] != DATA_KIND
        || header[5] != LOCAL_VERSION
        || header[6..8] != [0, 0]
        || header[40..48] != [0; 8]
    {
        return None;
    }
    let block_id = u64::from_be_bytes(header[8..16].try_into().ok()?);
    let symbol_id = u64::from_be_bytes(header[16..24].try_into().ok()?);
    let source_symbols = u32::from_be_bytes(header[24..28].try_into().ok()?);
    let symbol_len = u32::from_be_bytes(header[28..32].try_into().ok()?) as usize;
    let block_len = u64::from_be_bytes(header[32..40].try_into().ok()?);
    let block_len = usize::try_from(block_len).ok()?;
    let shape = BlockShape::new(source_symbols, symbol_len, block_len).ok()?;
    Some(SymbolMeta {
        block_id: BlockId::new(block_id),
        symbol_id: SymbolId::new(symbol_id),
        shape,
    })
}

fn feedback_message(feedback: Feedback) -> Vec<u8> {
    let mut message = vec![0; FEEDBACK_MESSAGE_LEN];
    message[0..4].copy_from_slice(&LOCAL_MAGIC);
    message[4] = match feedback.kind {
        FeedbackKind::Ack => ACK_KIND,
        FeedbackKind::Nack => NACK_KIND,
    };
    message[5] = LOCAL_VERSION;
    message[8..16].copy_from_slice(&feedback.block_id.get().to_be_bytes());
    message[16..20].copy_from_slice(&feedback.packets_received_count.to_be_bytes());
    message[20..24].copy_from_slice(&feedback.requested_additional.to_be_bytes());
    message
}

/// Build a local reverse-user feedback handle for core policy processing.
///
/// A profile adapter decodes its own feedback content and uses this helper to
/// feed the resulting [`Feedback`] through [`ReliabilitySender::receive_feedback`].
pub fn reliability_feedback_packet(feedback: Feedback) -> PacketHandle {
    let mut builder = PacketBuilder::with_capacity(FEEDBACK_MESSAGE_LEN, 0);
    builder
        .payload_mut()
        .copy_from_slice(&feedback_message(feedback));
    builder.freeze()
}

fn parse_feedback_message(message: &[u8]) -> Option<Feedback> {
    if message.len() != FEEDBACK_MESSAGE_LEN
        || message[0..4] != LOCAL_MAGIC
        || message[5] != LOCAL_VERSION
        || message[6..8] != [0, 0]
        || message[24..32] != [0; 8]
    {
        return None;
    }
    let kind = match message[4] {
        ACK_KIND => FeedbackKind::Ack,
        NACK_KIND => FeedbackKind::Nack,
        _ => return None,
    };
    Some(Feedback {
        block_id: BlockId::new(u64::from_be_bytes(message[8..16].try_into().ok()?)),
        kind,
        packets_received_count: u32::from_be_bytes(message[16..20].try_into().ok()?),
        requested_additional: u32::from_be_bytes(message[20..24].try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(copies: &PayloadCopyCounter) -> PacketMetrics {
        PacketMetrics {
            backings: crate::accounting::BackingAccounting::new(),
            payload_copies: copies.clone(),
        }
    }

    #[test]
    fn systematic_codec_counts_encode_and_recovers_out_of_order() {
        let copies = PayloadCopyCounter::new();
        let block = BlockId::new(7);
        let data = b"reliability".to_vec();
        let mut encoder = SystematicBlockCodec::new(4, copies.clone()).unwrap();
        let shape = encoder.add_block(block, data.clone()).unwrap();
        let mut symbol = vec![0; shape.symbol_len];
        let mut symbols = Vec::new();
        for id in 0..shape.source_symbols as u64 {
            encoder
                .encode(block, SymbolId::new(id), &mut symbol)
                .unwrap();
            symbols.push(symbol.clone());
        }
        assert_eq!(copies.count(), shape.source_symbols as u64);

        let mut decoder = SystematicBlockCodec::new(4, PayloadCopyCounter::new()).unwrap();
        for (id, bytes) in [(2, &symbols[2]), (0, &symbols[0]), (1, &symbols[1])] {
            let status = decoder
                .accumulate(
                    SymbolMeta {
                        block_id: block,
                        symbol_id: SymbolId::new(id),
                        shape,
                    },
                    bytes,
                )
                .unwrap();
            let expected = if id == 1 {
                DecodeStatus::BlockRecovered
            } else {
                DecodeStatus::NeedMore
            };
            assert_eq!(status, expected);
        }
        assert_eq!(decoder.take_recovered_block(block).unwrap(), data);
    }

    #[test]
    fn one_way_counter_and_timer_stop_without_feedback() {
        let copies = PayloadCopyCounter::new();
        let mut codec = SystematicBlockCodec::new(4, copies.clone()).unwrap();
        let block = BlockId::new(1);
        codec.add_block(block, b"abcdefgh".to_vec()).unwrap();
        let mut sender = ReliabilitySender::new(
            codec,
            OneWayBudget::new(2),
            QueueLimits::new(4, 4096, 4096),
            metrics(&copies),
        );
        sender.register_block(block, MonoNs::ZERO).unwrap();
        assert_eq!(sender.stage(MonoNs::ZERO, 1).generated, 1);
        assert_eq!(sender.stage(MonoNs::ZERO, 1).generated, 1);
        assert_eq!(
            sender.status(block),
            Some(BlockStatus::Sending),
            "the counter is checked before the next symbol"
        );
        assert_eq!(sender.stage(MonoNs::ZERO, 1).generated, 0);
        assert_eq!(sender.status(block), Some(BlockStatus::StoppedByBudget));

        let copies = PayloadCopyCounter::new();
        let mut codec = SystematicBlockCodec::new(4, copies.clone()).unwrap();
        let block = BlockId::new(2);
        codec.add_block(block, b"abcdefgh".to_vec()).unwrap();
        let mut timed = ReliabilitySender::new(
            codec,
            OneWayBudget::new(100).with_time_budget(MonoNs::new(10)),
            QueueLimits::new(4, 4096, 4096),
            metrics(&copies),
        );
        timed.register_block(block, MonoNs::ZERO).unwrap();
        assert_eq!(timed.stage(MonoNs::new(9), 1).generated, 1);
        assert_eq!(timed.stage(MonoNs::new(10), 1).generated, 0);
        assert_eq!(timed.status(block), Some(BlockStatus::StoppedByBudget));
    }

    #[test]
    fn one_way_policy_ignores_reverse_feedback() {
        let mut policy = OneWayBudget::new(10);
        let snapshot = BlockSnapshot {
            status: BlockStatus::Sending,
            started_at: MonoNs::ZERO,
            phase_started_at: MonoNs::ZERO,
            generated_symbols: 2,
            first_ack_at: None,
        };
        assert_eq!(
            policy.on_feedback(
                BlockId::new(1),
                Feedback::ack(BlockId::new(1)),
                snapshot,
                MonoNs::ZERO
            ),
            FeedbackDisposition::Ignore
        );
        assert!(!policy.cancel_unsent_on_ack());
    }

    #[test]
    fn bidirectional_ack_is_idempotent_and_nack_after_ack_is_ignored() {
        let block = BlockId::new(9);
        let mut policy = BidirectionalAck::new(8, MonoNs::new(2_000_000_000));
        let sending = BlockSnapshot {
            status: BlockStatus::Sending,
            started_at: MonoNs::ZERO,
            phase_started_at: MonoNs::ZERO,
            generated_symbols: 2,
            first_ack_at: None,
        };
        assert_eq!(
            policy.on_feedback(block, Feedback::nack(block, 2, 3), sending, MonoNs::ZERO),
            FeedbackDisposition::NackAccepted
        );
        assert_eq!(
            policy.on_feedback(block, Feedback::ack(block), sending, MonoNs::ZERO),
            FeedbackDisposition::Acked
        );

        let acked = BlockSnapshot {
            status: BlockStatus::Acked,
            phase_started_at: MonoNs::ZERO,
            first_ack_at: Some(MonoNs::ZERO),
            ..sending
        };
        assert_eq!(
            policy.on_feedback(block, Feedback::ack(block), acked, MonoNs::new(1_000_000)),
            FeedbackDisposition::Ignore
        );
        assert_eq!(
            policy.on_feedback(
                block,
                Feedback::nack(block, 4, 1),
                acked,
                MonoNs::new(1_000_000)
            ),
            FeedbackDisposition::Ignore
        );
        assert!(policy.cancel_unsent_on_ack());
        assert_eq!(policy.block_window(), Some(1));
        assert_eq!(policy.linger(), MonoNs::new(2_000_000_000));
    }

    #[test]
    fn bidirectional_ack_lingers_then_completes_or_stops_without_ack() {
        let block = BlockId::new(10);
        let mut policy = BidirectionalAck::new(4, MonoNs::new(2_000_000_000));
        let acked = BlockSnapshot {
            status: BlockStatus::Acked,
            started_at: MonoNs::ZERO,
            phase_started_at: MonoNs::ZERO,
            generated_symbols: 3,
            first_ack_at: Some(MonoNs::ZERO),
        };
        assert_eq!(
            policy.poll(block, acked, MonoNs::new(1_999_999_999)),
            PolicyPoll::Wait
        );
        assert_eq!(
            policy.poll(block, acked, MonoNs::new(2_000_000_000)),
            PolicyPoll::Finish(PolicyCompletion::Delivered)
        );

        let unacked = BlockSnapshot {
            status: BlockStatus::LingerWithoutAck,
            phase_started_at: MonoNs::ZERO,
            first_ack_at: None,
            ..acked
        };
        assert_eq!(
            policy.poll(block, unacked, MonoNs::new(2_000_000_000)),
            PolicyPoll::Finish(PolicyCompletion::StoppedWithoutAck)
        );
    }

    #[test]
    fn local_feedback_message_round_trips_ack_and_nack_hints() {
        let ack = Feedback::ack(BlockId::new(3));
        let nack = Feedback::nack(BlockId::new(4), 7, 2);
        assert_eq!(parse_feedback_message(&feedback_message(ack)), Some(ack));
        assert_eq!(parse_feedback_message(&feedback_message(nack)), Some(nack));
        assert_eq!(
            parse_feedback_message(&data_header(SymbolMeta {
                block_id: BlockId::new(1),
                symbol_id: SymbolId::new(0),
                shape: BlockShape::new(1, 1, 1).unwrap(),
            })),
            None
        );
    }
}
