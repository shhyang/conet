//! First usable Conet reference file-transfer application.
//!
//! The default policy is one-way/open-loop. A closed-loop ACK/NACK policy is
//! opt-in. The application uses one reliability block and one attachment per
//! endpoint; network adaptation, multiplexing, cross-layer QoS intent, and
//! external traffic are intentionally outside this slice.

#![forbid(unsafe_code)]

use core::fmt;
use std::net::UdpSocket;

use conet_core::{
    BackingAccounting, BidirectionalAck, BlockCodec, BlockId, BlockShape, BlockStatus,
    EnqueueError, EnqueueErrorKind, EnqueueStatus, Feedback, FeedbackKind, InvalidReason,
    LinkSender, MonoNs, Occupancy, OneWayBudget, PacketHandle, PacketMetrics, PacketQueue,
    PayloadCopyCounter, QueueLimits, ReliabilitySender, SymbolMeta, decode_reliability_data,
    decode_reliability_feedback, encode_reliability_data, parse_reliability_data_header,
    reliability_feedback_packet,
};
use conet_fountain::{FountainBlockCodec, FountainCodecConfig};
use conet_udp::{
    AssociationState, DatagramTransport, EndpointConfig, LoopbackUdpTransport,
    ProfileEnqueueErrorKind, Role, SendClass, SimNetwork, UdpLiEndpoint, payload_packet,
};

const MANIFEST_MAGIC: [u8; 4] = *b"OCNM";
const MANIFEST_VERSION: u8 = 1;
const BLOCK_ID: BlockId = BlockId::new(1);
const MANIFEST_INTERVAL: MonoNs = MonoNs::new(100_000_000);

/// Application policy and framing controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferConfig {
    pub symbol_len: usize,
    pub minimum_source_symbols: usize,
    pub one_way_symbol_budget: Option<u64>,
    pub closed_loop: bool,
    pub target_rate: u64,
    pub ack_repeats: u32,
    pub ack_interval: MonoNs,
    pub nack_interval: MonoNs,
    pub linger: MonoNs,
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            symbol_len: 256,
            minimum_source_symbols: 4,
            one_way_symbol_budget: None,
            closed_loop: false,
            target_rate: 1_000_000,
            ack_repeats: 3,
            ack_interval: MonoNs::new(50_000_000),
            nack_interval: MonoNs::new(100_000_000),
            linger: MonoNs::new(2_000_000_000),
        }
    }
}

/// Simulator-only path impairment. The simulator remains deterministic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimulatorImpairment {
    /// Drop one forward data-path datagram every N sends.
    pub forward_loss_every: Option<usize>,
    /// Drop one reverse feedback-path datagram every N sends.
    pub reverse_loss_every: Option<usize>,
}

/// Observable result of one completed reference transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferReport {
    pub file_name: String,
    pub file_len: usize,
    pub source_symbols: u32,
    pub symbol_len: usize,
    pub stated_symbol_budget: u64,
    pub generated_symbols: u64,
    pub closed_loop: bool,
    pub sender_status: BlockStatus,
    pub data_datagrams_sent: usize,
    pub data_datagrams_received: usize,
    pub manifests_received: usize,
    pub feedback_datagrams_sent: usize,
    pub acks_received: usize,
    pub nacks_received: usize,
    pub recovered_file: Vec<u8>,
}

/// Invalid manifest, file, or transfer configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    EmptyFile,
    FileNameTooLong,
    InvalidManifest(&'static str),
    InvalidFileLength {
        expected: usize,
        actual: usize,
    },
    AssociationFailed,
    Codec(String),
    NotRecovered {
        generated: u64,
        budget: u64,
        data_datagrams_received: usize,
        manifests_received: usize,
        received_symbols: usize,
    },
    Io(String),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFile => f.write_str("file transfer requires a non-empty file"),
            Self::FileNameTooLong => f.write_str("file name exceeds the manifest limit"),
            Self::InvalidManifest(reason) => write!(f, "invalid transfer manifest: {reason}"),
            Self::InvalidFileLength { expected, actual } => {
                write!(f, "recovered file length {actual}, expected {expected}")
            }
            Self::AssociationFailed => f.write_str("association did not establish"),
            Self::Codec(error) => write!(f, "fountain codec error: {error}"),
            Self::NotRecovered {
                generated,
                budget,
                data_datagrams_received,
                manifests_received,
                received_symbols,
            } => write!(
                f,
                "file not recovered after {generated} generated symbols and {received_symbols} received symbols (budget {budget}; {data_datagrams_received} data datagrams, {manifests_received} manifests)"
            ),
            Self::Io(error) => write!(f, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for TransferError {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileManifest {
    shape: BlockShape,
    file_name: String,
}

impl FileManifest {
    fn encode(&self) -> Vec<u8> {
        let name = self.file_name.as_bytes();
        let mut body = Vec::with_capacity(4 + 1 + 8 + 4 + 4 + 8 + 2 + name.len());
        body.extend_from_slice(&MANIFEST_MAGIC);
        body.push(MANIFEST_VERSION);
        body.extend_from_slice(&BLOCK_ID.get().to_be_bytes());
        body.extend_from_slice(&self.shape.source_symbols.to_be_bytes());
        body.extend_from_slice(&(self.shape.symbol_len as u32).to_be_bytes());
        body.extend_from_slice(&(self.shape.block_len as u64).to_be_bytes());
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(name);
        body
    }

    fn decode(body: &[u8]) -> Result<Option<Self>, TransferError> {
        if !body.starts_with(&MANIFEST_MAGIC) {
            return Ok(None);
        }
        if body.len() < 31 || body[4] != MANIFEST_VERSION {
            return Err(TransferError::InvalidManifest("header or version"));
        }
        let block_id = BlockId::new(u64::from_be_bytes(
            body[5..13]
                .try_into()
                .map_err(|_| TransferError::InvalidManifest("block id"))?,
        ));
        if block_id != BLOCK_ID {
            return Err(TransferError::InvalidManifest("unexpected block id"));
        }
        let source_symbols = u32::from_be_bytes(
            body[13..17]
                .try_into()
                .map_err(|_| TransferError::InvalidManifest("source symbols"))?,
        );
        let symbol_len = u32::from_be_bytes(
            body[17..21]
                .try_into()
                .map_err(|_| TransferError::InvalidManifest("symbol length"))?,
        ) as usize;
        let block_len = usize::try_from(u64::from_be_bytes(
            body[21..29]
                .try_into()
                .map_err(|_| TransferError::InvalidManifest("block length"))?,
        ))
        .map_err(|_| TransferError::InvalidManifest("block length overflow"))?;
        let name_len = u16::from_be_bytes(
            body[29..31]
                .try_into()
                .map_err(|_| TransferError::InvalidManifest("name length"))?,
        ) as usize;
        if body.len() != 31 + name_len {
            return Err(TransferError::InvalidManifest("name length mismatch"));
        }
        let file_name = String::from_utf8(body[31..].to_vec())
            .map_err(|_| TransferError::InvalidManifest("file name is not UTF-8"))?;
        let shape = BlockShape::new(source_symbols, symbol_len, block_len)
            .map_err(|_| TransferError::InvalidManifest("invalid block shape"))?;
        Ok(Some(Self { shape, file_name }))
    }
}

/// Run the deterministic loss-injecting simulated topology.
pub fn run_simulated_transfer(
    file_name: &str,
    file: &[u8],
    config: FileTransferConfig,
    impairment: SimulatorImpairment,
) -> Result<TransferReport, TransferError> {
    validate_file(file_name, file)?;
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut sender = UdpLiEndpoint::new(
        network.transport(0),
        endpoint_config(Role::Initiator, config.target_rate),
    );
    let mut receiver = UdpLiEndpoint::new(
        network.transport(1),
        endpoint_config(Role::Responder, config.target_rate),
    );
    sender
        .start_association()
        .map_err(|_| TransferError::AssociationFailed)?;
    let now = establish(&mut sender, &mut receiver, MonoNs::ZERO)?;
    if let Some(every) = impairment.forward_loss_every {
        network.set_loss_pattern(0, loss_pattern(every));
    }
    if let Some(every) = impairment.reverse_loss_every {
        network.set_loss_pattern(1, loss_pattern(every));
    }
    run_established_pair(
        &mut sender,
        &mut receiver,
        file_name,
        file,
        config,
        now,
        false,
    )
}

/// Run a self-contained one-way transfer between two real UDP sockets.
///
/// Both local and peer addresses are checked by `LoopbackUdpTransport` and
/// must resolve to loopback. This function does not sleep after completion.
pub fn run_loopback_transfer(
    file_name: &str,
    file: &[u8],
    config: FileTransferConfig,
) -> Result<TransferReport, TransferError> {
    validate_file(file_name, file)?;
    let socket_a = UdpSocket::bind("127.0.0.1:0").map_err(io_error)?;
    let socket_b = UdpSocket::bind("127.0.0.1:0").map_err(io_error)?;
    let addr_a = socket_a.local_addr().map_err(io_error)?;
    let addr_b = socket_b.local_addr().map_err(io_error)?;
    let transport_a = LoopbackUdpTransport::from_socket(socket_a, addr_b).map_err(io_error)?;
    let transport_b = LoopbackUdpTransport::from_socket(socket_b, addr_a).map_err(io_error)?;
    let mut sender = UdpLiEndpoint::new(
        transport_a,
        endpoint_config(Role::Initiator, config.target_rate).test_open(),
    );
    let mut receiver = UdpLiEndpoint::new(
        transport_b,
        endpoint_config(Role::Responder, config.target_rate).test_open(),
    );
    sender
        .start_association()
        .map_err(|_| TransferError::AssociationFailed)?;

    let mut now = MonoNs::ZERO;
    let started = std::time::Instant::now();
    while sender.state() != AssociationState::Established
        || receiver.state() != AssociationState::Established
    {
        if started.elapsed() > std::time::Duration::from_secs(2) {
            return Err(TransferError::AssociationFailed);
        }
        sender.drive(now);
        receiver.drive(now);
        std::thread::sleep(std::time::Duration::from_millis(1));
        now = now.saturating_add(ms(1));
    }
    run_established_pair(
        &mut sender,
        &mut receiver,
        file_name,
        file,
        config,
        now,
        true,
    )
}

fn endpoint_config(role: Role, target_rate: u64) -> EndpointConfig {
    let mut config = EndpointConfig::new(role, target_rate);
    config.initial_association_id = 0x5100_0001;
    config
}

fn establish<T: DatagramTransport, U: DatagramTransport>(
    sender: &mut UdpLiEndpoint<T>,
    receiver: &mut UdpLiEndpoint<U>,
    mut now: MonoNs,
) -> Result<MonoNs, TransferError> {
    for _ in 0..2_000 {
        sender.drive(now);
        receiver.drive(now);
        if sender.state() == AssociationState::Established
            && receiver.state() == AssociationState::Established
        {
            return Ok(now);
        }
        now = now.saturating_add(ms(1));
    }
    Err(TransferError::AssociationFailed)
}

fn run_established_pair<T: DatagramTransport, U: DatagramTransport>(
    sender_endpoint: &mut UdpLiEndpoint<T>,
    receiver_endpoint: &mut UdpLiEndpoint<U>,
    file_name: &str,
    file: &[u8],
    config: FileTransferConfig,
    mut now: MonoNs,
    real_loopback: bool,
) -> Result<TransferReport, TransferError> {
    let copies = PayloadCopyCounter::new();
    let mut sender_codec = fountain_codec(&config, copies.clone()).map_err(codec_error)?;
    let shape = sender_codec
        .add_block(BLOCK_ID, file.to_vec())
        .map_err(codec_error)?;
    let manifest = FileManifest {
        shape,
        file_name: file_name.to_owned(),
    };
    let budget = config
        .one_way_symbol_budget
        .unwrap_or_else(|| default_symbol_budget(shape.source_symbols, config.closed_loop));
    let metrics = PacketMetrics {
        backings: BackingAccounting::new(),
        payload_copies: copies,
    };

    let mut receiver_codec =
        fountain_codec(&config, PayloadCopyCounter::new()).map_err(codec_error)?;
    let mut receiver_state = ReceiverState {
        manifest: None,
        received_symbols: 0,
        data_datagrams: 0,
        manifests_received: 0,
        recovered: false,
        next_nack_at: now,
        ack: None,
    };
    let mut feedback_queue = PacketQueue::new(QueueLimits::new(64, 64 * 1024, 64 * 1024));
    let mut acks_received = 0;
    let mut nacks_received = 0;
    let mut generated_symbols = 0;
    let mut sender_status = BlockStatus::Sending;
    let mut next_manifest_at = now;

    let max_ticks = budget
        .saturating_mul(4)
        .saturating_add((config.linger.as_nanos() / 1_000_000) as u64)
        .saturating_add(512) as usize;

    if config.closed_loop {
        let policy = BidirectionalAck::new(budget, config.linger)
            .with_time_budget(MonoNs::new(20_000_000_000));
        let mut sender = ReliabilitySender::new(
            sender_codec,
            policy,
            QueueLimits::new(256, 512 * 1024, 512 * 1024),
            metrics,
        );
        sender
            .register_block(BLOCK_ID, now)
            .map_err(|error| TransferError::Codec(error.to_string()))?;
        for _ in 0..max_ticks {
            if !receiver_state.recovered && now >= next_manifest_at {
                enqueue_manifest(sender_endpoint, &manifest)?;
                next_manifest_at = now.saturating_add(MANIFEST_INTERVAL);
            }
            let mut outgoing = UdpUserSender {
                endpoint: sender_endpoint,
            };
            sender.pump(&mut outgoing, now, 1, 4);
            sender_endpoint.drive(now);
            receiver_endpoint.drive(now);
            receiver_state.process(receiver_endpoint, &mut receiver_codec, now, true, &config)?;
            collect_feedback(
                sender_endpoint,
                &mut feedback_queue,
                &mut acks_received,
                &mut nacks_received,
            );
            sender.receive_feedback(&mut feedback_queue, now, 64);
            generated_symbols = sender.generated_symbols(BLOCK_ID).unwrap_or(0);
            sender_status = sender.status(BLOCK_ID).unwrap_or(BlockStatus::Sending);
            if receiver_state.recovered && sender_status == BlockStatus::Delivered {
                break;
            }
            now = advance(now, real_loopback);
        }
        let recovered_file = take_recovered(
            &mut receiver_codec,
            &receiver_state,
            shape,
            generated_symbols,
            budget,
        )?;
        return Ok(report(
            file_name,
            file.len(),
            shape,
            budget,
            generated_symbols,
            true,
            sender_status,
            sender_endpoint,
            receiver_endpoint,
            acks_received,
            nacks_received,
            receiver_state.data_datagrams,
            receiver_state.manifests_received,
            recovered_file,
        ));
    }

    let mut sender = ReliabilitySender::new(
        sender_codec,
        OneWayBudget::new(budget).with_time_budget(MonoNs::new(20_000_000_000)),
        QueueLimits::new(256, 512 * 1024, 512 * 1024),
        metrics,
    );
    sender
        .register_block(BLOCK_ID, now)
        .map_err(|error| TransferError::Codec(error.to_string()))?;
    for _ in 0..max_ticks {
        if !receiver_state.recovered && now >= next_manifest_at {
            enqueue_manifest(sender_endpoint, &manifest)?;
            next_manifest_at = now.saturating_add(MANIFEST_INTERVAL);
        }
        let mut outgoing = UdpUserSender {
            endpoint: sender_endpoint,
        };
        sender.pump(&mut outgoing, now, 1, 4);
        sender_endpoint.drive(now);
        receiver_endpoint.drive(now);
        receiver_state.process(receiver_endpoint, &mut receiver_codec, now, false, &config)?;
        generated_symbols = sender.generated_symbols(BLOCK_ID).unwrap_or(0);
        sender_status = sender.status(BLOCK_ID).unwrap_or(BlockStatus::Sending);
        if receiver_state.recovered && sender_status == BlockStatus::StoppedByBudget {
            break;
        }
        now = advance(now, real_loopback);
    }
    let recovered_file = take_recovered(
        &mut receiver_codec,
        &receiver_state,
        shape,
        generated_symbols,
        budget,
    )?;
    Ok(report(
        file_name,
        file.len(),
        shape,
        budget,
        generated_symbols,
        false,
        sender_status,
        sender_endpoint,
        receiver_endpoint,
        acks_received,
        nacks_received,
        receiver_state.data_datagrams,
        receiver_state.manifests_received,
        recovered_file,
    ))
}

#[allow(clippy::too_many_arguments)]
fn report<T: DatagramTransport, U: DatagramTransport>(
    file_name: &str,
    file_len: usize,
    shape: BlockShape,
    budget: u64,
    generated_symbols: u64,
    closed_loop: bool,
    sender_status: BlockStatus,
    sender: &UdpLiEndpoint<T>,
    receiver: &UdpLiEndpoint<U>,
    acks_received: usize,
    nacks_received: usize,
    data_datagrams_received: usize,
    manifests_received: usize,
    recovered_file: Vec<u8>,
) -> TransferReport {
    let data_datagrams_sent = sender
        .sent()
        .iter()
        .filter(|sent| sent.class == SendClass::FileData)
        .count();
    let feedback_datagrams_sent = receiver
        .sent()
        .iter()
        .filter(|sent| sent.class == SendClass::Feedback)
        .count();
    TransferReport {
        file_name: file_name.to_owned(),
        file_len,
        source_symbols: shape.source_symbols,
        symbol_len: shape.symbol_len,
        stated_symbol_budget: budget,
        generated_symbols,
        closed_loop,
        sender_status,
        data_datagrams_sent,
        data_datagrams_received,
        manifests_received,
        feedback_datagrams_sent,
        acks_received,
        nacks_received,
        recovered_file,
    }
}

struct ReceiverState {
    manifest: Option<FileManifest>,
    received_symbols: usize,
    data_datagrams: usize,
    manifests_received: usize,
    recovered: bool,
    next_nack_at: MonoNs,
    ack: Option<AckSchedule>,
}

struct AckSchedule {
    repeats_left: u32,
    next_at: MonoNs,
}

impl ReceiverState {
    fn process<T: DatagramTransport>(
        &mut self,
        endpoint: &mut UdpLiEndpoint<T>,
        codec: &mut FountainBlockCodec,
        now: MonoNs,
        closed_loop: bool,
        config: &FileTransferConfig,
    ) -> Result<(), TransferError> {
        for received in endpoint.take_received() {
            let payload = received.packet.payload_bytes();
            if payload.is_empty() {
                continue;
            }
            if let Some(manifest) = FileManifest::decode(payload)? {
                self.manifests_received = self.manifests_received.saturating_add(1);
                if let Some(existing) = &self.manifest {
                    if existing != &manifest {
                        return Err(TransferError::InvalidManifest(
                            "manifest changed during transfer",
                        ));
                    }
                } else {
                    self.manifest = Some(manifest);
                }
                continue;
            }
            let Some(manifest) = &self.manifest else {
                continue;
            };
            let Ok(content) =
                decode_reliability_data(conet_core::OpaqueBytes::copy_from_slice(payload))
            else {
                // ACK/NACK is user-body content too. It is not acknowledged,
                // and the receiving side only needs to consume it here.
                let _ =
                    decode_reliability_feedback(conet_core::OpaqueBytes::copy_from_slice(payload));
                continue;
            };
            self.data_datagrams = self.data_datagrams.saturating_add(1);
            if content.block_id != BLOCK_ID {
                continue;
            }
            let status = codec
                .accumulate(
                    SymbolMeta {
                        block_id: content.block_id,
                        symbol_id: content.rel_seq,
                        shape: manifest.shape,
                    },
                    &content.coded_vector,
                )
                .map_err(codec_error)?;
            self.received_symbols = self.received_symbols.saturating_add(1);
            if matches!(status, conet_core::DecodeStatus::BlockRecovered) {
                self.recovered = true;
                if closed_loop {
                    endpoint
                        .enqueue_feedback_value(Feedback::ack(BLOCK_ID))
                        .map_err(|_| TransferError::AssociationFailed)?;
                    self.ack = Some(AckSchedule {
                        repeats_left: config.ack_repeats,
                        next_at: now.saturating_add(config.ack_interval),
                    });
                }
            } else if closed_loop
                && matches!(status, conet_core::DecodeStatus::NeedMore)
                && now >= self.next_nack_at
            {
                endpoint
                    .enqueue_feedback_value(Feedback::nack(
                        BLOCK_ID,
                        self.received_symbols as u32,
                        0,
                    ))
                    .map_err(|_| TransferError::AssociationFailed)?;
                self.next_nack_at = now.saturating_add(config.nack_interval);
            }
        }

        if closed_loop
            && let Some(ack) = self.ack.as_mut()
            && ack.repeats_left > 0
            && now >= ack.next_at
        {
            endpoint
                .enqueue_feedback_value(Feedback::ack(BLOCK_ID))
                .map_err(|_| TransferError::AssociationFailed)?;
            ack.repeats_left -= 1;
            ack.next_at = now.saturating_add(config.ack_interval);
        }
        Ok(())
    }
}

fn collect_feedback<T: DatagramTransport>(
    endpoint: &mut UdpLiEndpoint<T>,
    queue: &mut PacketQueue,
    acks_received: &mut usize,
    nacks_received: &mut usize,
) {
    for received in endpoint.take_received() {
        let payload = received.packet.payload_bytes();
        if payload.is_empty() {
            continue;
        }
        let Ok(feedback) =
            decode_reliability_feedback(conet_core::OpaqueBytes::copy_from_slice(payload))
        else {
            continue;
        };
        match feedback.kind {
            FeedbackKind::Ack => *acks_received += 1,
            FeedbackKind::Nack => *nacks_received += 1,
        }
        let _ = queue.enqueue(reliability_feedback_packet(feedback));
    }
}

fn take_recovered(
    codec: &mut FountainBlockCodec,
    receiver: &ReceiverState,
    shape: BlockShape,
    generated: u64,
    budget: u64,
) -> Result<Vec<u8>, TransferError> {
    if !receiver.recovered {
        return Err(TransferError::NotRecovered {
            generated,
            budget,
            data_datagrams_received: receiver.data_datagrams,
            manifests_received: receiver.manifests_received,
            received_symbols: receiver.received_symbols,
        });
    }
    let file = codec
        .take_recovered_block(BLOCK_ID)
        .ok_or(TransferError::Codec(
            "decoder marked recovered without block data".into(),
        ))?;
    if file.len() != shape.block_len {
        return Err(TransferError::InvalidFileLength {
            expected: shape.block_len,
            actual: file.len(),
        });
    }
    Ok(file)
}

fn enqueue_manifest<T: DatagramTransport>(
    endpoint: &mut UdpLiEndpoint<T>,
    manifest: &FileManifest,
) -> Result<(), TransferError> {
    endpoint
        .enqueue_file_data(payload_packet(manifest.encode()))
        .map_err(|_| TransferError::AssociationFailed)?;
    Ok(())
}

fn fountain_codec(
    config: &FileTransferConfig,
    copies: PayloadCopyCounter,
) -> Result<FountainBlockCodec, conet_core::CodecError> {
    FountainBlockCodec::new(
        FountainCodecConfig {
            symbol_len: config.symbol_len,
            minimum_source_symbols: config.minimum_source_symbols,
        },
        copies,
    )
}

fn default_symbol_budget(source_symbols: u32, closed_loop: bool) -> u64 {
    let multiplier = if closed_loop { 4 } else { 3 };
    u64::from(source_symbols) * multiplier + 16
}

fn loss_pattern(every: usize) -> Vec<bool> {
    if every == 0 {
        return vec![false];
    }
    (1..=every * 16).map(|index| index % every == 0).collect()
}

fn validate_file(file_name: &str, file: &[u8]) -> Result<(), TransferError> {
    if file.is_empty() {
        return Err(TransferError::EmptyFile);
    }
    if file_name.len() > u16::MAX as usize {
        return Err(TransferError::FileNameTooLong);
    }
    Ok(())
}

fn codec_error(error: conet_core::CodecError) -> TransferError {
    TransferError::Codec(error.to_string())
}

fn io_error(error: std::io::Error) -> TransferError {
    TransferError::Io(error.to_string())
}

fn advance(now: MonoNs, real_loopback: bool) -> MonoNs {
    if real_loopback {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    now.saturating_add(ms(1))
}

fn ms(value: i64) -> MonoNs {
    MonoNs::new(value * 1_000_000)
}

struct UdpUserSender<'a, T: DatagramTransport> {
    endpoint: &'a mut UdpLiEndpoint<T>,
}

impl<T: DatagramTransport> LinkSender for UdpUserSender<'_, T> {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        let Some(meta) = parse_reliability_data_header(pkt.header().as_bytes()) else {
            return Err(EnqueueError::Closed { pkt });
        };
        let body = encode_reliability_data(meta.block_id, meta.symbol_id, pkt.payload_bytes());
        match self.endpoint.enqueue_file_data(payload_packet(body)) {
            Ok(status) => Ok(status),
            Err(error) => {
                let kind = error.kind();
                let _ = error.into_packet();
                match kind {
                    ProfileEnqueueErrorKind::Queue(EnqueueErrorKind::Full) => {
                        Err(EnqueueError::Full { pkt })
                    }
                    ProfileEnqueueErrorKind::DatagramTooLarge => Err(EnqueueError::Invalid {
                        pkt,
                        reason: InvalidReason::PacketTooLarge {
                            len: meta.shape.symbol_len + conet_core::RELIABILITY_DATA_PREFIX_LEN,
                            max: self.endpoint.config().max_datagram,
                        },
                    }),
                    _ => Err(EnqueueError::Closed { pkt }),
                }
            }
        }
    }

    fn occupancy(&self) -> Occupancy {
        self.endpoint.queue_occupancy(SendClass::FileData)
    }

    fn close(&mut self) {
        // The application owns endpoint lifecycle; reliability completion does
        // not close the association.
    }
}

#[cfg(test)]
mod wire_demux_tests {
    use super::*;
    use conet_core::{
        OpaqueBytes, QosClass, ReferenceWireCodec, WireFlags, WireHeader,
        encode_reliability_feedback,
    };
    use conet_udp::{Role, SimNetwork};

    fn inject_body(endpoint: &SimNetwork, qos: QosClass, body: Vec<u8>) {
        let codec = ReferenceWireCodec::default();
        let datagram = codec
            .build(
                WireHeader {
                    flags: WireFlags { qos },
                    epoch: 1,
                    link_seq: 1,
                    payload_len: 0,
                },
                OpaqueBytes::from(body),
                None,
            )
            .unwrap();
        endpoint.inject(1, codec.serialize(&datagram).unwrap(), true);
    }

    #[test]
    fn feedback_collection_uses_body_content_not_qos_label() {
        let network = SimNetwork::new();
        let mut endpoint = UdpLiEndpoint::new(
            network.transport(1),
            EndpointConfig::new(Role::Responder, u64::MAX),
        );
        endpoint.establish_for_test(1, 1).unwrap();
        inject_body(
            &network,
            QosClass::Bulk,
            encode_reliability_feedback(Feedback::ack(BlockId::new(9))),
        );
        endpoint.drive(MonoNs::ZERO);

        let mut queue = PacketQueue::new(QueueLimits::new(4, 1024, 1024));
        let mut acks = 0;
        let mut nacks = 0;
        collect_feedback(&mut endpoint, &mut queue, &mut acks, &mut nacks);
        assert_eq!((acks, nacks), (1, 0));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn receiver_manifest_path_does_not_demux_by_qos_label() {
        let network = SimNetwork::new();
        let mut endpoint = UdpLiEndpoint::new(
            network.transport(1),
            EndpointConfig::new(Role::Responder, u64::MAX),
        );
        endpoint.establish_for_test(1, 1).unwrap();
        let manifest = FileManifest {
            shape: BlockShape::new(4, 4, 16).unwrap(),
            file_name: "qos-independent.bin".into(),
        };
        inject_body(&network, QosClass::Feedback, manifest.encode());
        endpoint.drive(MonoNs::ZERO);

        let mut state = ReceiverState {
            manifest: None,
            received_symbols: 0,
            data_datagrams: 0,
            manifests_received: 0,
            recovered: false,
            next_nack_at: MonoNs::ZERO,
            ack: None,
        };
        let mut codec = FountainBlockCodec::new(
            FountainCodecConfig {
                symbol_len: 4,
                minimum_source_symbols: 4,
            },
            PayloadCopyCounter::new(),
        )
        .unwrap();
        state
            .process(
                &mut endpoint,
                &mut codec,
                MonoNs::ZERO,
                false,
                &FileTransferConfig::default(),
            )
            .unwrap();
        assert_eq!(state.manifests_received, 1);
        assert_eq!(state.manifest, Some(manifest));
    }
}
