//! First usable Conet reference file-transfer application.
//!
//! The default policy is one-way/open-loop. A closed-loop ACK/NACK policy is
//! opt-in. The application uses one reliability block and one attachment per
//! endpoint; network adaptation, multiplexing, cross-layer QoS intent, and
//! external traffic are intentionally outside this slice.

#![forbid(unsafe_code)]

use core::fmt;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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
    ConnectedUdpTransport, DatagramTransport, DriveReport, EndpointConfig, LocalSendOutcome,
    LoopbackUdpTransport, PeerAdmitPolicy, ProfileEnqueueErrorKind, ReflexiveReport, Role,
    SendClass, SimNetwork, UdpLiEndpoint, discover_reflexive, payload_packet,
    serve_reflexive_until,
};

const MANIFEST_MAGIC: [u8; 4] = *b"OCNM";
const MANIFEST_VERSION: u8 = 1;
const BLOCK_ID: BlockId = BlockId::new(1);
const MANIFEST_INTERVAL: MonoNs = MonoNs::new(100_000_000);
const UDP_TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_READY_WAIT: Option<Duration> = Some(Duration::from_millis(250));

/// Application policy and framing controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferConfig {
    pub symbol_len: usize,
    pub minimum_source_symbols: usize,
    pub one_way_symbol_budget: Option<u64>,
    pub closed_loop: bool,
    pub target_rate: u64,
    pub nack_interval: MonoNs,
    pub linger: MonoNs,
    /// UL-2/UL-6 lab bridge: admit the first Conet source IP even when it
    /// disagrees with `--peer` (HTTP vs UDP egress). Off by default.
    pub lab_observe_ip: bool,
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        Self {
            symbol_len: 256,
            minimum_source_symbols: 4,
            one_way_symbol_budget: None,
            closed_loop: false,
            target_rate: 1_000_000,
            nack_interval: MonoNs::new(100_000_000),
            linger: MonoNs::new(2_000_000_000),
            lab_observe_ip: false,
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

/// Sender-side result for one explicit-address UDP transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpSendReport {
    pub file_name: String,
    pub file_len: usize,
    pub source_symbols: u32,
    pub symbol_len: usize,
    pub stated_symbol_budget: u64,
    pub generated_symbols: u64,
    pub closed_loop: bool,
    pub sender_status: BlockStatus,
    pub data_datagrams_sent: usize,
    pub feedback_datagrams_sent: usize,
    pub acks_received: usize,
    pub nacks_received: usize,
}

/// Receiver-side result for one explicit-address UDP transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpReceiveReport {
    pub file_name: String,
    pub file_len: usize,
    pub source_symbols: u32,
    pub symbol_len: usize,
    pub data_datagrams_received: usize,
    pub manifests_received: usize,
    pub feedback_datagrams_sent: usize,
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
    LinkFailed,
    Codec(String),
    NotRecovered {
        generated: u64,
        budget: u64,
        data_datagrams_received: usize,
        manifests_received: usize,
        received_symbols: usize,
    },
    Io(String),
    TimedOut(&'static str),
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
            Self::LinkFailed => f.write_str("UDP link send failed"),
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
            Self::TimedOut(phase) => write!(f, "UDP transfer timed out during {phase}"),
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
        MonoNs::ZERO,
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
    run_established_pair(
        &mut sender,
        &mut receiver,
        file_name,
        file,
        config,
        MonoNs::ZERO,
        true,
    )
}

fn peer_policy(config: &FileTransferConfig) -> PeerAdmitPolicy {
    if config.lab_observe_ip {
        PeerAdmitPolicy::lab_observe_ip()
    } else {
        PeerAdmitPolicy::default()
    }
}

/// UL-6: probe a reflexive helper from `listen` on the association socket.
///
/// The result is a candidate for out-of-band `--peer` exchange. It is not a
/// validated path identity. Do not substitute an HTTP public-IP lookup.
pub fn run_reflexive_probe(
    listen: SocketAddr,
    helper: SocketAddr,
    timeout: Duration,
) -> Result<ReflexiveReport, TransferError> {
    let socket = UdpSocket::bind(listen).map_err(io_error)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    discover_reflexive(&socket, helper, timeout).map_err(|error| TransferError::Io(error.to_string()))
}

/// UL-6: serve reflexive requests on `listen` until `duration` elapses.
pub fn run_reflexive_helper(listen: SocketAddr, duration: Duration) -> Result<u64, TransferError> {
    let socket = UdpSocket::bind(listen).map_err(io_error)?;
    serve_reflexive_until(&socket, Instant::now() + duration)
        .map_err(|error| TransferError::Io(error.to_string()))
}

/// Send a file to one explicit UDP peer.
///
/// `listen` and `peer` may use any local or remote addresses, including
/// loopback. `peer` is the initial destination and IP filter; the transport
/// learns and locks the observed source endpoint before the socket closes.
/// Prefer a same-socket reflexive candidate (UL-6) over an HTTP public IP.
pub fn run_udp_sender(
    listen: SocketAddr,
    peer: SocketAddr,
    file_name: &str,
    file: &[u8],
    config: FileTransferConfig,
) -> Result<UdpSendReport, TransferError> {
    validate_file(file_name, file)?;
    let transport =
        ConnectedUdpTransport::bind_with_policy(listen, peer, peer_policy(&config)).map_err(io_error)?;
    let mut endpoint = UdpLiEndpoint::new(
        transport,
        endpoint_config(Role::Initiator, config.target_rate).test_open(),
    );
    let started = Instant::now();
    let mut now = udp_clock(started);
    let copies = PayloadCopyCounter::new();
    let mut codec = fountain_codec(&config, copies.clone()).map_err(codec_error)?;
    let shape = codec
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
    let mut next_manifest_at = now;
    let mut feedback_queue = PacketQueue::new(QueueLimits::new(64, 64 * 1024, 64 * 1024));
    let mut acks_received = 0;
    let mut nacks_received = 0;

    if config.closed_loop {
        let policy = BidirectionalAck::new(budget, config.linger)
            .with_time_budget(MonoNs::new(20_000_000_000));
        let mut sender = ReliabilitySender::new(
            codec,
            policy,
            QueueLimits::new(256, 512 * 1024, 512 * 1024),
            metrics,
        );
        sender
            .register_block(BLOCK_ID, now)
            .map_err(|error| TransferError::Codec(error.to_string()))?;
        loop {
            if started.elapsed() > UDP_TRANSFER_TIMEOUT {
                return Err(TransferError::TimedOut("send"));
            }
            if now >= next_manifest_at {
                enqueue_manifest(&mut endpoint, &manifest)?;
                next_manifest_at = now.saturating_add(MANIFEST_INTERVAL);
            }
            let mut outgoing = UdpUserSender {
                endpoint: &mut endpoint,
            };
            sender.pump(&mut outgoing, now, 1, 4);
            let drive = endpoint
                .drive_when_ready_with_timeout(|| udp_clock(started), UDP_READY_WAIT)
                .map_err(io_error)?;
            check_send_outcome(&drive)?;
            collect_feedback(
                &mut endpoint,
                &mut feedback_queue,
                &mut acks_received,
                &mut nacks_received,
            );
            sender.receive_feedback(&mut feedback_queue, now, 64);
            let status = sender.status(BLOCK_ID).unwrap_or(BlockStatus::Sending);
            let generated_symbols = sender.generated_symbols(BLOCK_ID).unwrap_or(0);
            now = udp_clock(started);
            if matches!(
                status,
                BlockStatus::Delivered
                    | BlockStatus::StoppedByBudget
                    | BlockStatus::StoppedWithoutAck
            ) && sender.staged_packets() == 0
                && endpoint.queued(SendClass::FileData) == 0
            {
                return Ok(UdpSendReport {
                    file_name: file_name.to_owned(),
                    file_len: file.len(),
                    source_symbols: shape.source_symbols,
                    symbol_len: shape.symbol_len,
                    stated_symbol_budget: budget,
                    generated_symbols,
                    closed_loop: true,
                    sender_status: status,
                    data_datagrams_sent: endpoint
                        .sent()
                        .iter()
                        .filter(|sent| sent.class == SendClass::FileData)
                        .count(),
                    feedback_datagrams_sent: endpoint
                        .sent()
                        .iter()
                        .filter(|sent| sent.class == SendClass::Feedback)
                        .count(),
                    acks_received,
                    nacks_received,
                });
            }
        }
    }

    let mut sender = ReliabilitySender::new(
        codec,
        OneWayBudget::new(budget).with_time_budget(MonoNs::new(20_000_000_000)),
        QueueLimits::new(256, 512 * 1024, 512 * 1024),
        metrics,
    );
    sender
        .register_block(BLOCK_ID, now)
        .map_err(|error| TransferError::Codec(error.to_string()))?;
    loop {
        if started.elapsed() > UDP_TRANSFER_TIMEOUT {
            return Err(TransferError::TimedOut("send"));
        }
        if now >= next_manifest_at {
            enqueue_manifest(&mut endpoint, &manifest)?;
            next_manifest_at = now.saturating_add(MANIFEST_INTERVAL);
        }
        let mut outgoing = UdpUserSender {
            endpoint: &mut endpoint,
        };
        sender.pump(&mut outgoing, now, 1, 4);
        let drive = endpoint
            .drive_when_ready_with_timeout(|| udp_clock(started), UDP_READY_WAIT)
            .map_err(io_error)?;
        check_send_outcome(&drive)?;
        let status = sender.status(BLOCK_ID).unwrap_or(BlockStatus::Sending);
        let generated_symbols = sender.generated_symbols(BLOCK_ID).unwrap_or(0);
        now = udp_clock(started);
        if status == BlockStatus::StoppedByBudget
            && sender.staged_packets() == 0
            && endpoint.queued(SendClass::FileData) == 0
        {
            return Ok(UdpSendReport {
                file_name: file_name.to_owned(),
                file_len: file.len(),
                source_symbols: shape.source_symbols,
                symbol_len: shape.symbol_len,
                stated_symbol_budget: budget,
                generated_symbols,
                closed_loop: false,
                sender_status: status,
                data_datagrams_sent: endpoint
                    .sent()
                    .iter()
                    .filter(|sent| sent.class == SendClass::FileData)
                    .count(),
                feedback_datagrams_sent: 0,
                acks_received: 0,
                nacks_received: 0,
            });
        }
    }
}

/// Receive one file from one explicit UDP peer.
///
/// The receiver accepts a small file encoded with the same transfer manifest
/// and fountain block format as the other modes. The socket is closed when the
/// file is recovered or the bounded wait expires.
pub fn run_udp_receiver(
    listen: SocketAddr,
    peer: SocketAddr,
    config: FileTransferConfig,
) -> Result<UdpReceiveReport, TransferError> {
    let transport =
        ConnectedUdpTransport::bind_with_policy(listen, peer, peer_policy(&config)).map_err(io_error)?;
    let mut endpoint = UdpLiEndpoint::new(
        transport,
        endpoint_config(Role::Responder, config.target_rate).test_open(),
    );
    let started = Instant::now();
    let mut now = udp_clock(started);
    let mut codec = fountain_codec(&config, PayloadCopyCounter::new()).map_err(codec_error)?;
    let mut state = ReceiverState {
        manifest: None,
        received_symbols: 0,
        data_datagrams: 0,
        manifests_received: 0,
        recovered: false,
        next_nack_at: now,
    };
    let mut last_progress = Instant::now();

    while !state.recovered {
        if started.elapsed() > UDP_TRANSFER_TIMEOUT {
            return Err(TransferError::TimedOut("receive"));
        }
        if last_progress.elapsed() > UDP_IDLE_TIMEOUT {
            return Err(TransferError::TimedOut("receive idle"));
        }
        let drive = endpoint
            .drive_when_ready_with_timeout(|| udp_clock(started), UDP_READY_WAIT)
            .map_err(io_error)?;
        check_send_outcome(&drive)?;
        if drive.received > 0 || drive.sent > 0 {
            last_progress = Instant::now();
        }
        now = udp_clock(started);
        state.process(&mut endpoint, &mut codec, now, config.closed_loop, &config)?;
    }

    // One-way senders cannot learn that recovery happened. Keep consuming for
    // the same bounded linger used by the closed-loop policy so they can drain
    // their local symbol budget without racing socket teardown.
    let linger_started = Instant::now();
    let linger = Duration::from_nanos(u64::try_from(config.linger.as_nanos()).unwrap_or(u64::MAX));
    while linger_started.elapsed() < linger {
        let drive = endpoint
            .drive_when_ready_with_timeout(|| udp_clock(started), UDP_READY_WAIT)
            .map_err(io_error)?;
        check_send_outcome(&drive)?;
        now = udp_clock(started);
        state.process(&mut endpoint, &mut codec, now, config.closed_loop, &config)?;
    }

    let manifest = state
        .manifest
        .as_ref()
        .ok_or(TransferError::InvalidManifest("missing manifest"))?;
    let shape = manifest.shape;
    let recovered_file = take_recovered(
        &mut codec,
        &state,
        shape,
        0,
        config.one_way_symbol_budget.unwrap_or(0),
    )?;
    Ok(UdpReceiveReport {
        file_name: manifest.file_name.clone(),
        file_len: shape.block_len,
        source_symbols: shape.source_symbols,
        symbol_len: shape.symbol_len,
        data_datagrams_received: state.data_datagrams,
        manifests_received: state.manifests_received,
        feedback_datagrams_sent: endpoint
            .sent()
            .iter()
            .filter(|sent| sent.class == SendClass::Feedback)
            .count(),
        recovered_file,
    })
}

fn udp_clock(started: Instant) -> MonoNs {
    let nanos = started.elapsed().as_nanos();
    MonoNs::new(i64::try_from(nanos).unwrap_or(i64::MAX))
}

/// Build the reference-transfer endpoint config (association id shared by both ends).
pub fn transfer_endpoint_config(role: Role, target_rate: u64) -> EndpointConfig {
    let mut config = EndpointConfig::new(role, target_rate);
    config.initial_association_id = 0x5100_0001;
    config
}

fn endpoint_config(role: Role, target_rate: u64) -> EndpointConfig {
    transfer_endpoint_config(role, target_rate)
}

/// Run a file transfer on caller-built endpoints.
///
/// Callers may install any `TxController` / `RxController` on the endpoints
/// before invoking this helper. Default CLI paths keep
/// [`UdpLiEndpoint::new`] / fixed-rate.
///
/// Set `real_udp` when the transports are real sockets (loopback/WAN) so the
/// driver yields briefly between ticks.
pub fn run_pair_transfer<T: DatagramTransport, U: DatagramTransport>(
    sender_endpoint: &mut UdpLiEndpoint<T>,
    receiver_endpoint: &mut UdpLiEndpoint<U>,
    file_name: &str,
    file: &[u8],
    config: FileTransferConfig,
    real_udp: bool,
) -> Result<TransferReport, TransferError> {
    validate_file(file_name, file)?;
    run_established_pair(
        sender_endpoint,
        receiver_endpoint,
        file_name,
        file,
        config,
        MonoNs::ZERO,
        real_udp,
    )
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
            check_send_outcome(&sender_endpoint.drive(now))?;
            check_send_outcome(&receiver_endpoint.drive(now))?;
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
        check_send_outcome(&sender_endpoint.drive(now))?;
        check_send_outcome(&receiver_endpoint.drive(now))?;
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
                        .map_err(|_| TransferError::LinkFailed)?;
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
                    .map_err(|_| TransferError::LinkFailed)?;
                self.next_nack_at = now.saturating_add(config.nack_interval);
            }
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
        .map_err(|_| TransferError::LinkFailed)?;
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

fn check_send_outcome(report: &DriveReport) -> Result<(), TransferError> {
    if report.send_outcome == Some(LocalSendOutcome::Fatal) {
        return Err(TransferError::LinkFailed);
    }
    Ok(())
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
    use conet_udp::{DriveReport, LocalSendOutcome, Role, SimNetwork};

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

    #[test]
    fn only_fatal_local_send_outcomes_fail_the_transfer_link() {
        for outcome in [
            LocalSendOutcome::WouldBlock,
            LocalSendOutcome::TransientDrop,
            LocalSendOutcome::Interrupted,
        ] {
            let report = DriveReport {
                send_failed: true,
                send_outcome: Some(outcome),
                ..DriveReport::default()
            };
            assert_eq!(check_send_outcome(&report), Ok(()));
        }

        let report = DriveReport {
            send_failed: true,
            send_outcome: Some(LocalSendOutcome::Fatal),
            ..DriveReport::default()
        };
        assert_eq!(check_send_outcome(&report), Err(TransferError::LinkFailed));
    }

    #[test]
    fn simulated_transfer_survives_nonfatal_local_send_errors() {
        for kind in [
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::HostUnreachable,
        ] {
            let network = SimNetwork::new();
            network.set_authenticated(true);
            let mut sender = UdpLiEndpoint::new(
                network.transport(0),
                endpoint_config(Role::Initiator, 1_000_000),
            );
            let mut receiver = UdpLiEndpoint::new(
                network.transport(1),
                endpoint_config(Role::Responder, 1_000_000),
            );
            network.fail_next_send_with(0, kind);
            let source: Vec<u8> = (0..4_097).map(|value| value as u8).collect();
            let config = FileTransferConfig {
                // Keep generating symbols beyond the next periodic manifest
                // after the injected write drops the initial manifest.
                one_way_symbol_budget: Some(512),
                ..FileTransferConfig::default()
            };

            let report = run_established_pair(
                &mut sender,
                &mut receiver,
                "transient-local-send.bin",
                &source,
                config,
                MonoNs::ZERO,
                false,
            )
            .unwrap_or_else(|error| panic!("{kind:?} became fatal: {error}"));

            assert_eq!(report.recovered_file, source, "{kind:?}");
            assert_eq!(sender.state(), conet_udp::AssociationState::Ready);
        }
    }

    #[test]
    fn simulated_transfer_fails_the_link_on_hard_send_error() {
        let network = SimNetwork::new();
        network.set_authenticated(true);
        let mut sender = UdpLiEndpoint::new(
            network.transport(0),
            endpoint_config(Role::Initiator, 1_000_000),
        );
        let mut receiver = UdpLiEndpoint::new(
            network.transport(1),
            endpoint_config(Role::Responder, 1_000_000),
        );
        network.fail_next_send_with(0, std::io::ErrorKind::InvalidInput);

        let error = run_established_pair(
            &mut sender,
            &mut receiver,
            "hard-local-send.bin",
            b"hard-local-send",
            FileTransferConfig::default(),
            MonoNs::ZERO,
            false,
        )
        .unwrap_err();
        assert_eq!(error, TransferError::LinkFailed);
    }
}
