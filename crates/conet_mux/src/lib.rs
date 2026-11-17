//! S12 end-host user multiplexer.
//!
//! Several user [`LinkEndpoint`]s share one lower endpoint. A ten-byte network
//! header inside the datagram body identifies the user. The lower link's fixed
//! tag-5 12-byte header is left untouched and never contains a user id.
//! The adapter forwards opaque payload bytes without invoking a block codec.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use conet_core::{
    EnqueueError, EnqueueStatus, HeaderBuf, InvalidReason, LinkEndpoint, LinkReceiver, LinkSender,
    MonoNs, Occupancy, PacketBuilder, PacketHandle, PacketQueue, QueueLimits,
};

/// Small mux network-header magic.
pub const MUX_HEADER_MAGIC: u16 = 0x434d;
/// Mux network-header version.
pub const MUX_HEADER_VERSION: u8 = 1;
/// Network-header length. This is not part of the lower link header.
pub const MUX_HEADER_LEN: usize = 10;

/// Stable local user identity.
pub type UserId = u32;

/// Queue configuration for both sides of one attached user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachLimits {
    pub outbound: QueueLimits,
    pub inbound: QueueLimits,
}

impl AttachLimits {
    pub const fn symmetrical(limits: QueueLimits) -> Self {
        Self {
            outbound: limits,
            inbound: limits,
        }
    }
}

/// One parsed network header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkHeader {
    pub user_id: UserId,
    pub payload_len: usize,
}

/// Fail-closed network-header parse errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkHeaderError {
    TooShort { len: usize },
    BadMagic { value: u16 },
    UnsupportedVersion { value: u8 },
    ReservedNonZero { value: u8 },
    PayloadLengthMismatch { declared: usize, actual: usize },
}

impl fmt::Display for NetworkHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => write!(f, "mux network header length {len} is too short"),
            Self::BadMagic { value } => write!(f, "bad mux network magic {value:#06x}"),
            Self::UnsupportedVersion { value } => {
                write!(f, "unsupported mux network version {value}")
            }
            Self::ReservedNonZero { value } => {
                write!(f, "mux network reserved byte is {value}")
            }
            Self::PayloadLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "mux network payload length {declared} does not match {actual}"
                )
            }
        }
    }
}

impl std::error::Error for NetworkHeaderError {}

impl NetworkHeader {
    pub const fn new(user_id: UserId, payload_len: usize) -> Self {
        Self {
            user_id,
            payload_len,
        }
    }

    pub fn encode(self) -> Result<HeaderBuf, NetworkHeaderError> {
        let payload_len = u16::try_from(self.payload_len).map_err(|_| {
            NetworkHeaderError::PayloadLengthMismatch {
                declared: self.payload_len,
                actual: u16::MAX as usize,
            }
        })?;
        let mut bytes = Vec::with_capacity(MUX_HEADER_LEN);
        bytes.extend_from_slice(&MUX_HEADER_MAGIC.to_be_bytes());
        bytes.push(MUX_HEADER_VERSION);
        bytes.push(0);
        bytes.extend_from_slice(&self.user_id.to_be_bytes());
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        Ok(HeaderBuf::from_bytes(bytes))
    }

    pub fn parse(bytes: &[u8], actual_payload_len: usize) -> Result<Self, NetworkHeaderError> {
        if bytes.len() < MUX_HEADER_LEN {
            return Err(NetworkHeaderError::TooShort { len: bytes.len() });
        }
        let magic = u16::from_be_bytes([bytes[0], bytes[1]]);
        if magic != MUX_HEADER_MAGIC {
            return Err(NetworkHeaderError::BadMagic { value: magic });
        }
        if bytes[2] != MUX_HEADER_VERSION {
            return Err(NetworkHeaderError::UnsupportedVersion { value: bytes[2] });
        }
        if bytes[3] != 0 {
            return Err(NetworkHeaderError::ReservedNonZero { value: bytes[3] });
        }
        let user_id = UserId::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let payload_len = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
        if payload_len != actual_payload_len {
            return Err(NetworkHeaderError::PayloadLengthMismatch {
                declared: payload_len,
                actual: actual_payload_len,
            });
        }
        Ok(Self {
            user_id,
            payload_len,
        })
    }
}

/// Scheduler metadata presented to the replaceable S12 scheduler port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyUser {
    pub user_id: UserId,
    pub queued_packets: usize,
}

/// Narrow S13 replacement point for per-user send scheduling.
pub trait SchedulerPort: Send {
    fn on_enqueue(&mut self, user_id: UserId);
    fn on_detach(&mut self, user_id: UserId);
    fn select(&mut self, ready: &[ReadyUser]) -> Option<UserId>;
}

impl<T: SchedulerPort + ?Sized> SchedulerPort for Box<T> {
    fn on_enqueue(&mut self, user_id: UserId) {
        (**self).on_enqueue(user_id);
    }

    fn on_detach(&mut self, user_id: UserId) {
        (**self).on_detach(user_id);
    }

    fn select(&mut self, ready: &[ReadyUser]) -> Option<UserId> {
        (**self).select(ready)
    }
}

/// Placeholder FIFO/round-robin scheduler.
#[derive(Debug, Default)]
pub struct RoundRobinScheduler {
    ready: VecDeque<UserId>,
    queued: HashSet<UserId>,
}

impl SchedulerPort for RoundRobinScheduler {
    fn on_enqueue(&mut self, user_id: UserId) {
        if self.queued.insert(user_id) {
            self.ready.push_back(user_id);
        }
    }

    fn on_detach(&mut self, user_id: UserId) {
        self.queued.remove(&user_id);
        self.ready.retain(|candidate| *candidate != user_id);
    }

    fn select(&mut self, ready: &[ReadyUser]) -> Option<UserId> {
        while let Some(user_id) = self.ready.pop_front() {
            let Some(entry) = ready.iter().find(|entry| entry.user_id == user_id) else {
                self.queued.remove(&user_id);
                continue;
            };
            if entry.queued_packets == 0 {
                self.queued.remove(&user_id);
                continue;
            }
            self.ready.push_back(user_id);
            return Some(user_id);
        }
        None
    }
}

/// Declarative shares for the hop-level [`TreeScheduler`].
///
/// This is a service-share tree over attached mux users (weights for fair
/// scheduling among users on one lower hop).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerNode {
    User {
        user_id: UserId,
        weight: u64,
    },
    Group {
        weight: u64,
        children: Vec<SchedulerNode>,
    },
}

impl SchedulerNode {
    pub const fn user(user_id: UserId, weight: u64) -> Self {
        Self::User { user_id, weight }
    }

    pub fn group(weight: u64, children: impl IntoIterator<Item = Self>) -> Self {
        Self::Group {
            weight,
            children: children.into_iter().collect(),
        }
    }
}

/// Alias used by callers that think of the configuration as a share tree.
pub type ShareTree = SchedulerNode;

#[derive(Debug)]
enum ScheduleNode {
    User {
        user_id: UserId,
        weight: u64,
        service: u128,
    },
    Group {
        weight: u64,
        service: u128,
        next_child: usize,
        children: Vec<ScheduleNode>,
    },
}

impl ScheduleNode {
    fn from_config(node: SchedulerNode) -> Self {
        match node {
            SchedulerNode::User { user_id, weight } => Self::User {
                user_id,
                weight: weight.max(1),
                service: 0,
            },
            SchedulerNode::Group { weight, children } => Self::Group {
                weight: weight.max(1),
                service: 0,
                next_child: 0,
                children: children.into_iter().map(Self::from_config).collect(),
            },
        }
    }

    fn contains_user(&self, user_id: UserId) -> bool {
        match self {
            Self::User {
                user_id: candidate, ..
            } => *candidate == user_id,
            Self::Group { children, .. } => {
                children.iter().any(|child| child.contains_user(user_id))
            }
        }
    }

    fn is_ready(&self, ready: &[ReadyUser], detached: &HashSet<UserId>) -> bool {
        match self {
            Self::User { user_id, .. } => {
                !detached.contains(user_id)
                    && ready
                        .iter()
                        .any(|entry| entry.user_id == *user_id && entry.queued_packets > 0)
            }
            Self::Group { children, .. } => {
                children.iter().any(|child| child.is_ready(ready, detached))
            }
        }
    }

    fn select(&mut self, ready: &[ReadyUser], detached: &HashSet<UserId>) -> Option<UserId> {
        match self {
            Self::User {
                user_id, service, ..
            } => {
                if detached.contains(user_id) {
                    return None;
                }
                *service = service.saturating_add(1);
                Some(*user_id)
            }
            Self::Group {
                children,
                service,
                next_child,
                ..
            } => {
                let mut selected = None;
                for (index, child) in children.iter().enumerate() {
                    if !child.is_ready(ready, detached) {
                        continue;
                    }
                    let (child_service, weight) = match child {
                        Self::User {
                            weight, service, ..
                        } => (*service, *weight),
                        Self::Group {
                            weight,
                            service: child_service,
                            ..
                        } => (*child_service, *weight),
                    };
                    let better = match selected {
                        None => true,
                        Some(current) => {
                            let (current_service, current_weight) = match &children[current] {
                                Self::User {
                                    weight, service, ..
                                } => (*service, *weight),
                                Self::Group {
                                    weight,
                                    service: child_service,
                                    ..
                                } => (*child_service, *weight),
                            };
                            let candidate_scaled =
                                child_service.saturating_mul(current_weight as u128);
                            let current_scaled = current_service.saturating_mul(weight as u128);
                            if candidate_scaled != current_scaled {
                                candidate_scaled < current_scaled
                            } else {
                                let candidate_distance =
                                    (index + children.len() - *next_child) % children.len();
                                let current_distance =
                                    (current + children.len() - *next_child) % children.len();
                                candidate_distance < current_distance
                            }
                        }
                    };
                    if better {
                        selected = Some(index);
                    }
                }
                let index = selected?;
                *service = service.saturating_add(1);
                *next_child = (index + 1) % children.len();
                children[index].select(ready, detached)
            }
        }
    }
}

/// Hierarchical weighted fair scheduler for the shared mux hop.
///
/// A selection walks from the root toward a ready leaf. At every group, the
/// child with the lowest accumulated service divided by its weight wins.
/// Equal ties rotate. The synthetic root supplies equal shares for users that
/// are not present in a custom tree, so [`TreeScheduler::default`] is a
/// dynamic equal-share tree.
#[derive(Debug)]
pub struct TreeScheduler {
    root: ScheduleNode,
    detached: HashSet<UserId>,
}

impl Default for TreeScheduler {
    fn default() -> Self {
        Self {
            root: ScheduleNode::from_config(SchedulerNode::group(1, [])),
            detached: HashSet::new(),
        }
    }
}

impl TreeScheduler {
    /// Build a scheduler from a declarative root. Zero weights are treated as
    /// one. Users omitted from the tree are added as equal root leaves when
    /// they first become ready.
    pub fn new(root: SchedulerNode) -> Self {
        let mut root = ScheduleNode::from_config(root);
        if matches!(root, ScheduleNode::User { .. }) {
            root = ScheduleNode::Group {
                weight: 1,
                service: 0,
                next_child: 0,
                children: vec![root],
            };
        }
        Self {
            root,
            detached: HashSet::new(),
        }
    }

    pub fn equal() -> Self {
        Self::default()
    }

    pub fn from_users(users: impl IntoIterator<Item = UserId>) -> Self {
        Self::new(SchedulerNode::group(
            1,
            users
                .into_iter()
                .map(|user_id| SchedulerNode::user(user_id, 1)),
        ))
    }

    pub fn from_weighted_users(users: impl IntoIterator<Item = (UserId, u64)>) -> Self {
        Self::new(SchedulerNode::group(
            1,
            users
                .into_iter()
                .map(|(user_id, weight)| SchedulerNode::user(user_id, weight)),
        ))
    }

    fn admit(&mut self, user_id: UserId) {
        self.detached.remove(&user_id);
        if self.root.contains_user(user_id) {
            return;
        }
        let ScheduleNode::Group { children, .. } = &mut self.root else {
            unreachable!("scheduler root is always a group");
        };
        children.push(ScheduleNode::from_config(SchedulerNode::user(user_id, 1)));
    }
}

impl SchedulerPort for TreeScheduler {
    fn on_enqueue(&mut self, user_id: UserId) {
        self.admit(user_id);
    }

    fn on_detach(&mut self, user_id: UserId) {
        self.detached.insert(user_id);
    }

    fn select(&mut self, ready: &[ReadyUser]) -> Option<UserId> {
        for entry in ready {
            if entry.queued_packets > 0 && !self.detached.contains(&entry.user_id) {
                self.admit(entry.user_id);
            }
        }
        self.root.select(ready, &self.detached)
    }
}

/// Attach failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachError {
    DuplicateUser(UserId),
    Closed,
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateUser(user_id) => write!(f, "user {user_id} is already attached"),
            Self::Closed => f.write_str("mux is closed"),
        }
    }
}

impl std::error::Error for AttachError {}

/// Per-program local attach failure.
#[derive(Debug)]
pub enum ProgramAttachError {
    DuplicateUser(UserId),
    Closed,
    Io(io::Error),
}

impl fmt::Display for ProgramAttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateUser(user_id) => write!(f, "user {user_id} is already attached"),
            Self::Closed => f.write_str("mux is closed"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ProgramAttachError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

struct LocalServer {
    socket: UnixDatagram,
    path: PathBuf,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct UserQueues {
    outbound: PacketQueue,
    inbound: PacketQueue,
    local: Option<LocalServer>,
}

struct MuxShared {
    users: BTreeMap<UserId, UserQueues>,
    scheduler: Box<dyn SchedulerPort>,
    closed: bool,
    dropped_unknown: u64,
    dropped_inbound_backpressure: u64,
    dropped_malformed: u64,
}

impl MuxShared {
    fn user(&self, user_id: UserId) -> Option<&UserQueues> {
        self.users.get(&user_id)
    }

    fn user_mut(&mut self, user_id: UserId) -> Option<&mut UserQueues> {
        self.users.get_mut(&user_id)
    }

    fn detach(&mut self, user_id: UserId) {
        if let Some(mut user) = self.users.remove(&user_id) {
            user.outbound.close();
            user.inbound.close();
            self.scheduler.on_detach(user_id);
        }
    }
}

fn lock_shared(
    shared: &std::sync::Arc<std::sync::Mutex<MuxShared>>,
) -> std::sync::MutexGuard<'_, MuxShared> {
    shared.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn tag_user_packet(user_id: UserId, pkt: PacketHandle) -> Result<PacketHandle, EnqueueError> {
    let original_len = pkt.len();
    let header = match NetworkHeader::new(user_id, original_len).encode() {
        Ok(header) => header,
        Err(_) => {
            return Err(EnqueueError::Invalid {
                pkt,
                reason: InvalidReason::PacketTooLarge {
                    len: original_len,
                    max: u16::MAX as usize,
                },
            });
        }
    };
    let body_len = match original_len.checked_add(MUX_HEADER_LEN) {
        Some(len) => len,
        None => {
            return Err(EnqueueError::Invalid {
                pkt,
                reason: InvalidReason::PacketTooLarge {
                    len: usize::MAX,
                    max: u16::MAX as usize,
                },
            });
        }
    };
    let mut builder = PacketBuilder::with_capacity(body_len, pkt.header().len());
    let payload = builder.payload_mut();
    payload[..MUX_HEADER_LEN].copy_from_slice(header.as_bytes());
    payload[MUX_HEADER_LEN..].copy_from_slice(pkt.payload_bytes());
    *builder.header_mut() = pkt.header().clone();
    Ok(builder.freeze())
}

/// One in-process user attachment to a mux.
pub struct InProcessMuxEndpoint {
    user_id: UserId,
    shared: std::sync::Arc<std::sync::Mutex<MuxShared>>,
}

impl InProcessMuxEndpoint {
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn detach(self) {
        lock_shared(&self.shared).detach(self.user_id);
    }

    fn enqueue_tagged(&self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        let tagged = tag_user_packet(self.user_id, pkt.fanout())?;
        let mut shared = lock_shared(&self.shared);
        if shared.closed {
            return Err(EnqueueError::Closed { pkt });
        }
        let Some(user) = shared.user_mut(self.user_id) else {
            return Err(EnqueueError::Closed { pkt });
        };
        user.outbound.enqueue(tagged)?;
        shared.scheduler.on_enqueue(self.user_id);
        Ok(EnqueueStatus::Accepted)
    }
}

impl LinkSender for InProcessMuxEndpoint {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        self.enqueue_tagged(pkt)
    }

    fn occupancy(&self) -> Occupancy {
        lock_shared(&self.shared)
            .user(self.user_id)
            .map_or_else(Occupancy::default, |user| user.outbound.occupancy())
    }

    fn close(&mut self) {
        lock_shared(&self.shared).detach(self.user_id);
    }
}

impl LinkReceiver for InProcessMuxEndpoint {
    fn recv(&mut self) -> Option<PacketHandle> {
        lock_shared(&self.shared)
            .user_mut(self.user_id)
            .and_then(|user| user.inbound.dequeue())
    }

    fn occupancy(&self) -> Occupancy {
        lock_shared(&self.shared)
            .user(self.user_id)
            .map_or_else(Occupancy::default, |user| user.inbound.occupancy())
    }
}

impl LinkEndpoint for InProcessMuxEndpoint {
    fn outgoing(&mut self) -> &mut dyn LinkSender {
        self
    }

    fn incoming(&mut self) -> &mut dyn LinkReceiver {
        self
    }

    fn drive(&mut self, _now: MonoNs) {}
}

fn encode_local_frame_into(bytes: &mut Vec<u8>, header: &[u8], payload: &[u8]) -> io::Result<()> {
    let header_len = u16::try_from(header.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "local header too large"))?;
    let capacity = 2_usize
        .checked_add(header.len())
        .and_then(|len| len.checked_add(payload.len()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "local frame too large"))?;
    bytes.clear();
    bytes.reserve(capacity);
    bytes.extend_from_slice(&header_len.to_be_bytes());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(payload);
    Ok(())
}

fn decode_local_packet(bytes: &[u8]) -> io::Result<PacketHandle> {
    if bytes.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local frame is too short",
        ));
    }
    let header_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let payload_start = 2_usize
        .checked_add(header_len)
        .filter(|start| *start <= bytes.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad local header length"))?;
    let mut builder = PacketBuilder::with_capacity(bytes.len() - payload_start, header_len);
    builder
        .payload_mut()
        .copy_from_slice(&bytes[payload_start..]);
    *builder.header_mut() = HeaderBuf::from_bytes(bytes[2..payload_start].to_vec());
    Ok(builder.freeze())
}

fn encode_tagged_local_frame(
    user_id: UserId,
    header: &[u8],
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let header_len = u16::try_from(header.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "local header too large"))?;
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "local payload too large"))?;
    let capacity = 2_usize
        .checked_add(header.len())
        .and_then(|len| len.checked_add(MUX_HEADER_LEN))
        .and_then(|len| len.checked_add(payload.len()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "local frame too large"))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&header_len.to_be_bytes());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&MUX_HEADER_MAGIC.to_be_bytes());
    bytes.push(MUX_HEADER_VERSION);
    bytes.push(0);
    bytes.extend_from_slice(&user_id.to_be_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// One user program's local datagram endpoint up to the mux process.
pub struct ProgramMuxEndpoint {
    socket: UnixDatagram,
    user_id: UserId,
    receive_buf: Vec<u8>,
    send_buf: Vec<u8>,
}

impl ProgramMuxEndpoint {
    pub fn connect(
        local_path: impl AsRef<Path>,
        mux_path: impl AsRef<Path>,
        user_id: UserId,
    ) -> io::Result<Self> {
        let socket = UnixDatagram::bind(local_path)?;
        socket.connect(mux_path)?;
        Ok(Self {
            socket,
            user_id,
            receive_buf: vec![0; u16::MAX as usize + 1024],
            send_buf: Vec::new(),
        })
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }
}

impl LinkSender for ProgramMuxEndpoint {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        let original_len = pkt.len();
        match encode_local_frame_into(
            &mut self.send_buf,
            pkt.header().as_bytes(),
            pkt.payload_bytes(),
        ) {
            Ok(()) => {}
            Err(_) => {
                return Err(EnqueueError::Invalid {
                    pkt,
                    reason: InvalidReason::PacketTooLarge {
                        len: original_len,
                        max: u16::MAX as usize,
                    },
                });
            }
        }
        match self.socket.send(&self.send_buf) {
            Ok(sent) if sent == self.send_buf.len() => Ok(EnqueueStatus::Accepted),
            Ok(_) => Err(EnqueueError::Closed { pkt }),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
                ) =>
            {
                Err(EnqueueError::Full { pkt })
            }
            Err(_) => Err(EnqueueError::Closed { pkt }),
        }
    }

    fn occupancy(&self) -> Occupancy {
        Occupancy::default()
    }

    fn close(&mut self) {
        if let Ok(address) = self.socket.local_addr() {
            if let Some(path) = address.as_pathname() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl LinkReceiver for ProgramMuxEndpoint {
    fn recv(&mut self) -> Option<PacketHandle> {
        loop {
            let len = self.socket.recv(&mut self.receive_buf).ok()?;
            let packet = decode_local_packet(&self.receive_buf[..len]).ok()?;
            if packet.payload_bytes().len() < MUX_HEADER_LEN {
                continue;
            }
            let payload = packet.payload_bytes();
            let Ok(network) =
                NetworkHeader::parse(&payload[..MUX_HEADER_LEN], payload.len() - MUX_HEADER_LEN)
            else {
                continue;
            };
            if network.user_id != self.user_id {
                continue;
            }
            let mut builder =
                PacketBuilder::with_capacity(network.payload_len, packet.header().len());
            builder
                .payload_mut()
                .copy_from_slice(&payload[MUX_HEADER_LEN..]);
            *builder.header_mut() = packet.header().clone();
            return Some(builder.freeze());
        }
    }

    fn occupancy(&self) -> Occupancy {
        Occupancy::default()
    }
}

impl LinkEndpoint for ProgramMuxEndpoint {
    fn outgoing(&mut self) -> &mut dyn LinkSender {
        self
    }

    fn incoming(&mut self) -> &mut dyn LinkReceiver {
        self
    }

    fn drive(&mut self, _now: MonoNs) {}
}

impl Drop for ProgramMuxEndpoint {
    fn drop(&mut self) {
        if let Ok(address) = self.socket.local_addr()
            && let Some(path) = address.as_pathname()
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// One drive's observable mux activity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MuxDriveReport {
    pub received: usize,
    pub delivered: usize,
    pub sent: usize,
    pub backpressured: usize,
    pub dropped_unknown: usize,
    pub dropped_malformed: usize,
    pub dropped_inbound_full: usize,
    /// The lower endpoint's controller hook wakeup after this drive completed.
    pub next_wakeup: Option<MonoNs>,
    /// The lower endpoint's aggregate next-drive deadline after this drive.
    pub next_drive: Option<MonoNs>,
}

/// Multiplexer owning exactly one lower [`LinkEndpoint`].
pub struct Mux<L> {
    lower: L,
    shared: std::sync::Arc<std::sync::Mutex<MuxShared>>,
}

impl<L> Mux<L>
where
    L: LinkEndpoint,
{
    pub fn new(lower: L) -> Self {
        Self::with_scheduler(lower, Box::new(RoundRobinScheduler::default()))
    }

    pub fn with_scheduler(lower: L, scheduler: impl SchedulerPort + 'static) -> Self {
        Self {
            lower,
            shared: std::sync::Arc::new(std::sync::Mutex::new(MuxShared {
                users: BTreeMap::new(),
                scheduler: Box::new(scheduler),
                closed: false,
                dropped_unknown: 0,
                dropped_inbound_backpressure: 0,
                dropped_malformed: 0,
            })),
        }
    }

    pub fn attach(
        &self,
        user_id: UserId,
        limits: AttachLimits,
    ) -> Result<InProcessMuxEndpoint, AttachError> {
        let mut shared = lock_shared(&self.shared);
        if shared.closed {
            return Err(AttachError::Closed);
        }
        if shared.users.contains_key(&user_id) {
            return Err(AttachError::DuplicateUser(user_id));
        }
        shared.users.insert(
            user_id,
            UserQueues {
                outbound: PacketQueue::new(limits.outbound),
                inbound: PacketQueue::new(limits.inbound),
                local: None,
            },
        );
        Ok(InProcessMuxEndpoint {
            user_id,
            shared: std::sync::Arc::clone(&self.shared),
        })
    }

    /// Bind one local Unix-datagram attachment. The returned path is owned by
    /// the mux until the user is detached or the mux is dropped.
    pub fn attach_program(
        &self,
        user_id: UserId,
        path: impl AsRef<Path>,
        limits: AttachLimits,
    ) -> Result<(), ProgramAttachError> {
        let mut shared = lock_shared(&self.shared);
        if shared.closed {
            return Err(ProgramAttachError::Closed);
        }
        if shared.users.contains_key(&user_id) {
            return Err(ProgramAttachError::DuplicateUser(user_id));
        }
        let path = path.as_ref().to_path_buf();
        let socket = UnixDatagram::bind(&path).map_err(ProgramAttachError::Io)?;
        socket
            .set_nonblocking(true)
            .map_err(ProgramAttachError::Io)?;
        shared.users.insert(
            user_id,
            UserQueues {
                outbound: PacketQueue::new(limits.outbound),
                inbound: PacketQueue::new(limits.inbound),
                local: Some(LocalServer { socket, path }),
            },
        );
        Ok(())
    }

    pub fn attached_users(&self) -> Vec<UserId> {
        lock_shared(&self.shared).users.keys().copied().collect()
    }

    pub fn dropped_unknown(&self) -> u64 {
        lock_shared(&self.shared).dropped_unknown
    }

    pub fn dropped_malformed(&self) -> u64 {
        lock_shared(&self.shared).dropped_malformed
    }

    /// The lower endpoint's currently armed controller hook wakeup, if any.
    pub fn next_wakeup(&self) -> Option<MonoNs> {
        self.lower.next_wakeup()
    }

    /// The lower endpoint's aggregate next-drive deadline, if any.
    pub fn next_drive(&self) -> Option<MonoNs> {
        self.lower.next_drive()
    }

    /// Drain inbound lower datagrams, then admit user datagrams to the one
    /// lower sender. A lower `Full` result returns the packet to its user queue.
    pub fn drive(&mut self, now: MonoNs, max_lower_packets: usize) -> MuxDriveReport {
        let mut report = MuxDriveReport::default();

        let mut local_inputs = Vec::new();
        {
            let shared = lock_shared(&self.shared);
            let mut buf = vec![0; u16::MAX as usize + 1024];
            for (user_id, user) in &shared.users {
                let Some(local) = &user.local else {
                    continue;
                };
                while let Ok((len, peer)) = local.socket.recv_from(&mut buf) {
                    if local.socket.peer_addr().is_err()
                        && let Some(peer_path) = peer.as_pathname()
                    {
                        let _ = local.socket.connect(peer_path);
                    }
                    local_inputs.push((*user_id, buf[..len].to_vec()));
                }
            }
        }
        for (user_id, frame) in local_inputs {
            let pkt = match decode_local_packet(&frame) {
                Ok(packet) => packet,
                Err(_) => {
                    lock_shared(&self.shared).dropped_malformed += 1;
                    report.dropped_malformed += 1;
                    continue;
                }
            };
            let tagged = match tag_user_packet(user_id, pkt) {
                Ok(tagged) => tagged,
                Err(_) => {
                    lock_shared(&self.shared).dropped_malformed += 1;
                    report.dropped_malformed += 1;
                    continue;
                }
            };
            let mut shared = lock_shared(&self.shared);
            let Some(user) = shared.user_mut(user_id) else {
                continue;
            };
            match user.outbound.enqueue(tagged) {
                Ok(_) => shared.scheduler.on_enqueue(user_id),
                Err(_) => {
                    report.backpressured += 1;
                }
            }
        }

        for _ in 0..max_lower_packets {
            let Some(pkt) = self.lower.incoming().recv() else {
                break;
            };
            report.received += 1;
            let bytes = pkt.payload_bytes();
            if bytes.len() < MUX_HEADER_LEN {
                lock_shared(&self.shared).dropped_malformed += 1;
                report.dropped_malformed += 1;
                continue;
            }
            let header = match NetworkHeader::parse(bytes, bytes.len() - MUX_HEADER_LEN) {
                Ok(header) => header,
                Err(_) => {
                    lock_shared(&self.shared).dropped_malformed += 1;
                    report.dropped_malformed += 1;
                    continue;
                }
            };
            let payload = match pkt.slice(MUX_HEADER_LEN, header.payload_len) {
                Ok(payload) => payload,
                Err(_) => {
                    lock_shared(&self.shared).dropped_malformed += 1;
                    report.dropped_malformed += 1;
                    continue;
                }
            };
            let mut shared = lock_shared(&self.shared);
            let Some(user) = shared.user_mut(header.user_id) else {
                shared.dropped_unknown += 1;
                report.dropped_unknown += 1;
                continue;
            };
            match user.inbound.enqueue(payload) {
                Ok(_) => report.delivered += 1,
                Err(_) => {
                    shared.dropped_inbound_backpressure += 1;
                    report.dropped_inbound_full += 1;
                }
            }
        }

        {
            let mut shared = lock_shared(&self.shared);
            for (user_id, user) in &mut shared.users {
                let Some(local) = &user.local else {
                    continue;
                };
                while let Some(pkt) = user.inbound.dequeue() {
                    let frame = encode_tagged_local_frame(
                        *user_id,
                        pkt.header().as_bytes(),
                        pkt.payload_bytes(),
                    )
                    .expect("lower payload fits the mux network header");
                    match local.socket.send(&frame) {
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
                            ) =>
                        {
                            user.inbound
                                .enqueue(pkt)
                                .expect("dequeued local slot is available again");
                            report.backpressured += 1;
                            break;
                        }
                        Err(_) => {
                            report.backpressured += 1;
                        }
                    }
                }
            }
        }

        for _ in 0..max_lower_packets {
            let selected = {
                let mut shared = lock_shared(&self.shared);
                let ready: Vec<_> = shared
                    .users
                    .iter()
                    .map(|(user_id, user)| ReadyUser {
                        user_id: *user_id,
                        queued_packets: user.outbound.len(),
                    })
                    .collect();
                let Some(user_id) = shared.scheduler.select(&ready) else {
                    break;
                };
                let Some(user) = shared.user_mut(user_id) else {
                    break;
                };
                user.outbound.dequeue()
            };
            let Some(pkt) = selected else {
                continue;
            };
            match self.lower.outgoing().enqueue(pkt) {
                Ok(_) => report.sent += 1,
                Err(error) => {
                    report.backpressured += 1;
                    let pkt = error.into_packet();
                    let user_id = NetworkHeader::parse(
                        &pkt.payload_bytes()[..MUX_HEADER_LEN],
                        pkt.len() - MUX_HEADER_LEN,
                    )
                    .map(|header| header.user_id)
                    .expect("mux-generated network headers stay valid");
                    lock_shared(&self.shared)
                        .user_mut(user_id)
                        .expect("selected user remains attached")
                        .outbound
                        .enqueue(pkt)
                        .expect("dequeued user slot is available again");
                    break;
                }
            }
        }

        self.lower.drive(now);
        report.next_wakeup = self.lower.next_wakeup();
        report.next_drive = self.lower.next_drive();
        report
    }

    pub fn close(&mut self) {
        {
            let mut shared = lock_shared(&self.shared);
            shared.closed = true;
            for user in shared.users.values_mut() {
                user.outbound.close();
                user.inbound.close();
            }
            shared.users.clear();
        }
        self.lower.outgoing().close();
    }
}

impl<L> Drop for Mux<L> {
    fn drop(&mut self) {
        let mut shared = lock_shared(&self.shared);
        shared.closed = true;
        for user in shared.users.values_mut() {
            user.outbound.close();
            user.inbound.close();
        }
    }
}
