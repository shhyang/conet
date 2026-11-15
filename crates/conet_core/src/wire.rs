//! Profile-local reference wire parser, serializer, and opaque control container.
//!
//! This module implements the illustrative packed big-endian layout tag `5`
//! from the implementation design. It is a testable profile choice, not a
//! published standard. The fixed link header is:
//!
//! ```text
//!  0 u16 magic (0x554c)       2 u8 version (5)
//!  3 u8 flags                 4 u32 link_seq
//!  8 u16 payload_len         10 u16 epoch
//! 12 body, then optional link-control trailer
//! ```
//!
//! Flag bits 0-2 are the link-local QoS class; bits 3-7 must be zero. QoS is a
//! scheduling label, not a payload class or demux field. A control trailer
//! exists exactly when bytes remain after `payload_len` body bytes. Association
//! controls use `u8 ctrl_type, u32 ctrl_seq, body[remaining]`; CC controls use
//! `u8 ctrl_type, opaque_body[remaining]`. The type byte selects the layout, so
//! no controller-private bytes are parsed by the link and the fixed 12-byte
//! header does not change.
//!
//! Reliability content is carried in the user body. [`ReliabilityDataContent`]
//! and the reliability-feedback helpers below encode only reliability fields;
//! they do not stack the in-process `OCNR` framing or repeat per-block shape
//! metadata on every symbol.

use core::fmt;

use crate::accounting::PacketMetrics;
use crate::control::OpaqueBytes;
use crate::packet::{HeaderBuf, PacketHandle};
use crate::reliability::{BlockId, Feedback, FeedbackKind, SymbolId};

/// Length of the fixed reference-profile link header.
pub const REFERENCE_WIRE_HEADER_LEN: usize = 12;
/// Reference-profile magic value.
pub const REFERENCE_WIRE_MAGIC: u16 = 0x554c;
/// Reference-profile layout version tag.
pub const REFERENCE_WIRE_VERSION: u8 = 5;
/// Reliability DATA prefix length in the user body.
pub const RELIABILITY_DATA_PREFIX_LEN: usize = 16;
/// Reliability FEEDBACK content length in the user body.
pub const RELIABILITY_FEEDBACK_LEN: usize = 17;

const QOS_MASK: u8 = 0b111;
const RESERVED_FLAG_BITS: u8 = 0b1111_1000;
const CONTROL_TRAILER_PREFIX_LEN: usize = 5;

const FEEDBACK_KIND_ACK: u8 = 1;
const FEEDBACK_KIND_NACK: u8 = 2;

/// Link-local QoS/scheduling class.
///
/// These labels express intended send priority. They do not identify payload
/// layout, file data, ACK, NACK, or link-control. Demux uses `payload_len`, and
/// ACK versus NACK belongs to [`FeedbackKind`] inside the reliability body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum QosClass {
    #[default]
    Bulk = 0,
    Feedback = 1,
    Control = 2,
}

impl QosClass {
    pub const fn wire_value(self) -> u8 {
        self as u8
    }

    fn from_wire(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::Bulk),
            1 => Ok(Self::Feedback),
            2 => Ok(Self::Control),
            _ => Err(WireError::UnknownQosClass { value }),
        }
    }
}

/// Link-control container type understood by the reference profile.
///
/// Names identify containers only. Their bodies are opaque in S6; association
/// state and controller-message interpretation are later slices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ControlType {
    Open = 1,
    Accept = 2,
    Close = 3,
    CloseAck = 4,
    CcOpaque = 5,
    Cc = 6,
}

impl ControlType {
    pub const fn wire_value(self) -> u8 {
        self as u8
    }

    fn from_wire(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Accept),
            3 => Ok(Self::Close),
            4 => Ok(Self::CloseAck),
            5 => Ok(Self::CcOpaque),
            6 => Ok(Self::Cc),
            _ => Err(WireError::UnknownControlType { value }),
        }
    }

    /// Whether this control type is sequenced by the hop-by-hop link window.
    pub const fn has_link_seq(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Accept | Self::Close | Self::CloseAck
        )
    }

    /// Whether this control type carries controller-private opaque bytes.
    pub const fn is_cc(self) -> bool {
        matches!(self, Self::CcOpaque | Self::Cc)
    }
}

/// Decoded link-header flag fields.
///
/// Bits 3-7 are not representable and must be zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireFlags {
    pub qos: QosClass,
}

impl WireFlags {
    const fn encode(self) -> u8 {
        self.qos.wire_value() & QOS_MASK
    }

    fn decode(flags: u8) -> Result<Self, WireError> {
        let reserved = flags & RESERVED_FLAG_BITS;
        if reserved != 0 {
            return Err(WireError::UnknownFlagBits { bits: reserved });
        }
        Ok(Self {
            qos: QosClass::from_wire(flags & QOS_MASK)?,
        })
    }
}

/// Link fields carried by every reference-profile datagram class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader {
    pub flags: WireFlags,
    pub epoch: u16,
    pub link_seq: u32,
    pub payload_len: u16,
}

/// One opaque link-control trailer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlMessage {
    pub ctrl_type: ControlType,
    /// Link-control sequence, present only for [`ControlType::has_link_seq`].
    pub ctrl_seq: Option<u32>,
    pub body: OpaqueBytes,
}

impl ControlMessage {
    /// Construct a trailer. The sequence is discarded for CC trailer types:
    /// their retransmission/replay identity belongs inside `body`.
    pub fn new(ctrl_type: ControlType, ctrl_seq: u32, body: OpaqueBytes) -> Self {
        Self {
            ctrl_type,
            ctrl_seq: ctrl_type.has_link_seq().then_some(ctrl_seq),
            body,
        }
    }

    /// Construct a controller-private CC trailer without a link sequence.
    pub fn cc(ctrl_type: ControlType, body: OpaqueBytes) -> Self {
        Self {
            ctrl_type,
            ctrl_seq: None,
            body,
        }
    }

    /// Link-sequenced control identity, absent for CC trailers.
    pub const fn link_seq(&self) -> Option<u32> {
        self.ctrl_seq
    }
}

/// Decoded profile limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLimits {
    pub max_datagram: usize,
    pub max_control_body: usize,
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_datagram: 1280,
            max_control_body: 256,
        }
    }
}

/// Decoded reliability DATA content from a user body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReliabilityDataContent {
    pub block_id: BlockId,
    pub rel_seq: SymbolId,
    pub coded_vector: OpaqueBytes,
}

/// Reliability-content parse failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReliabilityContentError {
    DataTooShort { len: usize },
    MissingCodedVector,
    FeedbackTooShort { len: usize },
    FeedbackHasTrailingBytes { len: usize },
    UnknownFeedbackKind { value: u8 },
}

impl ReliabilityContentError {
    /// Stable metric label for malformed reliability content.
    pub const fn drop_reason(self) -> &'static str {
        match self {
            Self::DataTooShort { .. } => "reliability_data_too_short",
            Self::MissingCodedVector => "reliability_data_missing_coded_vector",
            Self::FeedbackTooShort { .. } => "reliability_feedback_too_short",
            Self::FeedbackHasTrailingBytes { .. } => "reliability_feedback_trailing_bytes",
            Self::UnknownFeedbackKind { .. } => "unknown_feedback_kind",
        }
    }
}

impl fmt::Display for ReliabilityContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataTooShort { len } => {
                write!(
                    f,
                    "reliability DATA length {len} is shorter than its prefix"
                )
            }
            Self::MissingCodedVector => f.write_str("reliability DATA has no coded vector"),
            Self::FeedbackTooShort { len } => {
                write!(f, "reliability FEEDBACK length {len} is too short")
            }
            Self::FeedbackHasTrailingBytes { len } => {
                write!(
                    f,
                    "reliability FEEDBACK has {len} unexpected trailing bytes"
                )
            }
            Self::UnknownFeedbackKind { value } => {
                write!(f, "unknown reliability feedback kind {value}")
            }
        }
    }
}

impl std::error::Error for ReliabilityContentError {}

/// Encode a DATA user body as `block_id u64, rel_seq u64, coded vector`.
///
/// Coding-scheme id and block shape are deliberately absent: they are
/// session- or block-scoped metadata, not per-symbol wire fields.
pub fn encode_reliability_data(
    block_id: BlockId,
    rel_seq: SymbolId,
    coded_vector: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(RELIABILITY_DATA_PREFIX_LEN + coded_vector.len());
    body.extend_from_slice(&block_id.get().to_be_bytes());
    body.extend_from_slice(&rel_seq.get().to_be_bytes());
    body.extend_from_slice(coded_vector);
    body
}

/// Decode a DATA user body. The remainder after the fixed prefix is the coded
/// vector; the link codec does not parse it.
pub fn decode_reliability_data(
    body: OpaqueBytes,
) -> Result<ReliabilityDataContent, ReliabilityContentError> {
    if body.len() < RELIABILITY_DATA_PREFIX_LEN {
        return Err(ReliabilityContentError::DataTooShort { len: body.len() });
    }
    if body.len() == RELIABILITY_DATA_PREFIX_LEN {
        return Err(ReliabilityContentError::MissingCodedVector);
    }
    Ok(ReliabilityDataContent {
        block_id: BlockId::new(u64::from_be_bytes(
            body[0..8].try_into().expect("fixed reliability prefix"),
        )),
        rel_seq: SymbolId::new(u64::from_be_bytes(
            body[8..16].try_into().expect("fixed reliability prefix"),
        )),
        coded_vector: body.slice(RELIABILITY_DATA_PREFIX_LEN..),
    })
}

/// Encode reliability feedback without the in-process `OCNR` framing.
///
/// Packing: `kind u8, block_id u64, packets_received u32,
/// requested_additional u32`, all big-endian.
pub fn encode_reliability_feedback(feedback: Feedback) -> Vec<u8> {
    let mut body = Vec::with_capacity(RELIABILITY_FEEDBACK_LEN);
    body.push(match feedback.kind {
        FeedbackKind::Ack => FEEDBACK_KIND_ACK,
        FeedbackKind::Nack => FEEDBACK_KIND_NACK,
    });
    body.extend_from_slice(&feedback.block_id.get().to_be_bytes());
    body.extend_from_slice(&feedback.packets_received_count.to_be_bytes());
    body.extend_from_slice(&feedback.requested_additional.to_be_bytes());
    body
}

/// Decode reliability feedback from a FEEDBACK user body.
pub fn decode_reliability_feedback(body: OpaqueBytes) -> Result<Feedback, ReliabilityContentError> {
    if body.len() < RELIABILITY_FEEDBACK_LEN {
        return Err(ReliabilityContentError::FeedbackTooShort { len: body.len() });
    }
    if body.len() > RELIABILITY_FEEDBACK_LEN {
        return Err(ReliabilityContentError::FeedbackHasTrailingBytes {
            len: body.len() - RELIABILITY_FEEDBACK_LEN,
        });
    }
    let kind = match body[0] {
        FEEDBACK_KIND_ACK => FeedbackKind::Ack,
        FEEDBACK_KIND_NACK => FeedbackKind::Nack,
        value => return Err(ReliabilityContentError::UnknownFeedbackKind { value }),
    };
    Ok(Feedback {
        block_id: BlockId::new(u64::from_be_bytes(
            body[1..9].try_into().expect("fixed feedback content"),
        )),
        kind,
        packets_received_count: u32::from_be_bytes(
            body[9..13].try_into().expect("fixed feedback content"),
        ),
        requested_additional: u32::from_be_bytes(
            body[13..17].try_into().expect("fixed feedback content"),
        ),
    })
}

/// A validated datagram handle plus its demultiplexed opaque control sidecar.
///
/// The packet payload view contains only the user body. A trailer is kept
/// separately and can be serialized again without interpreting its body.
#[derive(Debug)]
pub struct WireDatagram {
    packet: PacketHandle,
    header: WireHeader,
    control: Option<ControlMessage>,
}

impl WireDatagram {
    pub fn packet(&self) -> &PacketHandle {
        &self.packet
    }

    pub fn header(&self) -> &WireHeader {
        &self.header
    }

    pub fn control(&self) -> Option<&ControlMessage> {
        self.control.as_ref()
    }

    pub fn into_packet(self) -> PacketHandle {
        self.packet
    }

    pub fn into_parts(self) -> (PacketHandle, WireHeader, Option<ControlMessage>) {
        (self.packet, self.header, self.control)
    }
}

/// Reference-profile parser/serializer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceWireCodec {
    limits: WireLimits,
}

impl Default for ReferenceWireCodec {
    fn default() -> Self {
        Self {
            limits: WireLimits::default(),
        }
    }
}

impl ReferenceWireCodec {
    pub const fn new(limits: WireLimits) -> Self {
        Self { limits }
    }

    pub const fn limits(&self) -> WireLimits {
        self.limits
    }

    /// Validate a complete datagram before freezing its accepted payload.
    ///
    /// All parsing is complete before a `PacketHandle` is constructed. Invalid
    /// input therefore cannot escape as a frozen handle or payload view.
    pub fn parse(&self, datagram: OpaqueBytes) -> Result<WireDatagram, WireError> {
        self.parse_with_metrics(datagram, PacketMetrics::default())
    }

    pub fn parse_with_metrics(
        &self,
        datagram: OpaqueBytes,
        metrics: PacketMetrics,
    ) -> Result<WireDatagram, WireError> {
        let datagram_len = datagram.len();
        if datagram_len > self.limits.max_datagram {
            return Err(WireError::DatagramTooLarge {
                len: datagram_len,
                max: self.limits.max_datagram,
            });
        }
        if datagram_len < REFERENCE_WIRE_HEADER_LEN {
            return Err(WireError::HeaderTooShort { len: datagram_len });
        }

        let magic = read_u16(&datagram, 0);
        if magic != REFERENCE_WIRE_MAGIC {
            return Err(WireError::BadMagic { value: magic });
        }
        let version = datagram[2];
        if version != REFERENCE_WIRE_VERSION {
            return Err(WireError::UnsupportedVersion { value: version });
        }

        let wire_flags = WireFlags::decode(datagram[3])?;
        let payload_len = read_u16(&datagram, 8) as usize;
        let body_and_trailer_len = datagram_len - REFERENCE_WIRE_HEADER_LEN;
        if payload_len > body_and_trailer_len {
            return Err(WireError::PayloadLengthMismatch {
                declared: payload_len,
                actual: body_and_trailer_len,
            });
        }
        let payload_end = REFERENCE_WIRE_HEADER_LEN + payload_len;
        let trailer_len = datagram_len - payload_end;
        if payload_len == 0 && trailer_len == 0 {
            return Err(WireError::EmptyDatagram);
        }

        let control = if trailer_len == 0 {
            None
        } else {
            if trailer_len < 1 {
                return Err(WireError::ControlTooShort { len: trailer_len });
            }
            let ctrl_type = ControlType::from_wire(datagram[payload_end])?;
            let prefix_len = if ctrl_type.has_link_seq() {
                CONTROL_TRAILER_PREFIX_LEN
            } else {
                1
            };
            if trailer_len < prefix_len {
                return Err(WireError::ControlTooShort { len: trailer_len });
            }
            let ctrl_seq = ctrl_type
                .has_link_seq()
                .then(|| read_u32(&datagram, payload_end + 1));
            let body_start = payload_end + prefix_len;
            let control_body_len = datagram_len - body_start;
            if control_body_len > self.limits.max_control_body {
                return Err(WireError::ControlBodyTooLarge {
                    len: control_body_len,
                    max: self.limits.max_control_body,
                });
            }
            Some(ControlMessage {
                ctrl_type,
                ctrl_seq,
                body: datagram.slice(body_start..),
            })
        };

        let header = WireHeader {
            flags: wire_flags,
            epoch: read_u16(&datagram, 10),
            link_seq: read_u32(&datagram, 4),
            payload_len: payload_len as u16,
        };
        let header_bytes =
            HeaderBuf::from_bytes(datagram.slice(..REFERENCE_WIRE_HEADER_LEN).to_vec());
        let payload = datagram.slice(REFERENCE_WIRE_HEADER_LEN..payload_end);
        let packet =
            PacketHandle::from_shared_payload(payload, datagram_len, header_bytes, metrics);

        Ok(WireDatagram {
            packet,
            header,
            control,
        })
    }

    /// Construct a validated handle and optional opaque control sidecar.
    ///
    /// `payload_len` in `header` is canonicalized from the supplied payload.
    pub fn build(
        &self,
        header: WireHeader,
        payload: OpaqueBytes,
        control: Option<ControlMessage>,
    ) -> Result<WireDatagram, WireError> {
        self.build_with_metrics(header, payload, control, PacketMetrics::default())
    }

    pub fn build_with_metrics(
        &self,
        mut header: WireHeader,
        payload: OpaqueBytes,
        control: Option<ControlMessage>,
        metrics: PacketMetrics,
    ) -> Result<WireDatagram, WireError> {
        let payload_len = u16::try_from(payload.len())
            .map_err(|_| WireError::PayloadTooLarge { len: payload.len() })?;
        header.payload_len = payload_len;
        if payload.is_empty() && control.is_none() {
            return Err(WireError::EmptyDatagram);
        }
        validate_control(&control, self.limits)?;

        let trailer_len = control_trailer_len(&control)?;
        let total_len = REFERENCE_WIRE_HEADER_LEN
            .checked_add(payload.len())
            .and_then(|len| len.checked_add(trailer_len))
            .ok_or(WireError::DatagramTooLarge {
                len: usize::MAX,
                max: self.limits.max_datagram,
            })?;
        if total_len > self.limits.max_datagram {
            return Err(WireError::DatagramTooLarge {
                len: total_len,
                max: self.limits.max_datagram,
            });
        }

        let header_bytes = encode_header(&header);
        let packet = PacketHandle::from_shared_payload(
            payload,
            payload_len as usize,
            HeaderBuf::from_bytes(header_bytes.to_vec()),
            metrics,
        );
        Ok(WireDatagram {
            packet,
            header,
            control,
        })
    }

    /// Serialize a validated handle and optional opaque control trailer.
    pub fn serialize(&self, datagram: &WireDatagram) -> Result<Vec<u8>, WireError> {
        if datagram.packet.is_empty() && datagram.control.is_none() {
            return Err(WireError::EmptyDatagram);
        }
        validate_control(&datagram.control, self.limits)?;
        if datagram.packet.header().as_bytes() != encode_header(&datagram.header) {
            return Err(WireError::HeaderMismatch);
        }

        let trailer_len = control_trailer_len(&datagram.control)?;
        let total_len = REFERENCE_WIRE_HEADER_LEN
            .checked_add(datagram.packet.len())
            .and_then(|len| len.checked_add(trailer_len))
            .ok_or(WireError::DatagramTooLarge {
                len: usize::MAX,
                max: self.limits.max_datagram,
            })?;
        if total_len > self.limits.max_datagram {
            return Err(WireError::DatagramTooLarge {
                len: total_len,
                max: self.limits.max_datagram,
            });
        }

        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&encode_header(&datagram.header));
        bytes.extend_from_slice(datagram.packet.payload_bytes());
        if let Some(message) = &datagram.control {
            bytes.push(message.ctrl_type.wire_value());
            if let Some(ctrl_seq) = message.ctrl_seq {
                bytes.extend_from_slice(&ctrl_seq.to_be_bytes());
            }
            bytes.extend_from_slice(&message.body);
        }
        Ok(bytes)
    }
}

fn validate_control(control: &Option<ControlMessage>, limits: WireLimits) -> Result<(), WireError> {
    let Some(control) = control else {
        return Ok(());
    };
    if control.body.len() > limits.max_control_body {
        return Err(WireError::ControlBodyTooLarge {
            len: control.body.len(),
            max: limits.max_control_body,
        });
    }
    if control.ctrl_type.has_link_seq() != control.ctrl_seq.is_some() {
        return Err(WireError::ControlSequenceMismatch {
            ctrl_type: control.ctrl_type,
        });
    }
    Ok(())
}

fn control_trailer_len(control: &Option<ControlMessage>) -> Result<usize, WireError> {
    control.as_ref().map_or(Ok(0), |message| {
        if message.ctrl_type.has_link_seq() {
            CONTROL_TRAILER_PREFIX_LEN
        } else {
            1
        }
        .checked_add(message.body.len())
        .ok_or(WireError::DatagramTooLarge {
            len: usize::MAX,
            max: usize::MAX,
        })
    })
}

fn encode_header(header: &WireHeader) -> [u8; REFERENCE_WIRE_HEADER_LEN] {
    let mut bytes = [0_u8; REFERENCE_WIRE_HEADER_LEN];
    bytes[0..2].copy_from_slice(&REFERENCE_WIRE_MAGIC.to_be_bytes());
    bytes[2] = REFERENCE_WIRE_VERSION;
    bytes[3] = header.flags.encode();
    bytes[4..8].copy_from_slice(&header.link_seq.to_be_bytes());
    bytes[8..10].copy_from_slice(&header.payload_len.to_be_bytes());
    bytes[10..12].copy_from_slice(&header.epoch.to_be_bytes());
    bytes
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Parse/serialize failure. Every variant is a fail-closed drop reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    DatagramTooLarge { len: usize, max: usize },
    HeaderTooShort { len: usize },
    BadMagic { value: u16 },
    UnsupportedVersion { value: u8 },
    UnknownFlagBits { bits: u8 },
    UnknownQosClass { value: u8 },
    PayloadLengthMismatch { declared: usize, actual: usize },
    ControlTooShort { len: usize },
    UnknownControlType { value: u8 },
    ControlSequenceMismatch { ctrl_type: ControlType },
    ControlBodyTooLarge { len: usize, max: usize },
    PayloadTooLarge { len: usize },
    EmptyDatagram,
    HeaderMismatch,
}

impl WireError {
    /// Stable metric label for a dropped malformed datagram.
    pub const fn drop_reason(self) -> &'static str {
        match self {
            Self::DatagramTooLarge { .. } => "datagram_too_large",
            Self::HeaderTooShort { .. } => "header_too_short",
            Self::BadMagic { .. } => "bad_magic",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::UnknownFlagBits { .. } => "unknown_flag_bits",
            Self::UnknownQosClass { .. } => "unknown_qos_class",
            Self::PayloadLengthMismatch { .. } => "payload_length_mismatch",
            Self::ControlTooShort { .. } => "control_too_short",
            Self::UnknownControlType { .. } => "unknown_control_type",
            Self::ControlSequenceMismatch { .. } => "control_sequence_mismatch",
            Self::ControlBodyTooLarge { .. } => "control_body_too_large",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::EmptyDatagram => "empty_datagram",
            Self::HeaderMismatch => "header_mismatch",
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatagramTooLarge { len, max } => {
                write!(f, "datagram length {len} exceeds limit {max}")
            }
            Self::HeaderTooShort { len } => {
                write!(f, "datagram length {len} is shorter than header")
            }
            Self::BadMagic { value } => write!(f, "bad wire magic 0x{value:04x}"),
            Self::UnsupportedVersion { value } => write!(f, "unsupported wire version {value}"),
            Self::UnknownFlagBits { bits } => write!(f, "unknown flag bits 0x{bits:02x}"),
            Self::UnknownQosClass { value } => write!(f, "unknown QoS class {value}"),
            Self::PayloadLengthMismatch { declared, actual } => {
                write!(f, "declared payload length {declared}, body bytes {actual}")
            }
            Self::ControlTooShort { len } => write!(f, "control trailer length {len} is too short"),
            Self::UnknownControlType { value } => write!(f, "unknown control type {value}"),
            Self::ControlSequenceMismatch { ctrl_type } => {
                write!(
                    f,
                    "control type {ctrl_type:?} has the wrong sequence layout"
                )
            }
            Self::ControlBodyTooLarge { len, max } => {
                write!(f, "control body length {len} exceeds limit {max}")
            }
            Self::PayloadTooLarge { len } => write!(f, "payload length {len} does not fit u16"),
            Self::EmptyDatagram => f.write_str("datagram has neither payload nor control"),
            Self::HeaderMismatch => f.write_str("handle header does not match decoded metadata"),
        }
    }
}

impl std::error::Error for WireError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(qos: QosClass) -> WireHeader {
        WireHeader {
            flags: WireFlags { qos },
            epoch: 2,
            link_seq: 3,
            payload_len: 0,
        }
    }

    #[test]
    fn flag_packing_uses_the_documented_bit_positions() {
        let encoded = WireFlags {
            qos: QosClass::Feedback,
        }
        .encode();
        assert_eq!(encoded, 0b0000_0001);
        let decoded = WireFlags::decode(encoded).unwrap();
        assert_eq!(decoded.qos, QosClass::Feedback);
        assert_eq!(
            WireFlags::decode(0b0000_0011),
            Err(WireError::UnknownQosClass { value: 3 })
        );
        assert_eq!(
            WireFlags::decode(0b0001_0001),
            Err(WireError::UnknownFlagBits { bits: 0b0001_0000 })
        );
    }

    #[test]
    fn constructed_handle_has_a_separate_fixed_header_and_payload() {
        let codec = ReferenceWireCodec::default();
        let data = OpaqueBytes::from_static(b"coded");
        let datagram = codec.build(header(QosClass::Bulk), data, None).unwrap();
        assert_eq!(datagram.packet().header().len(), REFERENCE_WIRE_HEADER_LEN);
        assert_eq!(datagram.packet().payload_bytes(), b"coded");
        assert_eq!(datagram.header().payload_len, 5);
        assert_eq!(datagram.packet().header().as_bytes()[8..10], [0, 5]);
    }

    #[test]
    fn reliability_content_helpers_round_trip_without_ocnr_framing() {
        let data = encode_reliability_data(BlockId::new(7), SymbolId::new(9), b"coded");
        assert_eq!(&data[..4], &[0, 0, 0, 0]);
        assert_ne!(&data[..4], b"OCNR");
        let decoded = decode_reliability_data(OpaqueBytes::from(data)).unwrap();
        assert_eq!(decoded.block_id, BlockId::new(7));
        assert_eq!(decoded.rel_seq, SymbolId::new(9));
        assert_eq!(decoded.coded_vector.as_ref(), b"coded");

        let feedback = Feedback::nack(BlockId::new(11), 12, 2);
        let body = encode_reliability_feedback(feedback);
        assert_ne!(&body[..4.min(body.len())], b"OCNR");
        assert_eq!(
            decode_reliability_feedback(OpaqueBytes::from(body)).unwrap(),
            feedback
        );
    }
}
