//! Opaque ACK/loss feedback for the validation substrate.
//!
//! The transport only recognizes this body as `CC_OPAQUE`. Encoding and
//! validation stay inside `conet_cc`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use conet_core::{ControlDisposition, MonoNs, Observation, OpaqueBytes, RxController};

const FEEDBACK_MAGIC: [u8; 4] = *b"CCV1";
const LEGACY_FEEDBACK_VERSION: u8 = 2;
const IDENTIFIED_FEEDBACK_VERSION: u8 = 3;
const LEGACY_HEADER_LEN: usize = 16;
const IDENTIFIED_HEADER_LEN: usize = 20;
const SINGLE_EVENT_LEN: usize = 9;
const SACK_EVENT_LEN: usize = 17;
const MAX_FEEDBACK_BODY_LEN: usize = 256;
const RTT_PRESENT: u8 = 0b0000_0001;
const KIND_ACK: u8 = 1;
const KIND_LOSS: u8 = 2;
const KIND_CUMULATIVE_ACK: u8 = 3;
const KIND_SACK: u8 = 4;
const LOSS_REORDER_WINDOW: u64 = 3;
const LOSS_TIMEOUT: MonoNs = MonoNs::new(20_000_000);
const MAX_TRACKED_GAP: u64 = 64;

/// Maximum events fitting one default 256-byte control body.
pub const MAX_FEEDBACK_EVENTS: usize =
    (MAX_FEEDBACK_BODY_LEN - LEGACY_HEADER_LEN) / SINGLE_EVENT_LEN;

/// Delay between timer-driven copies of the latest feedback batch.
pub const FEEDBACK_RESEND_INTERVAL: MonoNs = MonoNs::new(20_000_000);

/// Number of timer-driven copies after the original feedback batch.
pub const MAX_FEEDBACK_RESENDS: u8 = 2;

/// One exact acknowledgement, cumulative acknowledgement, SACK range, or
/// declared loss. SACK ranges are inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackEvent {
    Ack { seq: u64 },
    CumulativeAck { through: u64 },
    Sack { start: u64, end: u64 },
    Loss { seq: u64 },
}

impl FeedbackEvent {
    /// First sequence covered by this event.
    pub const fn seq(self) -> u64 {
        match self {
            Self::Ack { seq } | Self::Loss { seq } => seq,
            Self::CumulativeAck { through } => through,
            Self::Sack { start, .. } => start,
        }
    }

    const fn encoded_len(self) -> usize {
        match self {
            Self::Sack { .. } => SACK_EVENT_LEN,
            Self::Ack { .. } | Self::CumulativeAck { .. } | Self::Loss { .. } => SINGLE_EVENT_LEN,
        }
    }
}

/// Bounded batch of controller feedback.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedbackMessage {
    pub rtt_ns: Option<u64>,
    pub events: Vec<FeedbackEvent>,
    /// Private anti-replay identity. Legacy V0/V1 bodies decode with `None`.
    pub control_id: Option<u32>,
}

impl FeedbackMessage {
    pub fn new(rtt_ns: Option<u64>, events: Vec<FeedbackEvent>) -> Self {
        Self {
            rtt_ns,
            events,
            control_id: None,
        }
    }

    pub fn with_control_id(mut self, control_id: u32) -> Self {
        self.control_id = Some(control_id);
        self
    }

    pub fn ack(seq: u64) -> Self {
        Self::new(None, vec![FeedbackEvent::Ack { seq }])
    }

    pub fn loss(seq: u64) -> Self {
        Self::new(None, vec![FeedbackEvent::Loss { seq }])
    }

    pub fn cumulative_ack(through: u64) -> Self {
        Self::new(None, vec![FeedbackEvent::CumulativeAck { through }])
    }

    pub fn sack(start: u64, end: u64) -> Self {
        Self::new(None, vec![FeedbackEvent::Sack { start, end }])
    }

    /// Exact encoded length, or `None` when the message cannot fit in one
    /// default control body.
    pub fn encoded_len(&self) -> Option<usize> {
        if self.events.is_empty() || self.events.len() > MAX_FEEDBACK_EVENTS {
            return None;
        }
        let header_len = if self.control_id.is_some() {
            IDENTIFIED_HEADER_LEN
        } else {
            LEGACY_HEADER_LEN
        };
        let mut len = header_len;
        for event in &self.events {
            if matches!(
                event,
                FeedbackEvent::Sack { start, end } if start > end
            ) {
                return None;
            }
            len = len.checked_add(event.encoded_len())?;
        }
        (len <= MAX_FEEDBACK_BODY_LEN).then_some(len)
    }

    /// Encode without a datagram/control trailer. Returns `None` when the
    /// message has no events, has an invalid SACK range, or exceeds one
    /// control body.
    pub fn encode(&self) -> Option<OpaqueBytes> {
        let len = self.encoded_len()?;
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&FEEDBACK_MAGIC);
        bytes.push(if self.control_id.is_some() {
            IDENTIFIED_FEEDBACK_VERSION
        } else {
            LEGACY_FEEDBACK_VERSION
        });
        bytes.push(u8::try_from(self.events.len()).ok()?);
        bytes.push(if self.rtt_ns.is_some() {
            RTT_PRESENT
        } else {
            0
        });
        bytes.push(0);
        if let Some(control_id) = self.control_id {
            bytes.extend_from_slice(&control_id.to_be_bytes());
        }
        bytes.extend_from_slice(&self.rtt_ns.unwrap_or(0).to_be_bytes());
        for event in &self.events {
            match event {
                FeedbackEvent::Ack { seq } => {
                    bytes.push(KIND_ACK);
                    bytes.extend_from_slice(&seq.to_be_bytes());
                }
                FeedbackEvent::CumulativeAck { through } => {
                    bytes.push(KIND_CUMULATIVE_ACK);
                    bytes.extend_from_slice(&through.to_be_bytes());
                }
                FeedbackEvent::Sack { start, end } => {
                    bytes.push(KIND_SACK);
                    bytes.extend_from_slice(&start.to_be_bytes());
                    bytes.extend_from_slice(&end.to_be_bytes());
                }
                FeedbackEvent::Loss { seq } => {
                    bytes.push(KIND_LOSS);
                    bytes.extend_from_slice(&seq.to_be_bytes());
                }
            }
        }
        Some(bytes.into())
    }

    /// Decode a complete body. Any malformed field or trailing byte rejects
    /// the whole batch.
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < LEGACY_HEADER_LEN
            || body.len() > MAX_FEEDBACK_BODY_LEN
            || body[..4] != FEEDBACK_MAGIC
        {
            return None;
        }
        let (header_len, control_id) = match body[4] {
            LEGACY_FEEDBACK_VERSION => (LEGACY_HEADER_LEN, None),
            IDENTIFIED_FEEDBACK_VERSION if body.len() >= IDENTIFIED_HEADER_LEN => (
                IDENTIFIED_HEADER_LEN,
                Some(u32::from_be_bytes(body[8..12].try_into().ok()?)),
            ),
            _ => return None,
        };
        if body[7] != 0 {
            return None;
        }
        let count = usize::from(body[5]);
        if count == 0 || count > MAX_FEEDBACK_EVENTS {
            return None;
        }
        let flags = body[6];
        if flags & !RTT_PRESENT != 0 {
            return None;
        }
        let rtt_start = if control_id.is_some() {
            IDENTIFIED_HEADER_LEN - 8
        } else {
            LEGACY_HEADER_LEN - 8
        };
        let encoded_rtt = u64::from_be_bytes(body.get(rtt_start..rtt_start + 8)?.try_into().ok()?);
        let rtt_ns = (flags & RTT_PRESENT != 0).then_some(encoded_rtt);
        let mut events = Vec::with_capacity(count);
        let mut offset = header_len;
        for _ in 0..count {
            let kind = *body.get(offset)?;
            let event_len = match kind {
                KIND_ACK | KIND_LOSS | KIND_CUMULATIVE_ACK => SINGLE_EVENT_LEN,
                KIND_SACK => SACK_EVENT_LEN,
                _ => return None,
            };
            let event_end = offset.checked_add(event_len)?;
            let event = body.get(offset..event_end)?;
            let first = u64::from_be_bytes(event[1..9].try_into().ok()?);
            events.push(match kind {
                KIND_ACK => FeedbackEvent::Ack { seq: first },
                KIND_CUMULATIVE_ACK => FeedbackEvent::CumulativeAck { through: first },
                KIND_SACK => {
                    let end = u64::from_be_bytes(event[9..17].try_into().ok()?);
                    if first > end {
                        return None;
                    }
                    FeedbackEvent::Sack { start: first, end }
                }
                KIND_LOSS => FeedbackEvent::Loss { seq: first },
                _ => unreachable!(),
            });
            offset = event_end;
        }
        if offset != body.len() {
            return None;
        }
        Some(Self {
            rtt_ns,
            events,
            control_id,
        })
    }
}

/// Bounded private anti-replay window for identified feedback messages.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FeedbackReplayWindow {
    max_id: u32,
    seen: u64,
    initialized: bool,
}

impl FeedbackReplayWindow {
    pub(crate) const fn new() -> Self {
        Self {
            max_id: 0,
            seen: 0,
            initialized: false,
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::new();
    }

    /// Record a fresh ID. Duplicate and too-old IDs return `false`.
    pub(crate) fn accept(&mut self, id: u32) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_id = id;
            self.seen = 1;
            return true;
        }
        let ahead = id.wrapping_sub(self.max_id);
        if ahead == 0 {
            return false;
        }
        if ahead & (1 << 31) == 0 {
            self.seen = if ahead >= 64 {
                1
            } else {
                (self.seen << ahead) | 1
            };
            self.max_id = id;
            return true;
        }
        let behind = self.max_id.wrapping_sub(id);
        if behind >= 64 || self.seen & (1_u64 << behind) != 0 {
            return false;
        }
        self.seen |= 1_u64 << behind;
        true
    }
}

/// Receiver adapter that ACKs payload-bearing observations.
///
/// It does not require a send timestamp. The sender derives RTT locally when
/// the acknowledgement arrives.
///
#[derive(Debug, Default)]
pub struct AckReceiver {
    pending: VecDeque<(FeedbackEvent, Option<u64>)>,
    highest_seq: Option<u64>,
    holes: BTreeMap<u64, MonoNs>,
    received: BTreeSet<u64>,
    started: bool,
    cumulative: Option<u64>,
    last_events: Option<(Option<u64>, Vec<FeedbackEvent>)>,
    resend_at: Option<MonoNs>,
    resends_remaining: u8,
    next_control_id: u32,
    pending_feedback: Option<PendingFeedback>,
}

#[derive(Debug)]
struct PendingFeedback {
    body: OpaqueBytes,
    rtt_ns: Option<u64>,
    events: Vec<FeedbackEvent>,
    original: bool,
    scheduled_at: MonoNs,
}

impl AckReceiver {
    pub const fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            highest_seq: None,
            holes: BTreeMap::new(),
            received: BTreeSet::new(),
            started: false,
            cumulative: None,
            last_events: None,
            resend_at: None,
            resends_remaining: 0,
            next_control_id: 1,
            pending_feedback: None,
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn observe_sequence(&mut self, seq: u64, now: MonoNs, rtt_ns: Option<u64>) {
        self.pending
            .retain(|(event, _)| *event != FeedbackEvent::Loss { seq });
        if let Some(highest) = self.highest_seq {
            if seq > highest {
                let gap = seq.saturating_sub(highest).saturating_sub(1);
                for offset in 0..gap.min(MAX_TRACKED_GAP) {
                    self.holes
                        .entry(highest.saturating_add(1).saturating_add(offset))
                        .or_insert(now);
                }
                self.highest_seq = Some(seq);
            } else {
                self.holes.remove(&seq);
            }
        } else {
            self.highest_seq = Some(seq);
        }

        if !self.started {
            self.started = true;
            if seq == 0 {
                self.cumulative = Some(0);
                self.pending
                    .push_back((FeedbackEvent::CumulativeAck { through: 0 }, rtt_ns));
            } else {
                self.received.insert(seq);
                self.pending.push_back((
                    FeedbackEvent::Sack {
                        start: seq,
                        end: seq,
                    },
                    rtt_ns,
                ));
            }
        } else {
            match self.cumulative {
                None if seq == 0 => {
                    self.received.insert(seq);
                    self.advance_cumulative(rtt_ns);
                }
                None => {
                    self.received.insert(seq);
                    let (start, end) = self.contiguous_run(seq);
                    self.pending
                        .push_back((FeedbackEvent::Sack { start, end }, rtt_ns));
                }
                Some(through) if seq <= through => {}
                Some(through) if seq == through.saturating_add(1) => {
                    self.received.insert(seq);
                    self.advance_cumulative(rtt_ns);
                }
                Some(_) => {
                    self.received.insert(seq);
                    let (start, end) = self.contiguous_run(seq);
                    self.pending
                        .push_back((FeedbackEvent::Sack { start, end }, rtt_ns));
                }
            }
        }
        self.expire_after_distance();
        self.expire_after_timeout(now);
    }

    fn encode_batch(
        &self,
        rtt_ns: Option<u64>,
        events: &[FeedbackEvent],
        control_id: u32,
    ) -> Option<OpaqueBytes> {
        FeedbackMessage::new(rtt_ns, events.to_vec())
            .with_control_id(control_id)
            .encode()
    }

    fn advance_cumulative(&mut self, rtt_ns: Option<u64>) {
        let mut next = match self.cumulative {
            Some(through) => through.saturating_add(1),
            None if self.received.remove(&0) => {
                self.cumulative = Some(0);
                1
            }
            None => return,
        };
        while self.received.remove(&next) {
            self.cumulative = Some(next);
            next = next.saturating_add(1);
        }
        let through = self.cumulative.unwrap_or(0);
        self.holes.retain(|hole, _| *hole > through);
        self.pending
            .push_back((FeedbackEvent::CumulativeAck { through }, rtt_ns));
        self.queue_received_ranges(rtt_ns);
    }

    fn contiguous_run(&self, seq: u64) -> (u64, u64) {
        let mut start = seq;
        while start > 0 && self.received.contains(&start.saturating_sub(1)) {
            start = start.saturating_sub(1);
        }
        let mut end = seq;
        while let Some(next) = end.checked_add(1) {
            if !self.received.contains(&next) {
                break;
            }
            end = next;
        }
        (start, end)
    }

    fn queue_received_ranges(&mut self, rtt_ns: Option<u64>) {
        let sequences: Vec<u64> = self.received.iter().copied().collect();
        let mut index = 0;
        while index < sequences.len() {
            let start = sequences[index];
            let mut end = start;
            index += 1;
            while index < sequences.len() && sequences[index] == end.saturating_add(1) {
                end = sequences[index];
                index += 1;
            }
            self.pending
                .push_back((FeedbackEvent::Sack { start, end }, rtt_ns));
        }
    }

    fn expire_after_distance(&mut self) {
        let Some(highest) = self.highest_seq else {
            return;
        };
        let expired: Vec<u64> = self
            .holes
            .keys()
            .copied()
            .filter(|seq| highest.saturating_sub(*seq) >= LOSS_REORDER_WINDOW)
            .collect();
        for seq in expired {
            self.holes.remove(&seq);
            self.pending.push_back((FeedbackEvent::Loss { seq }, None));
        }
    }

    fn expire_after_timeout(&mut self, now: MonoNs) {
        let expired: Vec<u64> = self
            .holes
            .iter()
            .filter(|(_, first_seen)| now >= first_seen.saturating_add(LOSS_TIMEOUT))
            .map(|(&seq, _)| seq)
            .collect();
        for seq in expired {
            self.holes.remove(&seq);
            self.pending.push_back((FeedbackEvent::Loss { seq }, None));
        }
    }
}

impl RxController for AckReceiver {
    fn restart(&mut self) {
        *self = Self::new();
    }

    fn on_observed(&mut self, observation: Observation) -> ControlDisposition {
        let cc_unusable = observation.cc_bytes.is_some();
        if observation.payload_len == 0 {
            return if cc_unusable {
                ControlDisposition::Unusable
            } else {
                ControlDisposition::Usable
            };
        }
        let Some(seq) = observation.seq else {
            return if cc_unusable {
                ControlDisposition::Unusable
            } else {
                ControlDisposition::Usable
            };
        };
        self.observe_sequence(seq, observation.recv_ts, None);
        if cc_unusable {
            ControlDisposition::Unusable
        } else {
            ControlDisposition::Usable
        }
    }

    fn poll_control(&mut self, now: MonoNs) -> Option<OpaqueBytes> {
        if let Some(pending) = self.pending_feedback.as_ref() {
            return Some(pending.body.clone());
        }
        self.expire_after_timeout(now);
        if !self.pending.is_empty() {
            let count = self.drainable_event_count();
            let pending: Vec<_> = self.pending.iter().take(count).cloned().collect();
            let rtt_ns = pending.iter().rev().find_map(|(_, rtt_ns)| *rtt_ns);
            let events: Vec<_> = pending.into_iter().map(|(event, _)| event).collect();
            let body = self.encode_batch(rtt_ns, &events, self.next_control_id)?;
            self.pending.drain(..count);
            self.pending_feedback = Some(PendingFeedback {
                body: body.clone(),
                rtt_ns,
                events,
                original: true,
                scheduled_at: now,
            });
            return Some(body);
        }
        if self.resend_at.is_some_and(|deadline| now >= deadline) && self.resends_remaining > 0 {
            let (rtt_ns, events) = self.last_events.clone()?;
            let body = self.encode_batch(rtt_ns, &events, self.next_control_id)?;
            self.pending_feedback = Some(PendingFeedback {
                body: body.clone(),
                rtt_ns,
                events,
                original: false,
                scheduled_at: now,
            });
            return Some(body);
        }
        None
    }

    fn on_control_sent(&mut self, body: &OpaqueBytes) {
        let Some(pending) = self
            .pending_feedback
            .as_ref()
            .filter(|pending| pending.body == *body)
        else {
            return;
        };
        let original = pending.original;
        let rtt_ns = pending.rtt_ns;
        let events = pending.events.clone();
        let scheduled_at = pending.scheduled_at;

        self.next_control_id = self.next_control_id.wrapping_add(1).max(1);
        self.last_events = Some((rtt_ns, events));
        if original {
            self.resends_remaining = MAX_FEEDBACK_RESENDS;
        } else {
            self.resends_remaining = self.resends_remaining.saturating_sub(1);
        }
        self.resend_at = (self.resends_remaining > 0)
            .then(|| scheduled_at.saturating_add(FEEDBACK_RESEND_INTERVAL));
        self.pending_feedback = None;
    }

    fn next_wakeup(&self) -> Option<MonoNs> {
        if self.pending_feedback.is_some() {
            return Some(MonoNs::ZERO);
        }
        if !self.pending.is_empty() {
            return Some(MonoNs::ZERO);
        }
        let loss_deadline = self
            .holes
            .values()
            .map(|first_seen| first_seen.saturating_add(LOSS_TIMEOUT))
            .min();
        match (loss_deadline, self.resend_at) {
            (Some(loss), Some(resend)) => Some(loss.min(resend)),
            (Some(loss), None) => Some(loss),
            (None, Some(resend)) => Some(resend),
            (None, None) => None,
        }
    }
}

impl AckReceiver {
    fn drainable_event_count(&self) -> usize {
        let mut count = 0;
        let mut len = IDENTIFIED_HEADER_LEN;
        for (event, _) in &self.pending {
            let event_len = event.encoded_len();
            if count == MAX_FEEDBACK_EVENTS || len + event_len > MAX_FEEDBACK_BODY_LEN {
                break;
            }
            count += 1;
            len += event_len;
        }
        count.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll_sent(receiver: &mut AckReceiver, now: MonoNs) -> Option<OpaqueBytes> {
        let body = receiver.poll_control(now)?;
        receiver.on_control_sent(&body);
        Some(body)
    }

    #[test]
    fn feedback_round_trips_and_rejects_malformed_bodies() {
        let message = FeedbackMessage::new(
            Some(12_345),
            vec![
                FeedbackEvent::Ack { seq: 3 },
                FeedbackEvent::CumulativeAck { through: 5 },
                FeedbackEvent::Sack { start: 7, end: 9 },
                FeedbackEvent::Loss { seq: 4 },
            ],
        );
        let body = message.encode().unwrap();
        assert_eq!(FeedbackMessage::decode(&body), Some(message));

        let mut trailing = body.to_vec();
        trailing.push(0);
        assert_eq!(FeedbackMessage::decode(&trailing), None);

        let mut bad_kind = body.to_vec();
        bad_kind[LEGACY_HEADER_LEN] = 0xee;
        assert_eq!(FeedbackMessage::decode(&bad_kind), None);

        let mut bad_flags = body.to_vec();
        bad_flags[6] = 0x80;
        assert_eq!(FeedbackMessage::decode(&bad_flags), None);

        assert!(FeedbackMessage::sack(9, 7).encode().is_none());
    }

    #[test]
    fn ack_receiver_ignores_control_only_observations() {
        let mut receiver = AckReceiver::new();
        let mut control = Observation::new(MonoNs::new(10_000), 21);
        control.payload_len = 0;
        control.seq = Some(10);
        receiver.on_observed(control);
        assert!(receiver.poll_control(MonoNs::new(10_000)).is_none());

        let mut data = Observation::new(MonoNs::new(10_000), 1_050);
        data.payload_len = 1_000;
        data.seq = Some(11);
        receiver.on_observed(data);
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut receiver, MonoNs::new(10_000)).unwrap())
                .unwrap();
        assert_eq!(feedback.rtt_ns, None);
        assert_eq!(
            feedback.events,
            vec![FeedbackEvent::Sack { start: 11, end: 11 }]
        );
    }

    #[test]
    fn reordered_sequence_within_the_window_is_sacked() {
        let mut receiver = AckReceiver::new();
        for (seq, at) in [(1, 0), (3, 1_000_000)] {
            receiver.on_observed(data_observation(seq, at));
        }
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut receiver, MonoNs::new(2_000_000)).unwrap())
                .unwrap();
        assert_eq!(
            feedback.events,
            vec![
                FeedbackEvent::Sack { start: 1, end: 1 },
                FeedbackEvent::Sack { start: 3, end: 3 }
            ]
        );

        receiver.on_observed(data_observation(2, 3_000_000));
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut receiver, MonoNs::new(4_000_000)).unwrap())
                .unwrap();
        assert_eq!(
            feedback.events,
            vec![FeedbackEvent::Sack { start: 1, end: 3 }]
        );
    }

    #[test]
    fn cumulative_ack_and_sack_are_emitted_together_from_a_known_zero_base() {
        let mut receiver = AckReceiver::new();
        receiver.on_observed(data_observation(0, 0));
        receiver.on_observed(data_observation(2, 1_000_000));
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut receiver, MonoNs::new(2_000_000)).unwrap())
                .unwrap();
        assert_eq!(
            feedback.events,
            vec![
                FeedbackEvent::CumulativeAck { through: 0 },
                FeedbackEvent::Sack { start: 2, end: 2 }
            ]
        );

        receiver.on_observed(data_observation(1, 3_000_000));
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut receiver, MonoNs::new(4_000_000)).unwrap())
                .unwrap();
        assert_eq!(
            feedback.events,
            vec![FeedbackEvent::CumulativeAck { through: 2 }]
        );
    }

    #[test]
    fn skipped_sequence_is_declared_lost_after_distance_or_timeout() {
        let mut receiver = AckReceiver::new();
        receiver.on_observed(data_observation(1, 0));
        receiver.on_observed(data_observation(3, 1_000_000));
        assert!(poll_sent(&mut receiver, MonoNs::new(1_000_000)).is_some());
        assert_eq!(receiver.next_wakeup(), Some(MonoNs::new(21_000_000)));

        receiver.on_observed(data_observation(5, 2_000_000));
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut receiver, MonoNs::new(2_000_000)).unwrap())
                .unwrap();
        assert!(feedback.events.contains(&FeedbackEvent::Loss { seq: 2 }));
        assert!(!feedback.events.contains(&FeedbackEvent::Ack { seq: 2 }));

        let mut timed = AckReceiver::new();
        timed.on_observed(data_observation(7, 0));
        timed.on_observed(data_observation(9, 1_000_000));
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut timed, MonoNs::new(21_000_000)).unwrap())
                .unwrap();
        assert!(feedback.events.contains(&FeedbackEvent::Loss { seq: 8 }));
    }

    #[test]
    fn latest_feedback_batch_is_resent_on_a_bounded_timer() {
        let mut receiver = AckReceiver::new();
        receiver.on_observed(data_observation(1, 0));
        let original = poll_sent(&mut receiver, MonoNs::new(1_000_000)).unwrap();
        assert!(FeedbackMessage::decode(&original).is_some());
        assert_eq!(
            receiver.next_wakeup(),
            Some(MonoNs::new(1_000_000).saturating_add(FEEDBACK_RESEND_INTERVAL))
        );

        let mut copies = 0;
        let original = FeedbackMessage::decode(&original).unwrap();
        let mut now = MonoNs::new(1_000_000).saturating_add(FEEDBACK_RESEND_INTERVAL);
        while let Some(copy) = poll_sent(&mut receiver, now) {
            let copy = FeedbackMessage::decode(&copy).unwrap();
            assert_eq!(copy.rtt_ns, original.rtt_ns);
            assert_eq!(copy.events, original.events);
            assert_ne!(copy.control_id, original.control_id);
            copies += 1;
            now = now.saturating_add(FEEDBACK_RESEND_INTERVAL);
        }
        assert_eq!(copies, usize::from(MAX_FEEDBACK_RESENDS));
        assert_eq!(receiver.next_wakeup(), None);
    }

    #[test]
    fn uncommitted_feedback_reuses_its_private_identity() {
        let mut receiver = AckReceiver::new();
        receiver.on_observed(data_observation(1, 0));
        let first = receiver.poll_control(MonoNs::new(1_000_000)).unwrap();
        assert_eq!(receiver.next_wakeup(), Some(MonoNs::ZERO));
        assert_eq!(
            receiver.poll_control(MonoNs::new(50_000_000)),
            Some(first.clone())
        );

        receiver.on_control_sent(&first);
        let resent = poll_sent(
            &mut receiver,
            MonoNs::new(1_000_000).saturating_add(FEEDBACK_RESEND_INTERVAL),
        )
        .unwrap();
        assert_eq!(FeedbackMessage::decode(&first).unwrap().control_id, Some(1));
        assert_eq!(
            FeedbackMessage::decode(&resent).unwrap().control_id,
            Some(2)
        );
    }

    #[test]
    fn restart_discards_reorder_and_feedback_state() {
        let mut receiver = AckReceiver::new();
        receiver.on_observed(data_observation(1, 0));
        receiver.on_observed(data_observation(3, 1_000_000));
        receiver.restart();
        assert_eq!(receiver.pending_len(), 0);
        assert_eq!(receiver.next_wakeup(), None);

        receiver.on_observed(data_observation(1, 2_000_000));
        let feedback =
            FeedbackMessage::decode(&poll_sent(&mut receiver, MonoNs::new(2_000_000)).unwrap())
                .unwrap();
        assert_eq!(
            feedback.events,
            vec![FeedbackEvent::Sack { start: 1, end: 1 }]
        );
    }

    fn data_observation(seq: u64, at: i64) -> Observation {
        let mut observation = Observation::new(MonoNs::new(at), 100);
        observation.seq = Some(seq);
        observation
    }
}
