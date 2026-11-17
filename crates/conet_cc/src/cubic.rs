//! A validation-oriented CUBIC-style congestion window.
//!
//! This is intentionally not a Linux TCP-CUBIC port. It implements the classic
//! cubic curve, a multiplicative decrease, exact-sequence inflight accounting,
//! and a small deterministic timer. See `RESULTS.md` in the validation job for
//! the complete simplification list.

use conet_core::{ControlDisposition, Delivery, MonoNs, OpaqueBytes, Pace, TxController};

use crate::feedback::{FeedbackEvent, FeedbackMessage, FeedbackReplayWindow};
use crate::ledger::InflightLedger;

/// Linux CUBIC's scaling constant when windows are measured in segments.
pub const CUBIC_C: f64 = 0.4;
/// Validation-controller multiplicative decrease factor.
pub const CUBIC_BETA: f64 = 0.7;
/// Initial window in segments.
pub const INITIAL_WINDOW_SEGMENTS: u64 = 10;
/// Lower bound in segments after repeated loss.
pub const MIN_WINDOW_SEGMENTS: u64 = 2;
/// Default segment size used to convert the byte-oriented Pace.
pub const DEFAULT_MSS_BYTES: u16 = 1_200;
/// Clock interval used to sample the cubic curve while packets remain live.
pub const CUBIC_GROWTH_TICK: MonoNs = MonoNs::new(10_000_000);

/// Window-only CUBIC-style sender controller.
#[derive(Clone, Debug)]
pub struct CubicController {
    ledger: InflightLedger,
    mss_bytes: u16,
    growth_tick: MonoNs,
    cwnd_bytes: f64,
    min_cwnd_bytes: f64,
    w_max_bytes: f64,
    epoch_start: MonoNs,
    k_s: f64,
    curve_active: bool,
    next_wakeup: Option<MonoNs>,
    feedback_replay: FeedbackReplayWindow,
}

impl CubicController {
    pub fn new(now: MonoNs) -> Self {
        Self::with_segment_size(now, DEFAULT_MSS_BYTES)
    }

    pub fn with_segment_size(now: MonoNs, mss_bytes: u16) -> Self {
        let mss = u64::from(mss_bytes.max(1));
        Self {
            ledger: InflightLedger::new(),
            mss_bytes: mss_bytes.max(1),
            growth_tick: CUBIC_GROWTH_TICK,
            cwnd_bytes: (INITIAL_WINDOW_SEGMENTS * mss) as f64,
            min_cwnd_bytes: (MIN_WINDOW_SEGMENTS * mss) as f64,
            w_max_bytes: (INITIAL_WINDOW_SEGMENTS * mss) as f64,
            epoch_start: now,
            k_s: 0.0,
            curve_active: false,
            next_wakeup: None,
            feedback_replay: FeedbackReplayWindow::default(),
        }
    }

    pub const fn with_growth_tick(mut self, growth_tick: MonoNs) -> Self {
        self.growth_tick = growth_tick;
        self
    }

    pub fn cwnd_bytes(&self) -> u64 {
        self.cwnd_bytes.round().max(1.0) as u64
    }

    pub fn w_max_bytes(&self) -> u64 {
        self.w_max_bytes.round().max(1.0) as u64
    }

    pub fn k_seconds(&self) -> f64 {
        self.k_s
    }

    pub fn ledger(&self) -> &InflightLedger {
        &self.ledger
    }

    pub fn apply_feedback(&mut self, now: MonoNs, message: &FeedbackMessage) {
        for event in &message.events {
            match *event {
                FeedbackEvent::Ack { seq } => self.acknowledge(now, seq, message.rtt_ns),
                FeedbackEvent::CumulativeAck { through } => {
                    self.acknowledge_cumulative(now, through, message.rtt_ns);
                }
                FeedbackEvent::Sack { start, end } => {
                    self.acknowledge_sack(now, start, end, message.rtt_ns);
                }
                FeedbackEvent::Loss { seq } => self.declare_loss(now, seq),
            }
        }
    }

    fn acknowledge(&mut self, now: MonoNs, seq: u64, rtt_ns: Option<u64>) {
        let Some(packet) = self.ledger.on_ack_at(seq, now, rtt_ns) else {
            return;
        };
        if self.curve_active {
            self.apply_cubic_curve(now);
            self.next_wakeup =
                (self.ledger.inflight_bytes() > 0).then(|| now.saturating_add(self.growth_tick));
        } else {
            // Before the first validation loss this controller uses ACK-clocked
            // slow start. HyStart and bandwidth probing are intentionally absent.
            self.cwnd_bytes += f64::from(packet.bytes);
        }
    }

    fn acknowledge_sack(&mut self, now: MonoNs, start: u64, end: u64, rtt_ns: Option<u64>) {
        let packets = self.ledger.on_sack_at(start, end, now, rtt_ns);
        self.acknowledge_released(now, &packets);
    }

    fn acknowledge_cumulative(&mut self, now: MonoNs, through: u64, rtt_ns: Option<u64>) {
        let packets = self.ledger.on_cumulative_ack_at(through, now, rtt_ns);
        self.acknowledge_released(now, &packets);
    }

    fn acknowledge_released(&mut self, now: MonoNs, packets: &[crate::SentPacket]) {
        if packets.is_empty() {
            return;
        }
        if self.curve_active {
            self.apply_cubic_curve(now);
            self.next_wakeup =
                (self.ledger.inflight_bytes() > 0).then(|| now.saturating_add(self.growth_tick));
        } else {
            let bytes: u64 = packets.iter().map(|packet| u64::from(packet.bytes)).sum();
            self.cwnd_bytes += bytes as f64;
        }
    }

    fn declare_loss(&mut self, now: MonoNs, seq: u64) {
        if self.ledger.on_loss(seq).is_none() {
            return;
        }
        let previous = self.cwnd_bytes.max(self.min_cwnd_bytes);
        self.w_max_bytes = previous;
        self.cwnd_bytes = (previous * CUBIC_BETA).max(self.min_cwnd_bytes);
        let mss = f64::from(self.mss_bytes);
        let reduced_segments = (self.w_max_bytes - self.cwnd_bytes) / mss;
        self.k_s = (reduced_segments / CUBIC_C).max(0.0).cbrt();
        self.epoch_start = now;
        self.curve_active = true;
        self.next_wakeup = Some(now.saturating_add(self.growth_tick));
    }

    fn apply_cubic_curve(&mut self, now: MonoNs) {
        let elapsed_s = now
            .as_nanos()
            .saturating_sub(self.epoch_start.as_nanos())
            .max(0) as f64
            / 1e9;
        let cubic_segments =
            CUBIC_C * (elapsed_s - self.k_s).powi(3) + self.w_max_bytes / f64::from(self.mss_bytes);
        let target = (cubic_segments * f64::from(self.mss_bytes)).max(self.min_cwnd_bytes);
        if target > self.cwnd_bytes {
            self.cwnd_bytes = target;
        }
    }
}

impl TxController for CubicController {
    fn restart(&mut self) {
        self.ledger.clear();
        let mss = u64::from(self.mss_bytes);
        self.cwnd_bytes = (INITIAL_WINDOW_SEGMENTS * mss) as f64;
        self.min_cwnd_bytes = (MIN_WINDOW_SEGMENTS * mss) as f64;
        self.w_max_bytes = self.cwnd_bytes;
        self.epoch_start = MonoNs::ZERO;
        self.k_s = 0.0;
        self.curve_active = false;
        self.next_wakeup = None;
        self.feedback_replay.clear();
    }

    fn on_clock(&mut self, now: MonoNs) {
        if !self.curve_active || self.next_wakeup.is_none_or(|deadline| now < deadline) {
            return;
        }
        self.apply_cubic_curve(now);
        self.next_wakeup =
            (self.ledger.inflight_bytes() > 0).then(|| now.saturating_add(self.growth_tick));
    }

    fn on_peer_control(&mut self, now: MonoNs, body: OpaqueBytes) -> ControlDisposition {
        let Some(message) = FeedbackMessage::decode(&body) else {
            return ControlDisposition::Unusable;
        };
        if message
            .control_id
            .is_none_or(|id| self.feedback_replay.accept(id))
        {
            self.apply_feedback(now, &message);
        }
        ControlDisposition::Usable
    }

    fn on_packet_sent(&mut self, now: MonoNs, bytes: u16, seq: Option<u64>) {
        if let Some(seq) = seq {
            self.ledger.on_packet_sent(now, seq, bytes);
        }
    }

    fn on_delivery(&mut self, now: MonoNs, delivery: Delivery) {
        let Some(seq) = delivery.seq else {
            return;
        };
        if delivery.acked {
            self.acknowledge(now, seq, delivery.rtt_ns);
        } else if delivery.lost {
            self.declare_loss(now, seq);
        }
    }

    fn inflight_bytes(&self) -> Option<u64> {
        Some(self.ledger.inflight_bytes())
    }

    fn pace(&self) -> Pace {
        Pace::set_inflight_limit(self.cwnd_bytes())
    }

    fn next_wakeup(&self) -> Option<MonoNs> {
        self.next_wakeup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conet_core::Delivery;

    fn sent(controller: &mut CubicController, seq: u64, at_ms: i64) {
        controller.on_packet_sent(MonoNs::new(at_ms * 1_000_000), 1_000, Some(seq));
    }

    #[test]
    fn loss_decreases_window_and_arms_the_curve_clock() {
        let now = MonoNs::ZERO;
        let mut controller = CubicController::new(now);
        for seq in 0..4 {
            sent(&mut controller, seq, 0);
        }
        let before = controller.cwnd_bytes();
        controller.on_peer_control(
            MonoNs::new(1_000_000),
            FeedbackMessage::loss(1).encode().unwrap(),
        );
        assert!(controller.cwnd_bytes() < before);
        assert_eq!(controller.cwnd_bytes(), (before as f64 * CUBIC_BETA) as u64);
        assert_eq!(controller.next_wakeup(), Some(MonoNs::new(11_000_000)));
        assert_eq!(controller.k_seconds() > 0.0, true);
    }

    #[test]
    fn window_follows_cubic_curve_after_loss() {
        let mut controller = CubicController::new(MonoNs::ZERO);
        for seq in 0..4 {
            sent(&mut controller, seq, 0);
        }
        controller.on_peer_control(
            MonoNs::new(1_000_000),
            FeedbackMessage::loss(1).encode().unwrap(),
        );
        let after_loss = controller.cwnd_bytes();
        controller.on_clock(MonoNs::new(2_500_000_000));
        assert!(controller.cwnd_bytes() > after_loss);
        assert!(controller.next_wakeup().is_some());

        for seq in [0, 2, 3] {
            controller.on_peer_control(
                MonoNs::new(2_600_000_000),
                FeedbackMessage::ack(seq).encode().unwrap(),
            );
        }
        assert_eq!(controller.next_wakeup(), None);
    }

    #[test]
    fn malformed_or_unknown_feedback_does_not_move_the_window() {
        let mut controller = CubicController::new(MonoNs::ZERO);
        sent(&mut controller, 1, 0);
        let before = controller.cwnd_bytes();
        controller.on_peer_control(
            MonoNs::new(1),
            OpaqueBytes::from_static(b"not-cubic-feedback"),
        );
        controller.on_peer_control(MonoNs::new(1), FeedbackMessage::ack(99).encode().unwrap());
        assert_eq!(controller.cwnd_bytes(), before);
        assert_eq!(controller.ledger().inflight_bytes(), 1_000);
    }

    #[test]
    fn delivery_hook_acknowledges_and_samples_rtt() {
        let mut controller = CubicController::new(MonoNs::ZERO);
        sent(&mut controller, 4, 0);
        controller.on_delivery(
            MonoNs::new(10_000_000),
            Delivery {
                seq: Some(4),
                bytes: 1_000,
                acked: true,
                lost: false,
                rtt_ns: None,
            },
        );
        assert_eq!(controller.ledger().inflight_bytes(), 0);
        assert_eq!(controller.ledger().latest_rtt_ns(), Some(10_000_000));
    }

    #[test]
    fn feedback_rtt_comes_from_local_ledger_without_a_data_send_timestamp() {
        let mut controller = CubicController::new(MonoNs::ZERO);
        sent(&mut controller, 1, 2);
        controller.on_peer_control(
            MonoNs::new(12_000_000),
            FeedbackMessage::new(Some(999), vec![FeedbackEvent::Sack { start: 1, end: 1 }])
                .encode()
                .unwrap(),
        );
        assert_eq!(controller.ledger().latest_rtt_ns(), Some(10_000_000));
        assert_eq!(controller.ledger().inflight_bytes(), 0);
    }

    #[test]
    fn cumulative_feedback_releases_only_live_exact_sequences() {
        let mut controller = CubicController::new(MonoNs::ZERO);
        sent(&mut controller, 1, 0);
        sent(&mut controller, 3, 0);
        sent(&mut controller, 5, 0);
        controller.on_peer_control(
            MonoNs::new(1_000_000),
            FeedbackMessage::cumulative_ack(3).encode().unwrap(),
        );
        assert_eq!(controller.ledger().inflight_bytes(), 1_000);
        assert_eq!(controller.ledger().get(5).map(|packet| packet.seq), Some(5));
    }

    #[test]
    fn sack_feedback_releases_only_live_sequences_in_the_range() {
        let mut controller = CubicController::new(MonoNs::ZERO);
        sent(&mut controller, 1, 0);
        sent(&mut controller, 3, 0);
        sent(&mut controller, 5, 0);
        controller.on_peer_control(
            MonoNs::new(1_000_000),
            FeedbackMessage::sack(2, 4).encode().unwrap(),
        );
        assert_eq!(controller.ledger().inflight_bytes(), 2_000);
        assert_eq!(controller.ledger().get(1).map(|packet| packet.seq), Some(1));
        assert_eq!(controller.ledger().get(5).map(|packet| packet.seq), Some(5));
        assert_eq!(
            controller.ledger().acknowledged_bytes(),
            1_000,
            "only the exact live sequence in 2..=4 is released"
        );
    }

    #[test]
    fn restart_returns_to_a_clean_startup_window() {
        let now = MonoNs::ZERO;
        let mut controller = CubicController::new(now);
        for seq in 0..3 {
            sent(&mut controller, seq, 0);
        }
        controller.on_peer_control(now, FeedbackMessage::loss(1).encode().unwrap());
        assert!(controller.ledger().inflight_bytes() > 0);
        assert!(controller.next_wakeup().is_some());

        controller.restart();
        let initial_cwnd = INITIAL_WINDOW_SEGMENTS * u64::from(DEFAULT_MSS_BYTES);
        assert_eq!(controller.cwnd_bytes(), initial_cwnd);
        assert_eq!(controller.w_max_bytes(), initial_cwnd);
        assert_eq!(controller.ledger().inflight_bytes(), 0);
        assert_eq!(controller.ledger().acknowledged_bytes(), 0);
        assert_eq!(controller.ledger().lost_bytes(), 0);
        assert_eq!(controller.next_wakeup(), None);
        assert_eq!(controller.k_seconds(), 0.0);
    }
}
