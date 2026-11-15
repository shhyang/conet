//! A small BBRv1-style validation controller over the shared ACK substrate.
//!
//! This is not a Linux BBR port. It estimates delivery bandwidth from ACKs,
//! tracks a sender-observed minimum RTT, and exposes a pacing-rate plus
//! inflight-cap proposal through the same ledger and opaque-feedback path used
//! by [`crate::CubicController`].

use conet_core::{ByteRate, ControlDisposition, Delivery, MonoNs, OpaqueBytes, Pace, TxController};

use crate::feedback::{FeedbackEvent, FeedbackMessage, FeedbackReplayWindow};
use crate::ledger::{InflightLedger, SentPacket};

/// BBRv1 Startup pacing gain.
pub const BBR_STARTUP_PACING_GAIN: f64 = 2.885;
/// BBRv1 pacing gain used to drain Startup's queue.
pub const BBR_DRAIN_PACING_GAIN: f64 = 1.0 / BBR_STARTUP_PACING_GAIN;
/// BBRv1 default cwnd gain.
pub const BBR_CWND_GAIN: f64 = 2.0;
/// Gain multiplier for the reduced inflight cap after loss.
pub const BBR_LOSS_HEADROOM: f64 = 0.8;
/// Initial delivery-rate estimate in bytes per second.
pub const BBR_INITIAL_BANDWIDTH: ByteRate = 12_000;
/// Initial sender-observed RTT before a real sample arrives.
pub const BBR_INITIAL_RTT: MonoNs = MonoNs::new(100_000_000);
/// Default segment size used for the small-pipe inflight floor.
pub const BBR_MSS_BYTES: u16 = 1_200;
/// Samples below this threshold count toward Startup's bandwidth plateau.
pub const BBR_FULL_BW_GROWTH: f64 = 1.25;
/// Consecutive plateau samples that exit Startup.
pub const BBR_FULL_BW_ROUNDS: u8 = 3;
/// ACKs spent in each simplified ProbeBW gain.
pub const BBR_PROBE_ACKS_PER_GAIN: u8 = 3;

const MIN_RATE_SAMPLE: MonoNs = MonoNs::new(1_000_000);
const MIN_LOSS_HEADROOM: f64 = 0.35;
const PROBE_GAINS: [f64; 3] = [1.25, 0.75, 1.0];

/// Simplified validation-law phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbrMode {
    Startup,
    Drain,
    ProbeBw,
}

/// BBR-style sender controller sharing the V0/V1 ACK and ledger substrate.
#[derive(Clone, Debug)]
pub struct BbrController {
    ledger: InflightLedger,
    mss_bytes: u16,
    mode: BbrMode,
    initial_bandwidth_bytes_per_sec: f64,
    bandwidth_bytes_per_sec: f64,
    full_bandwidth_bytes_per_sec: f64,
    full_bandwidth_rounds: u8,
    min_rtt_ns: Option<u64>,
    rate_sample_start: Option<MonoNs>,
    rate_sample_bytes: u64,
    probe_gain_index: usize,
    probe_acks: u8,
    loss_headroom: f64,
    feedback_replay: FeedbackReplayWindow,
}

impl BbrController {
    pub fn new(_now: MonoNs) -> Self {
        Self::with_initial_bandwidth(BBR_INITIAL_BANDWIDTH)
    }

    pub fn with_initial_bandwidth(bytes_per_sec: ByteRate) -> Self {
        let bandwidth = bytes_per_sec.max(1) as f64;
        Self {
            ledger: InflightLedger::new(),
            mss_bytes: BBR_MSS_BYTES,
            mode: BbrMode::Startup,
            initial_bandwidth_bytes_per_sec: bandwidth,
            bandwidth_bytes_per_sec: bandwidth,
            full_bandwidth_bytes_per_sec: bandwidth,
            full_bandwidth_rounds: 0,
            min_rtt_ns: None,
            rate_sample_start: None,
            rate_sample_bytes: 0,
            probe_gain_index: 0,
            probe_acks: 0,
            loss_headroom: 1.0,
            feedback_replay: FeedbackReplayWindow::default(),
        }
    }

    pub fn with_segment_size(mut self, mss_bytes: u16) -> Self {
        self.mss_bytes = mss_bytes.max(1);
        self
    }

    pub const fn mode(&self) -> BbrMode {
        self.mode
    }

    pub fn bandwidth_estimate_bytes_per_sec(&self) -> ByteRate {
        self.bandwidth_bytes_per_sec.round().max(1.0) as ByteRate
    }

    pub fn min_rtt_ns(&self) -> u64 {
        self.min_rtt_ns.unwrap_or(BBR_INITIAL_RTT.as_nanos() as u64)
    }

    pub fn bdp_bytes(&self) -> u64 {
        (self.bandwidth_bytes_per_sec * self.min_rtt_ns() as f64 / 1e9)
            .round()
            .max(1.0) as u64
    }

    pub fn inflight_limit_bytes(&self) -> u64 {
        let bdp = self.bdp_bytes() as f64;
        let gain = match self.mode {
            BbrMode::Startup => BBR_CWND_GAIN,
            BbrMode::Drain => 1.0,
            BbrMode::ProbeBw => match self.probe_gain_index {
                1 => 1.0,
                _ => BBR_CWND_GAIN,
            },
        };
        (bdp * gain * self.loss_headroom)
            .round()
            .max(f64::from(self.mss_bytes) * 2.0) as u64
    }

    pub fn pacing_rate_bytes_per_sec(&self) -> ByteRate {
        (self.bandwidth_bytes_per_sec * self.pacing_gain())
            .round()
            .max(1.0) as ByteRate
    }

    pub fn pacing_gain(&self) -> f64 {
        match self.mode {
            BbrMode::Startup => BBR_STARTUP_PACING_GAIN,
            BbrMode::Drain => BBR_DRAIN_PACING_GAIN,
            BbrMode::ProbeBw => PROBE_GAINS[self.probe_gain_index],
        }
    }

    pub fn ledger(&self) -> &InflightLedger {
        &self.ledger
    }

    pub fn apply_feedback(&mut self, now: MonoNs, message: &FeedbackMessage) {
        for event in &message.events {
            match *event {
                FeedbackEvent::Ack { seq } => self.acknowledge(now, seq, message.rtt_ns),
                FeedbackEvent::CumulativeAck { through } => {
                    let packets = self
                        .ledger
                        .on_cumulative_ack_at(through, now, message.rtt_ns);
                    if self.record_acknowledged(now, &packets, message.rtt_ns) {
                        self.advance_after_ack();
                    }
                }
                FeedbackEvent::Sack { start, end } => {
                    let packets = self.ledger.on_sack_at(start, end, now, message.rtt_ns);
                    if self.record_acknowledged(now, &packets, message.rtt_ns) {
                        self.advance_after_ack();
                    }
                }
                FeedbackEvent::Loss { seq } => self.declare_loss(seq),
            }
        }
    }

    fn acknowledge(&mut self, now: MonoNs, seq: u64, peer_rtt_ns: Option<u64>) {
        let Some(packet) = self.ledger.on_ack_at(seq, now, peer_rtt_ns) else {
            return;
        };
        if self.record_acknowledged(now, &[packet], peer_rtt_ns) {
            self.advance_after_ack();
        }
    }

    fn record_acknowledged(
        &mut self,
        now: MonoNs,
        packets: &[SentPacket],
        peer_rtt_ns: Option<u64>,
    ) -> bool {
        if packets.is_empty() {
            return false;
        }
        let earliest_send = packets
            .iter()
            .map(|packet| packet.sent_at)
            .min()
            .unwrap_or(now);
        for packet in packets {
            if let Some(rtt_ns) = packet_rtt_ns(packet, now, peer_rtt_ns) {
                self.min_rtt_ns = Some(self.min_rtt_ns.map_or(rtt_ns, |old| old.min(rtt_ns)));
            }
            self.rate_sample_bytes = self
                .rate_sample_bytes
                .saturating_add(u64::from(packet.bytes));
        }

        let sample_start = match self.rate_sample_start {
            Some(start) => start.min(earliest_send),
            None => earliest_send,
        };
        self.rate_sample_start = Some(sample_start);
        let elapsed = MonoNs::new(now.as_nanos().saturating_sub(sample_start.as_nanos()));
        if elapsed >= MIN_RATE_SAMPLE && elapsed.as_nanos() > 0 {
            let sample = self.rate_sample_bytes as f64 * 1e9 / elapsed.as_nanos() as f64;
            self.rate_sample_start = Some(now);
            self.rate_sample_bytes = 0;
            self.update_bandwidth_estimate(sample);
        }
        true
    }

    fn update_bandwidth_estimate(&mut self, sample_bytes_per_sec: f64) {
        let sample = sample_bytes_per_sec.max(1.0);
        if sample > self.bandwidth_bytes_per_sec {
            self.bandwidth_bytes_per_sec = sample;
            self.loss_headroom = (self.loss_headroom + 0.05).min(1.0);
        }
        if self.mode != BbrMode::Startup {
            return;
        }
        if sample >= self.full_bandwidth_bytes_per_sec * BBR_FULL_BW_GROWTH {
            self.full_bandwidth_bytes_per_sec = self.full_bandwidth_bytes_per_sec.max(sample);
            self.full_bandwidth_rounds = 0;
        } else {
            self.full_bandwidth_rounds = self.full_bandwidth_rounds.saturating_add(1);
            if self.full_bandwidth_rounds >= BBR_FULL_BW_ROUNDS {
                self.enter_drain();
            }
        }
    }

    fn declare_loss(&mut self, seq: u64) {
        if self.ledger.on_loss(seq).is_none() {
            return;
        }
        self.loss_headroom = (self.loss_headroom * BBR_LOSS_HEADROOM).max(MIN_LOSS_HEADROOM);
        match self.mode {
            BbrMode::Startup => self.enter_drain(),
            BbrMode::Drain => {}
            BbrMode::ProbeBw => {
                self.probe_gain_index = 1;
                self.probe_acks = 0;
            }
        }
    }

    fn enter_drain(&mut self) {
        self.mode = BbrMode::Drain;
        self.full_bandwidth_rounds = 0;
        self.probe_gain_index = 0;
        self.probe_acks = 0;
    }

    fn advance_after_ack(&mut self) {
        match self.mode {
            BbrMode::ProbeBw => {
                self.probe_acks = self.probe_acks.saturating_add(1);
                if self.probe_acks >= BBR_PROBE_ACKS_PER_GAIN {
                    self.probe_acks = 0;
                    self.probe_gain_index = (self.probe_gain_index + 1) % PROBE_GAINS.len();
                }
            }
            BbrMode::Startup | BbrMode::Drain => {}
        }
    }
}

impl TxController for BbrController {
    fn restart(&mut self) {
        let mss_bytes = self.mss_bytes;
        *self = Self::with_initial_bandwidth(
            self.initial_bandwidth_bytes_per_sec.round().max(1.0) as ByteRate
        )
        .with_segment_size(mss_bytes);
    }

    fn on_clock(&mut self, _now: MonoNs) {
        if self.mode == BbrMode::Drain && self.ledger.inflight_bytes() <= self.bdp_bytes() {
            self.mode = BbrMode::ProbeBw;
            self.probe_gain_index = 0;
            self.probe_acks = 0;
        }
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
            self.declare_loss(seq);
        }
    }

    fn inflight_bytes(&self) -> Option<u64> {
        Some(self.ledger.inflight_bytes())
    }

    fn pace(&self) -> Pace {
        Pace::set_rate_and_inflight(
            self.pacing_rate_bytes_per_sec(),
            self.inflight_limit_bytes(),
        )
    }
}

fn packet_rtt_ns(packet: &SentPacket, now: MonoNs, peer_rtt_ns: Option<u64>) -> Option<u64> {
    now.as_nanos()
        .checked_sub(packet.sent_at.as_nanos())
        .filter(|rtt| *rtt > 0)
        .and_then(|rtt| u64::try_from(rtt).ok())
        .or(peer_rtt_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: i64) -> MonoNs {
        MonoNs::new(value * 1_000_000)
    }

    fn send(controller: &mut BbrController, seq: u64, at: MonoNs, bytes: u16) {
        controller.on_packet_sent(at, bytes, Some(seq));
    }

    fn feedback(controller: &mut BbrController, now: MonoNs, message: FeedbackMessage) {
        let body = message.encode().unwrap();
        assert_eq!(
            controller.on_peer_control(now, body),
            ControlDisposition::Usable
        );
    }

    #[test]
    fn startup_raises_rate_and_inflight_from_ack_delivery() {
        let mut controller = BbrController::new(MonoNs::ZERO);
        let initial_rate = controller.pacing_rate_bytes_per_sec();
        let initial_cap = controller.inflight_limit_bytes();
        for seq in 0..3 {
            send(&mut controller, seq, MonoNs::ZERO, 1_200);
        }
        feedback(
            &mut controller,
            ms(20),
            FeedbackMessage::cumulative_ack(2).with_control_id(1),
        );

        assert_eq!(controller.mode(), BbrMode::Startup);
        assert!(controller.pacing_rate_bytes_per_sec() > initial_rate);
        assert!(controller.inflight_limit_bytes() > initial_cap);
        assert_eq!(controller.ledger().inflight_bytes(), 0);
    }

    #[test]
    fn startup_plateau_enters_drain_with_an_inflight_cap_at_bdp() {
        let mut controller = BbrController::new(MonoNs::ZERO);
        for seq in 0..3 {
            send(&mut controller, seq, MonoNs::ZERO, 1_200);
        }
        feedback(
            &mut controller,
            ms(20),
            FeedbackMessage::cumulative_ack(2).with_control_id(1),
        );
        let startup_cap = controller.inflight_limit_bytes();

        for (round, through) in [5, 8, 11].into_iter().enumerate() {
            for seq in (3 + round as u64 * 3)..(6 + round as u64 * 3) {
                send(&mut controller, seq, ms(20 + round as i64 * 20), 1_200);
            }
            feedback(
                &mut controller,
                ms(40 + round as i64 * 20),
                FeedbackMessage::cumulative_ack(through).with_control_id(2 + round as u32),
            );
        }

        assert_eq!(controller.mode(), BbrMode::Drain);
        assert_eq!(controller.inflight_limit_bytes(), controller.bdp_bytes());
        assert!(controller.inflight_limit_bytes() < startup_cap);
        assert_eq!(
            controller.pacing_rate_bytes_per_sec(),
            (controller.bandwidth_bytes_per_sec * BBR_DRAIN_PACING_GAIN).round() as ByteRate
        );
    }

    #[test]
    fn loss_reduces_inflight_and_new_rtt_samples_raise_the_estimate() {
        let mut controller = BbrController::new(MonoNs::ZERO);
        for seq in 0..6 {
            send(&mut controller, seq, MonoNs::ZERO, 1_200);
        }
        feedback(
            &mut controller,
            ms(40),
            FeedbackMessage::cumulative_ack(2).with_control_id(1),
        );
        let bandwidth_before = controller.bandwidth_estimate_bytes_per_sec();
        let cap_before_loss = controller.inflight_limit_bytes();

        feedback(
            &mut controller,
            ms(41),
            FeedbackMessage::loss(3).with_control_id(2),
        );
        assert!(controller.inflight_limit_bytes() < cap_before_loss);

        for seq in 6..9 {
            send(&mut controller, seq, ms(40), 1_200);
        }
        feedback(
            &mut controller,
            ms(45),
            FeedbackMessage::cumulative_ack(8).with_control_id(3),
        );
        assert_eq!(controller.min_rtt_ns(), 5_000_000);
        assert!(controller.bandwidth_estimate_bytes_per_sec() > bandwidth_before);
    }

    #[test]
    fn private_feedback_identity_is_consumed_only_for_usable_bodies() {
        let mut controller = BbrController::new(MonoNs::ZERO);
        send(&mut controller, 0, MonoNs::ZERO, 1_200);
        send(&mut controller, 1, MonoNs::ZERO, 1_200);
        let before = controller.ledger().inflight_bytes();

        assert_eq!(
            controller.on_peer_control(ms(1), OpaqueBytes::from_static(b"bad-bbr-body")),
            ControlDisposition::Unusable
        );
        feedback(
            &mut controller,
            ms(10),
            FeedbackMessage::ack(0).with_control_id(1),
        );
        assert!(controller.ledger().inflight_bytes() < before);
        let after_ack = controller.ledger().inflight_bytes();

        feedback(
            &mut controller,
            ms(11),
            FeedbackMessage::ack(99).with_control_id(2),
        );
        assert_eq!(controller.ledger().inflight_bytes(), after_ack);
        feedback(
            &mut controller,
            ms(12),
            FeedbackMessage::ack(1).with_control_id(2),
        );
        assert_eq!(controller.ledger().inflight_bytes(), after_ack);

        feedback(
            &mut controller,
            ms(13),
            FeedbackMessage::ack(1).with_control_id(3),
        );
        assert_eq!(controller.ledger().inflight_bytes(), 0);
    }

    #[test]
    fn restart_returns_to_startup_with_a_clean_ledger() {
        let mut controller = BbrController::new(MonoNs::ZERO);
        for seq in 0..3 {
            send(&mut controller, seq, MonoNs::ZERO, 1_200);
        }
        feedback(
            &mut controller,
            ms(20),
            FeedbackMessage::cumulative_ack(2).with_control_id(1),
        );
        assert!(controller.bandwidth_estimate_bytes_per_sec() > BBR_INITIAL_BANDWIDTH);
        controller.restart();
        assert_eq!(controller.mode(), BbrMode::Startup);
        assert_eq!(controller.ledger(), &InflightLedger::new());
        assert_eq!(
            controller.bandwidth_estimate_bytes_per_sec(),
            BBR_INITIAL_BANDWIDTH
        );
        assert_eq!(controller.min_rtt_ns(), BBR_INITIAL_RTT.as_nanos() as u64);
    }
}
