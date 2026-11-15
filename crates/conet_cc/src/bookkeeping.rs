//! A small controller used to validate the shared substrate before a real law.

use conet_core::{ControlDisposition, Delivery, MonoNs, OpaqueBytes, Pace, TxController};

use crate::feedback::{FeedbackEvent, FeedbackMessage, FeedbackReplayWindow};
use crate::ledger::InflightLedger;

/// Window-only test controller whose state changes solely through ledger
/// acknowledgements, RTT samples, loss, and sent-packet bookkeeping.
#[derive(Clone, Debug)]
pub struct BookkeepingTestController {
    ledger: InflightLedger,
    initial_window: u64,
    window: u64,
    feedback_replay: FeedbackReplayWindow,
}

impl BookkeepingTestController {
    pub const fn new(initial_window: u64) -> Self {
        Self {
            ledger: InflightLedger::new(),
            initial_window,
            window: initial_window,
            feedback_replay: FeedbackReplayWindow::new(),
        }
    }

    pub const fn window_bytes(&self) -> u64 {
        self.window
    }

    pub fn ledger(&self) -> &InflightLedger {
        &self.ledger
    }

    pub fn apply_feedback(&mut self, now: MonoNs, message: &FeedbackMessage) {
        for event in &message.events {
            match *event {
                FeedbackEvent::Ack { seq } => self.ack(now, seq, message.rtt_ns),
                FeedbackEvent::CumulativeAck { through } => {
                    let packets = self
                        .ledger
                        .on_cumulative_ack_at(through, now, message.rtt_ns);
                    let released: u64 = packets.iter().map(|packet| u64::from(packet.bytes)).sum();
                    self.window = self.window.saturating_add(released);
                }
                FeedbackEvent::Sack { start, end } => {
                    let packets = self.ledger.on_sack_at(start, end, now, message.rtt_ns);
                    let released: u64 = packets.iter().map(|packet| u64::from(packet.bytes)).sum();
                    self.window = self.window.saturating_add(released);
                }
                FeedbackEvent::Loss { seq } => self.loss(seq),
            }
        }
    }

    fn ack(&mut self, now: MonoNs, seq: u64, rtt_ns: Option<u64>) {
        if let Some(packet) = self.ledger.on_ack_at(seq, now, rtt_ns) {
            self.window = self.window.saturating_add(u64::from(packet.bytes));
        }
    }

    fn loss(&mut self, seq: u64) {
        if self.ledger.on_loss(seq).is_some() {
            self.window = self.window.saturating_sub((self.window / 2).max(1));
        }
    }
}

impl TxController for BookkeepingTestController {
    fn restart(&mut self) {
        self.ledger.clear();
        self.window = self.initial_window;
        self.feedback_replay.clear();
    }

    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, now: MonoNs, body: OpaqueBytes) -> ControlDisposition {
        if let Some(message) = FeedbackMessage::decode(&body) {
            if message
                .control_id
                .is_none_or(|id| self.feedback_replay.accept(id))
            {
                self.apply_feedback(now, &message);
            }
            ControlDisposition::Usable
        } else {
            ControlDisposition::Unusable
        }
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
            self.ack(now, seq, delivery.rtt_ns);
        } else if delivery.lost {
            self.loss(seq);
        }
    }

    fn inflight_bytes(&self) -> Option<u64> {
        Some(self.ledger.inflight_bytes())
    }

    fn pace(&self) -> Pace {
        Pace::set_inflight_limit(self.window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conet_core::Delivery;

    #[test]
    fn test_controller_changes_window_only_from_bookkeeping() {
        let mut controller = BookkeepingTestController::new(1_000);
        controller.on_packet_sent(MonoNs::new(1_000_000), 100, Some(1));
        assert_eq!(controller.pace(), Pace::set_inflight_limit(1_000));
        controller.on_peer_control(MonoNs::new(1), OpaqueBytes::from_static(b"malformed"));
        assert_eq!(controller.window_bytes(), 1_000);

        controller.on_delivery(
            MonoNs::new(3_000_000),
            Delivery {
                seq: Some(1),
                bytes: 100,
                acked: true,
                lost: false,
                rtt_ns: None,
            },
        );
        assert_eq!(controller.window_bytes(), 1_100);
        assert_eq!(controller.ledger().latest_rtt_ns(), Some(2_000_000));

        controller.on_packet_sent(MonoNs::new(3), 100, Some(2));
        controller.on_delivery(
            MonoNs::new(4),
            Delivery {
                seq: Some(2),
                bytes: 100,
                acked: false,
                lost: true,
                rtt_ns: None,
            },
        );
        assert_eq!(controller.window_bytes(), 550);
    }

    #[test]
    fn cumulative_ack_and_restart_preserve_fail_closed_accounting() {
        let mut controller = BookkeepingTestController::new(1_000);
        controller.on_packet_sent(MonoNs::ZERO, 100, Some(1));
        controller.on_packet_sent(MonoNs::ZERO, 200, Some(3));
        controller.on_packet_sent(MonoNs::ZERO, 300, Some(5));
        controller.apply_feedback(MonoNs::ZERO, &FeedbackMessage::cumulative_ack(3));
        assert_eq!(controller.ledger().inflight_bytes(), 300);
        assert_eq!(controller.window_bytes(), 1_300);

        controller.restart();
        assert_eq!(controller.ledger().inflight_bytes(), 0);
        assert_eq!(controller.window_bytes(), 1_000);
    }

    #[test]
    fn cumulative_ack_and_sack_apply_together_without_double_release() {
        let mut controller = BookkeepingTestController::new(1_000);
        controller.on_packet_sent(MonoNs::ZERO, 100, Some(1));
        controller.on_packet_sent(MonoNs::ZERO, 300, Some(3));
        controller.on_packet_sent(MonoNs::ZERO, 500, Some(5));
        let message = FeedbackMessage::new(
            None,
            vec![
                FeedbackEvent::CumulativeAck { through: 1 },
                FeedbackEvent::Sack { start: 3, end: 5 },
            ],
        );

        controller.apply_feedback(MonoNs::ZERO, &message);
        assert_eq!(controller.ledger().inflight_bytes(), 0);
        assert_eq!(controller.ledger().acknowledged_bytes(), 900);
        assert_eq!(controller.window_bytes(), 1_900);

        controller.apply_feedback(MonoNs::ZERO, &message);
        assert_eq!(controller.ledger().acknowledged_bytes(), 900);
        assert_eq!(controller.window_bytes(), 1_900);
    }
}
