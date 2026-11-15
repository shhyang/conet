//! ACK-clocked byte accounting shared by validation controllers.
//!
//! The ledger deliberately tracks exact sequence numbers. It treats an ACK or
//! loss for an unknown sequence as stale input, so a malformed or spoofed
//! acknowledgement cannot release outstanding bytes.

use std::collections::BTreeMap;

use conet_core::{Delivery, MonoNs};

/// One successfully emitted packet retained until ACK or loss feedback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentPacket {
    pub seq: u64,
    pub bytes: u32,
    pub sent_at: MonoNs,
}

/// Exact-sequence inflight, acknowledgement, loss, and RTT bookkeeping.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InflightLedger {
    sent: BTreeMap<u64, SentPacket>,
    inflight_bytes: u64,
    acknowledged_bytes: u64,
    lost_bytes: u64,
    acknowledged_packets: u64,
    lost_packets: u64,
    latest_rtt_ns: Option<u64>,
}

impl InflightLedger {
    pub const fn new() -> Self {
        Self {
            sent: BTreeMap::new(),
            inflight_bytes: 0,
            acknowledged_bytes: 0,
            lost_bytes: 0,
            acknowledged_packets: 0,
            lost_packets: 0,
            latest_rtt_ns: None,
        }
    }

    /// Record a successfully emitted packet. Reusing a live sequence replaces
    /// its ledger entry rather than double-charging bytes.
    pub fn on_packet_sent(&mut self, now: MonoNs, seq: u64, bytes: u16) -> Option<SentPacket> {
        if bytes == 0 {
            return None;
        }
        let previous = self.remove_live(seq);
        let packet = SentPacket {
            seq,
            bytes: u32::from(bytes),
            sent_at: now,
        };
        self.sent.insert(seq, packet);
        self.inflight_bytes = self.inflight_bytes.saturating_add(u64::from(bytes));
        previous
    }

    /// Release an exact sequence and optionally retain a peer RTT sample.
    pub fn on_ack(&mut self, seq: u64, rtt_ns: Option<u64>) -> Option<SentPacket> {
        let packet = self.remove_live(seq)?;
        if let Some(rtt_ns) = rtt_ns {
            self.latest_rtt_ns = Some(rtt_ns);
        }
        self.acknowledged_packets = self.acknowledged_packets.saturating_add(1);
        self.acknowledged_bytes = self
            .acknowledged_bytes
            .saturating_add(u64::from(packet.bytes));
        Some(packet)
    }

    /// Release an exact sequence and sample RTT from the sender's local
    /// send-time ledger and the arrival time of the acknowledgement.
    pub fn on_ack_at(
        &mut self,
        seq: u64,
        arrived_at: MonoNs,
        peer_rtt_ns: Option<u64>,
    ) -> Option<SentPacket> {
        let local_rtt_ns = self
            .get(seq)
            .and_then(|packet| local_rtt_ns(packet.sent_at, arrived_at))
            .or(peer_rtt_ns);
        self.on_ack(seq, local_rtt_ns)
    }

    /// Release an exact sequence after loss feedback.
    pub fn on_loss(&mut self, seq: u64) -> Option<SentPacket> {
        let packet = self.remove_live(seq)?;
        self.lost_packets = self.lost_packets.saturating_add(1);
        self.lost_bytes = self.lost_bytes.saturating_add(u64::from(packet.bytes));
        Some(packet)
    }

    /// Acknowledge every exact live sequence at or below `cumulative`.
    ///
    /// Gaps have no ledger entry and therefore remain fail-closed rather than
    /// being synthesized into acknowledgements.
    pub fn on_cumulative_ack(&mut self, cumulative: u64, rtt_ns: Option<u64>) -> Vec<SentPacket> {
        let sequences: Vec<u64> = self
            .sent
            .range(..=cumulative)
            .map(|(&seq, _)| seq)
            .collect();
        let mut acknowledged = Vec::with_capacity(sequences.len());
        for seq in sequences {
            if let Some(packet) = self.on_ack(seq, rtt_ns) {
                acknowledged.push(packet);
            }
        }
        acknowledged
    }

    pub fn on_cumulative_ack_at(
        &mut self,
        cumulative: u64,
        arrived_at: MonoNs,
        peer_rtt_ns: Option<u64>,
    ) -> Vec<SentPacket> {
        let sequences: Vec<u64> = self
            .sent
            .range(..=cumulative)
            .map(|(&seq, _)| seq)
            .collect();
        let mut acknowledged = Vec::with_capacity(sequences.len());
        for seq in sequences {
            if let Some(packet) = self.on_ack_at(seq, arrived_at, peer_rtt_ns) {
                acknowledged.push(packet);
            }
        }
        acknowledged
    }

    /// Acknowledge exact live sequences inside an inclusive SACK range.
    ///
    /// Sequence numbers without a live ledger entry remain untouched.
    pub fn on_sack(&mut self, start: u64, end: u64, rtt_ns: Option<u64>) -> Vec<SentPacket> {
        if start > end {
            return Vec::new();
        }
        let sequences: Vec<u64> = self.sent.range(start..=end).map(|(&seq, _)| seq).collect();
        let mut acknowledged = Vec::with_capacity(sequences.len());
        for seq in sequences {
            if let Some(packet) = self.on_ack(seq, rtt_ns) {
                acknowledged.push(packet);
            }
        }
        acknowledged
    }

    pub fn on_sack_at(
        &mut self,
        start: u64,
        end: u64,
        arrived_at: MonoNs,
        peer_rtt_ns: Option<u64>,
    ) -> Vec<SentPacket> {
        if start > end {
            return Vec::new();
        }
        let sequences: Vec<u64> = self.sent.range(start..=end).map(|(&seq, _)| seq).collect();
        let mut acknowledged = Vec::with_capacity(sequences.len());
        for seq in sequences {
            if let Some(packet) = self.on_ack_at(seq, arrived_at, peer_rtt_ns) {
                acknowledged.push(packet);
            }
        }
        acknowledged
    }

    /// Apply the link's delivery ingress. Unknown or simultaneous ACK/loss
    /// entries are ignored fail-closed; ACK wins over a zero-byte stale loss.
    pub fn on_delivery(&mut self, delivery: Delivery) -> Option<SentPacket> {
        let seq = delivery.seq?;
        if delivery.acked {
            self.on_ack(seq, delivery.rtt_ns)
        } else if delivery.lost {
            self.on_loss(seq)
        } else {
            None
        }
    }

    pub fn on_rtt_sample(&mut self, rtt_ns: u64) {
        self.latest_rtt_ns = Some(rtt_ns);
    }

    pub const fn inflight_bytes(&self) -> u64 {
        self.inflight_bytes
    }

    pub fn inflight_packets(&self) -> usize {
        self.sent.len()
    }

    pub const fn acknowledged_bytes(&self) -> u64 {
        self.acknowledged_bytes
    }

    pub const fn lost_bytes(&self) -> u64 {
        self.lost_bytes
    }

    pub const fn acknowledged_packets(&self) -> u64 {
        self.acknowledged_packets
    }

    pub const fn lost_packets(&self) -> u64 {
        self.lost_packets
    }

    pub const fn latest_rtt_ns(&self) -> Option<u64> {
        self.latest_rtt_ns
    }

    pub fn get(&self, seq: u64) -> Option<&SentPacket> {
        self.sent.get(&seq)
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    fn remove_live(&mut self, seq: u64) -> Option<SentPacket> {
        let packet = self.sent.remove(&seq)?;
        self.inflight_bytes = self.inflight_bytes.saturating_sub(u64::from(packet.bytes));
        Some(packet)
    }
}

fn local_rtt_ns(sent_at: MonoNs, arrived_at: MonoNs) -> Option<u64> {
    arrived_at
        .as_nanos()
        .checked_sub(sent_at.as_nanos())
        .filter(|elapsed| *elapsed >= 0)
        .and_then(|elapsed| u64::try_from(elapsed).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ack_and_loss_move_bytes_out_of_flight() {
        let mut ledger = InflightLedger::new();
        ledger.on_packet_sent(MonoNs::ZERO, 7, 100);
        ledger.on_packet_sent(MonoNs::new(1), 8, 140);
        assert_eq!(ledger.inflight_bytes(), 240);

        assert_eq!(ledger.on_ack(77, Some(9_000)), None);
        assert_eq!(ledger.inflight_bytes(), 240);
        assert_eq!(ledger.latest_rtt_ns(), None);
        assert_eq!(ledger.on_ack(7, Some(10_000)).unwrap().bytes, 100);
        assert_eq!(ledger.on_loss(8).unwrap().bytes, 140);
        assert_eq!(ledger.inflight_bytes(), 0);
        assert_eq!(ledger.acknowledged_bytes(), 100);
        assert_eq!(ledger.lost_bytes(), 140);
        assert_eq!(ledger.latest_rtt_ns(), Some(10_000));
    }

    #[test]
    fn acknowledgement_arrival_derives_rtt_from_the_local_send_ledger() {
        let mut ledger = InflightLedger::new();
        ledger.on_packet_sent(MonoNs::new(1_000_000), 7, 100);
        ledger.on_ack_at(7, MonoNs::new(9_000_000), Some(1));
        assert_eq!(ledger.latest_rtt_ns(), Some(8_000_000));

        ledger.on_packet_sent(MonoNs::new(10_000_000), 8, 100);
        ledger.on_sack_at(8, 8, MonoNs::new(25_000_000), None);
        assert_eq!(ledger.latest_rtt_ns(), Some(15_000_000));

        ledger.on_packet_sent(MonoNs::new(30_000_000), 9, 100);
        ledger.on_cumulative_ack_at(9, MonoNs::new(32_000_000), Some(99));
        assert_eq!(ledger.latest_rtt_ns(), Some(2_000_000));
    }

    #[test]
    fn replacing_a_live_sequence_does_not_double_charge() {
        let mut ledger = InflightLedger::new();
        ledger.on_packet_sent(MonoNs::ZERO, 1, 100);
        ledger.on_packet_sent(MonoNs::new(1), 1, 200);
        assert_eq!(ledger.inflight_bytes(), 200);
        assert_eq!(ledger.inflight_packets(), 1);
    }

    #[test]
    fn cumulative_ack_releases_only_exact_live_sequences() {
        let mut ledger = InflightLedger::new();
        ledger.on_packet_sent(MonoNs::ZERO, 1, 100);
        ledger.on_packet_sent(MonoNs::new(1), 3, 300);
        ledger.on_packet_sent(MonoNs::new(2), 5, 500);

        let acknowledged = ledger.on_cumulative_ack(3, Some(7_000));
        assert_eq!(
            acknowledged
                .iter()
                .map(|packet| packet.seq)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(ledger.inflight_bytes(), 500);
        assert_eq!(ledger.inflight_packets(), 1);
        assert_eq!(ledger.get(2), None);
        assert_eq!(ledger.get(4), None);
        assert_eq!(ledger.latest_rtt_ns(), Some(7_000));
    }

    #[test]
    fn sack_releases_only_exact_live_sequences_inside_the_range() {
        let mut ledger = InflightLedger::new();
        ledger.on_packet_sent(MonoNs::ZERO, 1, 100);
        ledger.on_packet_sent(MonoNs::new(1), 3, 300);
        ledger.on_packet_sent(MonoNs::new(2), 5, 500);
        ledger.on_packet_sent(MonoNs::new(3), 8, 800);

        let acknowledged = ledger.on_sack(2, 6, Some(9_000));
        assert_eq!(
            acknowledged
                .iter()
                .map(|packet| packet.seq)
                .collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert_eq!(ledger.inflight_bytes(), 900);
        assert_eq!(ledger.get(2), None);
        assert_eq!(ledger.get(4), None);
        assert_eq!(ledger.get(6), None);
        assert_eq!(ledger.get(8).map(|packet| packet.seq), Some(8));
        assert_eq!(ledger.latest_rtt_ns(), Some(9_000));
    }

    #[test]
    fn clear_resets_live_and_retained_startup_state() {
        let mut ledger = InflightLedger::new();
        ledger.on_packet_sent(MonoNs::ZERO, 1, 100);
        ledger.on_ack(1, Some(2_000));
        ledger.on_packet_sent(MonoNs::new(3), 2, 200);
        ledger.on_loss(2);
        ledger.on_packet_sent(MonoNs::new(4), 3, 300);

        ledger.clear();
        assert_eq!(ledger.inflight_bytes(), 0);
        assert_eq!(ledger.inflight_packets(), 0);
        assert_eq!(ledger.acknowledged_bytes(), 0);
        assert_eq!(ledger.lost_bytes(), 0);
        assert_eq!(ledger.acknowledged_packets(), 0);
        assert_eq!(ledger.lost_packets(), 0);
        assert_eq!(ledger.latest_rtt_ns(), None);
    }
}
