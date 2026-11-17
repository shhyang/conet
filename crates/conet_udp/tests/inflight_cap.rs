use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use conet_core::{
    BlockId, ByteRate, ControlDisposition, Feedback, MonoNs, OpaqueBytes, Pace, TxController,
};
use conet_udp::{
    EndpointConfig, Role, SendClass, SimNetwork, SimTransport, UdpLiEndpoint, payload_packet,
};

type SimEndpoint = UdpLiEndpoint<SimTransport>;

struct LenLedgerController {
    cap: u64,
    inflight: u64,
}

impl TxController for LenLedgerController {
    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn on_packet_sent(&mut self, _now: MonoNs, bytes: u16, _seq: Option<u64>) {
        self.inflight = self.inflight.saturating_add(u64::from(bytes));
    }

    fn inflight_bytes(&self) -> Option<u64> {
        Some(self.inflight)
    }

    fn pace(&self) -> Pace {
        Pace::set_inflight_limit(self.cap)
    }
}

struct RateOnlyController {
    rate: ByteRate,
}

struct TrailerController {
    cap: Arc<AtomicU64>,
    inflight: u64,
    trailer: OpaqueBytes,
}

impl TxController for RateOnlyController {
    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn pace(&self) -> Pace {
        Pace::set_target_rate(self.rate)
    }
}

impl TxController for TrailerController {
    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn inflight_bytes(&self) -> Option<u64> {
        Some(self.inflight)
    }

    fn pace(&self) -> Pace {
        Pace::set_inflight_limit(self.cap.load(Ordering::Relaxed))
    }

    fn attach_cc(&self) -> Option<OpaqueBytes> {
        Some(self.trailer.clone())
    }
}

fn endpoint(network: &SimNetwork, role: Role, controller: Box<dyn TxController>) -> SimEndpoint {
    UdpLiEndpoint::with_controllers(
        network.transport(0),
        EndpointConfig::new(role, u64::MAX),
        controller,
        None,
    )
}

#[test]
fn udp_endpoint_stops_bulk_before_the_reported_window_cap() {
    let network = SimNetwork::new();
    let mut endpoint = endpoint(
        &network,
        Role::Initiator,
        Box::new(LenLedgerController {
            cap: 250,
            inflight: 0,
        }),
    );
    for value in 0..3 {
        endpoint
            .enqueue_file_data(payload_packet([value; 100]))
            .unwrap();
    }
    for step in 0..3 {
        endpoint.drive(MonoNs::new(step * 1_000_000));
    }
    assert_eq!(endpoint.sent().len(), 2);
    assert_eq!(endpoint.queued(SendClass::FileData), 1);
    assert_eq!(endpoint.controller_inflight_bytes(), Some(224));
    assert_eq!(endpoint.inflight_limit_bytes(), Some(250));

    // Control-only egress is not blocked by the data window, so it can carry
    // the ACK that eventually releases the remaining bulk packet.
    endpoint
        .enqueue_feedback_value(Feedback::ack(BlockId::new(1)))
        .unwrap();
    endpoint.drive(MonoNs::new(3_000_000));
    assert_eq!(endpoint.sent().len(), 3);
    endpoint.drive(MonoNs::new(5_000_000));
    assert_eq!(endpoint.queued(SendClass::Feedback), 0);
}

#[test]
fn rate_only_controller_without_an_inflight_sample_is_unaffected() {
    let network = SimNetwork::new();
    let mut endpoint = endpoint(
        &network,
        Role::Initiator,
        Box::new(RateOnlyController { rate: u64::MAX }),
    );
    for value in 0..4 {
        endpoint
            .enqueue_file_data(payload_packet([value; 100]))
            .unwrap();
    }

    for step in 0..4 {
        endpoint.drive(MonoNs::new(step * 1_000_000));
    }
    assert_eq!(endpoint.sent().len(), 4);
    assert_eq!(endpoint.queued(SendClass::FileData), 0);
    assert_eq!(endpoint.inflight_limit_bytes(), None);
    assert_eq!(endpoint.controller_inflight_bytes(), None);
}

#[test]
fn trailer_tipped_data_stays_queued_without_blocking_control_egress() {
    let network = SimNetwork::new();
    let cap = Arc::new(AtomicU64::new(55));
    let mut endpoint = endpoint(
        &network,
        Role::Initiator,
        Box::new(TrailerController {
            cap: Arc::clone(&cap),
            inflight: 0,
            trailer: OpaqueBytes::copy_from_slice(&[0xcc; 24]),
        }),
    );
    endpoint
        .enqueue_file_data(payload_packet([0x44; 32]))
        .unwrap();
    endpoint
        .enqueue_feedback_value(Feedback::ack(BlockId::new(1)))
        .unwrap();
    endpoint
        .enqueue_link_control(OpaqueBytes::from_static(b"control"))
        .unwrap();

    let report = endpoint.drive(MonoNs::ZERO);
    assert_eq!(report.sent, 1);
    assert!(!report.send_failed);
    assert_eq!(endpoint.sent()[0].class, SendClass::Feedback);
    assert_eq!(endpoint.queued(SendClass::Feedback), 0);
    assert_eq!(endpoint.queued(SendClass::LinkControl), 0);
    assert_eq!(endpoint.queued(SendClass::FileData), 1);
    assert_eq!(endpoint.next_drive(), None);

    for _ in 0..8 {
        assert_eq!(endpoint.drive(MonoNs::ZERO).sent, 0);
    }
    assert_eq!(endpoint.queued(SendClass::FileData), 1);

    let resume_at = endpoint.ready_at();
    cap.store(u64::MAX, Ordering::Relaxed);
    let report = endpoint.drive(resume_at);
    assert_eq!(report.sent, 1);
    assert_eq!(endpoint.sent().last().unwrap().class, SendClass::FileData);
    assert_eq!(endpoint.queued(SendClass::FileData), 0);
    assert!(endpoint.sent().last().unwrap().bytes > 55);
}
