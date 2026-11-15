use std::sync::{Arc, Mutex};

use conet_cc::{
    ControlDisposition, MonoNs, Observation, OpaqueBytes, Pace, RxController, TxController,
};
use conet_udp::{EndpointConfig, Role, SimNetwork, SimTransport, UdpLiEndpoint, payload_packet};

type SimEndpoint = UdpLiEndpoint<SimTransport>;

#[derive(Default)]
struct Evidence {
    peer_bodies: Vec<OpaqueBytes>,
    observations: Vec<Observation>,
}

struct DummyController {
    trailer: Option<OpaqueBytes>,
    feedback: Option<OpaqueBytes>,
    arm_feedback: Arc<Mutex<bool>>,
    evidence: Arc<Mutex<Evidence>>,
}

impl TxController for DummyController {
    fn on_peer_control(&mut self, _now: MonoNs, body: OpaqueBytes) -> ControlDisposition {
        self.evidence.lock().unwrap().peer_bodies.push(body);
        ControlDisposition::Usable
    }

    fn on_clock(&mut self, _now: MonoNs) {}

    fn poll_control(&mut self, _now: MonoNs) -> Option<OpaqueBytes> {
        let mut armed = self.arm_feedback.lock().unwrap();
        if *armed {
            *armed = false;
            self.feedback.clone()
        } else {
            None
        }
    }

    fn attach_cc(&self) -> Option<OpaqueBytes> {
        self.trailer.clone()
    }

    fn pace(&self) -> Pace {
        Pace::set_rate_and_inflight(6_400, 4_096)
    }
}

impl RxController for DummyController {
    fn on_observed(&mut self, observation: Observation) -> ControlDisposition {
        self.evidence.lock().unwrap().observations.push(observation);
        ControlDisposition::Usable
    }

    fn poll_control(&mut self, _now: MonoNs) -> Option<OpaqueBytes> {
        None
    }
}

fn endpoint(
    network: &SimNetwork,
    host: usize,
    role: Role,
    trailer: Option<OpaqueBytes>,
) -> (SimEndpoint, Arc<Mutex<bool>>, Arc<Mutex<Evidence>>) {
    let arm_feedback = Arc::new(Mutex::new(false));
    let evidence = Arc::new(Mutex::new(Evidence::default()));
    let tx = DummyController {
        trailer: trailer.clone(),
        feedback: Some(OpaqueBytes::from_static(b"standalone-window")),
        arm_feedback: Arc::clone(&arm_feedback),
        evidence: Arc::clone(&evidence),
    };
    let rx = DummyController {
        trailer,
        feedback: None,
        arm_feedback: Arc::clone(&arm_feedback),
        evidence: Arc::clone(&evidence),
    };
    (
        UdpLiEndpoint::with_controllers(
            network.transport(host),
            EndpointConfig::new(role, u64::MAX),
            Box::new(tx),
            Some(Box::new(rx)),
        ),
        arm_feedback,
        evidence,
    )
}

#[test]
fn dummy_hook_uses_opaque_trailer_feedback_rate_and_window() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let trailer = OpaqueBytes::from_static(b"\x00not-a-residual-status\xff");
    let (mut sender, sender_arm, _) = endpoint(&network, 0, Role::Initiator, Some(trailer.clone()));
    let (mut receiver, _, receiver_evidence) = endpoint(&network, 1, Role::Responder, None);
    sender.establish_for_test(0x4343, 1).unwrap();
    receiver.establish_for_test(0x4343, 1).unwrap();

    sender
        .enqueue_file_data(payload_packet(b"format-agnostic-body"))
        .unwrap();
    sender.drive(MonoNs::ZERO);
    receiver.drive(MonoNs::ZERO);

    assert_eq!(sender.target_rate(), 6_400);
    assert_eq!(sender.inflight_limit_bytes(), Some(4_096));
    assert_eq!(
        receiver_evidence.lock().unwrap().observations[0]
            .cc_bytes
            .as_deref(),
        Some(trailer.as_ref())
    );
    assert_eq!(
        receiver_evidence.lock().unwrap().peer_bodies,
        vec![trailer.clone()]
    );

    *sender_arm.lock().unwrap() = true;
    sender
        .enqueue_file_data(payload_packet(b"next-data"))
        .unwrap();
    let later = MonoNs::new(10_000_000);
    sender.drive(later);
    receiver.drive(later);

    assert_eq!(
        receiver_evidence.lock().unwrap().peer_bodies,
        vec![trailer, OpaqueBytes::from_static(b"standalone-window")]
    );
}
