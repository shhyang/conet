use std::sync::{Arc, Mutex};

use conet_core::{ControlDisposition, MonoNs, OpaqueBytes, Pace, TxController};
use conet_udp::{EndpointConfig, Role, SimNetwork, UdpLiEndpoint, payload_packet};

struct PollIdentityController {
    pending: Option<(u32, OpaqueBytes)>,
    committed: Arc<Mutex<Vec<u32>>>,
}

impl PollIdentityController {
    fn new(committed: Arc<Mutex<Vec<u32>>>) -> Self {
        Self {
            pending: None,
            committed,
        }
    }
}

impl TxController for PollIdentityController {
    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn pace(&self) -> Pace {
        Pace::set_target_rate(u64::MAX)
    }

    fn poll_control(&mut self, _now: MonoNs) -> Option<OpaqueBytes> {
        if self.pending.is_none() && self.committed.lock().unwrap().is_empty() {
            let id = 1;
            self.pending = Some((id, OpaqueBytes::copy_from_slice(&id.to_be_bytes())));
        }
        self.pending.as_ref().map(|(_, body)| body.clone())
    }

    fn on_cc_sent(&mut self, body: &OpaqueBytes) {
        let Some((id, pending)) = self.pending.as_ref() else {
            return;
        };
        if pending == body {
            self.committed.lock().unwrap().push(*id);
            self.pending = None;
        }
    }
}

#[test]
fn standalone_tx_control_commits_only_after_send() {
    let network = SimNetwork::new();
    let committed = Arc::new(Mutex::new(Vec::new()));
    let mut endpoint = UdpLiEndpoint::with_controllers(
        network.transport(0),
        EndpointConfig::new(Role::Initiator, u64::MAX),
        Box::new(PollIdentityController::new(Arc::clone(&committed))),
        None,
    );
    endpoint
        .enqueue_file_data(payload_packet(b"keep-pacer-progress"))
        .expect("data enqueue");
    network.fail_next_send(0);

    let failed = endpoint.drive(MonoNs::ZERO);
    assert!(failed.send_failed);
    assert_eq!(endpoint.queued(conet_udp::SendClass::LinkControl), 1);
    assert!(committed.lock().unwrap().is_empty());

    let retried = endpoint.drive(MonoNs::new(1_000_000));
    assert_eq!(retried.sent, 1);
    assert_eq!(endpoint.queued(conet_udp::SendClass::LinkControl), 0);
    assert_eq!(*committed.lock().unwrap(), vec![1]);
}
