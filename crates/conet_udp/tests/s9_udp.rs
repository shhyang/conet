use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use conet_core::{
    BlockId, ControlDisposition, ControlMessage, ControlType, Feedback, MonoNs, OpaqueBytes, Pace,
    QosClass, QueueLimits, ReferenceWireCodec, TxController, WireFlags, WireHeader,
    decode_reliability_feedback, encode_reliability_feedback,
};
use conet_udp::{
    AssociationState, DatagramTransport, EndpointConfig, InboundDatagram, OpenStateBody,
    ProfileEnqueueErrorKind, Role, SendClass, SimNetwork, SimTransport, UDP_LI_PROFILE_ID,
    UdpLiEndpoint, payload_packet,
};

type SimEndpoint = UdpLiEndpoint<SimTransport>;

fn ms(value: i64) -> MonoNs {
    MonoNs::new(value * 1_000_000)
}

fn nanos(value: i64) -> MonoNs {
    MonoNs::new(value)
}

fn endpoint(network: &SimNetwork, host: usize, role: Role, rate: u64) -> SimEndpoint {
    UdpLiEndpoint::new(network.transport(host), EndpointConfig::new(role, rate))
}

fn established_pair(rate: u64) -> (SimNetwork, SimEndpoint, SimEndpoint) {
    let network = SimNetwork::new();
    let mut a = endpoint(&network, 0, Role::Initiator, rate);
    let mut b = endpoint(&network, 1, Role::Responder, rate);
    a.establish_for_test(0x1122_3344, 1).unwrap();
    b.establish_for_test(0x1122_3344, 1).unwrap();
    (network, a, b)
}

fn handshake_pair(rate: u64) -> (SimNetwork, SimEndpoint, SimEndpoint) {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut a = endpoint(&network, 0, Role::Initiator, rate);
    let b = endpoint(&network, 1, Role::Responder, rate);
    a.start_association().unwrap();
    (network, a, b)
}

fn pump_handshake(network: &SimNetwork, a: &mut SimEndpoint, b: &mut SimEndpoint, now: MonoNs) {
    for step in 0..8 {
        let drive_at = now.saturating_add(ms(step + 1));
        a.drive(drive_at);
        b.drive(drive_at);
        if a.state() == AssociationState::Established
            && b.state() == AssociationState::Established
            && network.pending(0) == 0
            && network.pending(1) == 0
        {
            return;
        }
    }
    panic!(
        "association did not establish: A={:?}, B={:?}",
        a.state(),
        b.state()
    );
}

fn header(epoch: u16, link_seq: u32, qos: QosClass) -> WireHeader {
    WireHeader {
        flags: WireFlags { qos },
        epoch,
        link_seq,
        payload_len: 0,
    }
}

fn wire_frame(
    epoch: u16,
    link_seq: u32,
    qos: QosClass,
    payload: OpaqueBytes,
    control: Option<ControlMessage>,
) -> Vec<u8> {
    let codec = ReferenceWireCodec::default();
    let datagram = codec
        .build(header(epoch, link_seq, qos), payload, control)
        .unwrap();
    codec.serialize(&datagram).unwrap()
}

fn data_frame(epoch: u16, link_seq: u32, payload: &[u8]) -> Vec<u8> {
    wire_frame(
        epoch,
        link_seq,
        QosClass::Bulk,
        OpaqueBytes::copy_from_slice(payload),
        None,
    )
}

#[derive(Debug, Default)]
struct ReadinessTransport {
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    waits: Arc<Mutex<Vec<Option<Duration>>>>,
}

impl DatagramTransport for ReadinessTransport {
    fn send_datagram(&mut self, _now: MonoNs, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn recv_datagram(&mut self, _now: MonoNs) -> std::io::Result<Option<InboundDatagram>> {
        Ok(self
            .inbound
            .lock()
            .unwrap()
            .pop_front()
            .map(|bytes| InboundDatagram::from_vec(bytes, true)))
    }

    fn wait_readable(&mut self, timeout: Option<Duration>) -> std::io::Result<bool> {
        self.waits.lock().unwrap().push(timeout);
        Ok(!self.inbound.lock().unwrap().is_empty())
    }
}

#[derive(Debug, Default)]
struct ControllerEvidence {
    peer_bodies: Vec<OpaqueBytes>,
    sent: Vec<(i64, u16, Option<u64>)>,
    timer_calls: Vec<MonoNs>,
}

struct RecordingController {
    configured_rate: u64,
    suggestion: Option<u64>,
    evidence: Arc<Mutex<ControllerEvidence>>,
}

struct DeadlineController {
    deadline: Option<MonoNs>,
    rate: u64,
    calls: Arc<Mutex<Vec<MonoNs>>>,
}

impl TxController for DeadlineController {
    fn on_clock(&mut self, now: MonoNs) {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.calls.lock().unwrap().push(now);
            self.deadline = None;
            self.rate = 7_000;
        }
    }

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn pace(&self) -> Pace {
        Pace::set_target_rate(self.rate)
    }

    fn next_wakeup(&self) -> Option<MonoNs> {
        self.deadline
    }
}

impl TxController for RecordingController {
    fn on_clock(&mut self, now: MonoNs) {
        self.evidence.lock().unwrap().timer_calls.push(now);
    }

    fn on_peer_control(&mut self, _now: MonoNs, body: OpaqueBytes) -> ControlDisposition {
        self.evidence.lock().unwrap().peer_bodies.push(body);
        if let Some(suggestion) = self.suggestion {
            self.configured_rate = suggestion;
        }
        ControlDisposition::Usable
    }

    fn on_packet_sent(&mut self, now: MonoNs, bytes: u16, seq: Option<u64>) {
        self.evidence
            .lock()
            .unwrap()
            .sent
            .push((now.as_nanos(), bytes, seq));
    }

    fn pace(&self) -> Pace {
        Pace::set_target_rate(self.configured_rate)
    }
}

fn recording_endpoint(
    network: &SimNetwork,
    host: usize,
    role: Role,
    rate: u64,
    suggestion: Option<u64>,
) -> (SimEndpoint, Arc<Mutex<ControllerEvidence>>) {
    let evidence = Arc::new(Mutex::new(ControllerEvidence::default()));
    let controller = RecordingController {
        configured_rate: rate,
        suggestion,
        evidence: Arc::clone(&evidence),
    };
    let endpoint = UdpLiEndpoint::with_controllers(
        network.transport(host),
        EndpointConfig::new(role, rate),
        Box::new(controller),
        None,
    );
    (endpoint, evidence)
}

#[test]
fn association_open_accept_close_and_fresh_id() {
    let (network, mut a, mut b) = handshake_pair(u64::MAX);
    let first_id = a.association_id().unwrap();
    assert_eq!(a.epoch(), 1);
    pump_handshake(&network, &mut a, &mut b, MonoNs::ZERO);

    a.close().unwrap();
    for step in 0..6 {
        a.drive(ms(step + 1));
        b.drive(ms(step + 1));
    }
    assert_eq!(a.state(), AssociationState::Closed);
    assert_eq!(b.state(), AssociationState::Closed);
    let codec = ReferenceWireCodec::default();
    let controls: Vec<_> = network
        .frames_from(0)
        .into_iter()
        .filter_map(|frame| {
            codec
                .parse(OpaqueBytes::from(frame.bytes))
                .ok()
                .and_then(|datagram| datagram.control().cloned())
        })
        .collect();
    let open_seq = controls
        .iter()
        .find(|control| control.ctrl_type == ControlType::Open)
        .unwrap()
        .ctrl_seq;
    let close_seq = controls
        .iter()
        .find(|control| control.ctrl_type == ControlType::Close)
        .unwrap()
        .ctrl_seq;
    assert_ne!(close_seq, open_seq);

    a.start_association().unwrap();
    assert_ne!(a.association_id().unwrap(), first_id);
    assert_eq!(a.epoch(), 1);
}

#[test]
fn responder_handshakes_until_accept_is_sent() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut a = endpoint(&network, 0, Role::Initiator, u64::MAX);
    let mut b = endpoint(&network, 1, Role::Responder, u64::MAX);
    a.start_association().unwrap();

    a.drive(ms(1));
    b.drive(ms(1));
    assert_eq!(b.state(), AssociationState::Handshaking);
    assert_eq!(b.queued(SendClass::Association), 1);

    b.drive(ms(2));
    assert_eq!(b.state(), AssociationState::Established);
    a.drive(ms(2));
    assert_eq!(a.state(), AssociationState::Established);
}

#[test]
fn unauthenticated_association_controls_fail_closed_unless_overridden() {
    let network = SimNetwork::new();
    let mut a = endpoint(&network, 0, Role::Initiator, u64::MAX);
    let mut b = endpoint(&network, 1, Role::Responder, u64::MAX);
    a.start_association().unwrap();
    a.drive(ms(1));
    b.drive(ms(1));
    assert_eq!(b.state(), AssociationState::Idle);
    assert_eq!(b.drop_count("unauthenticated_association"), 1);

    let override_network = SimNetwork::new();
    let mut override_a = UdpLiEndpoint::new(
        override_network.transport(0),
        EndpointConfig::new(Role::Initiator, u64::MAX).test_open(),
    );
    let mut override_b = UdpLiEndpoint::new(
        override_network.transport(1),
        EndpointConfig::new(Role::Responder, u64::MAX).test_open(),
    );
    override_a.start_association().unwrap();
    pump_handshake(
        &override_network,
        &mut override_a,
        &mut override_b,
        MonoNs::ZERO,
    );
    override_a.close().unwrap();
    for step in 0..4 {
        let now = ms(10 + step);
        override_a.drive(now);
        override_b.drive(now);
    }
    assert_eq!(override_a.state(), AssociationState::Closed);
    assert_eq!(override_b.state(), AssociationState::Closed);
}

#[test]
fn authenticated_open_has_no_header_send_timestamp() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut b = endpoint(&network, 1, Role::Responder, u64::MAX);
    let open = OpenStateBody {
        profile_id: UDP_LI_PROFILE_ID,
        max_datagram: 1280,
        nonce: 0x5151,
    }
    .encode();
    network.inject(
        1,
        wire_frame(
            1,
            0,
            QosClass::Control,
            OpaqueBytes::new(),
            Some(ControlMessage::new(ControlType::Open, 1, open)),
        ),
        true,
    );

    b.drive(MonoNs::ZERO);
    assert_eq!(b.state(), AssociationState::Handshaking);
    assert_eq!(b.drop_count("unfresh_control"), 0);
}

#[test]
fn live_zero_time_handshake_establishes_without_retry() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut a = endpoint(&network, 0, Role::Initiator, u64::MAX);
    let mut b = endpoint(&network, 1, Role::Responder, u64::MAX);
    a.start_association().unwrap();

    a.drive(MonoNs::ZERO);
    b.drive(MonoNs::ZERO);
    b.drive(MonoNs::ZERO);
    a.drive(MonoNs::ZERO);

    assert_eq!(a.state(), AssociationState::Established);
    assert_eq!(b.state(), AssociationState::Established);
    let codec = ReferenceWireCodec::default();
    let opens: Vec<_> = network
        .frames_from(0)
        .into_iter()
        .filter_map(|frame| codec.parse(OpaqueBytes::from(frame.bytes)).ok())
        .filter_map(|datagram| datagram.control().cloned())
        .filter(|control| control.ctrl_type == ControlType::Open)
        .collect();
    assert_eq!(opens.len(), 1);
    let parsed = codec
        .parse(OpaqueBytes::from(network.frames_from(0).remove(0).bytes))
        .unwrap();
    assert_eq!(parsed.packet().header().len(), 12);
    assert_eq!(parsed.packet().header().as_bytes()[2], 5);
}

#[test]
fn authenticated_association_rejects_unauthenticated_close() {
    let (network, mut a, mut b) = handshake_pair(u64::MAX);
    pump_handshake(&network, &mut a, &mut b, MonoNs::ZERO);
    network.set_authenticated(false);

    a.close().unwrap();
    a.drive(ms(10));
    b.drive(ms(10));
    assert_eq!(a.state(), AssociationState::Closing);
    assert_eq!(b.state(), AssociationState::Established);
    assert_eq!(b.drop_count("unauthenticated_association"), 1);
}

#[test]
fn duplicated_open_is_bounded_to_five_sends_then_fails() {
    let network = SimNetwork::new();
    let mut a = endpoint(&network, 0, Role::Initiator, u64::MAX);
    a.start_association().unwrap();

    for step in 0..5 {
        a.drive(ms(step * 200));
    }
    let frames = network.frames_from(0);
    assert_eq!(frames.len(), 5);
    let codec = ReferenceWireCodec::default();
    let mut ctrl_seqs = Vec::new();
    for frame in &frames {
        let parsed = codec
            .parse(OpaqueBytes::copy_from_slice(&frame.bytes))
            .unwrap();
        let control = parsed.control().unwrap();
        assert_eq!(control.ctrl_type, ControlType::Open);
        ctrl_seqs.push(control.ctrl_seq);
    }
    assert!(ctrl_seqs.windows(2).all(|pair| pair[0] == pair[1]));

    let report = a.drive(ms(1_000));
    assert!(report.association_failed);
    assert_eq!(a.state(), AssociationState::Failed);
    assert_eq!(network.frames_from(0).len(), 5);
}

#[test]
fn authenticated_cc_applies_without_send_timestamp_or_delay() {
    let network = SimNetwork::new();
    let (mut b, evidence) = recording_endpoint(&network, 1, Role::Responder, 1_000, Some(2_000));
    b.establish_for_test(0x3030, 1).unwrap();
    network.inject(
        1,
        wire_frame(
            1,
            1,
            QosClass::Bulk,
            OpaqueBytes::from_static(b"user-body"),
            Some(ControlMessage::new(
                ControlType::CcOpaque,
                1,
                OpaqueBytes::from_static(b"control"),
            )),
        ),
        true,
    );

    b.drive(MonoNs::ZERO);
    assert_eq!(b.target_rate(), 2_000);
    assert_eq!(b.drop_count("unfresh_control"), 0);
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 1);
    let received = b.take_received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].packet.payload_bytes(), b"user-body");
}

#[test]
fn cc_replay_is_left_to_the_private_codec_while_payload_remains_independent() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let (mut b, evidence) = recording_endpoint(&network, 1, Role::Responder, 1_000, Some(2_000));
    b.establish_for_test(0x3030, 1).unwrap();

    let piggybacked = wire_frame(
        1,
        1,
        QosClass::Bulk,
        OpaqueBytes::from_static(b"user-body"),
        Some(ControlMessage::new(
            ControlType::CcOpaque,
            41,
            OpaqueBytes::from_static(b"first-control"),
        )),
    );
    network.inject(1, piggybacked.clone(), true);
    b.drive(MonoNs::ZERO);
    assert_eq!(b.target_rate(), 2_000);

    network.inject(1, piggybacked, true);
    b.drive(ms(1));
    assert_eq!(b.target_rate(), 2_000);
    let received = b.take_received();
    assert_eq!(
        received
            .iter()
            .map(|datagram| datagram.packet.payload_bytes())
            .collect::<Vec<_>>(),
        vec![b"user-body".as_slice(), b"user-body".as_slice()]
    );
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 2);

    let standalone = wire_frame(
        1,
        2,
        QosClass::Control,
        OpaqueBytes::new(),
        Some(ControlMessage::new(
            ControlType::CcOpaque,
            42,
            OpaqueBytes::from_static(b"standalone-control"),
        )),
    );
    network.inject(1, standalone.clone(), true);
    b.drive(ms(2));
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 3);
    assert_eq!(b.take_received().len(), 1);

    network.inject(1, standalone, true);
    let replay = b.drive(ms(3));
    assert_eq!(replay.dropped, 0);
    assert_eq!(b.drop_count("replayed_control"), 0);
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 4);
    assert_eq!(b.take_received().len(), 1);
}

#[test]
fn cc_without_private_identity_is_not_rejected_by_the_link_window() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let (mut b, evidence) = recording_endpoint(&network, 1, Role::Responder, 1_000, Some(2_000));
    b.establish_for_test(0x3033, 1).unwrap();

    for (link_seq, ctrl_seq, body) in [
        (1, 100, b"first-control".as_slice()),
        (2, 164, b"window-advance".as_slice()),
    ] {
        network.inject(
            1,
            wire_frame(
                1,
                link_seq,
                QosClass::Control,
                OpaqueBytes::new(),
                Some(ControlMessage::new(
                    ControlType::CcOpaque,
                    ctrl_seq,
                    OpaqueBytes::copy_from_slice(body),
                )),
            ),
            true,
        );
    }
    b.drive(MonoNs::ZERO);
    b.drive(ms(1));
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 2);
    assert_eq!(b.take_received().len(), 2);

    network.inject(
        1,
        wire_frame(
            1,
            3,
            QosClass::Bulk,
            OpaqueBytes::from_static(b"late-user-body"),
            Some(ControlMessage::new(
                ControlType::CcOpaque,
                100,
                OpaqueBytes::from_static(b"evicted-control"),
            )),
        ),
        true,
    );
    b.drive(ms(2));
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 3);
    let received = b.take_received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].packet.payload_bytes(), b"late-user-body");

    network.inject(
        1,
        wire_frame(
            1,
            4,
            QosClass::Control,
            OpaqueBytes::new(),
            Some(ControlMessage::new(
                ControlType::CcOpaque,
                100,
                OpaqueBytes::from_static(b"evicted-control"),
            )),
        ),
        true,
    );
    let report = b.drive(ms(3));
    assert_eq!(report.dropped, 0);
    assert_eq!(b.drop_count("old_control"), 0);
    assert_eq!(b.drop_count("replayed_control"), 0);
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 4);
    assert_eq!(b.take_received().len(), 1);
}

#[test]
fn attached_cc_replay_is_still_passed_to_the_private_codec() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut b = endpoint(&network, 1, Role::Responder, u64::MAX);
    b.establish_for_test(0x3032, 1).unwrap();
    let frame = wire_frame(
        1,
        1,
        QosClass::Bulk,
        OpaqueBytes::from_static(b"cc-user-body"),
        Some(ControlMessage::new(
            ControlType::Cc,
            0,
            OpaqueBytes::from_static(b"private-cc-body"),
        )),
    );

    network.inject(1, frame.clone(), true);
    b.drive(MonoNs::ZERO);
    assert!(b.observations()[0].cc_bytes.is_some());

    network.inject(1, frame, true);
    b.drive(ms(1));
    assert_eq!(b.observations().len(), 2);
    assert!(b.observations()[1].cc_bytes.is_some());
    let received = b.take_received();
    assert_eq!(received.len(), 2);
    assert!(
        received
            .iter()
            .all(|datagram| datagram.packet.payload_bytes() == b"cc-user-body")
    );
}

#[test]
fn open_retries_with_reused_ctrl_seq_stay_first_copy_wins() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let mut b = endpoint(&network, 1, Role::Responder, u64::MAX);
    let open = OpenStateBody {
        profile_id: UDP_LI_PROFILE_ID,
        max_datagram: 1280,
        nonce: 0x5252,
    }
    .encode();

    network.inject(
        1,
        wire_frame(
            1,
            0,
            QosClass::Control,
            OpaqueBytes::new(),
            Some(ControlMessage::new(ControlType::Open, 77, open.clone())),
        ),
        true,
    );
    b.drive(MonoNs::ZERO);
    assert_eq!(b.state(), AssociationState::Handshaking);
    assert_eq!(b.queued(SendClass::Association), 1);

    network.inject(
        1,
        wire_frame(
            1,
            1,
            QosClass::Control,
            OpaqueBytes::new(),
            Some(ControlMessage::new(ControlType::Open, 77, open)),
        ),
        true,
    );
    b.drive(MonoNs::ZERO);
    assert_eq!(b.state(), AssociationState::Established);
    assert_eq!(b.queued(SendClass::Association), 0);
    assert_eq!(b.drop_count("replayed_control"), 1);
    assert_eq!(network.frames_from(1).len(), 1);

    b.drive(ms(1));
    assert_eq!(network.frames_from(1).len(), 1);
}

#[test]
fn control_delay_alone_does_not_cause_a_drop() {
    let network = SimNetwork::new();
    network.set_authenticated(true);
    let (mut b, evidence) = recording_endpoint(&network, 1, Role::Responder, 1_000, Some(3_000));
    b.establish_for_test(0x3031, 1).unwrap();
    network.inject(
        1,
        wire_frame(
            1,
            1,
            QosClass::Bulk,
            OpaqueBytes::from_static(b"delayed-body"),
            Some(ControlMessage::new(
                ControlType::CcOpaque,
                9,
                OpaqueBytes::from_static(b"delayed-control"),
            )),
        ),
        true,
    );

    let report = b.drive(ms(10_000));
    assert_eq!(report.dropped, 0);
    assert_eq!(b.target_rate(), 3_000);
    assert_eq!(b.drop_count("stale_control"), 0);
    assert_eq!(b.drop_count("unfresh_control"), 0);
    assert_eq!(b.drop_count("replayed_control"), 0);
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 1);
    assert_eq!(b.take_received().len(), 1);
}

#[test]
fn t2_profile_mixed_classes_debit_full_udp_payload_lengths() {
    let (_network, mut a, _b) = established_pair(1_000);
    a.enqueue_file_data(payload_packet([0x11; 80])).unwrap();
    a.enqueue_feedback_value(Feedback::ack(BlockId::new(7)))
        .unwrap();
    a.enqueue_file_data(payload_packet([0x22; 80])).unwrap();

    a.drive(MonoNs::ZERO);
    a.drive(ms(100));
    a.drive(ms(200));

    let trace: Vec<_> = a
        .sent()
        .iter()
        .map(|sent| (sent.at, sent.bytes, sent.class, sent.ready_at))
        .collect();
    assert_eq!(
        trace,
        vec![
            (MonoNs::ZERO, 29, SendClass::Feedback, ms(29)),
            (ms(100), 92, SendClass::FileData, ms(192)),
            (ms(200), 92, SendClass::FileData, ms(292)),
        ]
    );
}

#[test]
fn t3_file_queue_backpressure_returns_handle_and_respects_bounds() {
    let network = SimNetwork::new();
    let mut config = EndpointConfig::new(Role::Initiator, u64::MAX);
    config.file_data_limits = QueueLimits::new(2, 200, 200).with_max_packet_bytes(100);
    let mut a = UdpLiEndpoint::new(network.transport(0), config);
    a.establish_for_test(9, 1).unwrap();

    a.enqueue_file_data(payload_packet([1; 80])).unwrap();
    a.enqueue_file_data(payload_packet([2; 80])).unwrap();
    let third = payload_packet([3; 80]);
    let id = third.backing_id();
    let error = a.enqueue_file_data(third).unwrap_err();
    assert_eq!(
        error.kind(),
        ProfileEnqueueErrorKind::Queue(conet_core::EnqueueErrorKind::Full)
    );
    assert_eq!(error.packet().backing_id(), id);
    let occupancy = a.queue_occupancy(SendClass::FileData);
    assert_eq!(occupancy.count, 2);
    assert!(occupancy.visible_bytes <= 200);
    assert!(occupancy.unique_backing_bytes <= 200);
}

#[test]
fn t4_transmit_fields_use_exclusive_header_and_shared_payload_is_immutable() {
    let (network, mut a, _b) = established_pair(u64::MAX);
    let payload = payload_packet(b"shared-fanout-payload");
    let sibling = payload.fanout();
    let backing = payload.backing_id();
    a.enqueue_file_data(payload).unwrap();
    assert_eq!(sibling.header().as_bytes()[4..8], [0; 4]);

    a.drive(ms(5));
    let frame = &network.frames_from(0)[0].bytes;
    let codec = ReferenceWireCodec::default();
    let parsed = codec.parse(OpaqueBytes::copy_from_slice(frame)).unwrap();
    assert_eq!(parsed.header().link_seq, 0);
    assert_eq!(parsed.packet().payload_bytes(), b"shared-fanout-payload");

    assert_eq!(sibling.backing_id(), backing);
    assert_eq!(sibling.header().as_bytes()[4..8], [0; 4]);
    assert_eq!(sibling.payload_bytes(), b"shared-fanout-payload");
}

#[test]
fn t12_m12_failed_send_rolls_back_and_retry_has_one_completion() {
    let network = SimNetwork::new();
    let (mut a, evidence) = recording_endpoint(&network, 0, Role::Initiator, u64::MAX, None);
    a.establish_for_test(17, 1).unwrap();
    a.enqueue_file_data(payload_packet([0xab; 48])).unwrap();
    network.fail_next_send(0);

    let failed = a.drive(ms(10));
    assert!(failed.send_failed);
    assert_eq!(failed.sent, 0);
    assert_eq!(a.next_link_seq(), 0);
    assert_eq!(a.queued(SendClass::FileData), 1);
    assert_eq!(
        &a.queued_front_header(SendClass::FileData).unwrap()[4..8],
        &[0; 4]
    );
    assert!(evidence.lock().unwrap().sent.is_empty());
    assert!(network.frames_from(0).is_empty());

    let retried = a.drive(ms(20));
    assert_eq!(retried.sent, 1);
    assert_eq!(a.next_link_seq(), 1);
    let sent = evidence.lock().unwrap().sent.clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, ms(20).as_nanos());
    assert_eq!(sent[0].1, 60);
    assert_eq!(sent[0].2, Some(0));
    let frame = &network.frames_from(0)[0].bytes;
    let parsed = ReferenceWireCodec::default()
        .parse(OpaqueBytes::copy_from_slice(frame))
        .unwrap();
    assert_eq!(parsed.header().link_seq, 0);
}

#[test]
fn t8_t9_stale_and_future_epochs_do_not_change_state_or_rate() {
    let (network, _a, mut b) = established_pair(2_000);
    b.restart().unwrap();
    assert_eq!(b.epoch(), 2);
    let state = b.state();
    let rate = b.target_rate();
    let observations = b.observations().len();
    let queued = b.queued(SendClass::FileData);

    network.inject(1, data_frame(1, 7, b"stale"), false);
    let stale = b.drive(MonoNs::ZERO);
    assert_eq!(stale.dropped, 1);
    assert_eq!(b.state(), state);
    assert_eq!(b.epoch(), 2);
    assert_eq!(b.target_rate(), rate);
    assert_eq!(b.observations().len(), observations);
    assert_eq!(b.queued(SendClass::FileData), queued);

    network.inject(1, data_frame(3, 8, b"future"), false);
    let future = b.drive(MonoNs::ZERO);
    assert_eq!(future.dropped, 1);
    assert_eq!(b.state(), state);
    assert_eq!(b.epoch(), 2);
    assert_eq!(b.target_rate(), rate);
    assert_eq!(b.observations().len(), observations);
    assert_eq!(b.queued(SendClass::FileData), queued);
}

#[test]
fn t13_t14_profile_validation_drops_without_rate_or_association_change() {
    let network = SimNetwork::new();
    let (mut b, evidence) = recording_endpoint(&network, 1, Role::Responder, 1_000, Some(9_000));
    b.establish_for_test(0x4455_6677, 1).unwrap();
    let original_state = b.state();
    let original_rate = b.target_rate();
    let original_observations = b.observations().len();

    let valid_data = data_frame(1, 1, b"valid-shape");
    let mut unknown_version = valid_data.clone();
    unknown_version[2] = 9;
    let mut reserved = valid_data.clone();
    reserved[3] |= 0b0001_0000;
    let mut unknown_qos = valid_data;
    unknown_qos[3] = 3;
    let mut malformed_length = data_frame(1, 2, b"length");
    malformed_length[8..10].copy_from_slice(&999_u16.to_be_bytes());
    let mut unknown_control = wire_frame(
        1,
        9,
        QosClass::Control,
        OpaqueBytes::new(),
        Some(ControlMessage::new(
            ControlType::CcOpaque,
            4,
            OpaqueBytes::from_static(b"opaque"),
        )),
    );
    unknown_control[12] = 0xff;

    for frame in [
        unknown_version,
        reserved,
        unknown_qos,
        malformed_length,
        unknown_control,
    ] {
        network.inject(1, frame, true);
        let report = b.drive(MonoNs::ZERO);
        assert_eq!(report.dropped, 1);
    }

    assert_eq!(b.state(), original_state);
    assert_eq!(b.target_rate(), original_rate);
    assert_eq!(b.observations().len(), original_observations);
    assert!(b.take_received().is_empty());
    assert!(evidence.lock().unwrap().peer_bodies.is_empty());
}

#[test]
fn t15_unauthenticated_cc_is_fail_closed_even_for_test_open() {
    let network = SimNetwork::new();
    let (mut b, evidence) = recording_endpoint(&network, 1, Role::Responder, 1_000, Some(4_000));
    b.establish_for_test(21, 1).unwrap();
    assert!(!b.config().allow_unauthenticated_cc);

    let control = Some(ControlMessage::new(
        ControlType::CcOpaque,
        10,
        OpaqueBytes::from_static(b"set-rate-4000"),
    ));
    let cc = wire_frame(
        1,
        1,
        QosClass::Bulk,
        OpaqueBytes::from_static(b"coded"),
        control.clone(),
    );
    network.inject(1, cc.clone(), false);
    let denied = b.drive(MonoNs::ZERO);
    assert_eq!(b.target_rate(), 1_000);
    assert_eq!(b.drop_count("unauthenticated_cc"), 1);
    assert_eq!(denied.dropped, 0);
    assert_eq!(b.observations().len(), 1);
    assert!(evidence.lock().unwrap().peer_bodies.is_empty());
    assert_eq!(b.state(), AssociationState::Established);
    let delivered = b.take_received();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].packet.payload_bytes(), b"coded");

    network.set_authenticated(true);
    network.inject(1, cc, true);
    b.drive(ms(1));
    assert_eq!(b.target_rate(), 4_000);
    assert_eq!(evidence.lock().unwrap().peer_bodies.len(), 1);
    assert_eq!(b.state(), AssociationState::Established);

    let open_network = SimNetwork::new();
    let open_evidence = Arc::new(Mutex::new(ControllerEvidence::default()));
    let open_controller = RecordingController {
        configured_rate: 1_000,
        suggestion: Some(5_000),
        evidence: Arc::clone(&open_evidence),
    };
    let mut test_open = UdpLiEndpoint::with_controllers(
        open_network.transport(1),
        EndpointConfig::new(Role::Responder, 1_000).test_open(),
        Box::new(open_controller),
        None,
    );
    test_open.establish_for_test(22, 1).unwrap();
    open_network.inject(
        1,
        wire_frame(
            1,
            1,
            QosClass::Bulk,
            OpaqueBytes::from_static(b"coded"),
            control,
        ),
        false,
    );
    test_open.drive(MonoNs::ZERO);
    assert_eq!(test_open.target_rate(), 1_000);
    assert_eq!(test_open.drop_count("unauthenticated_cc"), 1);
    assert!(open_evidence.lock().unwrap().peer_bodies.is_empty());

    let stale_network = SimNetwork::new();
    let (mut stale, stale_evidence) =
        recording_endpoint(&stale_network, 1, Role::Responder, 1_000, Some(7_000));
    stale.establish_for_test(23, 1).unwrap();
    stale_network.inject(
        1,
        wire_frame(
            1,
            1,
            QosClass::Bulk,
            OpaqueBytes::from_static(b"coded"),
            Some(ControlMessage::new(
                ControlType::CcOpaque,
                11,
                OpaqueBytes::from_static(b"stale"),
            )),
        ),
        true,
    );
    stale.drive(ms(3_000));
    assert_eq!(stale.target_rate(), 7_000);
    assert_eq!(stale.drop_count("stale_control"), 0);
    assert_eq!(stale.observations().len(), 1);
    let delivered = stale.take_received();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].packet.payload_bytes(), b"coded");
    assert_eq!(stale_evidence.lock().unwrap().peer_bodies.len(), 1);
}

#[test]
fn t11_two_non_file_sends_maximum_when_file_data_waits() {
    let (_network, mut a, _b) = established_pair(u64::MAX);
    for block in 1..=3 {
        a.enqueue_feedback_value(Feedback::ack(BlockId::new(block)))
            .unwrap();
    }
    for byte in 0..6 {
        a.enqueue_file_data(payload_packet([byte; 20])).unwrap();
    }

    for step in 0..9 {
        a.drive(nanos(step));
    }
    let classes: Vec<_> = a.sent().iter().map(|sent| sent.class).collect();
    assert_eq!(classes.len(), 9);
    let longest_non_file = classes
        .split(|class| *class == SendClass::FileData)
        .map(<[SendClass]>::len)
        .max()
        .unwrap();
    assert!(longest_non_file <= 2, "trace was {classes:?}");
}

#[test]
fn control_piggybacks_on_an_existing_reverse_path_datagram() {
    let (network, mut a, _b) = established_pair(u64::MAX);
    a.enqueue_file_data(payload_packet(b"reverse-path-data"))
        .unwrap();
    a.enqueue_link_control(OpaqueBytes::from_static(b"cc-body"))
        .unwrap();
    let report = a.drive(MonoNs::ZERO);
    assert_eq!(report.sent, 1);
    assert_eq!(a.sent()[0].class, SendClass::FileData);
    assert_eq!(a.queued(SendClass::LinkControl), 0);

    let frames = network.frames_from(0);
    assert_eq!(frames.len(), 1);
    let parsed = ReferenceWireCodec::default()
        .parse(OpaqueBytes::copy_from_slice(&frames[0].bytes))
        .unwrap();
    assert_eq!(parsed.header().flags.qos, QosClass::Bulk);
    assert_eq!(parsed.packet().payload_bytes(), b"reverse-path-data");
    let control = parsed.control().unwrap();
    assert_eq!(control.ctrl_type, ControlType::CcOpaque);
    assert_eq!(control.body.as_ref(), b"cc-body");
    assert_eq!(frames[0].bytes.len(), 12 + 17 + 1 + 7);
}

#[test]
fn feedback_piggyback_keeps_feedback_qos_when_control_rides_along() {
    let (network, mut a, _b) = established_pair(u64::MAX);
    a.enqueue_feedback_value(Feedback::ack(BlockId::new(8)))
        .unwrap();
    a.enqueue_link_control(OpaqueBytes::from_static(b"cc"))
        .unwrap();

    let report = a.drive(MonoNs::ZERO);
    assert_eq!(report.sent, 1);
    assert_eq!(a.sent()[0].class, SendClass::Feedback);

    let parsed = ReferenceWireCodec::default()
        .parse(OpaqueBytes::copy_from_slice(
            &network.frames_from(0)[0].bytes,
        ))
        .unwrap();
    assert_eq!(parsed.header().flags.qos, QosClass::Feedback);
    assert_eq!(
        decode_reliability_feedback(OpaqueBytes::from(parsed.packet().payload_bytes().to_vec(),))
            .unwrap(),
        Feedback::ack(BlockId::new(8))
    );
    assert_eq!(
        parsed.control().map(|control| control.ctrl_type),
        Some(ControlType::CcOpaque)
    );
}

#[test]
fn receive_demux_uses_payload_len_instead_of_qos_class() {
    let (network, _a, mut b) = established_pair(u64::MAX);
    let feedback = Feedback::nack(BlockId::new(8), 3, 1);
    let body = encode_reliability_feedback(feedback);
    network.inject(
        1,
        wire_frame(1, 9, QosClass::Bulk, OpaqueBytes::from(body), None),
        true,
    );

    let report = b.drive(MonoNs::ZERO);
    assert_eq!(report.received, 1);
    assert_eq!(report.dropped, 0);
    let received = b.take_received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].class, QosClass::Bulk);
    assert_eq!(
        decode_reliability_feedback(OpaqueBytes::from(
            received[0].packet.payload_bytes().to_vec(),
        ))
        .unwrap(),
        feedback
    );
}

#[test]
fn t16_backward_clock_jump_resets_pacing_and_notifies_controller() {
    let network = SimNetwork::new();
    let (mut a, evidence) = recording_endpoint(&network, 0, Role::Initiator, 1_000, None);
    a.establish_for_test(31, 1).unwrap();
    a.enqueue_file_data(payload_packet([1; 80])).unwrap();
    a.enqueue_file_data(payload_packet([2; 80])).unwrap();

    a.drive(ms(100));
    let report = a.drive(ms(50));
    assert!(report.clock_discontinuity);
    assert_eq!(report.sent, 1);
    assert_eq!(a.sent().len(), 2);
    assert_eq!(a.sent()[1].at, ms(50));
    assert!(a.ready_at() >= ms(50));
    assert_eq!(evidence.lock().unwrap().timer_calls, vec![ms(100), ms(50)]);
}

#[test]
fn drive_calls_the_single_controller_clock_entry() {
    let network = SimNetwork::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let controller = DeadlineController {
        deadline: Some(ms(20)),
        rate: 1_000,
        calls: Arc::clone(&calls),
    };
    let mut endpoint = UdpLiEndpoint::with_controllers(
        network.transport(0),
        EndpointConfig::new(Role::Initiator, 1_000),
        Box::new(controller),
        None,
    );
    endpoint.establish_for_test(0x4040, 1).unwrap();

    assert_eq!(endpoint.next_wakeup(), Some(ms(20)));
    endpoint.drive(ms(19));
    assert_eq!(endpoint.target_rate(), 1_000);
    assert_eq!(endpoint.next_wakeup(), Some(ms(20)));
    let report = endpoint.drive(ms(20));
    assert_eq!(endpoint.target_rate(), 7_000);
    assert_eq!(report.next_wakeup, None);
    assert_eq!(endpoint.next_wakeup(), None);
    endpoint.drive(ms(21));
    assert_eq!(calls.lock().unwrap().as_slice(), &[ms(20)]);
}

#[test]
fn inbound_readiness_interrupts_a_longer_pacer_wait_once() {
    let inbound = Arc::new(Mutex::new(VecDeque::new()));
    let waits = Arc::new(Mutex::new(Vec::new()));
    let transport = ReadinessTransport {
        inbound: Arc::clone(&inbound),
        waits: Arc::clone(&waits),
    };
    let mut endpoint = UdpLiEndpoint::new(transport, EndpointConfig::new(Role::Initiator, 1_000));
    endpoint.establish_for_test(0x9191, 1).unwrap();
    endpoint
        .enqueue_file_data(payload_packet(b"first packet"))
        .unwrap();
    assert_eq!(endpoint.drive(MonoNs::ZERO).sent, 1);

    endpoint
        .enqueue_file_data(payload_packet(b"still paced"))
        .unwrap();
    let pacer_deadline = endpoint.next_drive().expect("queued pacer deadline");
    assert!(pacer_deadline > ms(1));
    inbound
        .lock()
        .unwrap()
        .push_back(data_frame(1, 4, b"inbound-before-pacer"));

    let mut clock_reads = 0;
    let report = endpoint
        .drive_when_ready(|| {
            clock_reads += 1;
            if clock_reads == 1 {
                MonoNs::ZERO
            } else {
                ms(1)
            }
        })
        .unwrap();

    assert_eq!(report.received, 1);
    assert_eq!(report.sent, 0);
    assert_eq!(report.next_wakeup, None);
    assert_eq!(clock_reads, 2);
    let waits = waits.lock().unwrap();
    assert_eq!(waits.len(), 1);
    assert_eq!(
        waits[0],
        Some(Duration::from_nanos(pacer_deadline.as_nanos() as u64))
    );
    let received = endpoint.take_received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].packet.payload_bytes(), b"inbound-before-pacer");
    assert_eq!(endpoint.queued(SendClass::FileData), 1);
}

#[test]
fn t17_restart_bumps_epoch_clears_queues_and_drops_old_epoch() {
    let (_network, mut a, mut b) = established_pair(u64::MAX);
    a.enqueue_file_data(payload_packet(b"old-epoch")).unwrap();
    a.drive(ms(10));
    a.enqueue_file_data(payload_packet(b"queued-old")).unwrap();
    assert_eq!(a.restart().unwrap(), 2);
    b.restart().unwrap();
    assert_eq!(a.next_link_seq(), 0);
    assert_eq!(a.cancelled_packets(), 1);
    assert_eq!(a.queued(SendClass::FileData), 0);
    let observations = b.observations().len();
    b.drive(ms(20));
    assert_eq!(b.drop_count("stale_epoch"), 1);
    assert_eq!(b.observations().len(), observations);

    a.enqueue_file_data(payload_packet(b"new-epoch")).unwrap();
    a.drive(ms(30));
    b.drive(ms(30));
    let received = b.take_received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].header.epoch, 2);
    assert_eq!(received[0].header.link_seq, 0);
    assert_eq!(received[0].packet.payload_bytes(), b"new-epoch");
}

#[test]
fn t19_enqueue_before_established_is_not_admitted_or_delivered() {
    let network = SimNetwork::new();
    let mut a = endpoint(&network, 0, Role::Initiator, 1_000);
    let error = a
        .enqueue_file_data(payload_packet(b"too-early"))
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ProfileEnqueueErrorKind::EnqueueBeforeEstablished
    );
    assert_eq!(a.queued(SendClass::FileData), 0);
    let feedback_error = a
        .enqueue_feedback_value(Feedback::ack(BlockId::new(1)))
        .unwrap_err();
    assert_eq!(
        feedback_error.kind(),
        ProfileEnqueueErrorKind::EnqueueBeforeEstablished
    );
    assert_eq!(a.queued(SendClass::Feedback), 0);

    let mut b = endpoint(&network, 1, Role::Responder, 1_000);
    network.inject(1, data_frame(1, 0, b"remote-too-early"), false);
    let report = b.drive(MonoNs::ZERO);
    assert_eq!(report.dropped, 1);
    assert_eq!(b.drop_count("not_established"), 1);
    assert!(b.take_received().is_empty());
}

#[test]
fn t20_boundary_lengths_drive_pacing_and_observations_consistently() {
    let (network, mut a, mut b) = established_pair(1_000);
    a.enqueue_file_data(payload_packet([1; 80])).unwrap();
    a.enqueue_feedback_value(Feedback::ack(BlockId::new(5)))
        .unwrap();
    a.enqueue_file_data(payload_packet([2; 80])).unwrap();

    for at in [MonoNs::ZERO, ms(100), ms(200)] {
        a.drive(at);
        b.drive(at);
    }

    let sent: Vec<_> = a.sent().to_vec();
    assert_eq!(
        sent.iter().map(|record| record.bytes).collect::<Vec<_>>(),
        vec![29, 92, 92]
    );
    assert_eq!(a.ready_at(), ms(292));
    let observations: Vec<_> = b
        .observations()
        .iter()
        .map(|observation| observation.len as usize)
        .collect();
    assert_eq!(observations, vec![29, 92, 92]);
    assert_eq!(
        b.observations()
            .iter()
            .map(|observation| observation.recv_ts)
            .collect::<Vec<_>>(),
        vec![MonoNs::ZERO, ms(100), ms(200)]
    );
    let frames = network.frames_from(0);
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.bytes.len())
            .collect::<Vec<_>>(),
        vec![29, 92, 92]
    );
}

#[test]
fn m7_send_failure_and_receive_completion_are_observed_once() {
    let network = SimNetwork::new();
    let (mut a, evidence) = recording_endpoint(&network, 0, Role::Initiator, u64::MAX, None);
    a.establish_for_test(77, 1).unwrap();
    a.enqueue_file_data(payload_packet(b"send-me")).unwrap();
    network.inject(0, data_frame(1, 3, b"receive-me"), true);
    network.fail_next_send(0);

    let report = a.drive(ms(1));
    assert!(report.send_failed);
    assert_eq!(report.sent, 0);
    assert_eq!(report.received, 1);
    assert_eq!(report.dropped, 0);
    assert_eq!(a.queued(SendClass::FileData), 1);
    assert!(evidence.lock().unwrap().sent.is_empty());
    let received = a.take_received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].packet.payload_bytes(), b"receive-me");

    let retry = a.drive(ms(2));
    assert_eq!(retry.sent, 1);
    assert_eq!(evidence.lock().unwrap().sent.len(), 1);
}

#[test]
#[ignore = "gated loopback conformance; never binds a non-loopback interface"]
fn loopback_udp_handshake_and_data() {
    use conet_udp::LoopbackUdpTransport;
    use std::net::UdpSocket;
    use std::time::Duration;

    let socket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    let transport_a = LoopbackUdpTransport::from_socket(socket_a, addr_b).unwrap();
    let transport_b = LoopbackUdpTransport::from_socket(socket_b, addr_a).unwrap();
    let mut a = UdpLiEndpoint::new(
        transport_a,
        EndpointConfig::new(Role::Initiator, 1_000_000).test_open(),
    );
    let mut b = UdpLiEndpoint::new(
        transport_b,
        EndpointConfig::new(Role::Responder, 1_000_000).test_open(),
    );
    a.start_association().unwrap();

    let started = std::time::Instant::now();
    let mut now = MonoNs::ZERO;
    while (a.state() != AssociationState::Established || b.state() != AssociationState::Established)
        && started.elapsed() < Duration::from_secs(2)
    {
        a.drive(now);
        b.drive(now);
        std::thread::sleep(Duration::from_millis(1));
        now = now.saturating_add(ms(1));
    }
    assert_eq!(a.state(), AssociationState::Established);
    assert_eq!(b.state(), AssociationState::Established);

    let foreign = UdpSocket::bind("127.0.0.1:0").unwrap();
    foreign.send_to(b"foreign-peer", addr_b).unwrap();
    a.enqueue_file_data(payload_packet(b"loopback-data"))
        .unwrap();
    for _ in 0..20 {
        a.drive(now);
        b.drive(now);
        if b.received_len() == 1 {
            break;
        }
        now = now.saturating_add(ms(1));
        std::thread::sleep(Duration::from_millis(1));
    }
    let received = b.take_received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].packet.payload_bytes(), b"loopback-data");
}
