use std::collections::{BTreeMap, VecDeque};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use conet_core::{
    ControlDisposition, EnqueueError, EnqueueErrorKind, EnqueueStatus, IdentityReceiver,
    IdentitySender, LinkEndpoint, LinkReceiver, LinkSender, MonoNs, Occupancy, OpaqueBytes, Pace,
    PacketBuilder, PacketHandle, QueueLimits, TxController,
};
use conet_mux::{
    AttachError, AttachLimits, MUX_HEADER_LEN, Mux, NetworkHeader, ReadyUser, RoundRobinScheduler,
    SchedulerNode, SchedulerPort, TreeScheduler, UserId,
};
use conet_udp::{
    EndpointConfig, ProfileEnqueueErrorKind, Role, SendClass, SimNetwork, SimTransport,
    UdpLiEndpoint,
};

fn packet(payload: &[u8], header: &[u8]) -> PacketHandle {
    let mut builder = PacketBuilder::with_capacity(payload.len(), header.len());
    builder.payload_mut().copy_from_slice(payload);
    *builder.header_mut() = conet_core::HeaderBuf::from_bytes(header.to_vec());
    builder.freeze()
}

fn user_packet(payload: &[u8]) -> PacketHandle {
    packet(payload, &[7; 12])
}

fn tagged_packet(user_id: UserId, payload: &[u8]) -> PacketHandle {
    let network = NetworkHeader::new(user_id, payload.len()).encode().unwrap();
    let mut body = Vec::from(network.as_bytes());
    body.extend_from_slice(payload);
    packet(&body, &[0; 16])
}

fn limits(packets: usize, bytes: usize) -> QueueLimits {
    QueueLimits::new(packets, bytes, bytes)
}

struct TestLower {
    outgoing: IdentitySender,
    incoming: IdentityReceiver,
}

struct UdpMuxLower {
    endpoint: UdpLiEndpoint<SimTransport>,
    pending: VecDeque<PacketHandle>,
}

struct DeadlineController {
    deadline: Option<MonoNs>,
    calls: Arc<Mutex<Vec<MonoNs>>>,
}

impl TxController for DeadlineController {
    fn on_clock(&mut self, now: MonoNs) {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.calls.lock().unwrap().push(now);
            self.deadline = None;
        }
    }

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn pace(&self) -> Pace {
        Pace::NOOP
    }

    fn next_wakeup(&self) -> Option<MonoNs> {
        self.deadline
    }
}

impl UdpMuxLower {
    fn new(endpoint: UdpLiEndpoint<SimTransport>) -> Self {
        Self {
            endpoint,
            pending: VecDeque::new(),
        }
    }
}

impl LinkSender for UdpMuxLower {
    fn enqueue(&mut self, pkt: PacketHandle) -> Result<EnqueueStatus, EnqueueError> {
        self.endpoint
            .enqueue_file_data(pkt)
            .map(|_| EnqueueStatus::Accepted)
            .map_err(|error| {
                let kind = error.kind();
                let pkt = error.into_packet();
                match kind {
                    ProfileEnqueueErrorKind::Queue(EnqueueErrorKind::Closed) => {
                        EnqueueError::Closed { pkt }
                    }
                    ProfileEnqueueErrorKind::Queue(EnqueueErrorKind::Invalid(reason)) => {
                        EnqueueError::Invalid { pkt, reason }
                    }
                    _ => EnqueueError::Full { pkt },
                }
            })
    }

    fn occupancy(&self) -> Occupancy {
        self.endpoint.queue_occupancy(SendClass::FileData)
    }

    fn close(&mut self) {}
}

impl LinkReceiver for UdpMuxLower {
    fn recv(&mut self) -> Option<PacketHandle> {
        self.pending.pop_front()
    }

    fn occupancy(&self) -> Occupancy {
        Occupancy {
            count: self.pending.len(),
            ..Occupancy::default()
        }
    }
}

impl LinkEndpoint for UdpMuxLower {
    fn outgoing(&mut self) -> &mut dyn LinkSender {
        self
    }

    fn incoming(&mut self) -> &mut dyn LinkReceiver {
        self
    }

    fn drive(&mut self, now: MonoNs) {
        self.endpoint.drive(now);
        self.pending.extend(
            self.endpoint
                .take_received()
                .into_iter()
                .map(|datagram| datagram.packet),
        );
    }

    fn next_wakeup(&self) -> Option<MonoNs> {
        self.endpoint.next_wakeup()
    }

    fn next_drive(&self) -> Option<MonoNs> {
        self.endpoint.next_drive()
    }
}

impl LinkEndpoint for TestLower {
    fn outgoing(&mut self) -> &mut dyn LinkSender {
        &mut self.outgoing
    }

    fn incoming(&mut self) -> &mut dyn LinkReceiver {
        &mut self.incoming
    }

    fn drive(&mut self, _now: MonoNs) {}
}

fn setup(lower_limits: QueueLimits) -> (Mux<TestLower>, IdentityReceiver, IdentitySender) {
    let (mux_out, peer_in) = conet_core::identity_link(lower_limits);
    let (peer_out, mux_in) = conet_core::identity_link(lower_limits);
    (
        Mux::new(TestLower {
            outgoing: mux_out,
            incoming: mux_in,
        }),
        peer_in,
        peer_out,
    )
}

fn recv_envelope(receiver: &mut IdentityReceiver) -> (UserId, Vec<u8>, Vec<u8>) {
    let pkt = receiver.recv().expect("lower datagram");
    parse_envelope(pkt)
}

fn parse_envelope(pkt: PacketHandle) -> (UserId, Vec<u8>, Vec<u8>) {
    let header = NetworkHeader::parse(
        &pkt.payload_bytes()[..MUX_HEADER_LEN],
        pkt.len() - MUX_HEADER_LEN,
    )
    .unwrap();
    (
        header.user_id,
        pkt.payload_bytes()[MUX_HEADER_LEN..].to_vec(),
        pkt.header().as_bytes().to_vec(),
    )
}

#[test]
fn two_in_process_users_share_one_lower_hop_bidirectionally() {
    let lower_limits = limits(16, 64 * 1024);
    let (mut mux, mut peer_in, mut peer_out) = setup(lower_limits);
    let mut user_a = mux
        .attach(11, AttachLimits::symmetrical(lower_limits))
        .unwrap();
    let mut user_b = mux
        .attach(22, AttachLimits::symmetrical(lower_limits))
        .unwrap();

    user_a
        .outgoing()
        .enqueue(user_packet(b"alpha payload"))
        .unwrap();
    user_b
        .outgoing()
        .enqueue(user_packet(b"beta payload"))
        .unwrap();
    let report = mux.drive(MonoNs::new(1), 16);
    assert_eq!(report.sent, 2);

    let (id_a, body_a, header_a) = recv_envelope(&mut peer_in);
    let (id_b, body_b, header_b) = recv_envelope(&mut peer_in);
    assert_eq!((id_a, body_a.as_slice()), (11, b"alpha payload".as_slice()));
    assert_eq!((id_b, body_b.as_slice()), (22, b"beta payload".as_slice()));

    assert_eq!(header_a, vec![7; 12]);
    assert_eq!(header_b, vec![7; 12]);
    assert_eq!(header_a.len(), conet_core::REFERENCE_WIRE_HEADER_LEN);
    assert!(
        !header_a
            .windows(4)
            .any(|window| window == 11_u32.to_be_bytes())
    );
    assert!(
        !header_b
            .windows(4)
            .any(|window| window == 22_u32.to_be_bytes())
    );

    peer_out.enqueue(tagged_packet(22, b"to beta")).unwrap();
    peer_out.enqueue(tagged_packet(11, b"to alpha")).unwrap();
    let report = mux.drive(MonoNs::new(2), 16);
    assert_eq!(report.delivered, 2);
    assert_eq!(
        user_b.incoming().recv().unwrap().payload_bytes(),
        b"to beta"
    );
    assert_eq!(
        user_a.incoming().recv().unwrap().payload_bytes(),
        b"to alpha"
    );
}

#[test]
fn unknown_and_malformed_user_tags_are_dropped_fail_closed() {
    let lower_limits = limits(8, 4096);
    let (mut mux, _peer_in, mut peer_out) = setup(lower_limits);
    let mut user = mux
        .attach(7, AttachLimits::symmetrical(lower_limits))
        .unwrap();

    peer_out.enqueue(tagged_packet(99, b"unknown")).unwrap();
    peer_out.enqueue(packet(b"bad", &[0; 16])).unwrap();
    let report = mux.drive(MonoNs::new(1), 8);

    assert_eq!(report.dropped_unknown, 1);
    assert_eq!(report.dropped_malformed, 1);
    assert_eq!(mux.dropped_unknown(), 1);
    assert_eq!(mux.dropped_malformed(), 1);
    assert!(user.incoming().recv().is_none());

    let mut bad_version = Vec::from(
        NetworkHeader::new(7, 1)
            .encode()
            .unwrap()
            .as_bytes()
            .to_vec(),
    );
    bad_version[2] = 2;
    bad_version.push(1);
    peer_out.enqueue(packet(&bad_version, &[0; 16])).unwrap();
    let report = mux.drive(MonoNs::new(2), 8);
    assert_eq!(report.dropped_malformed, 1);
    assert!(user.incoming().recv().is_none());
}

#[test]
fn mux_surfaces_and_preserves_lower_controller_wakeup() {
    let network = SimNetwork::new();
    let deadline = MonoNs::new(20);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = UdpLiEndpoint::with_controllers(
        network.transport(0),
        EndpointConfig::new(Role::Initiator, 1_000),
        Box::new(DeadlineController {
            deadline: Some(deadline),
            calls: Arc::clone(&calls),
        }),
        None,
    );
    let mut mux = Mux::new(UdpMuxLower::new(endpoint));

    assert_eq!(mux.next_wakeup(), Some(deadline));
    assert_eq!(mux.next_drive(), Some(deadline));
    let report = mux.drive(MonoNs::new(19), 16);
    assert_eq!(report.next_wakeup, Some(deadline));
    assert_eq!(report.next_drive, Some(deadline));
    assert_eq!(mux.next_wakeup(), Some(deadline));
    assert_eq!(mux.next_drive(), Some(deadline));
    assert!(calls.lock().unwrap().is_empty());

    let report = mux.drive(deadline, 16);
    assert_eq!(report.next_wakeup, None);
    assert_eq!(report.next_drive, None);
    assert_eq!(mux.next_wakeup(), None);
    assert_eq!(mux.next_drive(), None);
    assert_eq!(calls.lock().unwrap().as_slice(), &[deadline]);
}

#[test]
fn mux_reports_no_wakeup_when_lower_has_none() {
    let (mut mux, _peer_in, _peer_out) = setup(limits(8, 4096));

    assert_eq!(mux.next_wakeup(), None);
    assert_eq!(mux.next_drive(), None);
    let report = mux.drive(MonoNs::new(1), 8);
    assert_eq!(report.next_wakeup, None);
    assert_eq!(report.next_drive, None);
}

#[test]
fn mux_aggregate_drive_uses_only_lower_pacer_times() {
    let network = SimNetwork::new();
    let endpoint = UdpLiEndpoint::new(
        network.transport(0),
        EndpointConfig::new(Role::Initiator, 1_000),
    );
    let mut mux = Mux::new(UdpMuxLower::new(endpoint));
    let mut user = mux
        .attach(31, AttachLimits::symmetrical(limits(8, 4096)))
        .unwrap();
    user.outgoing()
        .enqueue(user_packet(b"first paced packet"))
        .unwrap();
    user.outgoing()
        .enqueue(user_packet(b"second paced packet"))
        .unwrap();

    let report = mux.drive(MonoNs::ZERO, 8);
    let pacer_deadline = report.next_drive.expect("queued lower data deadline");
    assert_eq!(report.next_wakeup, None);
    assert!(pacer_deadline > MonoNs::ZERO);
    assert_eq!(mux.next_wakeup(), None);
    assert_eq!(mux.next_drive(), Some(pacer_deadline));

    let report = mux.drive(pacer_deadline, 8);
    assert_eq!(report.sent, 0);
    assert_eq!(report.next_drive, None);

    let network = SimNetwork::new();
    let endpoint = UdpLiEndpoint::new(
        network.transport(1),
        EndpointConfig::new(Role::Initiator, 1_000),
    );
    let mux = Mux::new(UdpMuxLower::new(endpoint));
    assert_eq!(mux.next_wakeup(), None);
    assert_eq!(mux.next_drive(), None);
}

#[test]
fn per_user_backpressure_never_overfills_the_lower_queue() {
    let mux_limits = limits(8, 4096);
    let lower_limits = limits(1, 4096);
    let (mut mux, mut peer_in, _peer_out) = setup(lower_limits);
    let mut user = mux
        .attach(1, AttachLimits::symmetrical(mux_limits))
        .unwrap();

    user.outgoing().enqueue(user_packet(b"first")).unwrap();
    user.outgoing().enqueue(user_packet(b"second")).unwrap();
    let report = mux.drive(MonoNs::new(1), 8);
    assert_eq!(report.sent, 1);
    assert_eq!(report.backpressured, 1);
    assert_eq!(peer_in.occupancy().count, 1);
    assert_eq!(LinkSender::occupancy(&user).count, 1);

    recv_envelope(&mut peer_in);
    let report = mux.drive(MonoNs::new(2), 8);
    assert_eq!(report.sent, 1);
    assert_eq!(peer_in.occupancy().count, 1);
    assert_eq!(LinkSender::occupancy(&user).count, 0);
}

#[test]
fn attach_rejects_duplicate_ids_and_scheduler_port_is_replaceable() {
    #[derive(Default)]
    struct HighestFirst {
        ready: Vec<UserId>,
    }

    impl SchedulerPort for HighestFirst {
        fn on_enqueue(&mut self, user_id: UserId) {
            if !self.ready.contains(&user_id) {
                self.ready.push(user_id);
            }
        }

        fn on_detach(&mut self, user_id: UserId) {
            self.ready.retain(|candidate| *candidate != user_id);
        }

        fn select(&mut self, ready: &[ReadyUser]) -> Option<UserId> {
            let selected = self
                .ready
                .iter()
                .filter(|user_id| {
                    ready
                        .iter()
                        .any(|entry| entry.user_id == **user_id && entry.queued_packets > 0)
                })
                .max()
                .copied();
            if let Some(user_id) = selected {
                self.ready.retain(|candidate| *candidate != user_id);
            }
            selected
        }
    }

    let lower_limits = limits(8, 4096);
    let (mux_out, peer_in) = conet_core::identity_link(lower_limits);
    let (_peer_out, mux_in) = conet_core::identity_link(lower_limits);
    let mut mux = Mux::with_scheduler(
        TestLower {
            outgoing: mux_out,
            incoming: mux_in,
        },
        Box::new(HighestFirst::default()),
    );
    let mut low = mux
        .attach(1, AttachLimits::symmetrical(lower_limits))
        .unwrap();
    let mut high = mux
        .attach(9, AttachLimits::symmetrical(lower_limits))
        .unwrap();
    assert!(matches!(
        mux.attach(1, AttachLimits::symmetrical(lower_limits)),
        Err(AttachError::DuplicateUser(1))
    ));
    low.outgoing().enqueue(user_packet(b"low")).unwrap();
    high.outgoing().enqueue(user_packet(b"high")).unwrap();
    mux.drive(MonoNs::new(1), 8);
    let mut peer_in = peer_in;
    assert_eq!(recv_envelope(&mut peer_in).0, 9);
    assert_eq!(recv_envelope(&mut peer_in).0, 1);

    let mut round_robin = RoundRobinScheduler::default();
    round_robin.on_enqueue(1);
    round_robin.on_enqueue(2);
    assert_eq!(
        round_robin.select(&[
            ReadyUser {
                user_id: 1,
                queued_packets: 1
            },
            ReadyUser {
                user_id: 2,
                queued_packets: 1
            }
        ]),
        Some(1)
    );
    assert_eq!(
        round_robin.select(&[
            ReadyUser {
                user_id: 1,
                queued_packets: 1
            },
            ReadyUser {
                user_id: 2,
                queued_packets: 1
            }
        ]),
        Some(2)
    );
}

#[test]
fn tree_scheduler_splits_equal_weighted_and_hierarchical_shares() {
    fn ready(users: &[UserId]) -> Vec<ReadyUser> {
        users
            .iter()
            .map(|user_id| ReadyUser {
                user_id: *user_id,
                queued_packets: 1,
            })
            .collect()
    }

    let mut equal = TreeScheduler::default();
    for user_id in [1, 2, 3] {
        equal.on_enqueue(user_id);
    }
    let equal_order: Vec<_> = (0..9)
        .filter_map(|_| equal.select(&ready(&[1, 2, 3])))
        .collect();
    for user_id in [1, 2, 3] {
        assert_eq!(
            equal_order
                .iter()
                .filter(|candidate| **candidate == user_id)
                .count(),
            3
        );
    }
    assert!(
        !equal_order
            .windows(3)
            .any(|window| window.iter().all(|id| *id == 1))
    );

    let mut weighted = TreeScheduler::from_weighted_users([(1, 2), (2, 1)]);
    let weighted_order: Vec<_> = (0..24)
        .filter_map(|_| weighted.select(&ready(&[1, 2])))
        .collect();
    assert_eq!(
        weighted_order
            .iter()
            .filter(|candidate| **candidate == 1)
            .count(),
        16
    );
    assert_eq!(
        weighted_order
            .iter()
            .filter(|candidate| **candidate == 2)
            .count(),
        8
    );

    let mut hierarchical = TreeScheduler::new(SchedulerNode::group(
        1,
        [
            SchedulerNode::group(1, [SchedulerNode::user(1, 1), SchedulerNode::user(2, 1)]),
            SchedulerNode::group(1, [SchedulerNode::user(3, 1), SchedulerNode::user(4, 1)]),
        ],
    ));
    for user_id in [1, 2, 3, 4] {
        hierarchical.on_enqueue(user_id);
    }
    let hierarchical_order: Vec<_> = (0..16)
        .filter_map(|_| hierarchical.select(&ready(&[1, 2, 3, 4])))
        .collect();
    for user_id in [1, 2, 3, 4] {
        assert_eq!(
            hierarchical_order
                .iter()
                .filter(|candidate| **candidate == user_id)
                .count(),
            4
        );
    }

    hierarchical.on_detach(2);
    let remaining: Vec<_> = (0..16)
        .filter_map(|_| hierarchical.select(&ready(&[1, 2, 3, 4])))
        .collect();
    assert!(!remaining.contains(&2));
    assert_eq!(
        remaining
            .iter()
            .filter(|candidate| **candidate == 1)
            .count(),
        8
    );
    assert_eq!(
        remaining
            .iter()
            .filter(|candidate| **candidate == 3)
            .count(),
        4
    );
    assert_eq!(
        remaining
            .iter()
            .filter(|candidate| **candidate == 4)
            .count(),
        4
    );
}

#[test]
fn tree_scheduler_restores_detached_user_to_its_configured_group() {
    fn ready(users: &[UserId]) -> Vec<ReadyUser> {
        users
            .iter()
            .map(|user_id| ReadyUser {
                user_id: *user_id,
                queued_packets: 1,
            })
            .collect()
    }

    let mut hierarchical = TreeScheduler::new(SchedulerNode::group(
        1,
        [
            SchedulerNode::group(
                2,
                [SchedulerNode::group(
                    1,
                    [SchedulerNode::user(1, 1), SchedulerNode::user(2, 1)],
                )],
            ),
            SchedulerNode::group(1, [SchedulerNode::user(3, 1), SchedulerNode::user(4, 1)]),
        ],
    ));
    for user_id in [1, 2, 3, 4] {
        hierarchical.on_enqueue(user_id);
    }
    hierarchical.on_detach(2);
    hierarchical.on_enqueue(2);

    let order: Vec<_> = (0..96)
        .filter_map(|_| hierarchical.select(&ready(&[1, 2, 3, 4])))
        .collect();
    assert_eq!(
        order.iter().filter(|candidate| **candidate == 1).count(),
        32
    );
    assert_eq!(
        order.iter().filter(|candidate| **candidate == 2).count(),
        32
    );
    assert_eq!(
        order.iter().filter(|candidate| **candidate == 3).count(),
        16
    );
    assert_eq!(
        order.iter().filter(|candidate| **candidate == 4).count(),
        16
    );
}

#[test]
fn tree_scheduler_controls_send_opportunities_on_the_shared_lower_hop() {
    let lower_limits = limits(64, 64 * 1024);
    let (mux_out, mut peer_in) = conet_core::identity_link(lower_limits);
    let (_peer_out, mux_in) = conet_core::identity_link(lower_limits);
    let mut mux = Mux::with_scheduler(
        TestLower {
            outgoing: mux_out,
            incoming: mux_in,
        },
        TreeScheduler::from_weighted_users([(1, 2), (2, 1)]),
    );
    let mut high = mux
        .attach(1, AttachLimits::symmetrical(lower_limits))
        .unwrap();
    let mut low = mux
        .attach(2, AttachLimits::symmetrical(lower_limits))
        .unwrap();
    for index in 0..16 {
        high.outgoing()
            .enqueue(user_packet(format!("high-{index}").as_bytes()))
            .unwrap();
    }
    for index in 0..8 {
        low.outgoing()
            .enqueue(user_packet(format!("low-{index}").as_bytes()))
            .unwrap();
    }

    let report = mux.drive(MonoNs::new(1), 24);
    assert_eq!(report.sent, 24);
    let mut counts = BTreeMap::new();
    while peer_in.occupancy().count > 0 {
        *counts.entry(recv_envelope(&mut peer_in).0).or_insert(0) += 1;
    }
    assert_eq!(counts.get(&1), Some(&16));
    assert_eq!(counts.get(&2), Some(&8));
}
#[test]
fn two_separate_programs_use_only_local_links_to_one_lower_hop() {
    let lower_limits = limits(16, 64 * 1024);
    let network = SimNetwork::new();
    let mut mux_udp = UdpLiEndpoint::new(
        network.transport(0),
        EndpointConfig::new(Role::Initiator, u64::MAX),
    );
    let mut peer_udp = UdpLiEndpoint::new(
        network.transport(1),
        EndpointConfig::new(Role::Responder, u64::MAX),
    );
    mux_udp.establish_for_test(0x5152, 1).unwrap();
    peer_udp.establish_for_test(0x5152, 1).unwrap();
    let mut mux = Mux::with_scheduler(UdpMuxLower::new(mux_udp), TreeScheduler::default());
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("conet-mux-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mux_a = dir.join("mux-a.sock");
    let mux_b = dir.join("mux-b.sock");
    let program_a = dir.join("program-a.sock");
    let program_b = dir.join("program-b.sock");
    mux.attach_program(31, &mux_a, AttachLimits::symmetrical(lower_limits))
        .unwrap();
    mux.attach_program(32, &mux_b, AttachLimits::symmetrical(lower_limits))
        .unwrap();

    let executable = env!("CARGO_BIN_EXE_s12_program");
    let mut child_a = Command::new(executable)
        .args([
            program_a.to_str().unwrap(),
            mux_a.to_str().unwrap(),
            "31",
            "program-alpha",
        ])
        .spawn()
        .unwrap();
    let mut child_b = Command::new(executable)
        .args([
            program_b.to_str().unwrap(),
            mux_b.to_str().unwrap(),
            "32",
            "program-beta",
        ])
        .spawn()
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut lower_users = BTreeMap::new();
    let mut exited_a = false;
    let mut exited_b = false;
    let mut tick = 0_i64;
    while std::time::Instant::now() < deadline && !(exited_a && exited_b) {
        tick += 1_000_000;
        let now = MonoNs::new(tick);
        mux.drive(now, 16);
        peer_udp.drive(now);
        for datagram in peer_udp.take_received() {
            let (user_id, payload, _) = parse_envelope(datagram.packet);
            lower_users.insert(user_id, payload.clone());
            peer_udp
                .enqueue_file_data(tagged_packet(user_id, &payload))
                .unwrap();
        }
        peer_udp.drive(now);
        mux.drive(now, 16);
        exited_a = child_a.try_wait().unwrap().is_some();
        exited_b = child_b.try_wait().unwrap().is_some();
        std::thread::sleep(Duration::from_millis(5));
    }
    if !exited_a {
        let _ = child_a.kill();
    }
    if !exited_b {
        let _ = child_b.kill();
    }
    let status_a = child_a.wait().unwrap();
    let status_b = child_b.wait().unwrap();
    assert!(status_a.success(), "program A failed: {status_a}");
    assert!(status_b.success(), "program B failed: {status_b}");
    assert_eq!(lower_users.get(&31).unwrap(), b"program-alpha");
    assert_eq!(lower_users.get(&32).unwrap(), b"program-beta");
    assert_eq!(lower_users.len(), 2);
    let _ = std::fs::remove_dir_all(dir);
}
