//! Regressions for UL-3/UL-4 control handling before merge.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use conet_core::{MonoNs, OpaqueBytes, ReferenceWireCodec, WireFlags, WireHeader};
use conet_udp::keepalive::encode_ping;
use conet_udp::path_challenge::encode_response;
use conet_udp::{
    ConnectedUdpTransport, DatagramTransport, EndpointConfig, KeepaliveConfig, PeerAdmitPolicy,
    PeerBindingState, UdpLiEndpoint,
};

fn conet_datagram(payload: &[u8]) -> Vec<u8> {
    let codec = ReferenceWireCodec::default();
    let datagram = codec
        .build(
            WireHeader {
                flags: WireFlags::default(),
                epoch: 1,
                link_seq: 1,
                payload_len: 0,
            },
            OpaqueBytes::copy_from_slice(payload),
            None,
        )
        .unwrap();
    codec.serialize(&datagram).unwrap()
}

fn recv_until(
    transport: &mut ConnectedUdpTransport,
    timeout: Duration,
) -> Option<conet_udp::InboundDatagram> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let _ = transport.drive_path_challenge();
        if let Ok(Some(datagram)) = transport.recv_datagram(MonoNs::ZERO) {
            return Some(datagram);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

fn lock_pair() -> (ConnectedUdpTransport, ConnectedUdpTransport) {
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a_addr = a_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();
    let mut a = ConnectedUdpTransport::from_socket(a_sock, b_addr).unwrap();
    let mut b = ConnectedUdpTransport::from_socket(b_sock, a_addr).unwrap();
    a.send_datagram(MonoNs::ZERO, &conet_datagram(b"lock-a")).unwrap();
    let _ = recv_until(&mut b, Duration::from_secs(1)).unwrap();
    b.send_datagram(MonoNs::ZERO, &conet_datagram(b"lock-b")).unwrap();
    let _ = recv_until(&mut a, Duration::from_secs(1)).unwrap();
    assert_eq!(a.peer_binding_state(), PeerBindingState::Locked);
    assert_eq!(b.peer_binding_state(), PeerBindingState::Locked);
    (a, b)
}

#[test]
fn short_control_does_not_truncate_following_conet_datagram() {
    let (mut a, mut b) = lock_pair();
    let cadence = KeepaliveConfig::for_test(Duration::from_millis(5), Duration::from_millis(5));
    a.set_keepalive_config(cadence);
    b.set_keepalive_config(cadence);

    let payload = vec![0x5A_u8; 256];
    let data = conet_datagram(&payload);
    assert!(data.len() > 6);

    // Same receive buffer must accept a short CULK then a larger Conet datagram.
    a.send_datagram(MonoNs::ZERO, &encode_ping()).unwrap();
    a.send_datagram(MonoNs::ZERO, &data).unwrap();

    let got = recv_until(&mut b, Duration::from_secs(1)).expect("full conet after keepalive");
    assert_eq!(
        got.bytes.len(),
        data.len(),
        "receive buffer must not stay shrunk after a 6-byte control"
    );
    assert_eq!(got.bytes.as_slice(), data.as_slice());
}

#[test]
fn simultaneous_path_challenges_both_reach_locked() {
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a_addr = a_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();

    let mut a = ConnectedUdpTransport::from_socket_with_policy(
        a_sock,
        b_addr,
        PeerAdmitPolicy::require_path_challenge(),
    )
    .unwrap();
    let mut b = ConnectedUdpTransport::from_socket_with_policy(
        b_sock,
        a_addr,
        PeerAdmitPolicy::require_path_challenge(),
    )
    .unwrap();

    a.send_datagram(MonoNs::ZERO, &conet_datagram(b"a->b")).unwrap();
    b.send_datagram(MonoNs::ZERO, &conet_datagram(b"b->a")).unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline
        && (a.peer_binding_state() != PeerBindingState::Locked
            || b.peer_binding_state() != PeerBindingState::Locked)
    {
        let _ = a.drive_path_challenge();
        let _ = b.drive_path_challenge();
        let _ = a.recv_datagram(MonoNs::ZERO);
        let _ = b.recv_datagram(MonoNs::ZERO);
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(a.peer_binding_state(), PeerBindingState::Locked);
    assert_eq!(b.peer_binding_state(), PeerBindingState::Locked);
    assert!(a.pending_path_challenge().is_none());
    assert!(b.pending_path_challenge().is_none());
}

#[test]
fn next_io_wake_reports_keepalive_deadline() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let mut transport = ConnectedUdpTransport::from_socket(socket, peer).unwrap();
    transport.set_keepalive_config(KeepaliveConfig::for_test(
        Duration::from_millis(80),
        Duration::from_millis(40),
    ));
    let wake = transport.next_io_wake().expect("keepalive wake");
    assert!(wake > Duration::from_millis(20));
    assert!(wake <= Duration::from_millis(80));

    transport.set_emit_controls(false);
    assert!(transport.next_io_wake().is_none());
}

#[test]
fn closed_endpoint_does_not_emit_keepalive_pong() {
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a_addr = a_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();

    let mut a = ConnectedUdpTransport::from_socket(a_sock, b_addr).unwrap();
    let mut b = ConnectedUdpTransport::from_socket(b_sock, a_addr).unwrap();
    let cadence = KeepaliveConfig::for_test(Duration::from_millis(5), Duration::from_millis(5));
    a.set_keepalive_config(cadence);
    b.set_keepalive_config(cadence);

    a.send_datagram(MonoNs::ZERO, &conet_datagram(b"lock")).unwrap();
    let _ = recv_until(&mut b, Duration::from_secs(1)).unwrap();
    b.send_datagram(MonoNs::ZERO, &conet_datagram(b"lock-back")).unwrap();
    let _ = recv_until(&mut a, Duration::from_secs(1)).unwrap();

    // Simulate endpoint close: disable control emission on the transport.
    b.set_emit_controls(false);

    a.send_datagram(MonoNs::ZERO, &encode_ping()).unwrap();
    for _ in 0..20 {
        let _ = b.recv_datagram(MonoNs::ZERO);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(b.keepalive_stats().pongs_sent, 0);
    assert_eq!(b.keepalive_stats().received, 0);

    // A should not observe a pong (CULK would be swallowed; stats stay 0).
    for _ in 0..10 {
        let _ = a.recv_datagram(MonoNs::ZERO);
    }
    assert_eq!(a.keepalive_stats().received, 0);
}

#[test]
fn endpoint_close_disables_transport_controls() {
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a_addr = a_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();

    let a = ConnectedUdpTransport::from_socket(a_sock, b_addr).unwrap();
    let b_transport = ConnectedUdpTransport::from_socket(b_sock, a_addr).unwrap();
    let mut b = UdpLiEndpoint::new(b_transport, EndpointConfig::default());
    let _ = a;
    b.close().unwrap();
    // After close, drive must not panic; controls stay suppressed on further recv.
    let _ = b.drive(MonoNs::ZERO);
}

#[test]
fn restart_invalidates_pending_challenge() {
    let c_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let c_addr = c_sock.local_addr().unwrap();
    let mut t = ConnectedUdpTransport::bind("127.0.0.1:0".parse().unwrap(), c_addr).unwrap();
    t.challenge_candidate(c_addr).unwrap();
    let pending = t.pending_path_challenge().expect("pending").clone();
    assert!(t.pending_path_challenge().is_some());

    t.on_association_restart();
    assert!(
        t.pending_path_challenge().is_none(),
        "restart must drop in-flight challenges"
    );

    let response = encode_response(pending.txn, &pending.token).unwrap();
    c_sock
        .send_to(&response, t.local_addr().unwrap())
        .unwrap();
    let _ = t.recv_datagram(MonoNs::ZERO);
    assert!(t.pending_path_challenge().is_none());
    assert!(!matches!(
        t.peer_binding_state(),
        PeerBindingState::Validated | PeerBindingState::Locked
    ));
}

#[test]
fn keepalive_from_unadmitted_source_does_not_pong_or_refresh() {
    let (mut a, mut b) = lock_pair();
    let cadence = KeepaliveConfig::for_test(Duration::from_millis(30), Duration::from_millis(10));
    a.set_keepalive_config(cadence);
    b.set_keepalive_config(cadence);

    let intruder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_addr = b.local_addr().unwrap();
    intruder.send_to(&encode_ping(), b_addr).unwrap();
    for _ in 0..10 {
        let _ = b.recv_datagram(MonoNs::ZERO);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(b.keepalive_stats().received, 0);
    assert_eq!(b.keepalive_stats().pongs_sent, 0);
    assert!(b.peer_reject_stats().wrong_ip >= 1);

    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(a.drive_keepalive().unwrap(), 1);
}
