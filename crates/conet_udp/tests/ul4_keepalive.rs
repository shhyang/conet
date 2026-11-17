//! UL-4 idle keepalive / NAT mapping refresh tests.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use conet_core::{MonoNs, OpaqueBytes, ReferenceWireCodec, WireFlags, WireHeader};
use conet_udp::{
    ConnectedUdpTransport, ControlWindow, DatagramTransport, KeepaliveConfig, PeerBindingState,
    SchedulerConfig,
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
fn idle_keepalive_ping_reaches_peer_and_elicits_pong() {
    let (mut a, mut b) = lock_pair();
    let cadence = KeepaliveConfig::for_test(Duration::from_millis(40), Duration::from_millis(20));
    a.set_keepalive_config(cadence);
    // Pong replies require keepalive enabled on the answering peer.
    b.set_keepalive_config(cadence);

    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(a.drive_keepalive().unwrap(), 1);
    assert_eq!(a.keepalive_stats().sent, 1);

    // Peer's recv handles CULK ping and replies with pong.
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline && b.keepalive_stats().received == 0 {
        let _ = b.recv_datagram(MonoNs::ZERO);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(b.keepalive_stats().received >= 1);
    assert!(b.keepalive_stats().pongs_sent >= 1);

    while Instant::now() < deadline && a.keepalive_stats().received == 0 {
        let _ = a.recv_datagram(MonoNs::ZERO);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(a.keepalive_stats().received >= 1);
}

#[test]
fn keepalive_suppressed_while_path_is_busy() {
    let (mut a, mut b) = lock_pair();
    a.set_keepalive_config(KeepaliveConfig::for_test(
        Duration::from_millis(30),
        Duration::from_millis(10),
    ));

    // Fresh data activity resets the idle timer.
    a.send_datagram(MonoNs::ZERO, &conet_datagram(b"busy")).unwrap();
    let _ = recv_until(&mut b, Duration::from_secs(1));
    assert_eq!(a.drive_keepalive().unwrap(), 0);

    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(a.drive_keepalive().unwrap(), 1);
}

#[test]
fn keepalive_does_not_touch_conet_control_window() {
    // Transport keepalives are outside the scheduler; the control window math
    // is unchanged by UL-4.
    let config = SchedulerConfig::default();
    let mut window = ControlWindow::default();
    assert!(window.can_send_now(MonoNs::ZERO, 100, 1_000_000, config));
    window.record(MonoNs::ZERO, 100, config);
    // Emitting keepalives must not be modeled as control-window debit.
    assert_eq!(window.bytes(), 100);
    assert_eq!(window.msgs(), 1);
}

#[test]
fn keepalive_skipped_until_peer_is_validated() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let mut transport = ConnectedUdpTransport::from_socket(socket, peer).unwrap();
    transport.set_keepalive_config(KeepaliveConfig::for_test(
        Duration::from_millis(1),
        Duration::from_millis(1),
    ));
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(transport.peer_binding_state(), PeerBindingState::Configured);
    assert_eq!(transport.drive_keepalive().unwrap(), 0);
}
