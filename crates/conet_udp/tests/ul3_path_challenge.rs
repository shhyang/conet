//! UL-3 path challenge / response tests.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use conet_core::{MonoNs, OpaqueBytes, ReferenceWireCodec, WireFlags, WireHeader};
use conet_udp::{
    ConnectedUdpTransport, DatagramTransport, PathChallengePoll, PeerAdmitPolicy,
    PeerBindingState,
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

#[test]
fn path_challenge_promotes_observed_peer_before_trusted_send() {
    let sender_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sender_addr = sender_socket.local_addr().unwrap();
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();

    let mut sender = ConnectedUdpTransport::from_socket_with_policy(
        sender_socket,
        receiver_addr,
        PeerAdmitPolicy::require_path_challenge(),
    )
    .unwrap();
    let mut receiver = ConnectedUdpTransport::from_socket_with_policy(
        receiver_socket,
        sender_addr,
        PeerAdmitPolicy::require_path_challenge(),
    )
    .unwrap();

    let request = conet_datagram(b"need-challenge");
    sender.send_datagram(MonoNs::ZERO, &request).unwrap();
    let got = recv_until(&mut receiver, Duration::from_secs(1)).expect("conet delivered while observed");
    assert_eq!(got.bytes.as_slice(), request);
    assert_eq!(receiver.peer_binding_state(), PeerBindingState::Observed);
    assert!(receiver.pending_path_challenge().is_some());

    // Drive both sides until the response promotes the receiver.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline
        && receiver.peer_binding_state() != PeerBindingState::Locked
    {
        let _ = receiver.drive_path_challenge();
        let _ = sender.recv_datagram(MonoNs::ZERO);
        let _ = receiver.recv_datagram(MonoNs::ZERO);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(receiver.peer_binding_state(), PeerBindingState::Locked);
    assert_eq!(receiver.learned_peer_addr(), Some(sender_addr));
    assert!(receiver.pending_path_challenge().is_none());

    let reply = conet_datagram(b"trusted-reply");
    receiver.send_datagram(MonoNs::ZERO, &reply).unwrap();
    let got = recv_until(&mut sender, Duration::from_secs(1)).expect("reply after validate");
    assert_eq!(got.bytes.as_slice(), reply);
}

#[test]
fn spoofed_source_without_challenge_response_stays_untrusted() {
    let expected = UdpSocket::bind("127.0.0.1:0").unwrap();
    let expected_addr = expected.local_addr().unwrap();
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();
    let intruder = UdpSocket::bind("127.0.0.1:0").unwrap();

    let mut receiver = ConnectedUdpTransport::from_socket_with_policy(
        receiver_socket,
        expected_addr,
        PeerAdmitPolicy::require_path_challenge(),
    )
    .unwrap();

    expected
        .send_to(&conet_datagram(b"first"), receiver_addr)
        .unwrap();
    let _ = recv_until(&mut receiver, Duration::from_secs(1)).expect("first");
    assert_eq!(receiver.peer_binding_state(), PeerBindingState::Observed);

    // Intruder Conet traffic must not become the learned peer without a response.
    intruder
        .send_to(&conet_datagram(b"spoof"), receiver_addr)
        .unwrap();
    let _ = receiver.recv_datagram(MonoNs::ZERO);
    assert_eq!(receiver.learned_peer_addr(), Some(expected_addr));
    assert!(receiver.peer_reject_stats().locked_conflict >= 1 || receiver.pending_path_challenge().is_some());
}

#[test]
fn challenge_timeout_fails_closed_to_configured() {
    let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let mut transport = ConnectedUdpTransport::bind_with_policy(
        "127.0.0.1:0".parse().unwrap(),
        dead_addr,
        PeerAdmitPolicy::require_path_challenge(),
    )
    .unwrap();

    transport
        .challenge_candidate(dead_addr)
        .expect("challenge starts even if peer is silent");
    assert!(transport.pending_path_challenge().is_some());

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut timed_out = false;
    while Instant::now() < deadline {
        match transport.drive_path_challenge().unwrap() {
            PathChallengePoll::TimedOut { .. } => {
                timed_out = true;
                break;
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    assert!(timed_out, "challenge should time out against a silent peer");
    assert_eq!(transport.peer_binding_state(), PeerBindingState::Configured);
    assert!(transport.peer_reject_stats().challenge_timeout >= 1);
    assert!(transport.pending_path_challenge().is_none());
}

#[test]
fn explicit_challenge_switches_locked_peer_after_response() {
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a_addr = a_sock.local_addr().unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_addr = b_sock.local_addr().unwrap();
    let c_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let c_addr = c_sock.local_addr().unwrap();

    // Lock A↔B with default auto-validate.
    let mut a = ConnectedUdpTransport::from_socket(a_sock, b_addr).unwrap();
    let mut b = ConnectedUdpTransport::from_socket(b_sock, a_addr).unwrap();
    a.send_datagram(MonoNs::ZERO, &conet_datagram(b"lock")).unwrap();
    let _ = recv_until(&mut b, Duration::from_secs(1)).unwrap();
    assert_eq!(b.peer_binding_state(), PeerBindingState::Locked);

    // New candidate C: challenge without dropping the old lock until success.
    let mut c = ConnectedUdpTransport::from_socket(c_sock, b_addr).unwrap();
    b.challenge_candidate(c_addr).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && b.learned_peer_addr() != Some(c_addr) {
        let _ = b.drive_path_challenge();
        let _ = c.recv_datagram(MonoNs::ZERO); // answers CULP
        let _ = b.recv_datagram(MonoNs::ZERO);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(b.learned_peer_addr(), Some(c_addr));
    assert_eq!(b.peer_binding_state(), PeerBindingState::Locked);
}
