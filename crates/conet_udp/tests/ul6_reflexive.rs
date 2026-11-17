//! UL-6 same-socket reflexive helper tests.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use conet_core::{MonoNs, OpaqueBytes, ReferenceWireCodec, WireFlags, WireHeader};
use conet_udp::{
    ConnectedUdpTransport, DatagramTransport, PeerBindingState, discover_reflexive,
    serve_reflexive_until,
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

#[test]
fn http_like_wrong_ip_fails_but_reflexive_candidate_matches_filter() {
    let helper = UdpSocket::bind("127.0.0.1:0").unwrap();
    let helper_addr = helper.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client_addr = client.local_addr().unwrap();

    let helper_thread = std::thread::spawn(move || {
        serve_reflexive_until(&helper, Instant::now() + Duration::from_secs(2)).unwrap()
    });

    let report = discover_reflexive(&client, helper_addr, Duration::from_secs(1)).expect("reflexive");
    assert_eq!(report.reflexive, client_addr);
    assert!(helper_thread.join().unwrap() >= 1);

    // HTTP-style wrong peer IP → reject counter (WAN .74 vs .73 class).
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sink_addr = sink.local_addr().unwrap();
    let http_guess: std::net::SocketAddr = "127.0.0.2:9".parse().unwrap();
    let mut wrong = ConnectedUdpTransport::from_socket(sink, http_guess).unwrap();
    client
        .send_to(&conet_datagram(b"via-http-guess"), sink_addr)
        .unwrap();
    assert!(recv_until(&mut wrong, Duration::from_millis(200)).is_none());
    assert!(wrong.peer_reject_stats().wrong_ip >= 1);
    assert_eq!(wrong.peer_binding_state(), PeerBindingState::Configured);

    // Same-socket reflexive candidate as configured --peer → admit.
    let admit = UdpSocket::bind("127.0.0.1:0").unwrap();
    let admit_addr = admit.local_addr().unwrap();
    let mut right = ConnectedUdpTransport::from_socket(admit, report.reflexive).unwrap();
    client
        .send_to(&conet_datagram(b"via-reflexive"), admit_addr)
        .unwrap();
    let got = recv_until(&mut right, Duration::from_secs(1)).expect("reflexive peer admitted");
    assert_eq!(got.bytes.as_slice(), conet_datagram(b"via-reflexive"));
    assert_eq!(right.learned_peer_addr(), Some(client_addr));
}

#[test]
fn transport_probe_reflexive_uses_association_socket() {
    let helper = UdpSocket::bind("127.0.0.1:0").unwrap();
    let helper_addr = helper.local_addr().unwrap();
    let transport =
        ConnectedUdpTransport::bind("127.0.0.1:0".parse().unwrap(), helper_addr).unwrap();
    let local = transport.local_addr().unwrap();

    let helper_thread = std::thread::spawn(move || {
        serve_reflexive_until(&helper, Instant::now() + Duration::from_secs(2)).unwrap()
    });

    let report = transport
        .probe_reflexive(helper_addr, Duration::from_secs(1))
        .expect("probe on association socket");
    assert_eq!(report.reflexive, local);
    // Probe must not mutate peer binding trust.
    assert_eq!(transport.peer_binding_state(), PeerBindingState::Configured);
    assert_eq!(transport.learned_peer_addr(), None);
    assert!(helper_thread.join().unwrap() >= 1);
}
