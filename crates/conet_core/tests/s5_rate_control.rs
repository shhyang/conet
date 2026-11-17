use conet_core::{
    AppliedDecision, BackingAccounting, ByteRate, Clock, ControlDisposition, FixedRateController,
    LinkCaps, LinkReceiver, LinkSender, MonoNs, OpaqueBytes, Pace, PacketBuilder, PacketClass,
    PacketHandle, PacketMetrics, PayloadCopyCounter, QueueLimits, RateControlPolicy, TxController,
    VirtualClock, device_stub_link, paced_identity_link,
};

fn limits(packets: usize) -> QueueLimits {
    QueueLimits::new(packets, 32_768, 32_768)
}

fn packet_with(
    payload: &[u8],
    accounting: BackingAccounting,
    copies: PayloadCopyCounter,
) -> PacketHandle {
    let metrics = PacketMetrics {
        backings: accounting,
        payload_copies: copies,
    };
    let mut builder = PacketBuilder::with_capacity_and_metrics(payload.len(), 4, metrics);
    builder.payload_mut().copy_from_slice(payload);
    builder.freeze()
}

fn packet(len: usize, fill: u8) -> PacketHandle {
    let mut builder = PacketBuilder::with_capacity(len, 4);
    builder.payload_mut().fill(fill);
    builder.freeze()
}

fn nanos(value: i64) -> MonoNs {
    MonoNs::new(value)
}

#[test]
fn g4_pacer_reuse_matches_between_simulator_and_device_stub() {
    let rate: ByteRate = 1_000;
    let (mut simulator, mut sim_sink) = paced_identity_link(limits(8), rate);
    let (mut device, mut device_sink) = device_stub_link(limits(8), rate);
    let (unpaced, _unpaced_sink) = conet_core::identity_link(limits(1));

    let lengths = [1_000_usize, 500, 1_500];
    for (index, len) in lengths.into_iter().enumerate() {
        simulator.enqueue(packet(len, index as u8)).unwrap();
        device.enqueue(packet(len, index as u8)).unwrap();
    }

    let clock = VirtualClock::new(MonoNs::ZERO);
    for at in [
        0,
        500_000_000,
        1_000_000_000,
        1_250_000_000,
        1_500_000_000,
        2_999_999_999,
        3_000_000_000,
    ] {
        clock.drive(nanos(at)).unwrap();
        simulator.drive(clock.now());
        device.drive(clock.now());
    }

    let sim_trace: Vec<_> = simulator
        .sent()
        .iter()
        .map(|record| (record.at, record.bytes, record.ready_at))
        .collect();
    let device_trace: Vec<_> = device
        .sent()
        .iter()
        .map(|record| (record.at, record.bytes, record.ready_at))
        .collect();
    let expected = vec![
        (nanos(0), 1_000, nanos(1_000_000_000)),
        (nanos(1_000_000_000), 500, nanos(1_500_000_000)),
        (nanos(1_500_000_000), 1_500, nanos(3_000_000_000)),
    ];
    assert_eq!(sim_trace, expected);
    assert_eq!(device_trace, expected);

    let first = sim_sink.recv().unwrap();
    let first_device = device_sink.recv().unwrap();
    assert_eq!(first.len(), 1_000);
    assert_eq!(first_device.len(), 1_000);
    assert!(simulator.caps().paced);
    assert!(device.caps().paced);
    assert!(!unpaced.caps().paced);
    assert_eq!(unpaced.caps(), LinkCaps::UNPACED_IN_PROCESS);
}

#[test]
fn g5_fixed_rate_controller_ignores_bodies_and_exposes_its_pace() {
    let rate: ByteRate = 2_000;
    let mut controller = FixedRateController::new(rate);
    controller.on_peer_control(
        nanos(10),
        OpaqueBytes::from_static(b"peer asks for 999999 bytes/s"),
    );
    assert_eq!(controller.pace(), Pace::set_target_rate(rate));
    controller.on_clock(nanos(20));
    assert_eq!(controller.poll_control(nanos(35)), None);

    let (mut link, _sink) = paced_identity_link(limits(2), rate);
    let applied = link.handle_peer_control(
        &mut controller,
        nanos(40),
        OpaqueBytes::from_static(b"still opaque"),
        RateControlPolicy::test_allow_unauthenticated_cc(),
    );
    assert_eq!(
        applied,
        AppliedDecision::Applied {
            bytes_per_sec: Some(rate),
            inflight_limit_bytes: None,
        }
    );
    assert_eq!(link.target_rate(), rate);
}

struct SuggestRateController {
    suggested_rate: ByteRate,
    current_rate: ByteRate,
}

impl TxController for SuggestRateController {
    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        self.current_rate = self.suggested_rate;
        ControlDisposition::Usable
    }

    fn pace(&self) -> Pace {
        Pace::set_target_rate(self.current_rate)
    }
}

#[test]
fn g10_unauthenticated_control_cannot_change_applied_rate() {
    let initial_rate: ByteRate = 1_000;
    let suggested_rate: ByteRate = 4_000;
    let (mut link, _sink) = paced_identity_link(limits(2), initial_rate);
    let mut controller = SuggestRateController {
        suggested_rate,
        current_rate: initial_rate,
    };
    let body = OpaqueBytes::from_static(b"CC_OPAQUE set-target-rate=4000");

    assert!(!RateControlPolicy::default().allow_unauthenticated_cc);
    let rejected = link.handle_peer_control(
        &mut controller,
        MonoNs::ZERO,
        body.clone(),
        RateControlPolicy::default(),
    );
    assert_eq!(
        rejected,
        AppliedDecision::RejectedUnauthenticated {
            bytes_per_sec: Some(suggested_rate),
            inflight_limit_bytes: None,
        }
    );
    assert_eq!(link.target_rate(), initial_rate);

    let allowed = link.handle_peer_control(
        &mut controller,
        nanos(1),
        body,
        RateControlPolicy::test_allow_unauthenticated_cc(),
    );
    assert_eq!(
        allowed,
        AppliedDecision::Applied {
            bytes_per_sec: Some(suggested_rate),
            inflight_limit_bytes: None,
        }
    );
    assert_eq!(link.target_rate(), suggested_rate);
}

struct WindowOnlyController {
    inflight_limit_bytes: u64,
}

impl TxController for WindowOnlyController {
    fn on_clock(&mut self, _now: MonoNs) {}

    fn on_peer_control(&mut self, _now: MonoNs, _body: OpaqueBytes) -> ControlDisposition {
        ControlDisposition::Unusable
    }

    fn pace(&self) -> Pace {
        Pace::set_inflight_limit(self.inflight_limit_bytes)
    }
}

#[test]
fn window_only_pace_preserves_the_link_rate() {
    let initial_rate: ByteRate = 3_000;
    let (mut link, _sink) = paced_identity_link(limits(2), initial_rate);
    let mut controller = WindowOnlyController {
        inflight_limit_bytes: 12_288,
    };

    let applied = link.handle_clock(
        &mut controller,
        MonoNs::ZERO,
        RateControlPolicy::authenticated(),
    );
    assert_eq!(
        applied,
        AppliedDecision::Applied {
            bytes_per_sec: None,
            inflight_limit_bytes: Some(12_288),
        }
    );
    assert_eq!(link.target_rate(), initial_rate);
    assert_eq!(link.inflight_limit_bytes(), Some(12_288));
}

#[test]
fn t2_mixed_classes_debit_one_pacer_budget() {
    let rate: ByteRate = 1_000;
    let (mut link, mut sink) = paced_identity_link(limits(8), rate);
    link.enqueue_class(PacketClass::Data, packet(1_000, 0x11))
        .unwrap();
    link.enqueue_class(PacketClass::Control, packet(500, 0x22))
        .unwrap();
    link.enqueue_class(PacketClass::Data, packet(500, 0x33))
        .unwrap();

    let clock = VirtualClock::new(MonoNs::ZERO);
    for at in [0, 999_999_999, 1_000_000_000, 1_499_999_999, 1_500_000_000] {
        clock.drive(nanos(at)).unwrap();
        link.drive(clock.now());
    }

    let trace: Vec<_> = link
        .sent()
        .iter()
        .map(|record| (record.at, record.bytes, record.class, record.ready_at))
        .collect();
    assert_eq!(
        trace,
        vec![
            (nanos(0), 1_000, PacketClass::Data, nanos(1_000_000_000)),
            (
                nanos(1_000_000_000),
                500,
                PacketClass::Control,
                nanos(1_500_000_000)
            ),
            (
                nanos(1_500_000_000),
                500,
                PacketClass::Data,
                nanos(2_000_000_000)
            ),
        ]
    );

    let first = sink.recv().unwrap();
    let second = sink.recv().unwrap();
    let third = sink.recv().unwrap();
    assert_eq!(first.payload_bytes(), &[0x11; 1_000]);
    assert_eq!(second.payload_bytes(), &[0x22; 500]);
    assert_eq!(third.payload_bytes(), &[0x33; 500]);
}

#[test]
fn paced_composition_preserves_backing_and_payload_copy_count() {
    let copies = PayloadCopyCounter::new();
    let payload = vec![0x7a; 900];
    let pkt = packet_with(&payload, BackingAccounting::new(), copies.clone());
    let backing_id = pkt.backing_id();
    let (mut source, mut sink) = paced_identity_link(limits(2), 1_000);

    source.enqueue(pkt).unwrap();
    assert_eq!(source.drive(MonoNs::ZERO).len(), 1);

    let received = sink.recv().unwrap();
    assert_eq!(received.backing_id(), backing_id);
    assert_eq!(received.payload_bytes(), payload);
    assert_eq!(copies.count(), 0);
    assert_eq!(received.payload_copies().count(), 0);
}
