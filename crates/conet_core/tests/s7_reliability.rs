use conet_core::{
    BlockId, Clock, Drive, LinkSender, MonoNs, OneWayBudget, PacketMetrics, PayloadCopyCounter,
    QueueLimits, ReliabilityReceiver, ReliabilitySender, SystematicBlockCodec, VirtualClock,
    device_stub_link, paced_identity_link,
};

fn link_limits() -> QueueLimits {
    QueueLimits::new(8, 4096, 4096)
}

fn metrics(copies: &PayloadCopyCounter) -> PacketMetrics {
    PacketMetrics {
        backings: conet_core::BackingAccounting::new(),
        payload_copies: copies.clone(),
    }
}

fn run_one_way<S>(mut link: S, mut receiver: conet_core::IdentityReceiver) -> RunEvidence
where
    S: LinkSender + Drive,
{
    let block = BlockId::new(42);
    let object = b"one-way-object-recovered".to_vec();
    let encode_copies = PayloadCopyCounter::new();
    let decode_copies = PayloadCopyCounter::new();

    let mut encoder = SystematicBlockCodec::new(5, encode_copies.clone()).unwrap();
    let shape = encoder.add_block(block, object.clone()).unwrap();
    let decoder = SystematicBlockCodec::new(5, decode_copies.clone()).unwrap();

    let budget = shape.source_symbols as u64 + 2;
    let mut sender = ReliabilitySender::new(
        encoder,
        OneWayBudget::new(budget),
        QueueLimits::new(8, 4096, 4096),
        metrics(&encode_copies),
    );
    sender.register_block(block, MonoNs::ZERO).unwrap();
    let mut receiver_core = ReliabilityReceiver::new(decoder);

    let clock = VirtualClock::new(MonoNs::ZERO);
    let mut generated = 0;
    let mut enqueued = 0;
    for tick in 0..=budget {
        clock
            .drive(MonoNs::new((tick as i64) * 10_000_000))
            .unwrap();
        let pump = sender.pump(&mut link, clock.now(), 1, 1);
        generated += pump.generated as u64;
        enqueued += pump.enqueued as u64;
        let _ = link.drive(clock.now());
        receiver_core.drain(&mut receiver);
    }

    assert!(receiver_core.is_recovered(block));
    let recovered = receiver_core.take_recovered_block(block).unwrap();
    assert_eq!(recovered, object);
    assert_eq!(generated, budget);
    assert_eq!(enqueued, budget);
    assert_eq!(encode_copies.count(), budget);
    assert!(decode_copies.count() >= shape.source_symbols as u64);

    RunEvidence {
        object: recovered,
        generated,
        status: sender.status(block).unwrap(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RunEvidence {
    object: Vec<u8>,
    generated: u64,
    status: conet_core::BlockStatus,
}

#[test]
fn t1_one_way_open_loop_recovers_and_stops_on_counter() {
    let (sender, receiver) = paced_identity_link(link_limits(), 1_000);
    let evidence = run_one_way(sender, receiver);
    assert_eq!(evidence.object, b"one-way-object-recovered");
    assert_eq!(evidence.status, conet_core::BlockStatus::StoppedByBudget);
}

#[test]
fn g1_same_core_completes_on_simulator_and_device_stub() {
    let (simulator, sim_receiver) = paced_identity_link(link_limits(), 1_000);
    let (device, device_receiver) = device_stub_link(link_limits(), 1_000);
    let simulator_run = run_one_way(simulator, sim_receiver);
    let device_run = run_one_way(device, device_receiver);
    assert_eq!(simulator_run, device_run);
    assert_eq!(
        simulator_run.status,
        conet_core::BlockStatus::StoppedByBudget
    );
}

#[test]
fn g6_one_way_policy_stops_without_ack_path() {
    let (sender, receiver) = device_stub_link(link_limits(), 1_000);
    let evidence = run_one_way(sender, receiver);
    assert_eq!(evidence.generated, 7);
    assert_eq!(evidence.status, conet_core::BlockStatus::StoppedByBudget);
}
