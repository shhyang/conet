use conet_core::{Clock, Drive, MonoNs, SeededScheduler, StubEndpoint, VirtualClock};

fn replay(seed: u64) -> (Vec<(i64, u64, u64)>, Vec<String>) {
    let mut endpoint = StubEndpoint::new(MonoNs::ZERO, seed);
    endpoint.schedule_after(MonoNs::new(20), 20).unwrap();
    endpoint.schedule_after(MonoNs::new(10), 10).unwrap();
    endpoint.schedule_after(MonoNs::new(10), 11).unwrap();

    let mut trace = Vec::new();
    let mut names = Vec::new();
    for now in [5, 10, 20] {
        for event in endpoint.drive(MonoNs::new(now)).unwrap() {
            trace.push((event.at.as_nanos(), event.order, event.event));
            names.push(format!("event-{}@{}", event.event, event.at));
        }
    }
    (trace, names)
}

#[test]
fn g3_virtual_time_advances_only_when_driven() {
    let clock = VirtualClock::new(MonoNs::new(100));
    assert_eq!(clock.now(), MonoNs::new(100));

    // No sleep, no wall clock: only this explicit drive changes time.
    clock.drive(MonoNs::new(175)).unwrap();
    assert_eq!(clock.now(), MonoNs::new(175));

    assert!(clock.drive(MonoNs::new(174)).is_err());
    assert_eq!(clock.now(), MonoNs::new(175));
}

#[test]
fn g3_driveable_endpoint_emits_only_due_events() {
    let mut endpoint = StubEndpoint::new(MonoNs::ZERO, 7);
    endpoint.schedule_after(MonoNs::new(10), 1).unwrap();

    assert!(endpoint.drive(MonoNs::new(9)).unwrap().is_empty());
    assert_eq!(endpoint.now(), MonoNs::new(9));

    let due = endpoint.drive(MonoNs::new(10)).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event, 1);
    assert_eq!(endpoint.now(), MonoNs::new(10));
}

#[test]
fn g3_same_seed_and_script_replay_same_event_order() {
    let first = replay(0x5eed);
    let second = replay(0x5eed);
    assert_eq!(first, second);
    assert_eq!(
        first.1,
        vec![
            "event-10@10".to_string(),
            "event-11@10".to_string(),
            "event-20@20".to_string(),
        ]
    );
}

#[test]
fn g3_equal_time_tie_break_is_insertion_sequence() {
    let mut scheduler = SeededScheduler::new(42);
    scheduler.schedule(MonoNs::new(5), 'a').unwrap();
    scheduler.schedule(MonoNs::new(5), 'b').unwrap();
    let due = scheduler.drive_until(MonoNs::new(5)).unwrap();
    let order: Vec<_> = due.into_iter().map(|event| event.event).collect();
    assert_eq!(order, vec!['a', 'b']);
}
