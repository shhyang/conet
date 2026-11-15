use conet_core::{BackingAccounting, PacketBuilder, PacketMetrics, PayloadCopyCounter};

fn frozen(
    payload: &[u8],
    accounting: BackingAccounting,
    copies: PayloadCopyCounter,
) -> conet_core::PacketHandle {
    let metrics = PacketMetrics {
        backings: accounting,
        payload_copies: copies,
    };
    let mut builder = PacketBuilder::with_capacity_and_metrics(payload.len(), 8, metrics);
    builder.payload_mut().copy_from_slice(payload);
    builder.header_mut().resize(4, 0);
    builder.freeze()
}

#[test]
fn m2_slice_offsets_and_last_reference_frees_backing() {
    let accounting = BackingAccounting::new();
    let copies = PayloadCopyCounter::new();
    let parent = frozen(b"0123456789", accounting.clone(), copies.clone());
    let slice = parent.slice(2, 4).unwrap();

    assert_eq!(slice.backing_id(), parent.backing_id());
    assert_eq!(slice.payload().range(), (2, 4));
    assert_eq!(slice.payload_bytes(), b"2345");
    assert_eq!(accounting.snapshot().live_count, 1);

    drop(parent);
    assert_eq!(accounting.snapshot().live_count, 1);
    assert_eq!(accounting.snapshot().live_bytes, 10);

    drop(slice);
    assert_eq!(accounting.snapshot().live_count, 0);
    assert_eq!(accounting.snapshot().live_bytes, 0);
}

#[test]
fn m3_fanout_has_independent_headers_and_shared_immutable_payload() {
    let accounting = BackingAccounting::new();
    let copies = PayloadCopyCounter::new();
    let mut first = frozen(b"shared", accounting, copies);
    let second = first.fanout();

    assert_eq!(first.backing_id(), second.backing_id());
    assert_eq!(first.payload_bytes(), second.payload_bytes());

    first.header_mut().as_mut_bytes()[0] = 0xaa;
    first.header_mut().as_mut_bytes()[1] = 0xbb;
    assert_eq!(second.header().as_bytes(), &[0, 0, 0, 0]);
    assert_eq!(second.payload_bytes(), b"shared");
    assert_eq!(first.payload_bytes(), b"shared");
}

#[test]
fn m9_small_slice_is_charged_the_large_unique_backing() {
    let accounting = BackingAccounting::new();
    let copies = PayloadCopyCounter::new();
    let metrics = PacketMetrics {
        backings: accounting.clone(),
        payload_copies: copies,
    };
    let mut builder = PacketBuilder::with_capacity_and_metrics(1024 * 1024, 16, metrics);
    builder.payload_mut()[..8].copy_from_slice(b"tiny----");
    let parent = builder.freeze();
    let slice = parent.slice(0, 8).unwrap();

    assert_eq!(slice.len(), 8);
    assert_eq!(slice.charged_backing_bytes(), 1024 * 1024);
    assert_eq!(accounting.snapshot().live_bytes, 1024 * 1024);

    drop(parent);
    assert_eq!(accounting.snapshot().live_bytes, 1024 * 1024);
    drop(slice);
    assert_eq!(accounting.snapshot().live_bytes, 0);
}

#[test]
fn m10_fanout_and_slice_do_not_increment_payload_copy_counter() {
    let copies = PayloadCopyCounter::new();
    let parent = frozen(b"copy-free", BackingAccounting::new(), copies.clone());
    let fanned = parent.fanout();
    let sliced = parent.slice(1, 3).unwrap();

    assert_eq!(copies.count(), 0);
    assert_eq!(fanned.payload_bytes(), b"copy-free");
    assert_eq!(sliced.payload_bytes(), b"opy");

    // The hook is real; only an explicit future transformation calls it.
    copies.record_copy();
    assert_eq!(copies.count(), 1);
}

#[test]
fn s2_composition_builder_fanout_and_slice_share_one_backing() {
    let parent = frozen(
        b"0123456789",
        BackingAccounting::new(),
        PayloadCopyCounter::new(),
    );
    let left = parent.fanout();
    let right = parent.fanout();
    let middle = parent.slice(3, 4).unwrap();

    assert_eq!(left.backing_id(), parent.backing_id());
    assert_eq!(right.backing_id(), parent.backing_id());
    assert_eq!(middle.backing_id(), parent.backing_id());
    assert_eq!(middle.payload_bytes(), b"3456");
}
