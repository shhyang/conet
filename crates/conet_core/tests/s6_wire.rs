use conet_core::{
    BackingAccounting, BlockId, ControlMessage, ControlType, Feedback, FeedbackKind, OpaqueBytes,
    PacketMetrics, PayloadCopyCounter, QosClass, REFERENCE_WIRE_HEADER_LEN, ReferenceWireCodec,
    ReliabilityContentError, SymbolId, WireError, WireFlags, WireHeader,
    decode_reliability_data, decode_reliability_feedback, encode_reliability_data,
    encode_reliability_feedback,
};

const GOOD_CORPUS: &[(&str, &str)] = &[
    (
        "good_coded_data",
        include_str!("corpus/wire/good_coded_data.hex"),
    ),
    (
        "good_feedback",
        include_str!("corpus/wire/good_feedback.hex"),
    ),
    (
        "good_piggyback",
        include_str!("corpus/wire/good_piggyback.hex"),
    ),
    (
        "good_feedback_piggyback",
        include_str!("corpus/wire/good_feedback_piggyback.hex"),
    ),
    (
        "good_standalone_control",
        include_str!("corpus/wire/good_standalone_control.hex"),
    ),
];

const BAD_CORPUS: &[(&str, &str, &str)] = &[
    (
        "bad_version",
        include_str!("corpus/wire/bad_version.hex"),
        "unsupported_version",
    ),
    (
        "bad_magic",
        include_str!("corpus/wire/bad_magic.hex"),
        "bad_magic",
    ),
    (
        "bad_flag_bits",
        include_str!("corpus/wire/bad_flag_bits.hex"),
        "unknown_flag_bits",
    ),
    (
        "bad_qos_class",
        include_str!("corpus/wire/bad_qos_class.hex"),
        "unknown_qos_class",
    ),
    (
        "bad_control_type",
        include_str!("corpus/wire/bad_control_type.hex"),
        "unknown_control_type",
    ),
    (
        "bad_control_truncated",
        include_str!("corpus/wire/bad_control_truncated.hex"),
        "control_too_short",
    ),
    (
        "bad_payload_length",
        include_str!("corpus/wire/bad_payload_length.hex"),
        "payload_length_mismatch",
    ),
    (
        "bad_truncated",
        include_str!("corpus/wire/bad_truncated.hex"),
        "header_too_short",
    ),
    (
        "bad_empty",
        include_str!("corpus/wire/bad_empty.hex"),
        "empty_datagram",
    ),
];

fn decode_hex(text: &str) -> Vec<u8> {
    let digits: Vec<_> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(digits.len() % 2, 0, "hex corpus has an odd digit count");
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex digit");
            let low = (pair[1] as char).to_digit(16).expect("hex digit");
            ((high << 4) | low) as u8
        })
        .collect()
}

fn corpus_bytes(name: &str) -> Vec<u8> {
    GOOD_CORPUS
        .iter()
        .map(|(case, hex)| (*case, *hex))
        .chain(BAD_CORPUS.iter().map(|(case, hex, _)| (*case, *hex)))
        .find_map(|(case, hex)| (case == name).then(|| decode_hex(hex)))
        .unwrap_or_else(|| panic!("missing corpus case {name}"))
}

fn header(qos: QosClass) -> WireHeader {
    WireHeader {
        flags: WireFlags { qos },
        epoch: 1,
        link_seq: 7,
        payload_len: 0,
    }
}

#[test]
fn deterministic_good_corpus_round_trips_exactly() {
    let codec = ReferenceWireCodec::default();
    for (name, hex) in GOOD_CORPUS {
        let original = decode_hex(hex);
        let parsed = codec
            .parse(OpaqueBytes::from(original.clone()))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let serialized = codec
            .serialize(&parsed)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(serialized, original, "{name} changed on round-trip");

        let reparsed = codec.parse(OpaqueBytes::from(serialized)).unwrap();
        assert_eq!(reparsed.header(), parsed.header(), "{name}");
        assert_eq!(
            reparsed.packet().payload_bytes(),
            parsed.packet().payload_bytes(),
            "{name}"
        );
        assert_eq!(reparsed.control(), parsed.control(), "{name}");
    }
}

#[test]
fn deterministic_bad_corpus_is_dropped_for_the_expected_reason() {
    let codec = ReferenceWireCodec::default();
    for (name, hex, expected_reason) in BAD_CORPUS {
        let error = codec
            .parse(OpaqueBytes::from(decode_hex(hex)))
            .expect_err(name);
        assert_eq!(error.drop_reason(), *expected_reason, "{name}: {error}");
    }
}

#[test]
fn link_header_is_the_exact_layout_tag_5_prefix() {
    let codec = ReferenceWireCodec::default();
    let datagram = corpus_bytes("good_coded_data");

    assert_eq!(datagram.len(), 32);
    assert_eq!(&datagram[0..2], &[0x55, 0x4c]);
    assert_eq!(datagram[2], 5);
    assert_eq!(datagram[3], QosClass::Bulk.wire_value());
    assert_eq!(&datagram[4..8], &[0, 0, 0, 7]);
    assert_eq!(&datagram[8..10], &[0, 20]);
    assert_eq!(&datagram[10..12], &[0, 1]);

    let parsed = codec.parse(OpaqueBytes::from(datagram.clone())).unwrap();
    assert_eq!(parsed.packet().header().len(), 12);
    assert_eq!(parsed.packet().payload_bytes(), &datagram[12..]);
}

#[test]
fn parser_demuxes_bulk_feedback_piggyback_and_standalone_control() {
    let codec = ReferenceWireCodec::default();

    let coded = codec
        .parse(OpaqueBytes::from(corpus_bytes("good_coded_data")))
        .unwrap();
    assert_eq!(coded.header().flags.qos, QosClass::Bulk);
    assert_eq!(coded.header().link_seq, 7);
    let data = decode_reliability_data(OpaqueBytes::from(coded.packet().payload_bytes().to_vec()))
        .unwrap();
    assert_eq!(data.block_id, BlockId::new(5));
    assert_eq!(data.rel_seq, SymbolId::new(9));
    assert_eq!(data.coded_vector.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_ne!(&coded.packet().payload_bytes()[..4], b"OCNR");
    assert!(coded.control().is_none());

    let feedback_datagram = codec
        .parse(OpaqueBytes::from(corpus_bytes("good_feedback")))
        .unwrap();
    assert_eq!(feedback_datagram.header().flags.qos, QosClass::Feedback);
    assert_eq!(feedback_datagram.header().link_seq, 7);
    let feedback = decode_reliability_feedback(OpaqueBytes::from(
        feedback_datagram.packet().payload_bytes().to_vec(),
    ))
    .unwrap();
    assert_eq!(feedback, Feedback::nack(BlockId::new(77), 12, 2));
    assert_eq!(feedback.kind, FeedbackKind::Nack);
    assert_ne!(&feedback_datagram.packet().payload_bytes()[..4], b"OCNR");

    let piggyback = codec
        .parse(OpaqueBytes::from(corpus_bytes("good_piggyback")))
        .unwrap();
    assert_eq!(piggyback.header().flags.qos, QosClass::Bulk);
    let data = decode_reliability_data(OpaqueBytes::from(
        piggyback.packet().payload_bytes().to_vec(),
    ))
    .unwrap();
    assert_eq!(data.block_id, BlockId::new(5));
    assert_eq!(data.rel_seq, SymbolId::new(10));
    assert_eq!(data.coded_vector.as_ref(), &[0xaa, 0xbb, 0xcc]);
    let control = piggyback.control().expect("piggyback control");
    assert_eq!(control.ctrl_type, ControlType::Open);
    assert_eq!(control.ctrl_seq, Some(42));
    assert_eq!(control.body.as_ref(), &[0x00, 0x01, 0x05, 0x00, 1, 2, 3, 4]);

    let feedback_piggyback = codec
        .parse(OpaqueBytes::from(corpus_bytes("good_feedback_piggyback")))
        .unwrap();
    assert_eq!(feedback_piggyback.header().flags.qos, QosClass::Feedback);
    assert_eq!(
        decode_reliability_feedback(OpaqueBytes::from(
            feedback_piggyback.packet().payload_bytes().to_vec(),
        ))
        .unwrap(),
        Feedback::nack(BlockId::new(77), 12, 2)
    );
    let control = feedback_piggyback
        .control()
        .expect("feedback piggyback control");
    assert_eq!(control.ctrl_type, ControlType::Close);
    assert_eq!(control.ctrl_seq, Some(0x33));
    assert_eq!(control.body.as_ref(), &[0xca, 0xfe]);

    let standalone = codec
        .parse(OpaqueBytes::from(corpus_bytes("good_standalone_control")))
        .unwrap();
    assert_eq!(standalone.header().flags.qos, QosClass::Control);
    assert!(standalone.packet().payload_bytes().is_empty());
    let control = standalone.control().expect("standalone control");
    assert_eq!(control.ctrl_type, ControlType::CcOpaque);
    assert_eq!(control.ctrl_seq, None);
    assert_eq!(control.body.as_ref(), &[0xca, 0xfe, 0xba, 0xbe]);
}

#[test]
fn qos_is_scheduling_only_and_does_not_constrain_payload_layout() {
    let codec = ReferenceWireCodec::default();
    let control = ControlMessage::new(ControlType::Close, 1, OpaqueBytes::from_static(b"control"));

    for qos in [QosClass::Bulk, QosClass::Feedback, QosClass::Control] {
        let body = codec
            .build(
                header(qos),
                OpaqueBytes::from_static(b"opaque-user-body"),
                None,
            )
            .expect("a non-empty body is valid for every QoS label");
        assert_eq!(body.header().flags.qos, qos);

        let standalone = codec
            .build(header(qos), OpaqueBytes::new(), Some(control.clone()))
            .expect("a standalone trailer is valid for every QoS label");
        assert!(standalone.packet().payload_bytes().is_empty());
        assert_eq!(standalone.header().flags.qos, qos);
    }
}

#[test]
fn opaque_cc_body_round_trips_as_one_trailer() {
    let codec = ReferenceWireCodec::default();
    let cc_body = OpaqueBytes::from_static(&[2, 0, 0, 0, 77]);
    assert_eq!(ControlType::Cc.wire_value(), 6);
    let datagram = codec
        .build(
            header(QosClass::Bulk),
            OpaqueBytes::from_static(b"probe-body"),
            Some(ControlMessage::new(ControlType::Cc, 0, cc_body.clone())),
        )
        .unwrap();
    let bytes = codec.serialize(&datagram).unwrap();
    let parsed = codec.parse(OpaqueBytes::from(bytes)).unwrap();
    assert_eq!(parsed.packet().header().len(), REFERENCE_WIRE_HEADER_LEN);
    assert_eq!(parsed.packet().payload_bytes(), b"probe-body");
    let control = parsed.control().unwrap();
    assert_eq!(control.ctrl_type, ControlType::Cc);
    assert_eq!(control.body, cc_body);
}

#[test]
fn reliability_content_helpers_round_trip_ack_and_nack() {
    let data_body = encode_reliability_data(BlockId::new(0x0102), SymbolId::new(0x0304), b"xyz");
    assert_eq!(data_body.len(), 16 + 3);
    assert_eq!(&data_body[..8], &0x0102_u64.to_be_bytes());
    assert_eq!(&data_body[8..16], &0x0304_u64.to_be_bytes());
    assert_eq!(&data_body[16..], b"xyz");
    let data = decode_reliability_data(OpaqueBytes::from(data_body)).unwrap();
    assert_eq!(data.block_id, BlockId::new(0x0102));
    assert_eq!(data.rel_seq, SymbolId::new(0x0304));
    assert_eq!(data.coded_vector.as_ref(), b"xyz");

    for feedback in [
        Feedback::ack(BlockId::new(8)),
        Feedback::nack(BlockId::new(9), 4, 2),
    ] {
        let body = encode_reliability_feedback(feedback);
        assert_eq!(body.len(), 17);
        assert_eq!(
            decode_reliability_feedback(OpaqueBytes::from(body)).unwrap(),
            feedback
        );
    }
}

#[test]
fn reliability_content_helper_fails_closed_on_malformed_bodies() {
    assert_eq!(
        decode_reliability_data(OpaqueBytes::from_static(b"short")),
        Err(ReliabilityContentError::DataTooShort { len: 5 })
    );
    assert_eq!(
        decode_reliability_data(OpaqueBytes::from(vec![0; 16])),
        Err(ReliabilityContentError::MissingCodedVector)
    );
    assert_eq!(
        decode_reliability_feedback(OpaqueBytes::from_static(b"short")),
        Err(ReliabilityContentError::FeedbackTooShort { len: 5 })
    );

    let mut unknown = encode_reliability_feedback(Feedback::ack(BlockId::new(1)));
    unknown[0] = 0xff;
    assert_eq!(
        decode_reliability_feedback(OpaqueBytes::from(unknown)),
        Err(ReliabilityContentError::UnknownFeedbackKind { value: 0xff })
    );

    let mut trailing = encode_reliability_feedback(Feedback::ack(BlockId::new(1)));
    trailing.push(0);
    assert_eq!(
        decode_reliability_feedback(OpaqueBytes::from(trailing)),
        Err(ReliabilityContentError::FeedbackHasTrailingBytes { len: 1 })
    );
}

#[test]
fn serializer_round_trips_constructed_data_handle_with_opaque_control() {
    let codec = ReferenceWireCodec::default();
    let payload = OpaqueBytes::from(encode_reliability_data(
        BlockId::new(5),
        SymbolId::new(9),
        b"coded-payload",
    ));
    let payload_ptr = payload.as_ptr();
    let control = ControlMessage::new(
        ControlType::CcOpaque,
        0x1020_3040,
        OpaqueBytes::from_static(b"\x01\x02opaque-controller-body"),
    );
    let built = codec
        .build(header(QosClass::Bulk), payload, Some(control))
        .unwrap();
    assert_eq!(built.packet().payload_bytes().as_ptr(), payload_ptr);
    assert_eq!(built.header().payload_len, 29);

    let serialized = codec.serialize(&built).unwrap();
    let parsed = codec.parse(OpaqueBytes::from(serialized.clone())).unwrap();
    assert_eq!(codec.serialize(&parsed).unwrap(), serialized);
    assert_eq!(parsed.header(), built.header());
    let data = decode_reliability_data(OpaqueBytes::from(parsed.packet().payload_bytes().to_vec()))
        .unwrap();
    assert_eq!(data.block_id, BlockId::new(5));
    assert_eq!(data.rel_seq, SymbolId::new(9));
    assert_eq!(data.coded_vector.as_ref(), b"coded-payload");
    assert_eq!(parsed.control().unwrap().ctrl_type, ControlType::CcOpaque);
    assert_eq!(parsed.control().unwrap().ctrl_seq, None);
    assert_eq!(
        parsed.control().unwrap().body.as_ref(),
        b"\x01\x02opaque-controller-body"
    );
}

#[test]
fn standalone_control_serializer_round_trip_keeps_empty_payload() {
    let codec = ReferenceWireCodec::default();
    let control = ControlMessage::new(
        ControlType::Close,
        9,
        OpaqueBytes::from_static(b"close-body"),
    );
    let built = codec
        .build(header(QosClass::Control), OpaqueBytes::new(), Some(control))
        .unwrap();
    let serialized = codec.serialize(&built).unwrap();
    let parsed = codec.parse(OpaqueBytes::from(serialized)).unwrap();

    assert!(parsed.packet().payload_bytes().is_empty());
    assert_eq!(parsed.header().payload_len, 0);
    assert_eq!(parsed.header().link_seq, built.header().link_seq);
    assert_eq!(parsed.control().unwrap().ctrl_type, ControlType::Close);
}

#[test]
fn retried_open_keeps_ctrl_seq_while_link_seq_changes() {
    let codec = ReferenceWireCodec::default();
    let control = ControlMessage::new(
        ControlType::Open,
        0x0102_0304,
        OpaqueBytes::from_static(b"open"),
    );
    let mut first_header = header(QosClass::Control);
    first_header.link_seq = 40;
    let first = codec
        .build(first_header, OpaqueBytes::new(), Some(control.clone()))
        .unwrap();
    let mut retry_header = first_header;
    retry_header.link_seq = 41;
    let retry = codec
        .build(retry_header, OpaqueBytes::new(), Some(control))
        .unwrap();

    assert_eq!(
        first.control().unwrap().ctrl_seq,
        retry.control().unwrap().ctrl_seq
    );
    assert_eq!(first.header().link_seq, 40);
    assert_eq!(retry.header().link_seq, 41);
}

#[test]
fn m11_validate_before_freeze_never_exposes_invalid_handle_or_payload() {
    let codec = ReferenceWireCodec::default();
    let accounting = BackingAccounting::new();
    let copies = PayloadCopyCounter::new();
    let metrics = PacketMetrics {
        backings: accounting.clone(),
        payload_copies: copies.clone(),
    };
    let mut upward = Vec::new();

    for name in ["bad_version", "bad_qos_class"] {
        let result =
            codec.parse_with_metrics(OpaqueBytes::from(corpus_bytes(name)), metrics.clone());
        if let Ok(datagram) = result {
            upward.push(datagram.into_packet());
        }
    }

    assert!(upward.is_empty());
    assert_eq!(accounting.snapshot().live_count, 0);
    assert_eq!(accounting.snapshot().live_bytes, 0);
    assert_eq!(copies.count(), 0);

    let input = OpaqueBytes::from(corpus_bytes("good_coded_data"));
    let first_payload_byte = input.as_ptr().wrapping_add(12);
    let accepted = codec
        .parse_with_metrics(input, metrics)
        .expect("valid corpus datagram");
    assert_eq!(
        accepted.packet().payload_bytes().as_ptr(),
        first_payload_byte
    );
    assert_eq!(
        accepted.packet().charged_backing_bytes(),
        corpus_bytes("good_coded_data").len()
    );
    assert_eq!(accounting.snapshot().live_count, 1);
    assert_eq!(copies.count(), 0);
}

#[test]
fn deterministic_mutated_header_generator_never_panics_or_accepts_unknown_version() {
    let codec = ReferenceWireCodec::default();
    let good = corpus_bytes("good_coded_data");

    for offset in 0..REFERENCE_WIRE_HEADER_LEN {
        for delta in [0x01_u8, 0x20, 0x40, 0x80, 0xff] {
            let mut candidate = good.clone();
            candidate[offset] ^= delta;
            let _ = codec.parse(OpaqueBytes::from(candidate));
        }
    }
    for len in 0..good.len() {
        let _ = codec.parse(OpaqueBytes::from(good[..len].to_vec()));
    }

    for version in (0_u8..=u8::MAX).filter(|version| *version != 5) {
        let mut candidate = good.clone();
        candidate[2] = version;
        assert!(matches!(
            codec.parse(OpaqueBytes::from(candidate)),
            Err(WireError::UnsupportedVersion { value }) if value == version
        ));
    }
    for qos in 3_u8..=7 {
        let mut candidate = good.clone();
        candidate[3] = qos;
        assert!(matches!(
            codec.parse(OpaqueBytes::from(candidate)),
            Err(WireError::UnknownQosClass { value }) if value == qos
        ));
    }
}
