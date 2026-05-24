use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    AckNack, BindingKind, CloseReasonWire, CodecError, DataPackage, DatagramOpen, DeliveryMode,
    EventPci, EventSemantic, FlowSemanticsWire, Hello, LinkSample, MeshEvent, MeshFrame,
    OrderingClass, ReceiverMouth, ReliabilityClass, ReturnSemanticsWire, SeqRange, StreamOpen,
    StreamOpenRejectReason, decode_event, decode_frame, decode_mesh_frame_clear, encode_event,
    encode_frame, frame_event_meta, reconstruct_missing, xor_parity,
};

fn endpoint(host: &str, port: u16) -> Endpoint {
    Endpoint::new(host.to_string(), port).unwrap()
}

#[test]
fn hello_roundtrip_uses_versioned_envelope() {
    let frame = MeshFrame::Hello(Hello {
        node_id: "node-a".into(),
        binding: BindingKind::RawUdp,
        nonce: 42,
        spki_pin_sha256: None,
    });

    let encoded = encode_frame(&frame).unwrap();
    assert_eq!(&encoded[..2], &[0x4d, 0x42]);
    assert_eq!(encoded[2], mb_proto_mesh::PROTOCOL_VERSION);

    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn decode_rejects_bad_magic_and_unsupported_version() {
    let encoded = encode_frame(&MeshFrame::Hello(Hello {
        node_id: "node-a".into(),
        binding: BindingKind::RawUdp,
        nonce: 7,
        spki_pin_sha256: None,
    }))
    .unwrap();

    let mut bad_magic = encoded.clone();
    bad_magic[0] = 0;
    assert_eq!(
        decode_frame(&mut BytesMut::from(&bad_magic[..])).unwrap_err(),
        CodecError::BadMagic(0x0042)
    );

    let mut bad_version = encoded;
    bad_version[2] = mb_proto_mesh::PROTOCOL_VERSION + 1;
    assert_eq!(
        decode_frame(&mut BytesMut::from(&bad_version[..])).unwrap_err(),
        CodecError::UnsupportedVersion(mb_proto_mesh::PROTOCOL_VERSION + 1)
    );
}

#[test]
fn stream_open_round_trips_reentry_fields() {
    let frame = MeshFrame::StreamOpen(StreamOpen {
        session_id: "s-99".into(),
        open_token: 99,
        target: endpoint("example.com", 443),
        route_group: Some("wan-us".into()),
        flow_semantics: FlowSemanticsWire::ByteStream,
        return_semantics: ReturnSemanticsWire::Direct,
        source_node_id: "node-a".into(),
        path_trace: vec!["node-a".into(), "node-b".into()],
    });

    let encoded = encode_frame(&frame).unwrap();
    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn stream_data_round_trips_opaque_payload() {
    let data = MeshFrame::StreamData {
        session_id: "s-99".into(),
        seq: 1,
        payload: Bytes::from_static(b"hello"),
    };

    let encoded = encode_frame(&data).unwrap();
    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn stream_shutdown_and_close_round_trip() {
    let shutdown = MeshFrame::StreamShutdownWrite {
        session_id: "s-99".into(),
    };
    let close = MeshFrame::StreamClose {
        session_id: "s-99".into(),
        close_reason: CloseReasonWire::Normal,
    };

    for frame in [shutdown, close] {
        let encoded = encode_frame(&frame).unwrap();
        let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
        assert_eq!(decoded, frame);
    }
}

#[test]
fn datagram_return_round_trips_source_endpoint() {
    let frame = MeshFrame::DatagramReturn {
        session_id: "s-12".into(),
        seq: 77,
        source: endpoint("8.8.8.8", 53),
        payload: Bytes::from_static(b"dns-reply"),
    };

    let encoded = encode_frame(&frame).unwrap();
    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn datagram_send_roundtrip_preserves_target_endpoint() {
    let frame = MeshFrame::DatagramSend {
        session_id: "s-12".into(),
        seq: 76,
        target: endpoint("1.1.1.1", 53),
        payload: Bytes::from_static(b"dns-query"),
    };

    let encoded = encode_frame(&frame).unwrap();
    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn datagram_open_and_close_roundtrip_fixed_target_contract() {
    let open = MeshFrame::DatagramOpen(DatagramOpen {
        session_id: "s-44".into(),
        fixed_target: Some(endpoint("9.9.9.9", 53)),
        max_datagram_bytes: 1200,
    });
    let close = MeshFrame::DatagramClose {
        session_id: "s-44".into(),
        close_reason: CloseReasonWire::Normal,
    };

    let open_encoded = encode_frame(&open).unwrap();
    let close_encoded = encode_frame(&close).unwrap();

    assert_eq!(
        decode_frame(&mut BytesMut::from(&open_encoded[..])).unwrap(),
        open
    );
    assert_eq!(
        decode_frame(&mut BytesMut::from(&close_encoded[..])).unwrap(),
        close
    );
}

#[test]
fn stream_open_reject_roundtrip_names_reliable_stream_unsupported() {
    let accepted = MeshFrame::StreamOpenAccepted {
        session_id: "s-55".into(),
        open_token: 55,
    };
    let encoded = encode_frame(&accepted).unwrap();
    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, accepted);

    let frame = MeshFrame::StreamOpenReject {
        session_id: "s-55".into(),
        open_token: 55,
        reason: StreamOpenRejectReason::ReliableStreamUnsupported,
        close_reason: CloseReasonWire::Unsupported,
    };

    let encoded = encode_frame(&frame).unwrap();
    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, frame);
}

fn ordered_stream_event(seq: u64, payload: &'static [u8]) -> MeshEvent {
    MeshEvent {
        event_id: format!("evt-{seq}"),
        family_id: "fam-7".into(),
        semantic: EventSemantic::Stream,
        reliability: ReliabilityClass::Reliable,
        ordering: OrderingClass::OrderedWithinFamily,
        delivery_policy_id: "dp-steer-default".into(),
        path_epoch: 3,
        ttl: 16,
        pci: EventPci {
            checksum: Some("crc32:9af1".into()),
            compression: Some("none".into()),
        },
        package: Some(DataPackage {
            package_id: format!("pkg-fam7-{seq:06}"),
            seq,
            offset: seq * 1452,
            len: payload.len() as u32,
            fragment_id: 0,
            fragment_count: 1,
            payload: Bytes::from_static(payload),
        }),
    }
}

#[test]
fn mesh_event_roundtrip_uses_event_header_and_preserves_package() {
    let event = ordered_stream_event(7, b"hello-mesh-stream-sdu");

    let encoded = encode_event(&event).unwrap();
    assert_eq!(&encoded[..2], &[0x4d, 0x42]);
    assert_eq!(encoded[2], mb_proto_mesh::PROTOCOL_VERSION);
    assert_eq!(encoded[3], mb_proto_mesh::EVENT_MSG_TYPE);

    let decoded = decode_event(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, event);
}

#[test]
fn decode_event_rejects_legacy_frame_msg_type() {
    let frame = MeshFrame::Hello(Hello {
        node_id: "node-a".into(),
        binding: BindingKind::RawUdp,
        nonce: 1,
        spki_pin_sha256: None,
    });
    let encoded = encode_frame(&frame).unwrap();

    match decode_event(&mut BytesMut::from(&encoded[..])) {
        Err(CodecError::Decode(msg)) => assert!(msg.contains("not a mesh event")),
        other => panic!("expected decode rejection, got {other:?}"),
    }
}

#[test]
fn legacy_frame_roundtrip_unchanged_alongside_event_codec() {
    let frame = MeshFrame::StreamData {
        session_id: "s-99".into(),
        seq: 1,
        payload: Bytes::from_static(b"legacy-still-works"),
    };

    let _event = encode_event(&ordered_stream_event(1, b"x")).unwrap();

    let encoded = encode_frame(&frame).unwrap();
    let decoded = decode_frame(&mut BytesMut::from(&encoded[..])).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn decode_mesh_frame_clear_reverses_sealed_inner_bincode() {
    let frame = MeshFrame::StreamData {
        session_id: "s-clear".into(),
        seq: 7,
        payload: Bytes::from_static(b"sealed-inner-is-raw-bincode"),
    };

    // `seal_mesh_frame` seals exactly `bincode::serialize(frame)` (no
    // `encode_frame` envelope), so the post-`open_bytes` clear bytes decode
    // through `decode_mesh_frame_clear`, not `decode_frame`.
    let clear = bincode::serialize(&frame).unwrap();
    assert_eq!(decode_mesh_frame_clear(&clear).unwrap(), frame);

    // The MAGIC-framed wire is a different encoding; feeding it to the clear
    // decoder must not silently produce the same frame.
    let framed = encode_frame(&frame).unwrap();
    assert!(decode_mesh_frame_clear(&framed).map(|d| d == frame) != Ok(true));
}

#[test]
fn delivery_mode_all_variants_roundtrip_through_codec_serde() {
    for mode in [
        DeliveryMode::Steer,
        DeliveryMode::Stripe,
        DeliveryMode::Replicate,
        DeliveryMode::Repair,
        DeliveryMode::Probe,
    ] {
        let bytes = bincode::serialize(&mode).unwrap();
        let back: DeliveryMode = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, mode);
    }
}

#[test]
fn two_packages_same_family_preserve_payload_bytes() {
    let seq7 = ordered_stream_event(7, b"package-seven-payload");
    let seq8 = ordered_stream_event(8, b"package-eight-payload");

    let d7 = decode_event(&mut BytesMut::from(&encode_event(&seq7).unwrap()[..])).unwrap();
    let d8 = decode_event(&mut BytesMut::from(&encode_event(&seq8).unwrap()[..])).unwrap();

    assert_eq!(d7.family_id, d8.family_id);
    let p7 = d7.package.unwrap();
    let p8 = d8.package.unwrap();
    assert_eq!(p7.seq, 7);
    assert_eq!(p8.seq, 8);
    assert_eq!(p7.payload, Bytes::from_static(b"package-seven-payload"));
    assert_eq!(p8.payload, Bytes::from_static(b"package-eight-payload"));
}

#[test]
fn port_open_and_port_close_roundtrip_as_control() {
    let open = MeshFrame::PortOpen(ReceiverMouth {
        mouth_id: "mouth-1".into(),
        udp_addr: "127.0.0.1:7001".into(),
        family_filter: vec!["datagram".into(), "stream".into()],
        advertised_capacity: 4096,
        epoch: 3,
    });
    let close = MeshFrame::PortClose {
        mouth_id: "mouth-1".into(),
        epoch: 3,
    };

    let open_dec = decode_frame(&mut BytesMut::from(&encode_frame(&open).unwrap()[..])).unwrap();
    let close_dec = decode_frame(&mut BytesMut::from(&encode_frame(&close).unwrap()[..])).unwrap();
    assert_eq!(open_dec, open);
    assert_eq!(close_dec, close);

    let (open_family, open_seq, open_sem) = frame_event_meta(&open);
    assert_eq!(open_family, "mouth-1");
    assert_eq!(open_seq, 0);
    assert_eq!(open_sem, EventSemantic::Control);

    let (close_family, close_seq, close_sem) = frame_event_meta(&close);
    assert_eq!(close_family, "mouth-1");
    assert_eq!(close_seq, 0);
    assert_eq!(close_sem, EventSemantic::Control);
}

#[test]
fn link_sample_roundtrip_as_observation() {
    let sample = MeshFrame::LinkSample(LinkSample {
        source_node_id: "node-a".into(),
        mouth_id: "mouth-7".into(),
        epoch: 4,
        seq: 11,
        observed_at_ms: 1_700_000_000_123,
        rtt_us: 2_500,
        loss_permille: 12,
        goodput_bps: 9_500_000,
        queue_delay_us: 180,
        close_count: 1,
        saturated: false,
    });

    let decoded = decode_frame(&mut BytesMut::from(&encode_frame(&sample).unwrap()[..])).unwrap();
    assert_eq!(
        decoded, sample,
        "LinkSample survives the wire byte-for-byte"
    );

    // It is observation evidence: keyed by mouth, carries its own seq, and
    // rides the Observation bypass-reorder native path, never route truth.
    let (family, seq, sem) = frame_event_meta(&sample);
    assert_eq!(family, "mouth-7");
    assert_eq!(seq, 11);
    assert_eq!(sem, EventSemantic::Observation);
}

#[test]
fn ack_nack_roundtrips_as_family_keyed_control() {
    let frame = MeshFrame::AckNack(AckNack {
        family_id: "fam-9".into(),
        cumulative_seq: 4,
        received_bitmap: "0".repeat(32),
        missing_ranges: vec![SeqRange { start: 5, end: 6 }],
    });

    let decoded = decode_frame(&mut BytesMut::from(&encode_frame(&frame).unwrap()[..])).unwrap();
    assert_eq!(decoded, frame, "AckNack survives the wire byte-for-byte");

    // L5 feedback channel: family-keyed Control, never route/session truth.
    let (family, seq, sem) = frame_event_meta(&frame);
    assert_eq!(family, "fam-9");
    assert_eq!(seq, 0);
    assert_eq!(sem, EventSemantic::Control);
}

#[test]
fn delivery_mode_policy_id_round_trips_and_unknown_falls_back_to_steer() {
    for mode in [
        DeliveryMode::Steer,
        DeliveryMode::Stripe,
        DeliveryMode::Replicate,
        DeliveryMode::Repair,
        DeliveryMode::Probe,
    ] {
        assert_eq!(DeliveryMode::from_policy_id(mode.policy_id()), mode);
    }
    assert_eq!(DeliveryMode::policy_id(DeliveryMode::Steer), "steer");
    assert_eq!(
        DeliveryMode::from_policy_id("not-a-real-policy"),
        DeliveryMode::Steer,
        "unknown policy id is never route truth; it degrades to Steer"
    );
}

#[test]
fn one_xor_parity_reconstructs_exactly_one_lost_chunk_per_generation() {
    let a: &[u8] = b"alpha-fragment-0";
    let b: &[u8] = b"bravo-fragment-1xx"; // longer; parity zero-pads to widest
    let c: &[u8] = b"charlie-frag-2";
    let parity = xor_parity(&[a, b, c]);

    // Lose the middle chunk: surviving + parity must rebuild it.
    let rebuilt = reconstruct_missing(&[Some(a), None, Some(c)], &parity)
        .expect("exactly one missing chunk reconstructs");
    assert_eq!(
        &rebuilt[..b.len()],
        b,
        "lost chunk recovered via XOR parity"
    );

    // Zero missing -> nothing to repair; two missing -> unrecoverable.
    assert!(reconstruct_missing(&[Some(a), Some(b), Some(c)], &parity).is_none());
    assert!(reconstruct_missing(&[Some(a), None, None], &parity).is_none());
}
