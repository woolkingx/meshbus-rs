use mesh_bus_schema::*;

#[test]
fn endpoint_roundtrips() {
    let json = r#"{"host":"example.com","port":443}"#;
    let ep: Endpoint = serde_json::from_str(json).expect("deserialize Endpoint");
    assert_eq!(*ep.host, "example.com");
    assert_eq!(ep.port.get(), 443);
    let back: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&ep).expect("serialize Endpoint"))
            .expect("re-deserialize Endpoint as Value");
    let orig: serde_json::Value =
        serde_json::from_str(json).expect("deserialize original json as Value");
    assert_eq!(back, orig);
}

#[test]
fn return_event_data_variant_roundtrips() {
    let json = r#"{"kind":"Data","payload":"aGVsbG8=","seq":1}"#;
    let ev: ReturnEvent = serde_json::from_str(json).expect("deserialize ReturnEvent");
    match &ev {
        ReturnEvent::Data { seq, payload } => {
            assert_eq!(*seq, 1);
            assert_eq!(payload, "aGVsbG8=");
        }
        _ => panic!("expected Data variant"),
    }
    let back: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&ev).expect("serialize ReturnEvent"))
            .expect("re-deserialize ReturnEvent as Value");
    let orig: serde_json::Value =
        serde_json::from_str(json).expect("deserialize original json as Value");
    assert_eq!(back, orig);
}

#[test]
fn return_event_connected_variant_roundtrips() {
    let json = r#"{
        "kind":"Connected",
        "exit_id":"wan20",
        "local_endpoint":{"host":"127.0.0.1","port":49152},
        "rtt_ms":7
    }"#;
    let ev: ReturnEvent = serde_json::from_str(json).expect("deserialize ReturnEvent");
    match &ev {
        ReturnEvent::Connected {
            exit_id,
            local_endpoint,
            rtt_ms,
        } => {
            assert_eq!(**exit_id, "wan20");
            assert_eq!(
                local_endpoint.as_ref().expect("local endpoint").port.get(),
                49152
            );
            assert_eq!(*rtt_ms, 7);
        }
        _ => panic!("expected Connected variant"),
    }
    let back: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&ev).expect("serialize ReturnEvent"))
            .expect("re-deserialize ReturnEvent as Value");
    assert_eq!(back["kind"], "Connected");
}

#[test]
fn frame_roundtrips_protocol_return_semantics() {
    let json = r#"{
        "packet_id": 1,
        "flow_id": "flow-1",
        "session_id": "session-1",
        "seq": 1,
        "kind": "Datagram",
        "payload": "aGVsbG8=",
        "target": {"host":"example.com","port":53},
        "ttl": 8,
        "traffic_class": "Interactive",
        "flow_semantics": "Datagram",
        "return_semantics": "PacketDedup"
    }"#;
    let frame: Frame = serde_json::from_str(json).expect("deserialize Frame");
    assert_eq!(frame.flow_semantics, FrameFlowSemantics::Datagram);
    assert_eq!(frame.return_semantics, FrameReturnSemantics::PacketDedup);
    let back: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&frame).expect("serialize Frame"))
            .expect("re-deserialize Frame as Value");
    assert_eq!(back["flow_semantics"], "Datagram");
    assert_eq!(back["return_semantics"], "PacketDedup");
}

#[test]
fn transform_descriptor_roundtrips() {
    let json = r#"{"kind":"Encrypt","policy_ref":"noise://wan20"}"#;
    let td: TransformDescriptor =
        serde_json::from_str(json).expect("deserialize TransformDescriptor");
    assert_eq!(td.kind, TransformKind::Encrypt);
    assert_eq!(td.policy_ref.as_deref(), Some("noise://wan20"));
    let back: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&td).expect("serialize TransformDescriptor"))
            .expect("re-deserialize TransformDescriptor as Value");
    let orig: serde_json::Value =
        serde_json::from_str(json).expect("deserialize original json as Value");
    assert_eq!(back, orig);
}

#[test]
fn fragment_metadata_roundtrips() {
    let json = r#"{
        "group_id":"g1",
        "fragment_id":"f1",
        "seq":0,
        "total":4,
        "offset":0,
        "checksum":"deadbeef"
    }"#;
    let fm: FragmentMetadata = serde_json::from_str(json).expect("deserialize FragmentMetadata");
    assert_eq!(&*fm.group_id, "g1");
    assert_eq!(fm.total.get(), 4);
    assert_eq!(fm.seq, 0);
}

#[test]
fn reassembly_policy_roundtrips() {
    let json = r#"{"mode":"Reorder"}"#;
    let rp: ReassemblyPolicy = serde_json::from_str(json).expect("deserialize ReassemblyPolicy");
    assert_eq!(rp.mode, ReassemblyMode::Reorder);
    assert!(rp.policy_ref.is_none());
}

#[test]
fn exit_snapshot_roundtrips() {
    let json = r#"{
        "exit_id": "wan20",
        "protocol": "socks5",
        "supports_stream": true,
        "supports_datagram": true,
        "send_count": 2,
        "success_count": 2,
        "failure_count": 0,
        "last_rtt_ms": 12,
        "payload_bytes_total": 1024
    }"#;
    let snapshot: ExitSnapshot = serde_json::from_str(json).expect("deserialize ExitSnapshot");
    assert_eq!(*snapshot.exit_id, "wan20");
    assert_eq!(snapshot.send_count, 2);
}
