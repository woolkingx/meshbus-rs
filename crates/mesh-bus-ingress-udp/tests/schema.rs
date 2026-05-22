#[test]
fn adapter_schema_is_closed_and_names_datagram_boundary() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "adapter schema root must reject unknown fields"
    );
    assert!(
        schema.contains(r#""flow_semantics": { "const": "Datagram" }"#),
        "UDP ingress schema must declare Datagram flow semantics"
    );
    assert!(
        schema.contains(r#""return_semantics": { "const": "PacketDedup" }"#),
        "UDP ingress schema must declare PacketDedup return semantics"
    );
    assert!(
        schema.contains(r#""const": "one-recv-one-send""#),
        "UDP ingress schema must document one socket recv_from as one DatagramSession::send_to boundary"
    );
    assert!(
        schema.contains(r#""socket_recv_buffer_bytes""#)
            && schema.contains(r#""socket_send_buffer_bytes""#),
        "UDP ingress schema must expose optional socket buffer knobs"
    );
}
