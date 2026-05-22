#[test]
fn adapter_schema_is_closed_and_names_datagram_boundary() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "adapter schema root must reject unknown fields"
    );
    assert!(
        schema.contains(r#""supports_datagram": { "type": "boolean", "const": true }"#),
        "UDP egress schema must stay datagram-capable"
    );
    assert!(
        schema.contains(r#""supports_stream": { "type": "boolean", "const": false }"#),
        "UDP egress schema must not claim stream capability"
    );
    assert!(
        schema.contains(r#""const": "one-send-one-datagram""#),
        "UDP egress schema must document one send_to call as one UDP datagram boundary"
    );
    assert!(
        schema.contains(r#""socket_recv_buffer_bytes""#)
            && schema.contains(r#""socket_send_buffer_bytes""#),
        "UDP egress schema must expose optional socket buffer knobs"
    );
}
