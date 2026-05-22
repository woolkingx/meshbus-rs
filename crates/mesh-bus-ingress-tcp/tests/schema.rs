#[test]
fn adapter_schema_is_closed_and_names_stream_session_eof_semantics() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "adapter schema root must reject unknown fields"
    );
    assert!(
        !schema.contains("FrameKind") && !schema.contains("emit-close-frame"),
        "adapter schema must not expose retired raw Frame semantics"
    );
    assert!(
        schema.contains(r#""const": "stream-send-half-shutdown-write""#),
        "adapter schema must name the StreamSendHalf shutdown_write EOF behavior"
    );
    assert!(
        schema.contains(r#""socket_recv_buffer_bytes""#)
            && schema.contains(r#""socket_send_buffer_bytes""#),
        "adapter schema must expose optional TCP socket buffer knobs"
    );
}
