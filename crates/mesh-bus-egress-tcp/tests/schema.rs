#[test]
fn adapter_schema_is_closed_and_names_stream_semantics() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "adapter schema root must reject unknown fields"
    );
    for required in [
        r#""const": "full-duplex-byte-stream""#,
        r#""const": "release-session""#,
        r#""const": "tcp-write-half-shutdown""#,
    ] {
        assert!(
            schema.contains(required),
            "adapter schema must preserve stream semantics marker {required}"
        );
    }
    assert!(
        schema.contains(r#""socket_recv_buffer_bytes""#)
            && schema.contains(r#""socket_send_buffer_bytes""#),
        "adapter schema must expose optional TCP socket buffer knobs"
    );
}

#[test]
fn tcp_egress_exposes_raw_stream_for_splice() {
    let src = std::fs::read_to_string("src/lib.rs").expect("read tcp egress source");

    assert!(
        src.contains("into_tcp_splice"),
        "TCP egress must expose connected raw streams to the direct forwarder splice path"
    );
    assert!(
        src.contains(".into_std()"),
        "TCP egress splice path must hand off the raw std::net::TcpStream fd"
    );
}
