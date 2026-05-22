//! Application boundary guard for mesh-bus-ingress-socks5.
//!
//! This crate is an application participant (L7 ownership tag) that stitches L6 wire
//! codec (mb-proto-socks5) + L5 session control (Bus* surface) + opaque L4 transport
//! through the bus kernel. It must never name a kernel data-plane internal type.

use std::fs;
use std::path::PathBuf;

fn read_src_files() -> Vec<(PathBuf, String)> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    collect(&src, &mut out);
    assert!(!out.is_empty(), "expected at least one .rs file under src/");
    out
}

fn read_test_file(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn collect(dir: &std::path::Path, out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect(&p, out);
            continue;
        }
        if p.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&p) {
            out.push((p, text));
        }
    }
}

fn contains_token(haystack: &str, token: &str) -> bool {
    haystack
        .match_indices(token)
        .any(|(idx, _)| is_boundary(haystack, idx, token.len()))
}

fn is_boundary(s: &str, start: usize, len: usize) -> bool {
    let before = s.as_bytes().get(start.wrapping_sub(1)).copied();
    let after = s.as_bytes().get(start + len).copied();
    let ok_before = before.is_none_or(|b| !is_ident_byte(b));
    let ok_after = after.is_none_or(|b| !is_ident_byte(b));
    ok_before && ok_after
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[test]
fn adapter_never_names_kernel_internal_types() {
    // Kernel data-plane / scheduler internals.
    // BusPort is intentionally allowed: it is the application-facing entry point an
    // application adapter uses to open sessions through the kernel.
    let forbidden = [
        "FrameKind",
        "EgressPlugin",
        "SchedulerPlugin",
        "ScheduleDecision",
        "RankContext",
    ];

    let mut violations = Vec::new();
    for (path, text) in read_src_files() {
        for token in forbidden {
            if contains_token(&text, token) {
                violations.push(format!("{}: forbidden token `{token}`", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Application boundary violated; adapter source must not name kernel internals:\n{}",
        violations.join("\n")
    );
}

#[test]
fn adapter_never_names_bare_frame() {
    // `Frame` alone (not `FrameKind`, which is matched separately) is a bus-core data-plane type.
    for (path, text) in read_src_files() {
        let bytes = text.as_bytes();
        for (idx, _) in text.match_indices("Frame") {
            if !is_boundary(&text, idx, "Frame".len()) {
                continue;
            }
            let next = bytes.get(idx + "Frame".len()).copied();
            if matches!(next, Some(b) if is_ident_byte(b)) {
                continue;
            }
            panic!("{}: forbidden token `Frame` at byte {idx}", path.display());
        }
    }
}

#[test]
fn adapter_uses_canonical_bus_surface() {
    let any_src: String = read_src_files()
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("\n");
    for required in ["BusSessionRequest", "DisconnectReason"] {
        assert!(
            any_src.contains(required),
            "adapter should consume canonical session surface `{required}`"
        );
    }
}

#[test]
fn pipeline_runtime_fixture_uses_protocol_neutral_source_projection() {
    let text = read_test_file("pipeline_connect.rs");
    for forbidden in ["SourceId::new(\"socks5\")", "kind: \"socks5\".into()"] {
        assert!(
            !text.contains(forbidden),
            "PipelineRuntime fixture must use protocol-neutral SourceId/kind, found `{forbidden}`"
        );
    }
    assert!(
        text.contains("\"application/source\""),
        "PipelineRuntime fixture should model the generic application-source contract"
    );
}

#[test]
fn udp_associate_control_is_not_a_pipeline_event_builder_surface() {
    let event_builder = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("event_build.rs"),
    )
    .expect("read event_build.rs");

    assert!(
        !event_builder.contains("build_udp_associate_event"),
        "UDP ASSOCIATE control opens a relay before a target exists; PipelineRuntime events must be CONNECT or UDP relay-packet target decisions"
    );
}

#[test]
fn adapter_schema_is_closed_and_names_udp_pipeline_scope() {
    let schema: serde_json::Value = serde_json::from_str(include_str!("../schema.json"))
        .expect("schema.json should parse as JSON");

    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::Value::Bool(false)),
        "adapter schema root must reject unknown fields"
    );
    assert_eq!(
        schema["properties"]["pipeline_udp_decision_scope"]["const"], "per-relay-packet",
        "schema must document that PipelineRuntime UDP decisions run per relay packet"
    );
    assert!(
        schema["properties"]["pipeline_udp_decision_scope"]["description"]
            .as_str()
            .is_some_and(|s| s.contains("not the UDP ASSOCIATE control request")),
        "schema must explicitly exclude UDP ASSOCIATE control from PipelineRuntime forward decisions"
    );
}
