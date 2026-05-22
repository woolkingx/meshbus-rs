//! Application boundary guard for mesh-bus-egress-socks5.
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
    // The egress side is a StreamEgress/DatagramEgress factory, so BusPort
    // is not expected here either way.
    let forbidden = [
        "FrameKind",
        "EgressPlugin",
        "SchedulerPlugin",
        "BusPort",
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
    for required in ["BusSessionRequest", "BusSessionInfo", "StreamEgress"] {
        assert!(
            any_src.contains(required),
            "adapter should consume canonical session surface `{required}`"
        );
    }
}

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
}
