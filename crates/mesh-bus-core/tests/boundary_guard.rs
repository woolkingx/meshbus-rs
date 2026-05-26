//! Domain boundary guards for the bus kernel + transport substrate (forwarding / session / transform).
//!
//! Physical layout: src/kernel/ + src/transport/{forwarding,session,transform}/.
//! Ownership tags (L4 forwarding / L5 session / L6 transform) are CLAUDE.md contracts,
//! not directory names. These tests pin the contract surface and the directory layout
//! so future refactors cannot accidentally re-expose internal data-plane types or
//! smuggle application-layer / algorithm responsibilities into core.

use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_src(rel: &str) -> String {
    let p = manifest_dir().join("src").join(rel);
    fs::read_to_string(&p).unwrap_or_else(|_| panic!("read {}", p.display()))
}

fn workspace_root() -> PathBuf {
    manifest_dir()
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn domain_directories_exist() {
    // kernel/ stays at top level; transport substrate domains live under transport/.
    let kernel = manifest_dir().join("src").join("kernel");
    assert!(kernel.is_dir(), "missing kernel directory: src/kernel");

    let transport = manifest_dir().join("src").join("transport");
    assert!(
        transport.is_dir(),
        "missing transport directory: src/transport"
    );
    let mod_rs = transport.join("mod.rs");
    assert!(mod_rs.is_file(), "missing src/transport/mod.rs");

    for dir in ["forwarding", "session", "transform"] {
        let p = transport.join(dir);
        assert!(
            p.is_dir(),
            "missing transport domain directory: src/transport/{dir}"
        );
        for required in [
            "mod.rs",
            "types.rs",
            "data_handle.rs",
            "tests.rs",
            "CLAUDE.md",
        ] {
            let f = p.join(required);
            assert!(f.is_file(), "missing transport/{}/{}", dir, required);
        }
    }
}

#[test]
fn kernel_public_surface_reachable() {
    use mesh_bus_core::{Bus, BusBuilder, BusError, BusEvent, BusHandle, BusPort, Registry};
    let _: Option<BusBuilder> = None;
    fn _accept_bus(_: &Bus) {}
    fn _accept_handle(_: &BusHandle) {}
    fn _accept_port(_: &BusPort) {}
    let _: Option<Registry> = None;
    let _: Option<BusEvent> = None;
    let _: Option<BusError> = None;
}

#[test]
fn session_public_surface_reachable() {
    use mb_endpoint::Endpoint;
    use mesh_bus_core::{
        BusPathInfo, BusSessionInfo, BusSessionRequest, DisconnectReason, ScheduleMode, SendError,
    };
    let _req = BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("endpoint"));
    let _info = BusSessionInfo::empty_for_test(ScheduleMode::Ordered);
    let _: Option<BusPathInfo> = None;
    let _: Option<DisconnectReason> = None;
    let _: Option<SendError> = None;
}

#[test]
fn forwarding_public_surface_reachable() {
    use mesh_bus_core::{
        Capabilities, FlowSemantics, Measurement, RankContext, ReturnSemantics, ScheduleDecision,
        ScheduleHint, TrafficClass,
    };
    let _ = FlowSemantics::ByteStream;
    let _ = ReturnSemantics::Direct;
    let _ = TrafficClass::Bulk;
    let _ = ScheduleHint::Auto;
    let _ = ScheduleDecision::ordered(vec![0]);
    let _: Option<Capabilities> = None;
    let _: Option<Measurement> = None;
    let _: Option<RankContext> = None;
}

#[test]
fn transform_public_surface_reachable() {
    use mesh_bus_core::transport::transform::{
        FragmentMetadata, ReassemblyMode, ReassemblyPolicy, TransformDescriptor, TransformError,
        TransformKind, validate_fragment,
    };

    let descriptor = TransformDescriptor {
        kind: TransformKind::Fragment,
        policy_ref: None,
    };
    assert_eq!(descriptor.kind, TransformKind::Fragment);

    let meta = FragmentMetadata {
        group_id: "g".into(),
        fragment_id: "f".into(),
        seq: 0,
        total: 1,
        offset: 0,
        deadline_ms: None,
        checksum: String::new(),
    };
    assert!(validate_fragment(&meta).is_ok());

    let _ = ReassemblyPolicy {
        mode: ReassemblyMode::Dedup,
        policy_ref: None,
    };
    let _: Option<TransformError> = None;
}

#[test]
fn transform_domain_does_not_execute_algorithms() {
    let handle = read_src("transport/transform/data_handle.rs");
    let body = handle.to_lowercase();

    let forbidden_algo_tokens = [
        "compress",
        "decompress",
        "encrypt",
        "decrypt",
        "aead",
        "chacha",
        "aes",
        "sha2",
        "blake3",
        "md5",
        "crc32",
        "deflate",
        "gzip",
        "zstd",
        "reed_solomon",
    ];

    for token in forbidden_algo_tokens {
        assert!(
            !body.contains(token),
            "transport/transform/data_handle.rs must validate metadata only; token {token:?} suggests algorithm execution"
        );
    }
}

#[test]
fn old_top_level_shims_are_retired() {
    let src = manifest_dir().join("src");
    let retired = [
        "builder.rs",
        "error.rs",
        "event.rs",
        "port.rs",
        "registry.rs",
        "runtime.rs",
        "session_handle.rs",
        "l4_session.rs",
        "l4_runtime.rs",
    ];
    for name in retired {
        let p = src.join(name);
        assert!(
            !p.exists(),
            "retired top-level shim still present at src/{name}; module should live under its domain directory"
        );
    }
}

#[test]
fn lib_re_exports_through_domain_modules_only() {
    let lib = read_src("lib.rs");

    // Direct sub-module declarations must reference domain dirs, not retired flat files.
    for forbidden in [
        "pub mod builder;",
        "pub mod error;",
        "pub mod event;",
        "pub mod port;",
        "pub mod registry;",
        "pub mod runtime;",
        "pub mod session_handle;",
        "pub mod l4_session;",
        "pub mod l4_runtime;",
    ] {
        assert!(
            !lib.contains(forbidden),
            "lib.rs must not re-declare retired flat module: {forbidden}"
        );
    }

    for required in ["mod kernel", "mod transport"] {
        assert!(
            lib.contains(required),
            "lib.rs must declare top-level module {required}"
        );
    }
    for forbidden_flat in [
        "pub mod forwarding;",
        "pub mod session;",
        "pub mod transform;",
    ] {
        assert!(
            !lib.contains(forbidden_flat),
            "lib.rs must not declare {forbidden_flat} at top level; substrate domains live under transport/"
        );
    }
}

#[test]
fn non_test_source_files_stay_under_loc_cap() {
    let max_lines = 500usize;
    let src = manifest_dir().join("src");
    let mut violations: Vec<String> = Vec::new();
    walk_rs(&src, &mut |path, n| {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.ends_with("_tests.rs") || name == "tests.rs" {
            return;
        }
        if n > max_lines {
            violations.push(format!(
                "{}: {n} lines exceeds {max_lines}",
                path.strip_prefix(manifest_dir()).unwrap_or(path).display()
            ));
        }
    });
    assert!(
        violations.is_empty(),
        "non-test files exceed {max_lines}-LOC cap:\n{}",
        violations.join("\n")
    );
}

fn walk_rs(dir: &Path, visit: &mut dyn FnMut(&Path, usize)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk_rs(&p, visit);
            continue;
        }
        if p.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        visit(&p, text.lines().count());
    }
}

fn walk_workspace_rs(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if p.is_dir() {
            if matches!(
                name,
                "target" | ".git" | ".bare" | ".cleanup" | ".backup" | "release"
            ) {
                continue;
            }
            walk_workspace_rs(&p, visit);
            continue;
        }
        if p.extension().is_some_and(|e| e == "rs") {
            visit(&p);
        }
    }
}

#[test]
fn udp_loop_has_no_restore_inbound_front_escape_hatch() {
    let root = workspace_root();
    let mut hits = Vec::new();
    walk_workspace_rs(&root, &mut |path| {
        let text = fs::read_to_string(path).unwrap_or_default();
        if path.ends_with("tests/boundary_guard.rs") {
            return;
        }
        if text.contains("restore_inbound_front") {
            hits.push(
                path.strip_prefix(&root)
                    .unwrap_or(path)
                    .display()
                    .to_string(),
            );
        }
    });
    assert!(
        hits.is_empty(),
        "L4 must not expose payload-aware inbound restore escape hatch:\n{}",
        hits.join("\n")
    );
}

#[test]
fn udp_loop_drain_inbound_callers_are_allowlisted_packet_owners() {
    let root = workspace_root();
    let mut violations = Vec::new();
    walk_workspace_rs(&root, &mut |path| {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(path).unwrap_or_default();
        if rel == "crates/mesh-bus-core/tests/boundary_guard.rs" {
            return;
        }
        if !text.contains("drain_inbound(") {
            return;
        }
        let allowed = rel == "crates/mesh-bus-core/src/transport/udp_loop/mod.rs"
            || rel == "crates/mesh-bus-core/src/transport/udp_loop/queue.rs"
            || rel == "crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"
            || rel == "crates/mesh-bus-ingress-mesh-peer-udp/src/lib.rs"
            || rel.starts_with("crates/mesh-bus-core/tests/udp_loop")
            || rel == "crates/mesh-bus-bin/tests/throughput_transport.rs";
        if !allowed {
            violations.push(rel);
        }
    });
    assert!(
        violations.is_empty(),
        "drain_inbound callers must stay behind packet-loop owners/tests:\n{}",
        violations.join("\n")
    );
}

#[test]
fn flow_id_is_opaque_no_l7_naming_atom() {
    use mesh_bus_core::{FlowId, SessionId};
    let target = mb_endpoint::Endpoint::new("secret-host.example", 8443).unwrap();
    let sid = SessionId("sess-xyz".into());
    let fid = FlowId::mint_for(&sid, &target);
    let s = fid.0.as_str();
    // L4 identity must not embed the L7 host naming atom in cleartext.
    assert!(
        !s.contains("secret-host.example"),
        "FlowId leaks L7 host: {s}"
    );
    // Determinism: every frame of one logical flow collides to one id (affinity invariant).
    assert_eq!(fid, FlowId::mint_for(&sid, &target));
    // Distinct target ⇒ distinct flow.
    let other = mb_endpoint::Endpoint::new("secret-host.example", 9000).unwrap();
    assert_ne!(fid, FlowId::mint_for(&sid, &other));
}

#[test]
fn ontology_source_write_allowlist_is_stable() {
    // Pins M1↔M2: the data-ontology metadata_namespace_ownership allowlist must not
    // drift apart from the config/pipeline source.initial_writes reservation.
    // serde_json is not a dev-dependency of mesh-bus-core; assert on the raw text.
    let path = manifest_dir().join("../../docs/handbook/spec/data-ontology.schema.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display()));

    let owner_start = raw
        .find("\"metadata_namespace_ownership\"")
        .expect("metadata_namespace_ownership block missing");
    let owner = &raw[owner_start..];

    let line_for = |ns: &str| -> &str {
        let key = format!("\"{ns}\":");
        let at = owner
            .find(&key)
            .unwrap_or_else(|| panic!("namespace {ns} missing from ownership map"));
        let rest = &owner[at..];
        let end = rest.find('\n').unwrap_or(rest.len());
        &rest[..end]
    };

    for ns in ["policy", "transport"] {
        let l = line_for(ns);
        assert!(
            l.contains("\"source_initial_writes_allowed\": false"),
            "{ns} must stay reserved (source_initial_writes_allowed:false): {l}"
        );
    }
    for ns in ["net", "auth", "trace", "ext"] {
        let l = line_for(ns);
        assert!(
            l.contains("\"source_initial_writes_allowed\": true"),
            "{ns} must stay entry-writable (source_initial_writes_allowed:true): {l}"
        );
    }
}
