//! Kernel invariant: mesh-bus-core is bus runtime + transport substrate (forwarding /
//! session / transform metadata) only. Application-layer (L7) protocol concepts must
//! not appear in the manifest or in src/. Ownership tags L4/L5/L6 live in CLAUDE.md;
//! this test enforces that no L7 protocol identifier leaks into the kernel crate.
//!
//! Two layers of enforcement:
//! 1. Manifest grep — block protocol crates from `Cargo.toml`.
//! 2. Source/schema grep — block protocol identifiers from `src/`.

use std::fs;
use std::path::{Path, PathBuf};

const CORE_MANIFEST: &str = include_str!("../Cargo.toml");
const CORE_CLAUDE: &str = include_str!("../CLAUDE.md");
const CORE_TYPES: &str = include_str!("../src/kernel/types.rs");
const CORE_MOD: &str = include_str!("../src/kernel/mod.rs");
const EVENT_SCHEMA: &str = include_str!("../src/kernel/event/schema.json");
const METADATA_SCHEMA: &str = include_str!("../src/kernel/metadata/schema.json");
const PIPELINE_SCHEMA: &str = include_str!("../src/kernel/pipeline/schema.json");
const REGISTRY_SCHEMA: &str = include_str!("../src/kernel/registry/schema.json");
const VERDICT_SCHEMA: &str = include_str!("../src/kernel/verdict/schema.json");

#[test]
fn core_manifest_has_no_l7_or_protocol_dependencies() {
    let forbidden = [
        "mb-proto-socks5",
        "mesh-bus-ingress-socks5",
        "mesh-bus-egress-socks5",
        "hyper",
        "http",
        "h2",
        "rustls",
        "tokio-rustls",
        "native-tls",
        "quinn",
    ];

    for name in forbidden {
        assert!(
            !CORE_MANIFEST.contains(name),
            "mesh-bus-core must stay kernel + transport substrate; move protocol dependency {name:?} to an application adapter crate"
        );
    }
}

#[test]
fn core_source_has_no_l7_protocol_tokens() {
    // Tokens that imply L7 protocol parsing or recognition.
    // Case-insensitive substring match per source/schema line. Rust comments
    // are source too; only JSON Schema URI boilerplate is exempted.
    let forbidden = [
        "socks5",
        "socks4",
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
        "hysteria",
        "wireguard",
        "openvpn",
        "dns",
        "qname",
        "socks5_command",
        "http",
        "h2c",
        "http1",
        "http2",
        "http3",
        " sni ",
        "tls_handshake",
        "rustls",
        "quinn",
        "hyper::",
    ];

    let src = manifest_dir().join("src");
    let mut violations: Vec<String> = Vec::new();
    walk_contract_files(&src, &mut |path, line_no, line| {
        if is_allowed(path, line) {
            return;
        }
        let lower = line.to_lowercase();
        for token in forbidden {
            if lower.contains(token) {
                violations.push(format!(
                    "{}:{} contains forbidden L7 token {:?}: {}",
                    path.strip_prefix(manifest_dir()).unwrap_or(path).display(),
                    line_no,
                    token,
                    line.trim()
                ));
            }
        }
    });

    assert!(
        violations.is_empty(),
        "mesh-bus-core source must stay kernel + transport substrate only; move protocol-aware code into application adapter / proto-codec crates:\n{}",
        violations.join("\n")
    );
}

#[test]
fn l7_guard_does_not_exempt_rust_comments() {
    let source_path = manifest_dir().join("src").join("lib.rs");

    assert!(
        !is_allowed(&source_path, "//! socks5 belongs in an adapter"),
        "Rust source comments are part of the core contract and must not hide protocol tokens"
    );
}

#[test]
fn core_claude_keeps_l7_wire_syntax_out_of_l6_transform_boundary() {
    assert!(
        !CORE_CLAUDE.contains("generic L7 wire format") && !CORE_CLAUDE.contains("from L6 parse"),
        "mesh-bus-core CLAUDE must keep external protocol wire syntax in adapter/proto-codec ownership, not core L6 transform wording"
    );
}

#[test]
fn bus_event_no_longer_exposes_dispatch_result_or_failure() {
    assert!(
        !CORE_TYPES.contains("DispatchResult") && !CORE_TYPES.contains("DispatchFailure"),
        "legacy per-dispatch BusEvent variants must be retired; use CoreEventId over ObservationBus"
    );
}

#[test]
fn scheduler_feedback_observer_is_not_core_module() {
    assert!(
        !CORE_MOD.contains("scheduler_feedback_observer"),
        "scheduler feedback observation must live in scheduler plugin crates, not mesh-bus-core"
    );
    assert!(
        !manifest_dir()
            .join("src/kernel/scheduler_feedback_observer.rs")
            .exists(),
        "scheduler_feedback_observer.rs must be retired from core"
    );
}

#[test]
fn registry_schema_closes_spec_objects_and_requires_rust_fields() {
    assert!(
        REGISTRY_SCHEMA.contains(r##""$ref": "#/$defs/KernelRegistry""##),
        "registry schema root must validate a KernelRegistry object"
    );

    for required in [
        r#""required": ["sources", "sinks", "hooks", "pipelines", "wirings", "fns"]"#,
        r#""required": ["id", "kind", "allowed_namespaces", "reads", "writes", "may_terminate", "may_jump", "may_jump_to", "may_accept_to", "side_effect_only"]"#,
        r#""required": ["id", "kind", "initial_writes"]"#,
        r#""required": ["id", "kind"]"#,
    ] {
        assert!(
            REGISTRY_SCHEMA.contains(required),
            "registry schema must require every non-optional Rust field: {required}"
        );
    }

    for def_name in [
        "KernelRegistry",
        "HookSpec",
        "SourceSpec",
        "SinkSpec",
        "Pipeline",
        "Wiring",
    ] {
        let block = schema_def_block(def_name);
        assert!(
            block.contains(r#""additionalProperties": false"#),
            "registry schema {def_name} must reject unknown fields"
        );
    }

    let source_spec = schema_def_block("SourceSpec");
    assert!(
        source_spec.contains(r#""const": "application/source""#),
        "registry schema SourceSpec.kind must stay generic application/source"
    );
    assert!(
        source_spec.contains("protocol-neutral") && source_spec.contains("future adapters"),
        "registry schema SourceSpec.kind must document protocol-neutral adapter semantics"
    );
    let sink_spec = schema_def_block("SinkSpec");
    assert!(
        sink_spec.contains(r#""enum": ["stream_egress", "datagram_egress"]"#),
        "registry schema SinkSpec.kind must be capability-shaped"
    );
    assert!(
        sink_spec.contains("capability-shaped") && sink_spec.contains("future adapters"),
        "registry schema SinkSpec.kind must document capability-shaped adapter semantics"
    );

    let registry = schema_def_block("KernelRegistry");
    for (field, id_def) in [
        ("sources", "SourceId"),
        ("sinks", "SinkId"),
        ("hooks", "HookId"),
        ("pipelines", "PipelineId"),
        ("fns", "HookId"),
    ] {
        let expected = format!(
            r##""{field}": {{ "type": "object", "propertyNames": {{ "$ref": "#/$defs/{id_def}" }}"##
        );
        assert!(
            registry.contains(&expected),
            "registry schema map `{field}` must constrain property names with {id_def}"
        );
    }

    let hook_spec = schema_def_block("HookSpec");
    assert!(
        hook_spec.contains("Empty is not wildcard")
            && hook_spec.contains("any declared read/write must be covered"),
        "HookSpec.allowed_namespaces schema must document that empty is not a wildcard"
    );
}

#[test]
fn pipeline_and_verdict_schemas_close_objects_and_match_ids() {
    for (schema, def_name) in [
        (PIPELINE_SCHEMA, "Pipeline"),
        (PIPELINE_SCHEMA, "Wiring"),
        (VERDICT_SCHEMA, "Reason"),
    ] {
        let block = schema_def_block_in(schema, def_name);
        assert!(
            block.contains(r#""additionalProperties": false"#),
            "{def_name} schema must reject unknown fields"
        );
    }

    for tag in ["Continue", "Jump", "Accept", "Reject", "Drop"] {
        let block = format!(
            r#""additionalProperties": false, "properties": {{ "tag": {{ "const": "{tag}" }}"#
        );
        assert!(
            VERDICT_SCHEMA.contains(&block),
            "Verdict variant {tag} schema must reject unknown fields"
        );
    }

    let source_id = schema_def_block_in(VERDICT_SCHEMA, "SourceId");
    assert!(
        source_id.contains("[A-Za-z0-9_.:-]"),
        "SourceId schema must allow runtime-derived ids such as ingress:0"
    );
    let registry_source_id = schema_def_block_in(REGISTRY_SCHEMA, "SourceId");
    assert!(
        registry_source_id.contains("^[A-Za-z0-9_.:-]+$"),
        "KernelRegistry SourceId schema must match verdict SourceId id-shape contract"
    );
    let sink_id = schema_def_block_in(VERDICT_SCHEMA, "SinkId");
    assert!(
        sink_id.contains("^[A-Za-z0-9_.:-]+$"),
        "SinkId schema must use terminal target id-shape contract"
    );
    let registry_sink_id = schema_def_block_in(REGISTRY_SCHEMA, "SinkId");
    assert!(
        registry_sink_id.contains("^[A-Za-z0-9_.:-]+$"),
        "KernelRegistry SinkId schema must match verdict SinkId id-shape contract"
    );
    for (schema, def_name) in [
        (VERDICT_SCHEMA, "PipelineId"),
        (VERDICT_SCHEMA, "HookId"),
        (REGISTRY_SCHEMA, "PipelineId"),
        (REGISTRY_SCHEMA, "HookId"),
    ] {
        let block = schema_def_block_in(schema, def_name);
        assert!(
            block.contains("^[A-Za-z0-9_.:-]+$"),
            "{def_name} schema must use the shared kernel id-shape contract"
        );
    }
    let pipeline = schema_def_block_in(PIPELINE_SCHEMA, "Pipeline");
    assert!(
        pipeline.matches("^[A-Za-z0-9_.:-]+$").count() >= 2,
        "Pipeline.id and Pipeline.hooks must use the shared kernel id-shape contract"
    );
    let pipeline_wiring = schema_def_block_in(PIPELINE_SCHEMA, "Wiring");
    assert!(
        pipeline_wiring.matches("^[A-Za-z0-9_.:-]+$").count() >= 2,
        "Pipeline Wiring.source and Wiring.pipeline must use the shared kernel id-shape contract"
    );
    let run_error = schema_def_block_in(PIPELINE_SCHEMA, "PipelineRunError");
    for error in ["UndeclaredAcceptTarget", "UndeclaredJumpTarget"] {
        assert!(
            run_error.contains(error),
            "PipelineRunError schema must expose dynamic declaration enforcement error {error}"
        );
    }
}

#[test]
fn event_and_metadata_schemas_close_hot_struct_shapes() {
    for (schema, root_ref, name) in [
        (
            EVENT_SCHEMA,
            r##""$ref": "#/$defs/Event""##,
            "event schema root must validate Event",
        ),
        (
            METADATA_SCHEMA,
            r##""$ref": "#/$defs/TypedMap""##,
            "metadata schema root must validate TypedMap",
        ),
    ] {
        assert!(schema.contains(root_ref), "{name}");
    }

    for (schema, def_name) in [
        (EVENT_SCHEMA, "Event"),
        (EVENT_SCHEMA, "HookTrace"),
        (METADATA_SCHEMA, "TypedMap"),
        (METADATA_SCHEMA, "NetMeta"),
        (METADATA_SCHEMA, "TransportMeta"),
        (METADATA_SCHEMA, "PolicyMeta"),
        (METADATA_SCHEMA, "AuthMeta"),
        (METADATA_SCHEMA, "TraceMeta"),
    ] {
        let block = schema_def_block_in(schema, def_name);
        assert!(
            block.contains(r#""additionalProperties": false"#),
            "{def_name} schema must reject unknown fields"
        );
    }
    let hook_trace = schema_def_block_in(EVENT_SCHEMA, "HookTrace");
    assert!(
        hook_trace.contains("^[A-Za-z0-9_.:-]+$"),
        "HookTrace.hook_id schema must use the shared HookId shape"
    );
    let ext_key = schema_def_block_in(METADATA_SCHEMA, "ExtKey");
    assert!(
        ext_key.contains("^[A-Za-z0-9_]+(\\\\.[A-Za-z0-9_]+)*$"),
        "ExtKey schema must constrain local extension key tails"
    );
    assert!(
        ext_key.contains("^(net|transport|policy|auth|trace|ext)\\\\."),
        "ExtKey schema must reject full metadata-key prefixes"
    );
    let typed_map = schema_def_block_in(METADATA_SCHEMA, "TypedMap");
    assert!(
        typed_map.contains(r##""$ref": "#/$defs/ExtKey""##),
        "TypedMap.ext schema must use ExtKey for local extension key tails"
    );
    let net_meta = schema_def_block_in(METADATA_SCHEMA, "NetMeta");
    assert!(
        net_meta.contains(r#""src_ip":    {"#)
            && net_meta.contains(r#""format": "ipv4""#)
            && net_meta.contains(r#""format": "ipv6""#),
        "NetMeta.src_ip schema must constrain source IP metadata to IPv4 or IPv6 literals"
    );
    assert!(
        net_meta.contains(r#""dst_host":  { "type": ["string", "null"], "minLength": 1 }"#),
        "NetMeta.dst_host schema must reject empty hostname metadata"
    );
    assert!(
        net_meta.contains("L4 transport-family hint")
            && net_meta.contains("not an adapter protocol label")
            && net_meta.contains("not a protocol parser"),
        "NetMeta.protocol schema must document L4 transport-family semantics"
    );
    assert!(
        net_meta.contains(r#""enum": [null, "tcp", "udp"]"#),
        "NetMeta.protocol schema must be closed to tcp/udp/null"
    );
    let transport_meta = schema_def_block_in(METADATA_SCHEMA, "TransportMeta");
    assert!(
        transport_meta.contains("schedule_fanout_k"),
        "TransportMeta schema must preserve FanOut k payload separately from schedule_hint label"
    );

    for required in [
        r#""required": ["payload", "meta"]"#,
        r#""required": ["hook_id", "verdict"]"#,
        r#""required": ["net", "transport", "policy", "auth", "trace", "ext"]"#,
    ] {
        assert!(
            EVENT_SCHEMA.contains(required) || METADATA_SCHEMA.contains(required),
            "event/metadata schema must require fixed Rust fields: {required}"
        );
    }

    assert!(
        EVENT_SCHEMA.contains(r#""$ref": "../metadata/schema.json#/$defs/TypedMap""#),
        "Event.meta must reference sibling kernel/metadata schema"
    );

    for kind in ["string", "u64", "bool", "bytes"] {
        let marker = format!(
            r#""additionalProperties": false, "properties": {{ "kind": {{ "const": "{kind}" }}"#
        );
        assert!(
            METADATA_SCHEMA.contains(&marker),
            "MetaValue variant {kind} schema must reject unknown fields"
        );
    }
}

#[test]
fn pipeline_and_verdict_schemas_have_root_contracts() {
    for (schema, root_ref, name) in [
        (
            PIPELINE_SCHEMA,
            r##""$ref": "#/$defs/Pipeline""##,
            "pipeline schema root must validate Pipeline",
        ),
        (
            VERDICT_SCHEMA,
            r##""$ref": "#/$defs/Verdict""##,
            "verdict schema root must validate Verdict",
        ),
    ] {
        assert!(schema.contains(root_ref), "{name}");
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn schema_def_block(def_name: &str) -> &str {
    schema_def_block_in(REGISTRY_SCHEMA, def_name)
}

fn schema_def_block_in<'a>(schema: &'a str, def_name: &str) -> &'a str {
    let marker = format!(r#""{def_name}""#);
    let start = schema
        .find(&marker)
        .unwrap_or_else(|| panic!("missing schema def {def_name}"));
    let rest = &schema[start..];
    let end = rest
        .get(1..)
        .and_then(|tail| tail.find("\n    \"").map(|idx| idx + 1))
        .or_else(|| rest.find("\n  }\n}"))
        .unwrap_or_else(|| panic!("unterminated schema def {def_name}"));
    &rest[..end]
}

fn walk_contract_files(dir: &Path, visit: &mut dyn FnMut(&Path, usize, &str)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_contract_files(&path, visit);
            continue;
        }
        if !matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "json")
        ) {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for (idx, line) in content.lines().enumerate() {
            visit(&path, idx + 1, line);
        }
    }
}

fn is_allowed(path: &Path, line: &str) -> bool {
    let trimmed = line.trim_start();
    path.extension().and_then(|e| e.to_str()) == Some("json") && trimmed.starts_with(r#""$schema""#)
}
