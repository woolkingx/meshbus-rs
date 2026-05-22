//! Rust API surface tests for mesh-bus-runtime.
//! Parse-contract tests (parse_config YAML → Ok/Err assertions) have been
//! converted to data fixtures in tests/fixtures/config/ driven by
//! config_fixture_runner.rs. Only tests that assert a Rust API surface that
//! is not a config contract remain here.

use mesh_bus_runtime::{
    AuthUserCfg, Config, EgressCfg, IngressCfg, MeshSecPeerCfg, MeshSecProfileCfg,
    PipelineSourceCfg, Socks5UpstreamAuthCfg, TrafficClassCfg, egress_peer_labels, parse_config,
    run, selected_pipeline_source_index, validate_config,
};
use serde_json::Value;

// --- Rust type API surface tests ---

#[test]
fn pipeline_source_cfg_is_public_runtime_api() {
    let source = PipelineSourceCfg::default();
    assert_eq!(source.kind, "application/source");
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "serde_json::json! macro expands to unwrap"
)]
fn runtime_schema_exposes_current_operator_surface() {
    let schema: Value =
        serde_json::from_str(include_str!("../schema.json")).expect("runtime schema is valid json");

    assert_eq!(schema["x-schema-version"], "draft-08");
    assert_eq!(
        schema["properties"]["ingresses"]["minItems"], 1,
        "schema must reject the same empty ingress list as validate_config"
    );
    assert_eq!(
        schema["properties"]["egresses"]["minItems"], 1,
        "schema must reject the same empty egress list as validate_config"
    );

    assert!(
        schema["properties"]["pipeline"]["properties"]["rule_chain_path"].is_object(),
        "schema must expose top-level pipeline.rule_chain_path"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["geoip"]["properties"]["country_path"]
            .is_object(),
        "schema must expose pipeline.geoip.country_path"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["geoip"]["required"],
        serde_json::json!(["country_path", "asn_path"]),
        "schema must require complete GeoIP DB paths when geoip is configured"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["geosite"]["required"],
        serde_json::json!(["path"]),
        "schema must require geosite.path when geosite is configured"
    );
    for key in [
        "rule_chain_forward",
        "rule_chain_resolver",
        "geosite",
        "dns_cache",
        "source",
    ] {
        assert!(
            schema["properties"]["pipeline"]["properties"][key].is_object(),
            "schema must expose pipeline.{key}"
        );
    }
    for (field, value) in [
        (
            "rule_chain_path",
            &schema["properties"]["pipeline"]["properties"]["rule_chain_path"],
        ),
        (
            "rule_chain_forward",
            &schema["properties"]["pipeline"]["properties"]["rule_chain_forward"],
        ),
        (
            "rule_chain_resolver",
            &schema["properties"]["pipeline"]["properties"]["rule_chain_resolver"],
        ),
        (
            "geoip.country_path",
            &schema["properties"]["pipeline"]["properties"]["geoip"]["properties"]["country_path"],
        ),
        (
            "geoip.asn_path",
            &schema["properties"]["pipeline"]["properties"]["geoip"]["properties"]["asn_path"],
        ),
        (
            "geosite.path",
            &schema["properties"]["pipeline"]["properties"]["geosite"]["properties"]["path"],
        ),
    ] {
        assert!(
            value["description"]
                .as_str()
                .is_some_and(|description| description.contains("config file directory")),
            "schema must document that pipeline.{field} resolves relative to config file directory"
        );
    }
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["initial_writes"]
            .is_object(),
        "schema must expose pipeline.source.initial_writes"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["kind"]["const"],
        "application/source"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["kind"]
            ["description"]
            .as_str()
            .is_some_and(|description| description.contains("protocol-neutral")
                && description.contains("HTTP")
                && description.contains("HTTPS")),
        "schema must document that pipeline.source.kind stays generic across future adapters"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["id"]["pattern"],
        "^[A-Za-z0-9_.:-]+$",
        "schema must keep pipeline.source.id aligned with core SourceId"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["id"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("opaque SourceId")
                && description.contains("validates only SourceId shape")
                && description.contains("never interprets adapter protocol names")),
        "schema must document that pipeline.source.id is opaque instance identity"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["id"]["not"]
            .is_null(),
        "schema must not inspect protocol tokens inside opaque pipeline.source.id values"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["initial_writes"]["items"]
            ["pattern"],
        "^(net|transport|policy|auth|trace|ext)\\.[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)*$"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]
            ["initial_writes"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("HookSpec.reads")
                && description.contains("kernel_registry_verify")),
        "schema must document that pipeline.source.initial_writes is verified against hook reads"
    );
    assert_eq!(
        schema["properties"]["logging"]["properties"]["level"]["enum"],
        serde_json::json!(["trace", "debug", "info", "warn", "error"])
    );
    for idx in 0..2 {
        assert_eq!(
            schema["properties"]["metrics"]["oneOf"][idx]["properties"]["labels"]["propertyNames"]
                ["pattern"],
            "^[A-Za-z_][A-Za-z0-9_]*$",
            "schema metrics labels must stay valid Prometheus label names for oneOf[{idx}]"
        );
    }
    assert_eq!(
        schema["properties"]["operator"]["oneOf"][0]["properties"]["kind"]["const"],
        "LocalHttp"
    );
    assert_eq!(
        schema["properties"]["operator"]["oneOf"][0]["properties"]["listen"]["minLength"],
        1
    );
    assert!(
        schema["properties"]["operator"]["oneOf"][0]["properties"]["listen"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("Loopback")),
        "schema must document operator LocalHttp loopback boundary"
    );

    let socks5 = &schema["properties"]["ingresses"]["items"]["oneOf"][0]["properties"];
    for key in [
        "rule_chain_path",
        "auth",
        "handshake_timeout_ms",
        "accept_backoff_ms",
        "max_connections",
        "udp_forward_concurrency",
        "socket_recv_buffer_bytes",
        "socket_send_buffer_bytes",
    ] {
        assert!(
            socks5[key].is_object(),
            "schema must expose Socks5 ingress field {key}"
        );
    }
    assert_eq!(socks5["listen"]["minLength"], 1);
    assert!(
        socks5["rule_chain_path"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("config file directory")
                && description.contains("BusSessionRequest")),
        "schema must document that legacy ingress.rule_chain_path resolves relative to config file directory and is adapter projection gated"
    );

    let tcp_ingress = &schema["properties"]["ingresses"]["items"]["oneOf"][1]["properties"];
    assert_eq!(tcp_ingress["listen"]["minLength"], 1);
    assert_eq!(tcp_ingress["target"]["minLength"], 1);
    assert_eq!(tcp_ingress["socket_recv_buffer_bytes"]["minimum"], 1);
    assert_eq!(tcp_ingress["socket_send_buffer_bytes"]["minimum"], 1);

    let udp_ingress = &schema["properties"]["ingresses"]["items"]["oneOf"][2]["properties"];
    assert_eq!(udp_ingress["listen"]["minLength"], 1);
    assert_eq!(udp_ingress["target"]["minLength"], 1);
    assert_eq!(udp_ingress["socket_recv_buffer_bytes"]["minimum"], 1);
    assert_eq!(udp_ingress["socket_send_buffer_bytes"]["minimum"], 1);

    let http_connect_ingress = schema["properties"]["ingresses"]["items"]["oneOf"]
        .as_array()
        .expect("ingress oneOf array")
        .iter()
        .find(|variant| variant["properties"]["kind"]["const"] == "HttpConnect")
        .expect("HttpConnect ingress schema variant");
    let http_connect = &http_connect_ingress["properties"];
    assert_eq!(http_connect["listen"]["minLength"], 1);
    assert_eq!(http_connect["max_header_bytes"]["minimum"], 1);
    assert_eq!(http_connect["max_connections"]["minimum"], 1);
    assert_eq!(
        http_connect["auth"]["properties"]["users"]["items"]["properties"]["name"]["minLength"],
        1
    );
    assert_eq!(
        http_connect["auth"]["properties"]["users"]["items"]["properties"]["password"]["minLength"],
        1
    );

    let socks5_egress = &schema["properties"]["egresses"]["items"]["oneOf"][1]["properties"];
    assert_eq!(socks5_egress["upstream"]["minLength"], 1);

    let socks5_udp_egress = &schema["properties"]["egresses"]["items"]["oneOf"][2]["properties"];
    assert_eq!(socks5_udp_egress["kind"]["const"], "Socks5Udp");
    assert_eq!(socks5_udp_egress["upstream"]["minLength"], 1);
    assert_eq!(
        socks5_udp_egress["auth"]["properties"]["username"]["minLength"],
        1
    );
    assert_eq!(
        socks5_udp_egress["auth"]["properties"]["password"]["minLength"],
        1
    );

    assert_eq!(
        schema["properties"]["node"]["properties"]["id"]["pattern"],
        "^[A-Za-z0-9_.:-]+$"
    );
    assert_eq!(
        schema["properties"]["peers"]["items"]["properties"]["id"]["pattern"],
        "^[A-Za-z0-9_.:-]+$"
    );
    assert_eq!(
        schema["properties"]["ingresses"]["items"]["oneOf"][3]["properties"]["kind"]["const"],
        "MeshPeerUdp"
    );
    assert!(
        schema["properties"]["ingresses"]["items"]["oneOf"][3]["properties"]["listen"]
            ["description"]
            .as_str()
            .is_some_and(|description| description.contains("MeshSec")
                && description.contains("Non-loopback")
                && description.contains("loopback")),
        "schema must document MeshPeerUdp WAN MeshSec and loopback debug-clear boundaries"
    );

    for idx in 0..6 {
        let egress = &schema["properties"]["egresses"]["items"]["oneOf"][idx]["properties"];
        assert!(
            egress["groups"].is_object(),
            "schema must expose egress groups for oneOf[{idx}]"
        );
        assert_eq!(
            egress["id"]["pattern"], "^[A-Za-z0-9_.:-]+$",
            "schema egress id must stay aligned with SinkId for oneOf[{idx}]"
        );
        assert!(
            egress["id"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("SinkId")
                    && description.contains("may_accept_to")
                    && description.contains("pick_sink")),
            "schema egress id must document SinkId / pick_sink projection for oneOf[{idx}]"
        );
        assert_eq!(egress["wan_id"]["minLength"], 1);
        assert!(
            egress["wan_id"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("observability")
                    && description.contains("label")),
            "schema egress wan_id must document observability-label semantics for oneOf[{idx}]"
        );
        assert_eq!(egress["groups"]["items"]["minLength"], 1);
        assert!(
            egress["groups"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("route-group")
                    && description.contains("candidate")),
            "schema egress groups must document route-group candidate-label semantics for oneOf[{idx}]"
        );
        assert!(
            egress["priority"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("LoadBalance")
                    && description.contains("weight")),
            "schema egress priority must document load-balance weight semantics for oneOf[{idx}]"
        );
        if matches!(idx, 0 | 3 | 6) {
            assert_eq!(egress["socket_recv_buffer_bytes"]["minimum"], 1);
            assert_eq!(egress["socket_send_buffer_bytes"]["minimum"], 1);
        }
    }
    assert_eq!(
        schema["properties"]["egresses"]["items"]["oneOf"][4]["properties"]["kind"]["const"],
        "MeshPeerUdp"
    );
    assert_eq!(
        schema["properties"]["egresses"]["items"]["oneOf"][5]["properties"]["kind"]["const"],
        "ServiceTcp"
    );
    assert_eq!(
        schema["properties"]["egresses"]["items"]["oneOf"][6]["properties"]["kind"]["const"],
        "ServiceUdp"
    );
}

#[test]
fn ingress_pipeline_capability_is_declared_by_config_variant() {
    let socks5 = IngressCfg::Socks5 {
        listen: "127.0.0.1:19080".into(),
        rule_chain_path: None,
        auth: None,
        handshake_timeout_ms: None,
        accept_backoff_ms: None,
        max_connections: None,
        udp_forward_concurrency: None,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    };
    let tcp = IngressCfg::Tcp {
        listen: "127.0.0.1:19081".into(),
        target: "127.0.0.1:80".into(),
        route_group: None,
        traffic_class: None,
        deadline_ms: None,
        source_label: None,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    };
    let udp = IngressCfg::Udp {
        listen: "127.0.0.1:19082".into(),
        target: "127.0.0.1:53".into(),
        route_group: None,
        traffic_class: None,
        deadline_ms: None,
        source_label: None,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    };
    let http_connect = IngressCfg::HttpConnect {
        listen: "127.0.0.1:19083".into(),
        auth: None,
        handshake_timeout_ms: None,
        max_header_bytes: None,
        max_connections: None,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    };

    assert_eq!(socks5.pipeline_source_kind(), Some("application/source"));
    assert_eq!(
        http_connect.pipeline_source_kind(),
        Some("application/source")
    );
    assert_eq!(tcp.pipeline_source_kind(), Some("application/source"));
    assert_eq!(udp.pipeline_source_kind(), Some("application/source"));
    assert_eq!(
        socks5.pipeline_source_kind(),
        Some(PipelineSourceCfg::default().kind.as_str()),
        "pipeline-capable ingresses must declare the same generic SourceSpec.kind as pipeline.source"
    );
    assert_eq!(
        http_connect.pipeline_source_kind(),
        Some(PipelineSourceCfg::default().kind.as_str()),
        "HTTP CONNECT source must declare the same generic SourceSpec.kind as pipeline.source"
    );
    assert_eq!(
        tcp.pipeline_source_kind(),
        Some(PipelineSourceCfg::default().kind.as_str()),
        "direct Tcp source must declare the same generic SourceSpec.kind as pipeline.source"
    );
    assert_eq!(
        udp.pipeline_source_kind(),
        Some(PipelineSourceCfg::default().kind.as_str()),
        "direct Udp source must declare the same generic SourceSpec.kind as pipeline.source"
    );
}

#[test]
fn egress_pipeline_capability_is_declared_by_config_variant() {
    let tcp = EgressCfg::Tcp {
        id: "tcp".into(),
        wan_id: None,
        priority: 1,
        groups: vec![],
        timeout_ms: 1000,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    };
    let socks5 = EgressCfg::Socks5 {
        id: "socks5-upstream".into(),
        wan_id: None,
        priority: 1,
        groups: vec![],
        upstream: "127.0.0.1:1080".into(),
        timeout_ms: 1000,
    };
    let udp = EgressCfg::Udp {
        id: "udp".into(),
        wan_id: None,
        priority: 1,
        groups: vec![],
        timeout_ms: 1000,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    };

    assert_eq!(tcp.pipeline_sink_kind(), "stream_egress");
    assert_eq!(socks5.pipeline_sink_kind(), "stream_egress");
    assert_eq!(udp.pipeline_sink_kind(), "datagram_egress");
    assert_eq!(tcp.pipeline_capability_bits(), (true, false));
    assert_eq!(socks5.pipeline_capability_bits(), (true, false));
    assert_eq!(udp.pipeline_capability_bits(), (false, true));
}

#[test]
fn service_tcp_egress_is_stream_capability() {
    let svc = EgressCfg::ServiceTcp {
        id: "svc".into(),
        service_id: "echo-service".into(),
        wan_id: None,
        priority: 1,
        route_group: None,
        groups: vec![],
        connect: "127.0.0.1:9000".into(),
        timeout_ms: 1000,
    };
    assert_eq!(svc.pipeline_sink_kind(), "stream_egress");
    assert_eq!(svc.pipeline_capability_bits(), (true, false));
}

#[test]
fn service_udp_egress_is_datagram_capability() {
    let svc = EgressCfg::ServiceUdp {
        id: "svc-udp".into(),
        service_id: "dns-service".into(),
        wan_id: None,
        priority: 1,
        route_group: None,
        groups: vec![],
        connect: "127.0.0.1:53".into(),
        timeout_ms: 1000,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    };
    assert_eq!(svc.pipeline_sink_kind(), "datagram_egress");
    assert_eq!(svc.pipeline_capability_bits(), (false, true));
}

#[test]
fn direct_tcp_ingress_carries_direct_metadata() {
    let yaml = r#"
ingresses:
  - kind: Tcp
    listen: 127.0.0.1:19091
    target: 127.0.0.1:80
    route_group: premium
    traffic_class: Interactive
    deadline_ms: 2500
    source_label: edge-a
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#;
    let cfg: Config = parse_config(yaml).expect("valid direct tcp ingress with metadata");
    match &cfg.ingresses[0] {
        IngressCfg::Tcp {
            route_group,
            traffic_class,
            deadline_ms,
            source_label,
            ..
        } => {
            assert_eq!(route_group.as_deref(), Some("premium"));
            assert_eq!(*traffic_class, Some(TrafficClassCfg::Interactive));
            assert_eq!(*deadline_ms, Some(2500));
            assert_eq!(source_label.as_deref(), Some("edge-a"));
            assert_eq!(
                traffic_class.unwrap().to_core(),
                mesh_bus_core::TrafficClass::Interactive
            );
        }
        other => panic!("expected Tcp ingress, got {other:?}"),
    }
}

#[test]
fn direct_udp_ingress_carries_direct_metadata() {
    let yaml = r#"
ingresses:
  - kind: Udp
    listen: 127.0.0.1:19093
    target: 127.0.0.1:53
    route_group: premium
    traffic_class: Interactive
    deadline_ms: 2500
    source_label: edge-a
egresses:
  - kind: Udp
    id: direct
    timeout_ms: 1000
"#;
    let cfg: Config = parse_config(yaml).expect("valid direct udp ingress with metadata");
    match &cfg.ingresses[0] {
        IngressCfg::Udp {
            route_group,
            traffic_class,
            deadline_ms,
            source_label,
            ..
        } => {
            assert_eq!(route_group.as_deref(), Some("premium"));
            assert_eq!(*traffic_class, Some(TrafficClassCfg::Interactive));
            assert_eq!(*deadline_ms, Some(2500));
            assert_eq!(source_label.as_deref(), Some("edge-a"));
            assert_eq!(
                traffic_class.unwrap().to_core(),
                mesh_bus_core::TrafficClass::Interactive
            );
        }
        other => panic!("expected Udp ingress, got {other:?}"),
    }
}

#[test]
fn secrets_are_redacted_in_debug() {
    let m = MeshSecPeerCfg {
        profile: MeshSecProfileCfg::MeshSec0RttPskXChaCha,
        static_key_hex: Some(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
        ),
        active_key_id: None,
        keyring: Vec::new(),
    };
    let a = AuthUserCfg {
        name: "alice".into(),
        password: "s3cr3t-pw".into(),
    };
    let u = Socks5UpstreamAuthCfg {
        username: "bob".into(),
        password: "up-s3cr3t".into(),
    };
    let dm = format!("{m:?}");
    let da = format!("{a:?}");
    let du = format!("{u:?}");
    assert!(!dm.contains("00112233"), "PSK leaked: {dm}");
    assert!(!da.contains("s3cr3t-pw"), "password leaked: {da}");
    assert!(!du.contains("up-s3cr3t"), "upstream password leaked: {du}");
    assert!(dm.contains("redacted") && da.contains("redacted") && du.contains("redacted"));
}

#[test]
fn meshsec_keyring_uses_active_for_seal_and_accepts_old_keys() {
    let yaml = r#"
node:
  id: node-a
peers:
  - id: peer-b
    node_id: node-b
    meshsec:
      profile: MeshSec-0RTT-PSK-XChaCha
      active_key_id: k1
      keyring:
        - id: k1
          static_key_hex: "1111111111111111111111111111111111111111111111111111111111111111"
          role: active
        - id: k0
          static_key_hex: "0000000000000000000000000000000000000000000000000000000000000000"
          role: accept
ingresses:
  - kind: MeshPeerUdp
    listen: 0.0.0.0:19000
egresses:
  - kind: MeshPeerUdp
    id: peer-b-udp
    peer_id: peer-b
    peer: 127.0.0.1:19001
    timeout_ms: 1000
"#;
    let cfg = parse_config(yaml).expect("keyring config parses");
    let seal = cfg
        .meshsec_seal_context("peer-b", [1, 2, 3, 4])
        .expect("seal context");
    assert_eq!(seal.static_key, [0x11; 32], "active key seals new packets");
    let open = cfg.meshsec_open_keys();
    assert_eq!(open.len(), 2, "active + accept keys open inbound packets");
    assert_eq!(open[0].static_key, [0x11; 32], "active key tried first");
    assert_eq!(open[1].static_key, [0x00; 32], "accept key retained");
}

#[test]
fn meshsec_keyring_rejects_missing_active_key() {
    let yaml = r#"
node:
  id: node-a
peers:
  - id: peer-b
    node_id: node-b
    meshsec:
      profile: MeshSec-0RTT-PSK-XChaCha
      active_key_id: missing
      keyring:
        - id: k0
          static_key_hex: "0000000000000000000000000000000000000000000000000000000000000000"
          role: accept
ingresses:
  - kind: MeshPeerUdp
    listen: 0.0.0.0:19000
egresses:
  - kind: MeshPeerUdp
    id: peer-b-udp
    peer_id: peer-b
    peer: 127.0.0.1:19001
    timeout_ms: 1000
"#;
    let err = parse_config(yaml).expect_err("missing active key must fail");
    assert!(
        err.to_string().contains("active_key_id missing"),
        "unexpected error: {err}"
    );
}

#[test]
fn validate_pipeline_without_rule_chain_path_is_ok() {
    let yaml = r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19199
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
pipeline:
  rule_chain_path: /tmp/chain.yaml
"#;
    let cfg = parse_config(yaml).expect("parses");
    validate_config(&cfg).expect("pipeline-only config validates");
}

#[test]
fn validate_pipeline_plus_rule_chain_path_is_ok_and_pipeline_wins() {
    let yaml = r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19200
    rule_chain_path: /tmp/legacy.yaml
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
pipeline:
  rule_chain_path: /tmp/chain.yaml
"#;
    let cfg = parse_config(yaml).expect("parses");
    validate_config(&cfg).expect("coexistence allowed");
}

#[test]
fn egress_peer_labels_derive_from_node_and_mesh_peer_config() {
    let yaml = r#"
node:
  id: node-a
peers:
  - id: parent-a
    node_id: node-b
    route_groups: [wan-us]
ingresses:
  - kind: Udp
    listen: 127.0.0.1:19082
    target: 8.8.8.8:53
egresses:
  - kind: MeshPeerUdp
    id: peer-udp
    peer_id: parent-a
    peer: 127.0.0.1:29000
    timeout_ms: 1000
    groups: [wan-us]
  - kind: Udp
    id: direct-udp
    timeout_ms: 1000
"#;
    let cfg = parse_config(yaml).expect("valid mesh peer config");
    let labels = egress_peer_labels(cfg.node.as_ref(), &cfg.egresses);

    let peer = labels.get("peer-udp").expect("peer-udp labels");
    assert_eq!(peer.get("node_id").map(String::as_str), Some("node-a"));
    assert_eq!(peer.get("peer_id").map(String::as_str), Some("parent-a"));
    assert_eq!(peer.get("path_id").map(String::as_str), Some("peer-udp"));
    assert_eq!(peer.get("hop_count").map(String::as_str), Some("1"));

    let direct = labels.get("direct-udp").expect("direct-udp labels");
    assert_eq!(direct.get("node_id").map(String::as_str), Some("node-a"));
    assert!(direct.get("peer_id").is_none());
    assert!(direct.get("path_id").is_none());
}

#[test]
fn egress_peer_labels_empty_without_node_or_peer() {
    let yaml = r#"
ingresses:
  - kind: Udp
    listen: 127.0.0.1:19083
    target: 8.8.8.8:53
egresses:
  - kind: Udp
    id: direct-udp
    timeout_ms: 1000
"#;
    let cfg = parse_config(yaml).expect("valid direct config");
    let labels = egress_peer_labels(cfg.node.as_ref(), &cfg.egresses);
    assert!(labels.is_empty());
}

#[test]
fn status_text_prints_exit_snapshot_rows() {
    let yaml = r#"
scheduler:
  kind: LoadBalance
  mode: round-robin
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19088
egresses:
  - kind: Socks5
    id: wan20
    wan_id: wan-a
    priority: 2
    upstream: 198.51.100.20:1080
    timeout_ms: 1000
"#;
    let cfg = parse_config(yaml).expect("valid yaml");
    let status = mesh_bus_runtime::status_text(&cfg);

    assert!(status.contains("exit=wan20"));
    assert!(status.contains("wan=wan-a"));
    assert!(status.contains("priority=2"));
    assert!(status.contains("send_count=0"));
}

#[test]
fn operator_local_http_loopback_config_is_valid() {
    let cfg = parse_config(
        r#"
operator:
  kind: LocalHttp
  listen: 127.0.0.1:19080
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:11080
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#,
    )
    .expect("loopback operator API is valid");
    assert!(cfg.operator.is_some());
}

#[test]
fn operator_local_http_bearer_token_file_config_is_valid() {
    let yaml = r#"
operator:
  kind: LocalHttp
  listen: 127.0.0.1:19080
  auth:
    kind: BearerTokenFile
    path: /etc/mesh-bus/operator.token
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19090
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#;
    parse_config(yaml).expect("operator auth config parses");
}

#[test]
fn operator_local_http_wildcard_config_is_rejected() {
    let err = parse_config(
        r#"
operator:
  kind: LocalHttp
  listen: 0.0.0.0:19080
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:11080
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("operator") && err.to_string().contains("loopback"),
        "expected operator loopback rejection, got: {err}"
    );
}

// selected_pipeline_source_index: calls a public API fn, not just parse
#[test]
fn selected_pipeline_source_index_api() {
    let cfg = parse_config(
        r#"
ingresses:
  - kind: Tcp
    listen: 127.0.0.1:0
    target: example.com:80
  - kind: Socks5
    listen: 127.0.0.1:0
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
pipeline:
  rule_chain_path: /tmp/chain.yaml
  source:
    ingress_index: 1
"#,
    )
    .expect("parse");
    assert_eq!(
        selected_pipeline_source_index(&cfg).expect("source"),
        Some(1)
    );
}

fn base_pipeline_yaml_with_initial_writes(keys: &[&str]) -> String {
    let writes = keys
        .iter()
        .map(|k| format!("      - {k}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19204
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
pipeline:
  rule_chain_forward: /etc/mesh-bus/forward.yaml
  source:
    ingress_index: 0
    id: edge-0
    kind: application/source
    initial_writes:
{writes}
"#
    )
}

#[test]
fn pipeline_source_initial_writes_rejects_lower_layer_pci() {
    let yaml = base_pipeline_yaml_with_initial_writes(&["net.dst_host", "policy.route_group"]);
    let err = parse_config(&yaml).unwrap_err();
    assert!(
        err.to_string().contains("reserved lower-layer namespace"),
        "expected reserved-namespace rejection, got: {err}"
    );
    let yaml2 = base_pipeline_yaml_with_initial_writes(&["transport.schedule_hint"]);
    let err2 = parse_config(&yaml2).unwrap_err();
    assert!(err2.to_string().contains("reserved lower-layer namespace"));
    let ok = base_pipeline_yaml_with_initial_writes(&[
        "net.dst_host",
        "auth.user",
        "trace.flow_id",
        "ext.operation",
    ]);
    assert!(parse_config(&ok).is_ok());
}

// --- Boot/run tests that require file creation (imperative residue) ---

#[tokio::test]
async fn run_rejects_compose_allow_and_deny_chain() {
    let dir =
        std::env::temp_dir().join(format!("mesh-bus-runtime-bad-chain-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let chain_path = dir.join("bad_chain.yaml");
    std::fs::write(
        &chain_path,
        r#"
rules:
  - hostname: a.example.com
    action: { compose: [allow, deny] }
default: allow
"#,
    )
    .expect("write chain");
    let yaml = format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19091
    rule_chain_path: {path}
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#,
        path = chain_path.display()
    );
    let cfg: Config = parse_config(&yaml).expect("valid yaml");
    let outcome = run(cfg, std::path::Path::new(".")).await;
    let err = match outcome {
        Ok(handle) => {
            handle.shutdown().await;
            panic!("validate must reject compose allow+deny")
        }
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("validate rule_chain") && msg.contains("Compose"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn local_ruleset_path_resolved_relative_to_chain_file() {
    let dir = std::env::temp_dir().join(format!("mesh-bus-runtime-relpath-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rules")).expect("mkdir rules");
    std::fs::write(dir.join("rules").join("cn.txt"), ".cn\n").expect("write cn.txt");
    let chain_path = dir.join("chain.yaml");
    std::fs::write(
        &chain_path,
        r#"
rule_sets:
  cn_domains:
    type: local
    format: domain-suffix
    field: hostname
    path: ./rules/cn.txt
rules:
  - { ruleset: cn_domains, action: { set_route_group: cn } }
default: allow
"#,
    )
    .expect("write chain");
    let yaml = format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19092
    rule_chain_path: {path}
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
  - kind: Tcp
    id: cn
    groups: [cn]
    timeout_ms: 1000
"#,
        path = chain_path.display()
    );
    let cfg: Config = parse_config(&yaml).expect("valid yaml");
    let handle = run(cfg, std::path::Path::new("."))
        .await
        .expect("runtime must resolve ./rules/cn.txt relative to chain.yaml");
    handle.shutdown().await;
}

#[tokio::test]
async fn run_resolves_legacy_rule_chain_path_relative_to_config_base_dir() {
    let dir = std::env::temp_dir().join(format!(
        "mesh-bus-runtime-relative-legacy-chain-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rules")).expect("mkdir rules");
    std::fs::write(
        dir.join("rules").join("chain.yaml"),
        "default: allow\nrules: []\n",
    )
    .expect("write chain");
    let yaml = r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19093
    rule_chain_path: rules/chain.yaml
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#;
    let cfg: Config = parse_config(yaml).expect("valid yaml");
    let handle = run(cfg, &dir)
        .await
        .expect("runtime must resolve legacy ingress.rule_chain_path relative to base_dir");
    handle.shutdown().await;
}

#[tokio::test]
async fn run_rejects_legacy_rule_chain_with_unsupported_action_surface() {
    let dir = std::env::temp_dir().join(format!(
        "mesh-bus-runtime-legacy-unsupported-action-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("rules")).expect("mkdir rules");
    std::fs::write(
        dir.join("rules").join("chain.yaml"),
        r#"
rules: []
default:
  set_resolver_pool: dns-cn
"#,
    )
    .expect("write chain");
    let yaml = r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:0
    rule_chain_path: rules/chain.yaml
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#;
    let cfg: Config = parse_config(yaml).expect("valid yaml");

    let err = match run(cfg, &dir).await {
        Ok(handle) => {
            handle.shutdown().await;
            panic!("legacy RulePolicy unsupported actions must fail startup");
        }
        Err(err) => err,
    };

    assert!(
        format!("{err:#}").contains("unsupported legacy rule action"),
        "unexpected error: {err:#}"
    );
}
