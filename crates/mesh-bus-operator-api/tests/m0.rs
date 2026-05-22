use mesh_bus_core::kernel::forwarder::FlowCountersSnapshot;
use mesh_bus_core::{BusSnapshot, FlowId};
use mesh_bus_operator_api::{
    config_check_response, diagnose_bundle_response, effective_config_response,
    live_status_response, metrics_snapshot_response, status_response,
};
use mesh_bus_runtime::parse_config;
use std::path::Path;

const VALID: &str = r#"
logging:
  level: debug
  format: compact
node:
  id: node-a
peers:
  - id: peer-b
    node_id: node-b
    route_groups: [mesh]
    meshsec:
      profile: MeshSec-0RTT-PSK-XChaCha
      static_key_hex: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:1080
    auth:
      users:
        - name: alice
          password: secret-pass
egresses:
  - kind: MeshPeerUdp
    id: peer
    peer_id: peer-b
    peer: 127.0.0.1:19000
    groups: [mesh]
    timeout_ms: 1000
"#;

#[test]
fn status_projects_config_without_secret_material() {
    let cfg = parse_config(VALID).expect("parse config");
    let status = status_response(&cfg, Path::new("config.yaml"), VALID, "test-version");

    assert_eq!(status.kind, "operator.status");
    assert_eq!(status.version, "test-version");
    assert_eq!(status.node_id.as_deref(), Some("node-a"));
    assert_eq!(status.scheduler, "Cake");
    assert_eq!(status.logging, "debug/compact");
    assert_eq!(status.counts.peers, 1);
    assert_eq!(status.peers[0].id, "peer-b");
    assert!(status.peers[0].meshsec);
    assert_eq!(status.egresses[0].id, "peer");
    assert_eq!(status.egresses[0].peer_id.as_deref(), Some("peer-b"));
}

#[test]
fn config_check_uses_runtime_preflight() {
    let response = config_check_response(Path::new("config.yaml"), VALID, Path::new("."));
    assert!(response.ok, "{response:?}");
    assert!(response.error.is_none());
}

#[test]
fn config_check_reports_preflight_errors() {
    let yaml = r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:1080
    rule_chain_path: missing.yaml
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#;
    let response = config_check_response(Path::new("config.yaml"), yaml, Path::new("."));
    assert!(!response.ok);
    assert!(
        response
            .error
            .as_deref()
            .is_some_and(|e| e.contains("rule_chain_path not found")),
        "{response:?}"
    );
}

#[test]
fn effective_config_redacts_secret_fields() {
    let response = effective_config_response(Path::new("config.yaml"), VALID).expect("effective");

    assert!(response.redacted_yaml.contains("<redacted>"));
    assert!(!response.redacted_yaml.contains("secret-pass"));
    assert!(
        !response
            .redacted_yaml
            .contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn diagnose_bundle_removes_secret_markers_from_exportable_yaml() {
    let cfg = parse_config(VALID).expect("parse config");
    let snapshot = BusSnapshot::default();
    let response =
        diagnose_bundle_response(&cfg, Path::new("config.yaml"), VALID, "test", &snapshot)
            .expect("diagnose");

    assert_eq!(response.kind, "operator.diagnose_bundle");
    for marker in [
        "static_key_hex",
        "MESH_BUS_MESHSEC_KEY_HEX",
        "password=",
        "Authorization:",
        "Bearer ",
        "secret-pass",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        assert!(
            !response.effective_config.redacted_yaml.contains(marker),
            "diagnose bundle leaked marker {marker}"
        );
    }
}

#[test]
fn metrics_snapshot_projects_bus_snapshot() {
    let mut snapshot = BusSnapshot::default();
    snapshot.dispatch_success = 7;
    snapshot.dispatch_failure = 2;
    snapshot.bytes_sent = 4096;
    snapshot.meshsec_drop_total = 3;
    snapshot.meshsec_auth_drop_total = 1;
    snapshot.meshsec_replay_drop_total = 2;
    snapshot.native_drop_total = 4;
    snapshot.native_queue_overflow_drop_total = 1;
    snapshot.flows = vec![(
        FlowId("flow-a".into()),
        FlowCountersSnapshot {
            bytes_in: 10,
            bytes_out: 20,
        },
    )];

    let response = metrics_snapshot_response(Path::new("config.yaml"), VALID, &snapshot);

    assert_eq!(response.kind, "operator.metrics_snapshot");
    assert_eq!(response.dispatch_success, 7);
    assert_eq!(response.dispatch_failure, 2);
    assert_eq!(response.bytes_sent, 4096);
    assert_eq!(response.meshsec_drop_total, 3);
    assert_eq!(response.meshsec_auth_drop_total, 1);
    assert_eq!(response.meshsec_replay_drop_total, 2);
    assert_eq!(response.native_drop_total, 4);
    assert_eq!(response.native_queue_overflow_drop_total, 1);
    assert_eq!(response.datagram_send_total, 0);
    assert_eq!(response.datagram_failure_total, 0);
    assert_eq!(response.flows, 1);
    assert!(response.exits.is_empty());
}

#[test]
fn live_status_composes_config_status_and_metrics_snapshot() {
    let cfg = parse_config(VALID).expect("parse config");
    let mut snapshot = BusSnapshot::default();
    snapshot.dispatch_success = 1;
    snapshot.bytes_sent = 128;

    let response = live_status_response(&cfg, Path::new("config.yaml"), VALID, "test", &snapshot);

    assert_eq!(response.kind, "operator.live_status");
    assert_eq!(response.status.kind, "operator.status");
    assert_eq!(response.status.node_id.as_deref(), Some("node-a"));
    assert_eq!(response.metrics.kind, "operator.metrics_snapshot");
    assert_eq!(response.metrics.dispatch_success, 1);
    assert_eq!(response.metrics.bytes_sent, 128);
}
