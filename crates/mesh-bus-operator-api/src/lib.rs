//! Operator Plane M0: read-only status, config-check, and redacted effective
//! config response builders.

use mesh_bus_runtime::{Config, EgressCfg, IngressCfg, MetricsCfg, parse_config, preflight_config};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigIdentity {
    pub path: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub kind: &'static str,
    pub version: String,
    pub config: ConfigIdentity,
    pub node_id: Option<String>,
    pub scheduler: String,
    pub logging: String,
    pub metrics: String,
    pub counts: StatusCounts,
    pub peers: Vec<PeerStatus>,
    pub ingresses: Vec<IngressStatus>,
    pub egresses: Vec<EgressStatus>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusCounts {
    pub peers: usize,
    pub ingresses: usize,
    pub egresses: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeerStatus {
    pub id: String,
    pub node_id: String,
    pub route_groups: Vec<String>,
    pub meshsec: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IngressStatus {
    pub kind: &'static str,
    pub listen: String,
    pub pipeline_capable: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EgressStatus {
    pub id: String,
    pub kind: &'static str,
    pub wan_id: String,
    pub priority: u32,
    pub groups: Vec<String>,
    pub sink_kind: &'static str,
    pub supports_stream: bool,
    pub supports_datagram: bool,
    pub peer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConfigCheckResponse {
    pub kind: &'static str,
    pub ok: bool,
    pub config: ConfigIdentity,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EffectiveConfigResponse {
    pub kind: &'static str,
    pub config: ConfigIdentity,
    pub redacted_yaml: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveStatusResponse {
    pub kind: &'static str,
    pub status: StatusResponse,
    pub metrics: MetricsSnapshotResponse,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MetricsSnapshotResponse {
    pub kind: &'static str,
    pub config: ConfigIdentity,
    pub dispatch_success: u64,
    pub dispatch_failure: u64,
    pub bytes_sent: u64,
    pub meshsec_drop_total: u64,
    pub meshsec_auth_drop_total: u64,
    pub meshsec_replay_drop_total: u64,
    pub native_drop_total: u64,
    pub native_queue_overflow_drop_total: u64,
    pub datagram_send_total: u64,
    pub datagram_failure_total: u64,
    pub exits: Vec<LiveExitSnapshot>,
    pub flows: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProbeResponse {
    pub kind: &'static str,
    pub probe: &'static str,
    pub ok: bool,
    pub target: String,
    pub route_group: Option<String>,
    pub close_reason: String,
    pub dispatch_success_before: u64,
    pub dispatch_success_after: u64,
    pub dispatch_failure_before: u64,
    pub dispatch_failure_after: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DiagnoseBundleResponse {
    pub kind: &'static str,
    pub status: LiveStatusResponse,
    pub metrics: MetricsSnapshotResponse,
    pub effective_config: EffectiveConfigResponse,
}

pub fn probe_response(
    probe: &'static str,
    ok: bool,
    target: String,
    route_group: Option<String>,
    close_reason: String,
    before: &mesh_bus_core::BusSnapshot,
    after: &mesh_bus_core::BusSnapshot,
    duration_ms: u64,
) -> ProbeResponse {
    ProbeResponse {
        kind: "operator.probe_result",
        probe,
        ok,
        target,
        route_group,
        close_reason,
        dispatch_success_before: before.dispatch_success,
        dispatch_success_after: after.dispatch_success,
        dispatch_failure_before: before.dispatch_failure,
        dispatch_failure_after: after.dispatch_failure,
        duration_ms,
    }
}

pub fn diagnose_bundle_response(
    cfg: &Config,
    config_path: &Path,
    yaml: &str,
    version: &str,
    snapshot: &mesh_bus_core::BusSnapshot,
) -> anyhow::Result<DiagnoseBundleResponse> {
    let mut effective_config = effective_config_response(config_path, yaml)?;
    effective_config.redacted_yaml = diagnose_safe_yaml(&effective_config.redacted_yaml);
    Ok(DiagnoseBundleResponse {
        kind: "operator.diagnose_bundle",
        status: live_status_response(cfg, config_path, yaml, version, snapshot),
        metrics: metrics_snapshot_response(config_path, yaml, snapshot),
        effective_config,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LiveExitSnapshot {
    pub exit_id: String,
    pub protocol: String,
    pub supports_stream: bool,
    pub supports_datagram: bool,
    pub send_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub last_rtt_ms: u64,
    pub payload_bytes_total: u64,
}

pub fn status_response(
    cfg: &Config,
    config_path: &Path,
    yaml: &str,
    version: &str,
) -> StatusResponse {
    StatusResponse {
        kind: "operator.status",
        version: version.to_string(),
        config: config_identity(config_path, yaml),
        node_id: cfg.node.as_ref().map(|node| node.id.clone()),
        scheduler: cfg.scheduler.name().to_string(),
        logging: format!("{}/{}", cfg.logging.level, cfg.logging.format.name()),
        metrics: cfg
            .metrics
            .as_ref()
            .map(MetricsCfg::name)
            .unwrap_or("none")
            .to_string(),
        counts: StatusCounts {
            peers: cfg.peers.len(),
            ingresses: cfg.ingresses.len(),
            egresses: cfg.egresses.len(),
        },
        peers: cfg.peers.iter().map(peer_status).collect(),
        ingresses: cfg.ingresses.iter().map(ingress_status).collect(),
        egresses: cfg.egresses.iter().map(egress_status).collect(),
    }
}

pub fn config_check_response(
    config_path: &Path,
    yaml: &str,
    base_dir: &Path,
) -> ConfigCheckResponse {
    let config = config_identity(config_path, yaml);
    match parse_config(yaml).and_then(|cfg| preflight_config(&cfg, base_dir)) {
        Ok(()) => ConfigCheckResponse {
            kind: "operator.config_check",
            ok: true,
            config,
            error: None,
        },
        Err(error) => ConfigCheckResponse {
            kind: "operator.config_check",
            ok: false,
            config,
            error: Some(error.to_string()),
        },
    }
}

pub fn effective_config_response(
    config_path: &Path,
    yaml: &str,
) -> anyhow::Result<EffectiveConfigResponse> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    redact_value(&mut value);
    let redacted_yaml = serde_yaml::to_string(&value)?;
    Ok(EffectiveConfigResponse {
        kind: "operator.config_effective",
        config: config_identity(config_path, yaml),
        redacted_yaml,
    })
}

pub fn live_status_response(
    cfg: &Config,
    config_path: &Path,
    yaml: &str,
    version: &str,
    snapshot: &mesh_bus_core::BusSnapshot,
) -> LiveStatusResponse {
    LiveStatusResponse {
        kind: "operator.live_status",
        status: status_response(cfg, config_path, yaml, version),
        metrics: metrics_snapshot_response(config_path, yaml, snapshot),
    }
}

pub fn metrics_snapshot_response(
    config_path: &Path,
    yaml: &str,
    snapshot: &mesh_bus_core::BusSnapshot,
) -> MetricsSnapshotResponse {
    let datagram_send_total = snapshot
        .exits
        .iter()
        .filter(|exit| exit.supports_datagram)
        .map(|exit| exit.send_count)
        .sum();
    let datagram_failure_total = snapshot
        .exits
        .iter()
        .filter(|exit| exit.supports_datagram)
        .map(|exit| exit.failure_count)
        .sum();
    MetricsSnapshotResponse {
        kind: "operator.metrics_snapshot",
        config: config_identity(config_path, yaml),
        dispatch_success: snapshot.dispatch_success,
        dispatch_failure: snapshot.dispatch_failure,
        bytes_sent: snapshot.bytes_sent,
        meshsec_drop_total: snapshot.meshsec_drop_total,
        meshsec_auth_drop_total: snapshot.meshsec_auth_drop_total,
        meshsec_replay_drop_total: snapshot.meshsec_replay_drop_total,
        native_drop_total: snapshot.native_drop_total,
        native_queue_overflow_drop_total: snapshot.native_queue_overflow_drop_total,
        datagram_send_total,
        datagram_failure_total,
        exits: snapshot.exits.iter().map(live_exit_snapshot).collect(),
        flows: snapshot.flows.len(),
    }
}

fn config_identity(config_path: &Path, yaml: &str) -> ConfigIdentity {
    ConfigIdentity {
        path: config_path.display().to_string(),
        fingerprint: config_fingerprint(yaml),
    }
}

fn config_fingerprint(yaml: &str) -> String {
    let digest = Sha256::digest(yaml.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn peer_status(peer: &mesh_bus_runtime::PeerCfg) -> PeerStatus {
    PeerStatus {
        id: peer.id.clone(),
        node_id: peer.node_id.clone(),
        route_groups: peer.route_groups.clone(),
        meshsec: peer.meshsec.is_some(),
    }
}

fn ingress_status(ingress: &IngressCfg) -> IngressStatus {
    IngressStatus {
        kind: ingress_kind(ingress),
        listen: ingress_listen(ingress).to_string(),
        pipeline_capable: ingress.supports_pipeline(),
    }
}

fn egress_status(egress: &EgressCfg) -> EgressStatus {
    let (supports_stream, supports_datagram) = egress.pipeline_capability_bits();
    EgressStatus {
        id: egress.id().to_string(),
        kind: egress_kind(egress),
        wan_id: egress.wan_id().to_string(),
        priority: egress.priority(),
        groups: egress.groups().to_vec(),
        sink_kind: egress.pipeline_sink_kind(),
        supports_stream,
        supports_datagram,
        peer_id: egress_peer_id(egress).map(ToOwned::to_owned),
    }
}

fn ingress_kind(ingress: &IngressCfg) -> &'static str {
    match ingress {
        IngressCfg::Socks5 { .. } => "Socks5",
        IngressCfg::HttpConnect { .. } => "HttpConnect",
        IngressCfg::Tcp { .. } => "Tcp",
        IngressCfg::Udp { .. } => "Udp",
        IngressCfg::MeshPeerUdp { .. } => "MeshPeerUdp",
    }
}

fn ingress_listen(ingress: &IngressCfg) -> &str {
    match ingress {
        IngressCfg::Socks5 { listen, .. }
        | IngressCfg::HttpConnect { listen, .. }
        | IngressCfg::Tcp { listen, .. }
        | IngressCfg::Udp { listen, .. }
        | IngressCfg::MeshPeerUdp { listen, .. } => listen,
    }
}

fn egress_kind(egress: &EgressCfg) -> &'static str {
    match egress {
        EgressCfg::Tcp { .. } => "Tcp",
        EgressCfg::Socks5 { .. } => "Socks5",
        EgressCfg::Socks5Udp { .. } => "Socks5Udp",
        EgressCfg::Udp { .. } => "Udp",
        EgressCfg::MeshPeerUdp { .. } => "MeshPeerUdp",
        EgressCfg::ServiceTcp { .. } => "ServiceTcp",
        EgressCfg::ServiceUdp { .. } => "ServiceUdp",
    }
}

fn egress_peer_id(egress: &EgressCfg) -> Option<&str> {
    match egress {
        EgressCfg::MeshPeerUdp { peer_id, .. } => Some(peer_id),
        _ => None,
    }
}

fn live_exit_snapshot(exit: &mesh_bus_core::ExitSnapshot) -> LiveExitSnapshot {
    LiveExitSnapshot {
        exit_id: exit.exit_id.0.clone(),
        protocol: exit.protocol.clone(),
        supports_stream: exit.supports_stream,
        supports_datagram: exit.supports_datagram,
        send_count: exit.send_count,
        success_count: exit.success_count,
        failure_count: exit.failure_count,
        last_rtt_ms: exit.last_rtt_ms,
        payload_bytes_total: exit.payload_bytes_total,
    }
}

fn redact_value(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, value) in mapping.iter_mut() {
                if key.as_str().is_some_and(is_secret_key) {
                    *value = serde_yaml::Value::String("<redacted>".to_string());
                } else {
                    redact_value(value);
                }
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                redact_value(item);
            }
        }
        _ => {}
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "static_key_hex" || key.contains("password") || key.contains("secret")
}

fn diagnose_safe_yaml(yaml: &str) -> String {
    yaml.lines()
        .filter(|line| {
            !line.contains("static_key_hex")
                && !line.contains("MESH_BUS_MESHSEC_KEY_HEX")
                && !line.contains("password=")
                && !line.contains("Authorization:")
                && !line.contains("Bearer ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
