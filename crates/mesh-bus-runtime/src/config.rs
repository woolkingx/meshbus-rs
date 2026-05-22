//! YAML config schema for the bus runtime.
//!
//! Pure deserialization + validation. No tokio, no I/O, no plugin assembly —
//! `run()` in `lib.rs` owns runtime wiring.

pub use crate::config_validate::validate_config;
use anyhow::anyhow;
use mb_health::HealthPolicy;
use mesh_bus_scheduler_loadbalance::LoadBalanceMode;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Top-level config loaded from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub node: Option<NodeCfg>,
    #[serde(default)]
    pub peers: Vec<PeerCfg>,
    #[serde(default)]
    pub logging: LoggingCfg,
    #[serde(default)]
    pub health: HealthCfg,
    #[serde(default)]
    pub metrics: Option<MetricsCfg>,
    #[serde(default)]
    pub operator: Option<OperatorCfg>,
    #[serde(default)]
    pub scheduler: SchedulerCfg,
    pub ingresses: Vec<IngressCfg>,
    pub egresses: Vec<EgressCfg>,
    #[serde(default)]
    pub pipeline: Option<PipelineCfg>,
}

impl Config {
    /// Sender-side MeshSec material for the named adjacent peer. `boot_salt`
    /// is generated once per runtime boot by the caller. Returns `None` when
    /// the peer is unknown, has no `meshsec`, or `node.id` is absent
    /// (config validation already rejects meshsec without node.id).
    pub fn meshsec_seal_context(
        &self,
        peer_id: &str,
        boot_salt: [u8; 4],
    ) -> Option<mb_proto_mesh::MeshSecSealContext> {
        let local_node_id = self.node.as_ref()?.id.clone();
        let peer = self.peers.iter().find(|p| p.id == peer_id)?;
        let meshsec = peer.meshsec.as_ref()?;
        Some(mb_proto_mesh::MeshSecSealContext {
            local_node_id,
            remote_node_id: peer.node_id.clone(),
            static_key: meshsec.static_key()?,
            boot_salt,
        })
    }

    /// Receiver-side MeshSec keys for every configured peer that has
    /// `meshsec`. The opener resolves the right key per packet by
    /// `receiver_hint`, so all keys are offered together.
    pub fn meshsec_open_keys(&self) -> Vec<mb_proto_mesh::MeshSecOpenKey> {
        self.peers
            .iter()
            .flat_map(|peer| {
                let meshsec = peer.meshsec.as_ref()?;
                Some(meshsec.open_static_keys().into_iter().map(|static_key| {
                    mb_proto_mesh::MeshSecOpenKey {
                        peer_id: peer.id.clone(),
                        remote_node_id: peer.node_id.clone(),
                        static_key,
                    }
                }))
            })
            .flatten()
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeCfg {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerCfg {
    pub id: String,
    pub node_id: String,
    #[serde(default)]
    pub route_groups: Vec<String>,
    #[serde(default)]
    pub meshsec: Option<MeshSecPeerCfg>,
}

/// Optional MeshSec secure UDP envelope material for one adjacent peer.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshSecPeerCfg {
    pub profile: MeshSecProfileCfg,
    #[serde(default)]
    pub static_key_hex: Option<String>,
    #[serde(default)]
    pub active_key_id: Option<String>,
    #[serde(default)]
    pub keyring: Vec<MeshSecKeyCfg>,
}

impl std::fmt::Debug for MeshSecPeerCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshSecPeerCfg")
            .field("profile", &self.profile)
            .field("static_key_hex", &"<redacted>")
            .field("active_key_id", &self.active_key_id)
            .field(
                "keyring",
                &format_args!("<{} redacted>", self.keyring.len()),
            )
            .finish()
    }
}

/// One MeshSec PSK entry. `active` seals new outbound packets; `accept` opens
/// old packets during a bounded operational rollover window.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshSecKeyCfg {
    pub id: String,
    pub static_key_hex: String,
    pub role: MeshSecKeyRoleCfg,
}

impl std::fmt::Debug for MeshSecKeyCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshSecKeyCfg")
            .field("id", &self.id)
            .field("static_key_hex", &"<redacted>")
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MeshSecKeyRoleCfg {
    Active,
    Accept,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum MeshSecProfileCfg {
    #[serde(rename = "MeshSec-0RTT-PSK-XChaCha")]
    MeshSec0RttPskXChaCha,
}

impl MeshSecPeerCfg {
    /// Decode the 64-hex static key into raw 32 bytes. Shape is enforced by
    /// `validate_config`; this returns `None` only if validation was skipped.
    pub fn static_key(&self) -> Option<[u8; 32]> {
        self.active_static_key()
    }

    pub fn active_static_key(&self) -> Option<[u8; 32]> {
        if let Some(hex) = &self.static_key_hex {
            return decode_static_key_hex(hex);
        }
        let active_id = self.active_key_id.as_ref()?;
        let key = self
            .keyring
            .iter()
            .find(|key| key.id == *active_id && matches!(key.role, MeshSecKeyRoleCfg::Active))?;
        decode_static_key_hex(&key.static_key_hex)
    }

    pub fn open_static_keys(&self) -> Vec<[u8; 32]> {
        if let Some(hex) = &self.static_key_hex {
            return decode_static_key_hex(hex).into_iter().collect();
        }
        let Some(active_id) = self.active_key_id.as_ref() else {
            return Vec::new();
        };
        let mut keys = Vec::new();
        if let Some(active) = self.keyring.iter().find(|key| key.id == *active_id) {
            if let Some(key) = decode_static_key_hex(&active.static_key_hex) {
                keys.push(key);
            }
        }
        for accept in self
            .keyring
            .iter()
            .filter(|key| key.id != *active_id && matches!(key.role, MeshSecKeyRoleCfg::Accept))
        {
            if let Some(key) = decode_static_key_hex(&accept.static_key_hex) {
                keys.push(key);
            }
        }
        keys
    }
}

fn decode_static_key_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(key)
}

/// Top-level event-pipeline block; when present, runtime assembles a
/// protocol-neutral `PipelineRuntime`. The selected `pipeline.source`
/// adapter uses that runtime; unselected ingresses keep their own
/// legacy/no-policy path.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PipelineCfg {
    #[serde(default)]
    pub rule_chain_path: Option<PathBuf>,
    #[serde(default)]
    pub rule_chain_forward: Option<PathBuf>,
    #[serde(default)]
    pub rule_chain_resolver: Option<PathBuf>,
    #[serde(default)]
    pub geoip: Option<GeoIpCfg>,
    #[serde(default)]
    pub geosite: Option<GeositeCfg>,
    #[serde(default)]
    pub dns_cache: Option<DnsCacheCfg>,
    #[serde(default)]
    pub source: PipelineSourceCfg,
}

impl PipelineCfg {
    pub fn forward_rule_chain_path(&self) -> Option<&PathBuf> {
        self.rule_chain_forward
            .as_ref()
            .or(self.rule_chain_path.as_ref())
    }
}

/// SourceSpec projection for the event-pipeline registry.
///
/// `ingress_index` selects which configured source adapter owns this source.
/// `id`, `kind`, and `initial_writes` describe the protocol-neutral metadata
/// contract the adapter supplies to the kernel registry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PipelineSourceCfg {
    #[serde(default)]
    pub ingress_index: Option<usize>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default = "default_pipeline_source_kind")]
    pub kind: String,
    #[serde(default = "default_pipeline_source_initial_writes")]
    pub initial_writes: Vec<String>,
}

impl Default for PipelineSourceCfg {
    fn default() -> Self {
        Self {
            ingress_index: None,
            id: None,
            kind: default_pipeline_source_kind(),
            initial_writes: default_pipeline_source_initial_writes(),
        }
    }
}

fn default_pipeline_source_kind() -> String {
    "application/source".into()
}

fn default_pipeline_source_initial_writes() -> Vec<String> {
    vec![
        "net.dst_host".into(),
        "net.dst_port".into(),
        "net.protocol".into(),
        "net.src_ip".into(),
        "auth.user".into(),
        "trace.flow_id".into(),
        "ext.operation".into(),
        "ext.dst_ip_primary".into(),
    ]
}

/// Optional GeoIP database paths consumed by `net.enrich_geo_asn` hook.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct GeoIpCfg {
    #[serde(default)]
    pub country_path: Option<PathBuf>,
    #[serde(default)]
    pub asn_path: Option<PathBuf>,
}

/// Optional domain-side geosite data consumed by `net.enrich_geo_asn`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct GeositeCfg {
    #[serde(default)]
    pub path: Option<PathBuf>,
}

/// Optional DNS cache knobs for the resolver-backed pipeline hook.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsCacheCfg {
    #[serde(default)]
    pub serve_stale_window_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthCfg {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u8,
    #[serde(default = "default_recovery_window_ms")]
    pub recovery_window_ms: u64,
    #[serde(default = "default_probe_after_ms")]
    pub probe_after_ms: u64,
}

impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            recovery_window_ms: default_recovery_window_ms(),
            probe_after_ms: default_probe_after_ms(),
        }
    }
}

impl From<HealthCfg> for HealthPolicy {
    fn from(value: HealthCfg) -> Self {
        Self {
            failure_threshold: value.failure_threshold,
            recovery_window_ms: value.recovery_window_ms,
            probe_after_ms: value.probe_after_ms,
        }
    }
}

fn default_failure_threshold() -> u8 {
    HealthPolicy::default().failure_threshold
}

fn default_recovery_window_ms() -> u64 {
    HealthPolicy::default().recovery_window_ms
}

fn default_probe_after_ms() -> u64 {
    HealthPolicy::default().probe_after_ms
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoggingCfg {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    Compact,
    Pretty,
    Json,
}

impl Default for LoggingCfg {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::Compact,
        }
    }
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Compact
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum MetricsCfg {
    PrometheusTextfile {
        path: String,
        #[serde(default)]
        labels: HashMap<String, String>,
    },
    PrometheusHttp {
        listen: String,
        #[serde(default)]
        labels: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum OperatorCfg {
    LocalHttp {
        listen: String,
        #[serde(default)]
        auth: Option<OperatorAuthCfg>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum OperatorAuthCfg {
    BearerTokenFile { path: PathBuf },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum SchedulerCfg {
    Cake {},
    Replicate {},
    LoadBalance {
        mode: LoadBalanceModeCfg,
        #[serde(default = "default_sticky_ttl_secs")]
        sticky_ttl_secs: u64,
    },
}

impl Default for SchedulerCfg {
    fn default() -> Self {
        Self::Cake {}
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceModeCfg {
    RoundRobin,
    StickySessions,
    ConsistentHashing,
}

fn default_sticky_ttl_secs() -> u64 {
    600
}

/// Operator projection of the core L4 `TrafficClass` for direct sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum TrafficClassCfg {
    Interactive,
    Bulk,
    Control,
    Probe,
}

impl TrafficClassCfg {
    pub fn to_core(self) -> mesh_bus_core::TrafficClass {
        match self {
            Self::Interactive => mesh_bus_core::TrafficClass::Interactive,
            Self::Bulk => mesh_bus_core::TrafficClass::Bulk,
            Self::Control => mesh_bus_core::TrafficClass::Control,
            Self::Probe => mesh_bus_core::TrafficClass::Probe,
        }
    }
}

/// Operator projection of the mesh-peer UDP wire envelope selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NativeEventModeCfg {
    #[default]
    SecureUdpNative,
    MeshFrame,
}

impl NativeEventModeCfg {
    pub fn to_proto(self) -> mb_proto_mesh::NativeEventMode {
        match self {
            Self::SecureUdpNative => mb_proto_mesh::NativeEventMode::SecureUdpNative,
            Self::MeshFrame => mb_proto_mesh::NativeEventMode::MeshFrame,
        }
    }
}

/// Operator projection of the per-egress delivery policy. It changes only
/// delivery coordinates; `steer` (the default) keeps existing configs
/// byte-for-byte unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryModeCfg {
    #[default]
    Steer,
    Stripe,
    Replicate,
    Repair,
    Probe,
}

impl DeliveryModeCfg {
    pub fn to_proto(self) -> mb_proto_mesh::DeliveryMode {
        match self {
            Self::Steer => mb_proto_mesh::DeliveryMode::Steer,
            Self::Stripe => mb_proto_mesh::DeliveryMode::Stripe,
            Self::Replicate => mb_proto_mesh::DeliveryMode::Replicate,
            Self::Repair => mb_proto_mesh::DeliveryMode::Repair,
            Self::Probe => mb_proto_mesh::DeliveryMode::Probe,
        }
    }
}

fn default_replicate_fanout() -> u8 {
    2
}

fn default_probe_budget() -> u8 {
    4
}

/// One ingress listener entry.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum IngressCfg {
    Socks5 {
        listen: String,
        #[serde(default)]
        rule_chain_path: Option<String>,
        #[serde(default)]
        auth: Option<AuthCfg>,
        #[serde(default)]
        handshake_timeout_ms: Option<u64>,
        #[serde(default)]
        accept_backoff_ms: Option<u64>,
        #[serde(default)]
        max_connections: Option<usize>,
        #[serde(default)]
        udp_forward_concurrency: Option<usize>,
        #[serde(default)]
        socket_recv_buffer_bytes: Option<usize>,
        #[serde(default)]
        socket_send_buffer_bytes: Option<usize>,
    },
    HttpConnect {
        listen: String,
        #[serde(default)]
        auth: Option<AuthCfg>,
        #[serde(default)]
        handshake_timeout_ms: Option<u64>,
        #[serde(default)]
        max_header_bytes: Option<usize>,
        #[serde(default)]
        max_connections: Option<usize>,
        #[serde(default)]
        socket_recv_buffer_bytes: Option<usize>,
        #[serde(default)]
        socket_send_buffer_bytes: Option<usize>,
    },
    Tcp {
        listen: String,
        target: String,
        #[serde(default)]
        route_group: Option<String>,
        #[serde(default)]
        traffic_class: Option<TrafficClassCfg>,
        #[serde(default)]
        deadline_ms: Option<u64>,
        #[serde(default)]
        source_label: Option<String>,
        #[serde(default)]
        socket_recv_buffer_bytes: Option<usize>,
        #[serde(default)]
        socket_send_buffer_bytes: Option<usize>,
    },
    Udp {
        listen: String,
        target: String,
        #[serde(default)]
        route_group: Option<String>,
        #[serde(default)]
        traffic_class: Option<TrafficClassCfg>,
        #[serde(default)]
        deadline_ms: Option<u64>,
        #[serde(default)]
        source_label: Option<String>,
        #[serde(default)]
        socket_recv_buffer_bytes: Option<usize>,
        #[serde(default)]
        socket_send_buffer_bytes: Option<usize>,
    },
    MeshPeerUdp {
        listen: String,
        #[serde(default)]
        native_event_mode: NativeEventModeCfg,
    },
}

impl IngressCfg {
    pub fn pipeline_source_kind(&self) -> Option<&'static str> {
        match self {
            Self::Socks5 { .. }
            | Self::HttpConnect { .. }
            | Self::Tcp { .. }
            | Self::Udp { .. } => Some("application/source"),
            Self::MeshPeerUdp { .. } => None,
        }
    }

    pub fn supports_pipeline(&self) -> bool {
        self.pipeline_source_kind().is_some()
    }
}

/// RFC 1929 user/password authentication for SOCKS5 ingress.
///
/// `users` is a list of `{ name, password }` pairs. An empty list disables
/// auth (clients negotiate NoAuth as before).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCfg {
    #[serde(default)]
    pub users: Vec<AuthUserCfg>,
}

impl std::fmt::Debug for AuthCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCfg")
            .field("users", &self.users)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthUserCfg {
    pub name: String,
    pub password: String,
}

impl std::fmt::Debug for AuthUserCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthUserCfg")
            .field("name", &self.name)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// RFC 1929 credentials presented to an upstream SOCKS5 proxy by a
/// `Socks5Udp` egress. This is a single client-side `{ username, password }`
/// pair, distinct from ingress `AuthCfg.users` which authenticates inbound
/// clients.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5UpstreamAuthCfg {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Socks5UpstreamAuthCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5UpstreamAuthCfg")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// One egress exit entry.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum EgressCfg {
    Tcp {
        id: String,
        #[serde(default)]
        wan_id: Option<String>,
        #[serde(default = "default_priority")]
        priority: u32,
        #[serde(default)]
        groups: Vec<String>,
        timeout_ms: u64,
        #[serde(default)]
        socket_recv_buffer_bytes: Option<usize>,
        #[serde(default)]
        socket_send_buffer_bytes: Option<usize>,
    },
    Socks5 {
        id: String,
        #[serde(default)]
        wan_id: Option<String>,
        #[serde(default = "default_priority")]
        priority: u32,
        #[serde(default)]
        groups: Vec<String>,
        upstream: String,
        timeout_ms: u64,
    },
    Socks5Udp {
        id: String,
        #[serde(default)]
        wan_id: Option<String>,
        #[serde(default = "default_priority")]
        priority: u32,
        #[serde(default)]
        groups: Vec<String>,
        upstream: String,
        timeout_ms: u64,
        #[serde(default)]
        auth: Option<Socks5UpstreamAuthCfg>,
    },
    Udp {
        id: String,
        #[serde(default)]
        wan_id: Option<String>,
        #[serde(default = "default_priority")]
        priority: u32,
        #[serde(default)]
        groups: Vec<String>,
        timeout_ms: u64,
        #[serde(default)]
        socket_recv_buffer_bytes: Option<usize>,
        #[serde(default)]
        socket_send_buffer_bytes: Option<usize>,
    },
    MeshPeerUdp {
        id: String,
        peer_id: String,
        peer: String,
        #[serde(default)]
        wan_id: Option<String>,
        #[serde(default = "default_priority")]
        priority: u32,
        #[serde(default)]
        groups: Vec<String>,
        #[serde(default)]
        native_event_mode: NativeEventModeCfg,
        #[serde(default)]
        delivery_mode: DeliveryModeCfg,
        #[serde(default = "default_replicate_fanout")]
        replicate_fanout: u8,
        #[serde(default = "default_probe_budget")]
        probe_budget: u8,
        timeout_ms: u64,
    },
    ServiceTcp {
        id: String,
        service_id: String,
        #[serde(default)]
        wan_id: Option<String>,
        #[serde(default = "default_priority")]
        priority: u32,
        #[serde(default)]
        route_group: Option<String>,
        #[serde(default)]
        groups: Vec<String>,
        connect: String,
        timeout_ms: u64,
    },
    ServiceUdp {
        id: String,
        service_id: String,
        #[serde(default)]
        wan_id: Option<String>,
        #[serde(default = "default_priority")]
        priority: u32,
        #[serde(default)]
        route_group: Option<String>,
        #[serde(default)]
        groups: Vec<String>,
        connect: String,
        timeout_ms: u64,
        #[serde(default)]
        socket_recv_buffer_bytes: Option<usize>,
        #[serde(default)]
        socket_send_buffer_bytes: Option<usize>,
    },
}

fn default_priority() -> u32 {
    1
}

impl EgressCfg {
    pub fn id(&self) -> &str {
        match self {
            EgressCfg::Tcp { id, .. }
            | EgressCfg::Socks5 { id, .. }
            | EgressCfg::Socks5Udp { id, .. }
            | EgressCfg::Udp { id, .. }
            | EgressCfg::MeshPeerUdp { id, .. }
            | EgressCfg::ServiceTcp { id, .. }
            | EgressCfg::ServiceUdp { id, .. } => id,
        }
    }

    pub fn wan_id(&self) -> &str {
        match self {
            EgressCfg::Tcp { id, wan_id, .. }
            | EgressCfg::Socks5 { id, wan_id, .. }
            | EgressCfg::Socks5Udp { id, wan_id, .. }
            | EgressCfg::Udp { id, wan_id, .. }
            | EgressCfg::MeshPeerUdp { id, wan_id, .. }
            | EgressCfg::ServiceTcp { id, wan_id, .. }
            | EgressCfg::ServiceUdp { id, wan_id, .. } => wan_id.as_deref().unwrap_or(id),
        }
    }

    pub fn priority(&self) -> u32 {
        self.raw_priority().max(1)
    }

    pub(crate) fn raw_priority(&self) -> u32 {
        match self {
            EgressCfg::Tcp { priority, .. }
            | EgressCfg::Socks5 { priority, .. }
            | EgressCfg::Socks5Udp { priority, .. }
            | EgressCfg::Udp { priority, .. }
            | EgressCfg::MeshPeerUdp { priority, .. }
            | EgressCfg::ServiceTcp { priority, .. }
            | EgressCfg::ServiceUdp { priority, .. } => *priority,
        }
    }

    pub fn groups(&self) -> &[String] {
        match self {
            EgressCfg::Tcp { groups, .. }
            | EgressCfg::Socks5 { groups, .. }
            | EgressCfg::Socks5Udp { groups, .. }
            | EgressCfg::Udp { groups, .. }
            | EgressCfg::MeshPeerUdp { groups, .. }
            | EgressCfg::ServiceTcp { groups, .. }
            | EgressCfg::ServiceUdp { groups, .. } => groups,
        }
    }

    pub fn pipeline_sink_kind(&self) -> &'static str {
        match self {
            EgressCfg::Tcp { .. } | EgressCfg::Socks5 { .. } | EgressCfg::ServiceTcp { .. } => {
                "stream_egress"
            }
            EgressCfg::MeshPeerUdp { .. } => "stream_egress",
            EgressCfg::Socks5Udp { .. } | EgressCfg::Udp { .. } | EgressCfg::ServiceUdp { .. } => {
                "datagram_egress"
            }
        }
    }

    pub fn pipeline_capability_bits(&self) -> (bool, bool) {
        match self {
            EgressCfg::Tcp { .. } | EgressCfg::Socks5 { .. } | EgressCfg::ServiceTcp { .. } => {
                (true, false)
            }
            EgressCfg::Socks5Udp { .. } | EgressCfg::Udp { .. } | EgressCfg::ServiceUdp { .. } => {
                (false, true)
            }
            EgressCfg::MeshPeerUdp { .. } => (true, true),
        }
    }

    pub(crate) fn timeout_ms(&self) -> u64 {
        match self {
            EgressCfg::Tcp { timeout_ms, .. }
            | EgressCfg::Socks5 { timeout_ms, .. }
            | EgressCfg::Socks5Udp { timeout_ms, .. }
            | EgressCfg::Udp { timeout_ms, .. }
            | EgressCfg::MeshPeerUdp { timeout_ms, .. }
            | EgressCfg::ServiceTcp { timeout_ms, .. }
            | EgressCfg::ServiceUdp { timeout_ms, .. } => *timeout_ms,
        }
    }

    pub(crate) fn peer_id(&self) -> Option<&str> {
        match self {
            EgressCfg::MeshPeerUdp { peer_id, .. } => Some(peer_id),
            _ => None,
        }
    }

    pub(crate) fn native_event_mode(&self) -> mb_proto_mesh::NativeEventMode {
        match self {
            EgressCfg::MeshPeerUdp {
                native_event_mode, ..
            } => native_event_mode.to_proto(),
            _ => mb_proto_mesh::NativeEventMode::default(),
        }
    }

    /// Per-egress delivery policy as `(mode, replicate_fanout, probe_budget)`.
    /// Non-mesh-peer egresses report the default Steer tuple.
    pub(crate) fn delivery_policy(&self) -> (mb_proto_mesh::DeliveryMode, u8, u8) {
        match self {
            EgressCfg::MeshPeerUdp {
                delivery_mode,
                replicate_fanout,
                probe_budget,
                ..
            } => (delivery_mode.to_proto(), *replicate_fanout, *probe_budget),
            _ => (mb_proto_mesh::DeliveryMode::Steer, 2, 4),
        }
    }
}

impl SchedulerCfg {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cake { .. } => "Cake",
            Self::Replicate { .. } => "Replicate",
            Self::LoadBalance { .. } => "LoadBalance",
        }
    }
}

impl LogFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }
}

impl MetricsCfg {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PrometheusTextfile { .. } => "PrometheusTextfile",
            Self::PrometheusHttp { .. } => "PrometheusHttp",
        }
    }
}

impl From<LoadBalanceModeCfg> for LoadBalanceMode {
    fn from(value: LoadBalanceModeCfg) -> Self {
        match value {
            LoadBalanceModeCfg::RoundRobin => Self::RoundRobin,
            LoadBalanceModeCfg::StickySessions => Self::StickySessions,
            LoadBalanceModeCfg::ConsistentHashing => Self::ConsistentHashing,
        }
    }
}

/// Parse a `Config` from a YAML string.
pub fn parse_config(yaml: &str) -> anyhow::Result<Config> {
    let mut cfg: Config =
        serde_yaml::from_str(yaml).map_err(|e| anyhow!("config parse error: {e}"))?;
    for egress in &mut cfg.egresses {
        if let EgressCfg::ServiceTcp {
            route_group: Some(rg),
            groups,
            ..
        }
        | EgressCfg::ServiceUdp {
            route_group: Some(rg),
            groups,
            ..
        } = egress
        {
            if !rg.is_empty() && !groups.iter().any(|g| g == rg) {
                groups.push(rg.clone());
            }
        }
    }
    validate_config(&cfg)?;
    Ok(cfg)
}
