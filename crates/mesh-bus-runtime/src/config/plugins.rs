//! Ingress and egress plugin operator config.

use serde::Deserialize;

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
