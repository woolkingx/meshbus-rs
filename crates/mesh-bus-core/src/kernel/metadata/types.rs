use bytes::Bytes;

/// Extension map — linear-scan Vec keeps the hot path allocation-light.
pub type SmallMap = Vec<(&'static str, MetaValue)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaValue {
    String(String),
    U64(u64),
    Bool(bool),
    Bytes(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleHintLabel {
    Ordered,
    FanOut,
    Stripe,
}

#[derive(Debug, Clone, Default)]
pub struct NetMeta {
    pub src_ip: Option<String>,
    pub dst_host: Option<String>,
    pub dst_port: Option<u16>,
    /// L4 transport-family hint for capability matching, not an adapter protocol label.
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TransportMeta {
    pub deadline_ms: Option<u64>,
    pub schedule_hint: Option<ScheduleHintLabel>,
    pub schedule_fanout_k: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyMeta {
    pub route_group: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthMeta {
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TraceMeta {
    pub flow_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TypedMap {
    pub net: NetMeta,
    pub transport: TransportMeta,
    pub policy: PolicyMeta,
    pub auth: AuthMeta,
    pub trace: TraceMeta,
    pub ext: SmallMap,
}
