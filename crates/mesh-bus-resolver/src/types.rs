use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QType {
    A,
    Aaaa,
    Ptr,
    Cname,
    Txt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    pub qname: String,
    pub qtype: QType,
    pub consumer: ConsumerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveAnswer {
    pub records: Vec<AnswerRecord>,
    pub source: ResolverSource,
    pub truncated: bool,
    pub rtt: Duration,
    /// RFC 2181 §5.2 — minimum TTL across the answer RRset, capped to the cache's
    /// own max-TTL policy at write time. Default 60s when the source has no wire
    /// TTL available (system/getaddrinfo, IP literal, empty answer).
    pub min_rr_ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerRecord {
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Ptr(String),
    Cname(String),
    Txt(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverSource {
    System,
    MeshDirect { server: SocketAddr },
    Tunneled { server: SocketAddr },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPolicy {
    RoundRobin,
    ConsistentHash,
    FanOut { k: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolMode {
    SystemMode,
    MeshDirect { server_policy: ServerPolicy },
    Tunneled { server_policy: ServerPolicy },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub id: String,
    pub mode: PoolMode,
    pub servers: Vec<UpstreamServer>,
    pub route_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamServer {
    pub scheme: UpstreamScheme,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Udp,
    Tcp,
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("denied by rule")]
    Denied,
    #[error("nxdomain")]
    NxDomain,
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("upstream io: {0}")]
    Io(String),
    #[error("decode: {0}")]
    Decode(#[from] mb_proto_dns::DecodeError),
    #[error("pool not found: {0}")]
    PoolNotFound(String),
    #[error("no datagram-capable bus port")]
    NoDatagramPort,
    #[error("no stream-capable bus port")]
    NoStreamPort,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolutionSignals {
    pub qname_key: String,
    pub pool: String,
    pub resolver_rtt_ms: u64,
    pub winner_exit: WinnerExit,
    pub attempted: u32,
    pub answer_count: u32,
    pub truncated: bool,
    pub matched_rule_id: Option<String>,
    pub matched_rule_index: Option<u32>,
    pub default_used: bool,
    pub action: String,
    pub schedule_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinnerExit {
    SinglePath {
        server: SocketAddr,
    },
    FanOut {
        winner: SocketAddr,
        losers: Vec<SocketAddr>,
    },
    System,
}

impl Default for WinnerExit {
    fn default() -> Self {
        Self::System
    }
}
