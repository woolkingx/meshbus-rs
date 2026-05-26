use crate::{ExitId, FlowId, PacketId, SessionId};
use mb_endpoint::Endpoint;

// --- FlowSemantics ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowSemantics {
    ByteStream,
    Datagram,
    Message,
}

// --- ReturnSemantics ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReturnSemantics {
    Direct,
    PacketDedup,
    SequenceReorder,
}

// --- TrafficClass ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrafficClass {
    Interactive,
    Bulk,
    Control,
    Probe,
}

// --- ScheduleHint ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScheduleHint {
    Auto,
    SinglePath,
    FanOut { k: usize },
    Stripe { n: usize },
}

// --- ScheduleMode ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScheduleMode {
    Ordered,
    Replicate,
    Stripe,
}

// --- ScheduleDecision ---

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScheduleDecision {
    Ordered(Vec<usize>),
    Replicate(Vec<usize>),
}

impl ScheduleDecision {
    pub fn ordered(order: Vec<usize>) -> Self {
        Self::Ordered(order)
    }

    pub fn replicate(order: Vec<usize>) -> Self {
        Self::Replicate(order)
    }

    pub fn indices(&self) -> &[usize] {
        match self {
            Self::Ordered(order) | Self::Replicate(order) => order,
        }
    }
}

// --- Capabilities ---

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub protocol: String,
    pub supports_stream: bool,
    pub supports_datagram: bool,
    pub max_payload_bytes: Option<u64>,
    pub groups: Vec<String>,
}

// --- Measurement ---

#[derive(Debug, Clone)]
pub struct Measurement {
    pub exit_id: ExitId,
    pub at_ms: u64,
    pub rtt_ms: u64,
    pub payload_bytes: u64,
    pub jitter_ms: Option<u64>,
    pub throughput_bps: Option<u64>,
    pub success: bool,
}

// --- ExitResult ---

#[derive(Debug, Clone)]
pub struct ExitResult {
    pub exit_id: ExitId,
    pub success: bool,
    pub rtt_ms: u64,
    pub local_endpoint: Option<Endpoint>,
    pub return_event: crate::ReturnEvent,
}

// --- CloseReason ---

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    TtlExpired,
    SessionClosed,
    NoUsableExit,
    ConnectionRefused,
    NetworkUnreachable,
    HostUnreachable,
    TimedOut,
    NotConnected,
    ConnectionReset,
    UpstreamEof,
    ReaderClosed,
    AddressNotSupported,
    Other(String),
}

// --- RankContext ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceActivity {
    pub active_flows: u32,
    pub idle_since_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RankContext {
    pub packet_id: PacketId,
    pub flow_id: FlowId,
    pub session_id: SessionId,
    pub target: Endpoint,
    pub traffic_class: TrafficClass,
    pub policy_ref: Option<String>,
    pub deadline_ms: Option<u64>,
    pub schedule_hint: ScheduleHint,
    pub flow_semantics: FlowSemantics,
    pub return_semantics: ReturnSemantics,
    pub source_key: Option<String>,
    pub target_key: Option<String>,
    pub source_activity: Option<SourceActivity>,
}
