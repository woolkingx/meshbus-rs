use crate::{
    Capabilities, CloseReason, ExitId, FlowId, FlowSemantics, Measurement, ReturnSemantics,
    SessionId, TrafficClass,
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::net::TcpStream as StdTcpStream;
use std::sync::Arc;

pub use crate::transport::forwarding::{ScheduleHint, ScheduleMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusSessionRequest {
    pub target: Endpoint,
    pub flow_semantics: FlowSemantics,
    pub traffic_class: TrafficClass,
    pub deadline_ms: Option<u64>,
    pub policy_ref: Option<String>,
    pub return_semantics: ReturnSemantics,
    pub schedule_hint: ScheduleHint,
    pub source_key: Option<String>,
    pub target_key: Option<String>,
    pub route_group: Option<String>,
    pub target_sink: Option<String>,
}

impl BusSessionRequest {
    pub fn stream(target: Endpoint) -> Self {
        Self {
            target,
            flow_semantics: FlowSemantics::ByteStream,
            traffic_class: TrafficClass::Bulk,
            deadline_ms: None,
            policy_ref: None,
            return_semantics: ReturnSemantics::Direct,
            schedule_hint: ScheduleHint::Auto,
            source_key: None,
            target_key: None,
            route_group: None,
            target_sink: None,
        }
    }

    pub fn datagram(target: Endpoint) -> Self {
        Self {
            target,
            flow_semantics: FlowSemantics::Datagram,
            traffic_class: TrafficClass::Interactive,
            deadline_ms: None,
            policy_ref: None,
            return_semantics: ReturnSemantics::PacketDedup,
            schedule_hint: ScheduleHint::Auto,
            source_key: None,
            target_key: None,
            route_group: None,
            target_sink: None,
        }
    }

    pub fn with_source_key(mut self, key: impl Into<String>) -> Self {
        self.source_key = Some(key.into());
        self
    }

    pub fn with_target_key(mut self, key: impl Into<String>) -> Self {
        self.target_key = Some(key.into());
        self
    }

    pub fn with_route_group(mut self, group: impl Into<String>) -> Self {
        self.route_group = Some(group.into());
        self
    }

    pub fn with_target_sink(mut self, sink: impl Into<String>) -> Self {
        self.target_sink = Some(sink.into());
        self
    }

    pub fn with_schedule_hint(mut self, hint: ScheduleHint) -> Self {
        self.schedule_hint = hint;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisconnectReason {
    ConnectionRefused,
    NetworkUnreachable,
    HostUnreachable,
    TtlExpired,
    TimedOut,
    UpstreamEof,
    ConnectionReset,
    NotConnected,
    NoUsableExit,
    SessionClosed,
    ReaderClosed,
    AddressNotSupported,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct BusSessionInfo {
    pub session_id: SessionId,
    pub flow_id: FlowId,
    pub schedule_mode: ScheduleMode,
    pub paths: Vec<BusPathInfo>,
    pub primary: usize,
    pub path_trace: Vec<ExitId>,
    pub started_at_ms: u64,
}

impl BusSessionInfo {
    pub fn empty_for_test(schedule_mode: ScheduleMode) -> Self {
        Self {
            session_id: SessionId("test-session".into()),
            flow_id: FlowId("test-flow".into()),
            schedule_mode,
            paths: Vec::new(),
            primary: 0,
            path_trace: Vec::new(),
            started_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BusPathInfo {
    pub exit_id: ExitId,
    pub local: Endpoint,
    pub remote: Endpoint,
    pub measurement: Measurement,
    pub state: PathState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathState {
    Connecting,
    Active,
    Degraded,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendError {
    BufferFull,
    AddressNotSupported,
    PayloadTooLarge,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSpliceDirection {
    Up,
    Down,
}

#[async_trait]
pub trait TcpSpliceAccounting: Send + Sync + 'static {
    fn add_bytes(&self, direction: TcpSpliceDirection, bytes: u64);
    async fn close_once(&self, reason: CloseReason);
}

pub struct TcpSpliceSession {
    stream: StdTcpStream,
    accounting: Option<Arc<dyn TcpSpliceAccounting>>,
}

impl TcpSpliceSession {
    pub fn new(stream: StdTcpStream) -> Self {
        Self {
            stream,
            accounting: None,
        }
    }

    pub fn with_accounting(mut self, accounting: Arc<dyn TcpSpliceAccounting>) -> Self {
        self.accounting = Some(accounting);
        self
    }

    pub fn accounting(&self) -> Option<Arc<dyn TcpSpliceAccounting>> {
        self.accounting.clone()
    }

    pub fn into_std(self) -> StdTcpStream {
        self.stream
    }
}

#[async_trait]
pub trait StreamSession: Send + 'static {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason>;
    fn into_tcp_splice(self: Box<Self>) -> Result<TcpSpliceSession, Box<dyn StreamSession>>;
    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>);
    async fn abort(&mut self, reason: DisconnectReason);
    fn info(&self) -> &BusSessionInfo;
    fn last_error(&self) -> Option<&DisconnectReason>;
}

#[async_trait]
pub trait StreamSendHalf: Send + 'static {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason>;
    async fn shutdown_write(&mut self);
    async fn abort(&mut self, reason: DisconnectReason);
}

#[async_trait]
pub trait StreamRecvHalf: Send + 'static {
    async fn recv(&mut self) -> Option<Bytes>;
    fn last_error(&self) -> Option<&DisconnectReason>;
}

#[async_trait]
pub trait DatagramSendHalf: Send + 'static {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError>;
    async fn close(&mut self);
}

#[async_trait]
pub trait DatagramRecvHalf: Send + 'static {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)>;
    fn last_error(&self) -> Option<&DisconnectReason>;
}

#[async_trait]
pub trait DatagramSession: Send + 'static {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError>;
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)>;
    fn info(&self) -> &BusSessionInfo;
    fn max_payload_bytes(&self) -> usize;
    async fn close(&mut self);
    fn split(self: Box<Self>) -> (Box<dyn DatagramSendHalf>, Box<dyn DatagramRecvHalf>);
}

#[async_trait]
pub trait StreamEgress: Send + Sync + 'static {
    fn id(&self) -> &ExitId;
    fn capabilities(&self) -> &Capabilities;
    async fn open_stream(
        &self,
        request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason>;
}

#[async_trait]
pub trait DatagramEgress: Send + Sync + 'static {
    fn id(&self) -> &ExitId;
    fn capabilities(&self) -> &Capabilities;
    fn max_payload_bytes(&self) -> usize;
    async fn open_datagram(
        &self,
        request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn DatagramSession>, DisconnectReason>;
}

// Bus* names — canonical for new code; same trait, different alias.
pub use DatagramEgress as BusDatagramEgress;
pub use DatagramRecvHalf as BusDatagramRecvHalf;
pub use DatagramSendHalf as BusDatagramSendHalf;
pub use DatagramSession as BusDatagramSession;
pub use StreamEgress as BusStreamEgress;
pub use StreamRecvHalf as BusStreamRecvHalf;
pub use StreamSendHalf as BusStreamSendHalf;
pub use StreamSession as BusStreamSession;
