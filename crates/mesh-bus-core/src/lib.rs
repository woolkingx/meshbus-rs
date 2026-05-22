mod egress_adapter;
pub mod kernel;
pub mod transport;

pub use kernel::session_handle::SessionHandle;
pub use kernel::{
    Bus, BusBuilder, BusError, BusEvent, BusHandle, BusPort, BusSnapshotClient, Registry,
};
pub use transport::forwarding::{
    Capabilities, CloseReason, ExitResult, FlowSemantics, Measurement, RankContext,
    ReturnSemantics, ScheduleDecision, ScheduleHint, ScheduleMode, TrafficClass,
};
pub use transport::session::{
    BusDatagramEgress, BusDatagramRecvHalf, BusDatagramSendHalf, BusDatagramSession, BusPathInfo,
    BusSessionInfo, BusSessionRequest, BusStreamEgress, BusStreamRecvHalf, BusStreamSendHalf,
    BusStreamSession, DisconnectReason, PathState, SendError, TcpSpliceAccounting,
    TcpSpliceDirection, TcpSpliceSession,
};
pub use transport::session::{
    DatagramEgress, DatagramRecvHalf, DatagramSendHalf, DatagramSession, StreamEgress,
    StreamRecvHalf, StreamSendHalf, StreamSession,
};

use async_trait::async_trait;

#[allow(unused_imports)]
use mesh_bus_schema as schema;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExitId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketId(pub u64);

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Frame {
    pub packet_id: PacketId,
    pub flow_id: FlowId,
    pub session_id: SessionId,
    pub seq: u64,
    pub kind: FrameKind,
    pub payload: bytes::Bytes,
    pub target: mb_endpoint::Endpoint,
    pub ttl: u8,
    pub traffic_class: TrafficClass,
    pub policy_ref: Option<String>,
    pub deadline_ms: Option<u64>,
    pub schedule_hint: ScheduleHint,
    pub path_trace: Vec<String>,
    pub flow_semantics: FlowSemantics,
    pub return_semantics: ReturnSemantics,
    pub source_key: Option<String>,
    pub target_key: Option<String>,
    pub route_group: Option<String>,
    pub target_sink: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameKind {
    Open,
    Data,
    Datagram,
    ShutdownWrite,
    Close,
    Cancel,
    Probe,
}

impl FlowId {
    /// L4-owned flow identity. Minted in the L4 data plane (Frame constructors);
    /// L5 only *carries* it via BusSessionInfo and must not author its own copy.
    /// Opaque: deterministic over (session_id, target) so every frame of one
    /// logical flow collides to one id (affinity invariant), without embedding
    /// the L7 host naming atom in cleartext.
    pub fn mint_for(session_id: &SessionId, target: &mb_endpoint::Endpoint) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        session_id.0.hash(&mut h);
        target.host().hash(&mut h);
        target.port().hash(&mut h);
        Self(format!("f{:016x}", h.finish()))
    }
}

impl Frame {
    pub fn open(session_id: SessionId, target: mb_endpoint::Endpoint) -> Self {
        let flow_id = FlowId::mint_for(&session_id, &target);
        Self {
            packet_id: PacketId(0),
            flow_id,
            session_id,
            seq: 0,
            kind: FrameKind::Open,
            payload: bytes::Bytes::new(),
            target,
            ttl: 8,
            traffic_class: TrafficClass::Control,
            policy_ref: None,
            deadline_ms: None,
            schedule_hint: ScheduleHint::Auto,
            path_trace: Vec::new(),
            flow_semantics: FlowSemantics::ByteStream,
            return_semantics: ReturnSemantics::Direct,
            source_key: None,
            target_key: None,
            route_group: None,
            target_sink: None,
        }
    }

    pub fn data(
        session_id: SessionId,
        seq: u64,
        target: mb_endpoint::Endpoint,
        payload: bytes::Bytes,
    ) -> Self {
        let flow_id = FlowId::mint_for(&session_id, &target);
        Self {
            packet_id: PacketId(seq),
            flow_id,
            session_id,
            seq,
            kind: FrameKind::Data,
            payload,
            target,
            ttl: 8,
            traffic_class: TrafficClass::Bulk,
            policy_ref: None,
            deadline_ms: None,
            schedule_hint: ScheduleHint::Auto,
            path_trace: Vec::new(),
            flow_semantics: FlowSemantics::ByteStream,
            return_semantics: ReturnSemantics::Direct,
            source_key: None,
            target_key: None,
            route_group: None,
            target_sink: None,
        }
    }

    pub fn datagram(
        session_id: SessionId,
        seq: u64,
        target: mb_endpoint::Endpoint,
        payload: bytes::Bytes,
    ) -> Self {
        let flow_id = FlowId::mint_for(&session_id, &target);
        Self {
            packet_id: PacketId(seq),
            flow_id,
            session_id,
            seq,
            kind: FrameKind::Datagram,
            payload,
            target,
            ttl: 8,
            traffic_class: TrafficClass::Interactive,
            policy_ref: None,
            deadline_ms: None,
            schedule_hint: ScheduleHint::Auto,
            path_trace: Vec::new(),
            flow_semantics: FlowSemantics::Datagram,
            return_semantics: ReturnSemantics::PacketDedup,
            source_key: None,
            target_key: None,
            route_group: None,
            target_sink: None,
        }
    }

    pub fn close(session_id: SessionId, seq: u64, target: mb_endpoint::Endpoint) -> Self {
        let flow_id = FlowId::mint_for(&session_id, &target);
        Self {
            packet_id: PacketId(seq),
            flow_id,
            session_id,
            seq,
            kind: FrameKind::Close,
            payload: bytes::Bytes::new(),
            target,
            ttl: 8,
            traffic_class: TrafficClass::Control,
            policy_ref: None,
            deadline_ms: None,
            schedule_hint: ScheduleHint::Auto,
            path_trace: Vec::new(),
            flow_semantics: FlowSemantics::ByteStream,
            return_semantics: ReturnSemantics::Direct,
            source_key: None,
            target_key: None,
            route_group: None,
            target_sink: None,
        }
    }

    pub fn shutdown_write(session_id: SessionId, seq: u64, target: mb_endpoint::Endpoint) -> Self {
        let mut frame = Self::close(session_id, seq, target);
        frame.kind = FrameKind::ShutdownWrite;
        frame
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReturnEvent {
    Connected {
        exit_id: ExitId,
        local_endpoint: Option<mb_endpoint::Endpoint>,
        rtt_ms: u64,
    },
    Data {
        seq: u64,
        payload: bytes::Bytes,
    },
    Idle,
    Closed {
        reason: CloseReason,
    },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExitSnapshot {
    pub exit_id: ExitId,
    pub protocol: String,
    pub supports_stream: bool,
    pub supports_datagram: bool,
    pub send_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub last_rtt_ms: u64,
    pub payload_bytes_total: u64,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BusSnapshot {
    pub exits: Vec<ExitSnapshot>,
    pub dispatch_success: u64,
    pub dispatch_failure: u64,
    pub bytes_sent: u64,
    pub meshsec_drop_total: u64,
    pub meshsec_auth_drop_total: u64,
    pub meshsec_replay_drop_total: u64,
    pub native_drop_total: u64,
    pub native_queue_overflow_drop_total: u64,
    pub flows: Vec<(FlowId, kernel::forwarder::FlowCountersSnapshot)>,
}

/// Dispatch-layer egress plugin. Implementations control Frame forwarding.
///
/// # Published owner-test data contract (0.4.39)
/// This trait is public so that `dispatch_contract` integration tests can implement
/// test egresses using the same real API. Runtime application participants (L7
/// ingress/egress crates) must NOT implement this trait for routing or runtime wiring;
/// they must use `StreamEgress`/`DatagramEgress` instead.
#[async_trait]
pub trait EgressPlugin: Send + Sync + 'static {
    fn id(&self) -> &ExitId;
    fn capabilities(&self) -> &Capabilities;
    async fn open_forwarder_stream(
        &self,
        _frame: &Frame,
    ) -> Option<Result<kernel::forwarder::OpenedForwarderStream, DisconnectReason>> {
        None
    }
    async fn open_forwarder_datagram(
        &self,
        _frame: &Frame,
    ) -> Option<Result<kernel::forwarder::OpenedForwarderDatagram, DisconnectReason>> {
        None
    }
    async fn send(&self, frame: Frame) -> ExitResult;
    async fn poll(&self, session_id: &SessionId) -> ReturnEvent;
    async fn probe(&self, target: &mb_endpoint::Endpoint) -> Measurement;
    async fn close(&self, session_id: &SessionId);
}

pub trait SchedulerPlugin: Send + Sync + 'static {
    fn schedule(&self, candidates: &[ExitId], ctx: &RankContext) -> ScheduleDecision;

    fn feedback(&self, result: &ExitResult, payload_bytes: u64, at_ms: u64);

    fn on_observation(&self, _event: &kernel::observation::EventEnvelope) {}

    /// Numeric score for the given exit under the given context. Lower is better.
    /// Default impl returns 0 for all candidates, which disables hysteresis-based pin retention.
    fn score_for(&self, _exit_id: &ExitId, _candidates: &[ExitId], _ctx: &RankContext) -> u64 {
        0
    }

    /// Windowed goodput estimate for an exit in bytes/sec, if the scheduler maintains one.
    fn goodput_bps_for(&self, _exit_id: &ExitId) -> Option<u64> {
        None
    }
}

pub trait ObserverPlugin: Send + Sync + 'static {
    fn on_event(&self, event: &BusEvent);

    /// Core event types this observer subscribes to. Defaults to the full
    /// core set so existing observers keep identical fan-out; an observer
    /// may override this to narrow its routed subscription.
    fn subscribed_core_events(&self) -> &'static [kernel::observation::CoreEventId] {
        use kernel::observation::CoreEventId;
        &[
            CoreEventId::FlowOpened,
            CoreEventId::FlowClosed,
            CoreEventId::PathIoError,
        ]
    }

    fn subscribed_events(&self) -> &'static [kernel::observation::EventTypeId] {
        &[]
    }

    fn observation_writes(&self) -> &'static [kernel::observation::EventTypeId] {
        &[]
    }

    fn observation_pulls(&self) -> &'static [kernel::observation::PullSourceId] {
        &[]
    }
}

#[async_trait]
pub trait IngressPlugin: Send + 'static {
    fn name(&self) -> &str;
    async fn run(self: Box<Self>, port: BusPort) -> Result<(), BusError>;
}

#[cfg(test)]
mod conformance_datagram_tests;
#[cfg(test)]
mod conformance_stream_tests;
#[cfg(test)]
mod datagram_session_tests;
#[cfg(test)]
mod event_core_cost_tests;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod runtime_tests;
#[cfg(test)]
mod stream_session_tests;

/// Data-owner fixture: Frame construction + FlowId contract.
/// Owner: mesh-bus-core lib (Frame struct, FlowId::mint_for).
/// Schema: schemas/frame.schema.json.
/// No BusBuilder, no EgressPlugin, no SchedulerPlugin.
#[cfg(test)]
mod frame_construction_tests {
    use crate::{FlowId, Frame, FrameKind, ReturnSemantics, SessionId};
    use mb_endpoint::Endpoint;

    #[test]
    fn packet_header_classifies_flow_from_session_and_target() {
        // Temporal-free Frame construction: proves FlowId is deterministic over
        // (session, target) and does not embed the L7 host naming atom in cleartext
        // (data-ontology F2 invariant, schemas/frame.schema.json: flow_id field).
        let session = SessionId("s-1".into());
        let target = Endpoint::new("example.com", 443).expect("valid endpoint");
        let first = Frame::data(
            session.clone(),
            7,
            target.clone(),
            bytes::Bytes::from_static(b"a"),
        );
        let second = Frame::data(session, 8, target, bytes::Bytes::from_static(b"b"));

        assert_eq!(first.packet_id.0, 7);
        assert_eq!(second.packet_id.0, 8);
        assert_eq!(first.flow_id, second.flow_id);
        assert!(
            !first.flow_id.0.contains("example.com"),
            "FlowId leaks L7 host: {}",
            first.flow_id.0
        );
        assert_eq!(
            first.flow_id,
            FlowId::mint_for(
                &SessionId("s-1".into()),
                &Endpoint::new("example.com", 443).unwrap()
            )
        );
        assert_eq!(first.return_semantics, ReturnSemantics::Direct);
        assert_eq!(second.return_semantics, ReturnSemantics::Direct);
    }

    #[test]
    fn datagram_frame_uses_packet_dedup_return_semantics() {
        // Frame::datagram() sets PacketDedup return semantics per schema/frame contract.
        // Owner: mesh-bus-core lib; schema: schemas/frame.schema.json (return_semantics field).
        let session = SessionId("s-1".into());
        let target = Endpoint::new("example.com", 53).expect("valid endpoint");
        let frame = Frame::datagram(session, 3, target, bytes::Bytes::from_static(b"dgram"));

        assert_eq!(frame.kind, FrameKind::Datagram);
        assert_eq!(frame.return_semantics, ReturnSemantics::PacketDedup);
    }
}
