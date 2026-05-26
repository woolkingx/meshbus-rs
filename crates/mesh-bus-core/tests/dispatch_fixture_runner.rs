//! Dispatch SERVICE composition tests represented as YAML fixtures.
//!
//! Fixture rows own scenario data. Rust only interprets `case` through the
//! real public dispatch boundary.

mod dispatch_double;

use async_trait::async_trait;
use bytes::Bytes;
use dispatch_double::{Behavior, First, RecordingScheduler, TestEgress};
use mb_endpoint::Endpoint;
use mesh_bus_core::kernel::observation::{CoreEventId, EventTypeId};
use mesh_bus_core::{
    BusBuilder, BusEvent, BusSessionInfo, BusSessionRequest, Capabilities, CloseReason,
    DisconnectReason, ExitId, ExitResult, FlowId, Frame, PacketId, RankContext, ReturnEvent,
    ScheduleDecision, ScheduleHint, SchedulerPlugin, StreamEgress, StreamRecvHalf, StreamSendHalf,
    StreamSession, TrafficClass,
};
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::time::{Duration, timeout};

#[path = "dispatch_fixture_runner/execute.rs"]
mod execute;
use execute::{execute_datagram, execute_route_group, execute_stream, load_rows};

#[derive(Deserialize)]
struct FixtureRow {
    id: String,
    owner: String,
    kind: String,
    case: String,
    schema_ref: String,
    input: Input,
    expect: Expect,
    #[serde(default)]
    observations: Vec<Value>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct Input {
    target: Target,
    #[serde(default)]
    route_group: Option<String>,
    egresses: Vec<FixtureEgress>,
    #[serde(default)]
    scenario: Scenario,
    #[serde(default)]
    scheduler_context: Option<RankContextInput>,
    #[serde(default)]
    datagram: Option<DatagramScenario>,
}

#[derive(Clone, Deserialize)]
struct Target {
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct FixtureEgress {
    id: String,
    protocol: String,
    supports_stream: bool,
    supports_datagram: bool,
    #[serde(default)]
    max_payload_bytes: Option<u64>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Default, Deserialize)]
struct Scenario {
    #[serde(default)]
    packets: Vec<PacketInput>,
    #[serde(default)]
    preloaded_events: Vec<PacketInput>,
    #[serde(default)]
    flow_count: Option<usize>,
    #[serde(default)]
    frames_per_flow: Option<FramesPerFlow>,
}

#[derive(Deserialize)]
struct FramesPerFlow {
    count: usize,
}

#[derive(Clone, Deserialize)]
struct PacketInput {
    seq: u64,
    payload: String,
    #[serde(default)]
    ttl: Option<u8>,
    #[serde(default)]
    packet_id: Option<u64>,
    #[serde(default)]
    flow_id: Option<IdValue>,
}

#[derive(Deserialize)]
struct RankContextInput {
    packet_id: u64,
    flow_id: IdValue,
    traffic_class: String,
    policy_ref: String,
    deadline_ms: u64,
    flow_semantics: String,
    return_semantics: String,
}

#[derive(Default, Deserialize)]
struct DatagramScenario {
    open_target: Option<Target>,
    #[serde(default)]
    sends: Vec<DatagramSend>,
    #[serde(default)]
    close_after_send: bool,
    #[serde(default)]
    schedule_hint: Option<DatagramScheduleHint>,
}

#[derive(Clone, Deserialize)]
struct DatagramSend {
    target: Target,
    payload: String,
}

#[derive(Deserialize)]
struct DatagramScheduleHint {
    fanout_k: usize,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum IdValue {
    String(String),
    Number(u64),
}

impl IdValue {
    fn as_flow_id(&self) -> FlowId {
        match self {
            Self::String(v) => FlowId(v.clone()),
            Self::Number(v) => FlowId(v.to_string()),
        }
    }
}

#[derive(Deserialize)]
struct Expect {
    #[serde(default)]
    open_ok: bool,
    #[serde(default)]
    exit_id: Option<String>,
    #[serde(default)]
    open_errors: Vec<String>,
    #[serde(default)]
    calls: BTreeMap<String, u64>,
    #[serde(default)]
    assertions: Vec<Assertion>,
    #[serde(default)]
    datagram_assertions: DatagramAssertions,
}

#[derive(Deserialize)]
struct Assertion {
    kind: String,
    #[serde(default)]
    expected: AssertionExpected,
}

#[derive(Default, Deserialize)]
struct AssertionExpected {
    #[serde(default)]
    payloads: Vec<String>,
    #[serde(default)]
    returned_payloads: Vec<String>,
    #[serde(default)]
    close_reason: Option<String>,
    #[serde(default)]
    append_exit_id: Option<String>,
    #[serde(default)]
    packet_id: Option<u64>,
    #[serde(default)]
    flow_id: Option<IdValue>,
    #[serde(default)]
    traffic_class: Option<String>,
    #[serde(default)]
    policy_ref: Option<String>,
    #[serde(default)]
    deadline_ms: Option<u64>,
    #[serde(default)]
    flow_semantics: Option<String>,
    #[serde(default)]
    return_semantics: Option<String>,
    #[serde(default)]
    send_count: Option<u64>,
    #[serde(default)]
    success_count: Option<u64>,
    #[serde(default)]
    failure_count: Option<u64>,
    #[serde(default)]
    payload_bytes_total: Option<u64>,
}

#[derive(Default, Deserialize)]
struct DatagramAssertions {
    #[serde(default)]
    payloads: Vec<String>,
    #[serde(default)]
    expected_recv_source: Option<String>,
    #[serde(default)]
    frame_sends: Option<u64>,
    #[serde(default)]
    direct_sends: Option<u64>,
    #[serde(default)]
    flow_opened_shape: Option<u8>,
    #[serde(default)]
    flow_closed_shape: Option<u8>,
}

struct PluginCounters {
    sends: BTreeMap<String, Arc<AtomicU64>>,
    frame_sends: BTreeMap<String, Arc<AtomicUsize>>,
    direct_sends: BTreeMap<String, Arc<AtomicUsize>>,
    trace_seen: Option<Arc<tokio::sync::Mutex<Vec<String>>>>,
    rank_seen: Option<Arc<std::sync::Mutex<Vec<RankContext>>>>,
}

impl PluginCounters {
    fn new() -> Self {
        Self {
            sends: BTreeMap::new(),
            frame_sends: BTreeMap::new(),
            direct_sends: BTreeMap::new(),
            trace_seen: None,
            rank_seen: None,
        }
    }
}

#[tokio::test]
async fn dispatch_contract_fixtures() {
    let supported_cases: BTreeSet<&str> = [
        "dispatch.route_group.pins_matching_exit",
        "dispatch.route_group.no_match_fails_no_usable_exit",
        "dispatch.route_group.absent_uses_any_capability_match",
        "dispatch.stream.round_trip_through_bus",
        "dispatch.stream.ttl_zero_packet_is_dropped_before_egress",
        "dispatch.stream.scheduler_receives_packet_rank_context",
        "dispatch.stream.dispatch_appends_exit_id_to_path_trace",
        "dispatch.stream.ordered_duplicate_packet_id_for_flow_returns_directly",
        "dispatch.stream.unhealthy_exit_is_skipped_after_repeated_failures",
        "dispatch.stream.dispatch_filters_candidates_by_flow_semantics_capability",
        "dispatch.stream.snapshot_reports_exit_runtime_counters",
        "dispatch.stream.bytestream_poll_returns_continue_after_single_send",
        "dispatch.datagram.preserves_one_call_one_datagram",
        "dispatch.datagram.reports_source_from_send_to_target",
        "dispatch.datagram.unsupported_probe_falls_back_without_empty_send",
        "dispatch.datagram.fixed_target_skips_scheduler_after_open",
        "dispatch.datagram.replicate_stays_frame_router",
        "dispatch.datagram.closed_shape_matches_opened_shape",
    ]
    .into_iter()
    .collect();

    let rows = load_rows();
    assert_eq!(rows.len(), supported_cases.len(), "fixture count drift");
    for row in rows {
        assert_eq!(row.owner, "mesh-bus-core.dispatch", "[{}] owner", row.id);
        assert_eq!(row.kind, "service-composition", "[{}] kind", row.id);
        assert_eq!(
            row.schema_ref, "schemas/test-runtime.schema.json",
            "[{}] schema_ref",
            row.id
        );
        assert!(row.observations.is_empty(), "[{}] observations", row.id);
        assert!(row.tags.is_empty(), "[{}] tags", row.id);
        assert!(
            supported_cases.contains(row.case.as_str()),
            "[{}] unsupported case {}",
            row.id,
            row.case
        );

        if row.case.starts_with("dispatch.route_group.") {
            execute_route_group(&row).await;
        } else if row.case.starts_with("dispatch.stream.") {
            execute_stream(&row).await;
        } else if row.case.starts_with("dispatch.datagram.") {
            execute_datagram(&row).await;
        } else {
            unreachable!("supported case set checked above");
        }
    }
}

struct FirstScheduler;

impl SchedulerPlugin for FirstScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }

    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct CountingEgress {
    id: ExitId,
    caps: Capabilities,
    calls: Arc<AtomicU64>,
}

#[async_trait]
impl StreamEgress for CountingEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(InertSession { info, last: None }))
    }
}

struct InertSession {
    info: BusSessionInfo,
    last: Option<DisconnectReason>,
}

#[async_trait]
impl StreamSession for InertSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (Box::new(InertSend), Box::new(InertRecv { last: self.last }))
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        self.last = Some(reason);
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last.as_ref()
    }
}

struct InertSend;

#[async_trait]
impl StreamSendHalf for InertSend {
    async fn send(&mut self, _payload: Bytes) -> Result<(), DisconnectReason> {
        Ok(())
    }

    async fn shutdown_write(&mut self) {}

    async fn abort(&mut self, _reason: DisconnectReason) {}
}

struct InertRecv {
    last: Option<DisconnectReason>,
}

#[async_trait]
impl StreamRecvHalf for InertRecv {
    async fn recv(&mut self) -> Option<Bytes> {
        None
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last.as_ref()
    }
}
