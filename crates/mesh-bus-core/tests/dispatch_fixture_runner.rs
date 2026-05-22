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

fn load_rows() -> Vec<FixtureRow> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dispatch");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("fixtures/dispatch dir missing at {:?}", dir))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("yaml")).then_some(path)
        })
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let txt = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read fixture {path:?}: {err}"));
            serde_yaml::from_str(&txt).unwrap_or_else(|err| panic!("fixture {path:?}: {err}"))
        })
        .collect()
}

fn endpoint(target: &Target) -> Endpoint {
    Endpoint::new(&target.host, target.port).expect("fixture endpoint")
}

fn caps(egress: &FixtureEgress) -> Capabilities {
    Capabilities {
        protocol: egress.protocol.clone(),
        supports_stream: egress.supports_stream,
        supports_datagram: egress.supports_datagram,
        max_payload_bytes: egress.max_payload_bytes,
        groups: egress.groups.clone(),
    }
}

fn assertion<'a>(row: &'a FixtureRow, kind: &str) -> &'a AssertionExpected {
    &row.expect
        .assertions
        .iter()
        .find(|item| item.kind == kind)
        .unwrap_or_else(|| panic!("[{}] missing assertion {kind}", row.id))
        .expected
}

fn make_frame(
    row: &FixtureRow,
    session_id: mesh_bus_core::SessionId,
    packet: &PacketInput,
) -> Frame {
    let mut frame = Frame::data(
        session_id,
        packet.seq,
        endpoint(&row.input.target),
        Bytes::from(packet.payload.clone()),
    );
    if let Some(ttl) = packet.ttl {
        frame.ttl = ttl;
    }
    if let Some(packet_id) = packet.packet_id {
        frame.packet_id = PacketId(packet_id);
    }
    if let Some(flow_id) = &packet.flow_id {
        frame.flow_id = flow_id.as_flow_id();
    }
    if let Some(ctx) = &row.input.scheduler_context {
        frame.packet_id = PacketId(ctx.packet_id);
        frame.flow_id = ctx.flow_id.as_flow_id();
        frame.traffic_class = traffic_class(&ctx.traffic_class);
        frame.policy_ref = Some(ctx.policy_ref.clone());
        frame.deadline_ms = Some(ctx.deadline_ms);
    }
    frame
}

fn traffic_class(value: &str) -> TrafficClass {
    match value {
        "Interactive" => TrafficClass::Interactive,
        "Bulk" => TrafficClass::Bulk,
        "Control" => TrafficClass::Control,
        "Probe" => TrafficClass::Probe,
        other => panic!("unknown traffic class {other}"),
    }
}

async fn build_plugin_bus(row: &FixtureRow) -> (mesh_bus_core::Bus, PluginCounters) {
    let mut counters = PluginCounters::new();
    let mut builder = BusBuilder::new();

    if row.case == "dispatch.stream.scheduler_receives_packet_rank_context" {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        counters.rank_seen = Some(seen.clone());
        builder = builder.scheduler(Box::new(RecordingScheduler { seen }));
    } else {
        builder = builder.scheduler(Box::new(First));
    }

    for egress in &row.input.egresses {
        let behavior = behavior_for(row, egress, &mut counters);
        builder = builder.add_egress(TestEgress::boxed(&egress.id, caps(egress), behavior));
    }

    (builder.build().await, counters)
}

fn behavior_for(
    row: &FixtureRow,
    egress: &FixtureEgress,
    counters: &mut PluginCounters,
) -> Behavior {
    match row.case.as_str() {
        "dispatch.stream.dispatch_appends_exit_id_to_path_trace" => {
            let sends = counter(&mut counters.sends, &egress.id);
            let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            counters.trace_seen = Some(seen.clone());
            Behavior::TraceCapture { sends, seen }
        }
        "dispatch.stream.bytestream_poll_returns_continue_after_single_send" => {
            let (_tx, rx) = poll_queue(&row.input.scenario.preloaded_events);
            Behavior::PollQueue {
                rx: tokio::sync::Mutex::new(rx),
            }
        }
        "dispatch.stream.unhealthy_exit_is_skipped_after_repeated_failures"
            if egress.id == "bad" =>
        {
            Behavior::Fail {
                sends: counter(&mut counters.sends, &egress.id),
            }
        }
        "dispatch.datagram.fixed_target_skips_scheduler_after_open"
        | "dispatch.datagram.replicate_stays_frame_router"
        | "dispatch.datagram.closed_shape_matches_opened_shape" => {
            let frame_sends = usize_counter(&mut counters.frame_sends, &egress.id);
            let direct_sends = usize_counter(&mut counters.direct_sends, &egress.id);
            Behavior::Forwarder {
                frame_sends,
                direct_sends,
            }
        }
        "dispatch.datagram.unsupported_probe_falls_back_without_empty_send" => Behavior::Idle {
            sends: counter(&mut counters.sends, &egress.id),
        },
        _ => Behavior::Echo {
            sends: counter(&mut counters.sends, &egress.id),
        },
    }
}

fn counter(map: &mut BTreeMap<String, Arc<AtomicU64>>, id: &str) -> Arc<AtomicU64> {
    let value = Arc::new(AtomicU64::new(0));
    map.insert(id.to_string(), value.clone());
    value
}

fn usize_counter(map: &mut BTreeMap<String, Arc<AtomicUsize>>, id: &str) -> Arc<AtomicUsize> {
    let value = Arc::new(AtomicUsize::new(0));
    map.insert(id.to_string(), value.clone());
    value
}

fn poll_queue(
    events: &[PacketInput],
) -> (
    tokio::sync::mpsc::Sender<ReturnEvent>,
    tokio::sync::mpsc::Receiver<ReturnEvent>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    for event in events {
        tx.try_send(ReturnEvent::Data {
            seq: event.seq,
            payload: Bytes::from(event.payload.clone()),
        })
        .expect("queue preload");
    }
    (tx, rx)
}

fn assert_calls(row: &FixtureRow, counters: &PluginCounters) {
    for (id, want) in &row.expect.calls {
        let got = counters
            .sends
            .get(id)
            .map(|value| value.load(Ordering::SeqCst))
            .or_else(|| {
                counters
                    .frame_sends
                    .get(id)
                    .map(|value| value.load(Ordering::SeqCst) as u64)
            })
            .unwrap_or_else(|| panic!("[{}] missing egress counter for {}", row.id, id));
        assert_eq!(*want, got, "[{}] egress {} call count mismatch", row.id, id);
    }
}

async fn execute_route_group(row: &FixtureRow) {
    let mut builder = BusBuilder::new().scheduler(Box::new(FirstScheduler));
    let mut counters = BTreeMap::new();
    for egress in &row.input.egresses {
        let calls = Arc::new(AtomicU64::new(0));
        counters.insert(egress.id.clone(), calls.clone());
        builder = builder.add_stream_egress(Box::new(CountingEgress {
            id: ExitId(egress.id.clone()),
            caps: caps(egress),
            calls,
        }));
    }

    let bus = builder.build().await;
    let port = bus.port();
    let handle = bus.spawn();
    let mut request = BusSessionRequest::stream(endpoint(&row.input.target));
    if let Some(group) = &row.input.route_group {
        request = request.with_route_group(group.clone());
    }

    let mut selected = None;
    match port.open_stream(request).await {
        Ok(mut session) => match session.connect().await {
            Ok(info) => {
                assert!(
                    row.expect.open_ok,
                    "[{}] open unexpectedly succeeded",
                    row.id
                );
                selected = Some(info.paths[info.primary].exit_id.clone());
            }
            Err(err) => assert_route_group_error(row, &err),
        },
        Err(err) => assert_route_group_error(row, &err),
    }

    if row.expect.open_ok {
        let want = row
            .expect
            .exit_id
            .as_ref()
            .unwrap_or_else(|| panic!("[{}] expect.exit_id missing", row.id));
        assert_eq!(
            selected.as_ref(),
            Some(&ExitId(want.clone())),
            "[{}] wrong exit selection",
            row.id
        );
    }
    for (id, want) in &row.expect.calls {
        let got = counters
            .get(id)
            .unwrap_or_else(|| panic!("[{}] missing egress counter for {}", row.id, id))
            .load(Ordering::SeqCst);
        assert_eq!(*want, got, "[{}] egress {} call count", row.id, id);
    }
    handle.shutdown().await;
}

fn assert_route_group_error(row: &FixtureRow, err: &DisconnectReason) {
    assert!(
        !row.expect.open_ok,
        "[{}] expected open_ok=true but got {:?}",
        row.id, err
    );
    assert!(
        row.expect.open_errors.iter().any(|want| matches!(
            (want.as_str(), err),
            ("NoUsableExit", DisconnectReason::NoUsableExit)
                | ("HostUnreachable", DisconnectReason::HostUnreachable)
        )),
        "[{}] got error {:?}, expected one of {:?}",
        row.id,
        err,
        row.expect.open_errors
    );
}

async fn execute_stream(row: &FixtureRow) {
    match row.case.as_str() {
        "dispatch.stream.unhealthy_exit_is_skipped_after_repeated_failures" => {
            execute_unhealthy_stream(row).await
        }
        "dispatch.stream.snapshot_reports_exit_runtime_counters" => execute_snapshot(row).await,
        "dispatch.stream.bytestream_poll_returns_continue_after_single_send" => {
            execute_poll_stream(row).await
        }
        _ => execute_basic_stream(row).await,
    }
}

async fn execute_basic_stream(row: &FixtureRow) {
    let (bus, counters) = build_plugin_bus(row).await;
    let port = bus.port();
    let handle = bus.spawn();
    let mut session = port.open_session(endpoint(&row.input.target)).await;
    let packets = effective_packets(row);

    for packet in &packets {
        session
            .submit
            .send(make_frame(row, session.id.clone(), packet))
            .await
            .expect("send");
    }

    match row.case.as_str() {
        "dispatch.stream.ttl_zero_packet_is_dropped_before_egress" => {
            let expected = assertion(row, "drop_before_egress");
            match session.returns.recv().await.expect("return") {
                ReturnEvent::Closed { reason } => assert_eq!(
                    close_reason(expected.close_reason.as_deref().expect("close_reason")),
                    reason
                ),
                other => panic!("[{}] expected Closed, got {:?}", row.id, other),
            }
        }
        "dispatch.stream.scheduler_receives_packet_rank_context" => {
            let _ = session.returns.recv().await.expect("return");
            let input = row.input.scheduler_context.as_ref().expect("rank input");
            let expected = assertion(row, "rank_context");
            assert_eq!(
                input.flow_semantics,
                expected.flow_semantics.clone().expect("flow_semantics")
            );
            assert_eq!(
                input.return_semantics,
                expected.return_semantics.clone().expect("return_semantics")
            );
            let seen = counters
                .rank_seen
                .as_ref()
                .expect("rank seen")
                .lock()
                .expect("lock");
            assert_eq!(seen.len(), 1, "[{}] rank context count", row.id);
            assert_eq!(
                seen[0].packet_id,
                PacketId(expected.packet_id.expect("packet_id"))
            );
            assert_eq!(
                seen[0].flow_id,
                expected.flow_id.as_ref().expect("flow_id").as_flow_id()
            );
            assert_eq!(
                format!("{:?}", seen[0].traffic_class),
                expected.traffic_class.as_deref().expect("traffic_class")
            );
            assert_eq!(
                seen[0].policy_ref.as_deref(),
                expected.policy_ref.as_deref()
            );
            assert_eq!(seen[0].deadline_ms, expected.deadline_ms);
            assert_eq!(
                format!("{:?}", seen[0].flow_semantics),
                expected.flow_semantics.as_deref().expect("flow_semantics")
            );
            assert_eq!(
                format!("{:?}", seen[0].return_semantics),
                expected
                    .return_semantics
                    .as_deref()
                    .expect("return_semantics")
            );
        }
        "dispatch.stream.dispatch_appends_exit_id_to_path_trace" => {
            let _ = session.returns.recv().await.expect("return");
            let expected = assertion(row, "path_trace");
            let seen = counters.trace_seen.as_ref().expect("trace").lock().await;
            assert_eq!(
                *seen,
                vec![expected.append_exit_id.clone().expect("append_exit_id")]
            );
        }
        "dispatch.stream.ordered_duplicate_packet_id_for_flow_returns_directly" => {
            let expected = assertion(row, "duplicate_packet_delivery");
            let _ = session.returns.recv().await.expect("first");
            let second = timeout(Duration::from_millis(100), session.returns.recv())
                .await
                .expect("second direct")
                .expect("second event");
            assert_payloads(row, vec![second], &expected.returned_payloads);
        }
        "dispatch.stream.dispatch_filters_candidates_by_flow_semantics_capability" => {
            assert!(matches!(
                session.returns.recv().await.expect("return"),
                ReturnEvent::Data { .. }
            ));
        }
        _ => {
            let expected = assertion(row, "round_trip");
            let mut events = Vec::new();
            for _ in 0..expected.payloads.len() {
                events.push(session.returns.recv().await.expect("return"));
            }
            assert_payloads(row, events, &expected.payloads);
        }
    }

    assert_calls(row, &counters);
    handle.shutdown().await;
}

fn effective_packets(row: &FixtureRow) -> Vec<PacketInput> {
    if !row.input.scenario.packets.is_empty() {
        return row.input.scenario.packets.clone();
    }
    if let Some(ctx) = &row.input.scheduler_context {
        return vec![PacketInput {
            seq: ctx.packet_id,
            payload: "hello".into(),
            ttl: None,
            packet_id: Some(ctx.packet_id),
            flow_id: Some(ctx.flow_id.clone()),
        }];
    }
    vec![PacketInput {
        seq: 0,
        payload: "hello".into(),
        ttl: None,
        packet_id: None,
        flow_id: None,
    }]
}

async fn execute_unhealthy_stream(row: &FixtureRow) {
    let (bus, counters) = build_plugin_bus(row).await;
    let port = bus.port();
    let handle = bus.spawn();
    let flow_count = row.input.scenario.flow_count.expect("flow_count");
    let frames = row
        .input
        .scenario
        .frames_per_flow
        .as_ref()
        .map(|item| item.count)
        .unwrap_or(1);

    for flow_idx in 0..flow_count {
        let mut session = port.open_session(endpoint(&row.input.target)).await;
        for frame_idx in 0..frames {
            session
                .submit
                .send(Frame::data(
                    session.id.clone(),
                    frame_idx as u64,
                    endpoint(&row.input.target),
                    Bytes::from(format!("flow-{flow_idx}")),
                ))
                .await
                .expect("send");
            let _ = session.returns.recv().await.expect("return");
        }
    }

    assert_calls(row, &counters);
    handle.shutdown().await;
}

async fn execute_snapshot(row: &FixtureRow) {
    let (bus, counters) = build_plugin_bus(row).await;
    let port = bus.port();
    let handle = bus.spawn();
    let mut session = port.open_session(endpoint(&row.input.target)).await;
    let session_spec = row.input.scenario.packets.clone();
    let packets = if session_spec.is_empty() {
        vec![
            PacketInput {
                seq: 0,
                payload: "hello".into(),
                ttl: None,
                packet_id: None,
                flow_id: None,
            },
            PacketInput {
                seq: 1,
                payload: "world".into(),
                ttl: None,
                packet_id: None,
                flow_id: None,
            },
        ]
    } else {
        session_spec
    };

    for packet in &packets {
        session
            .submit
            .send(make_frame(row, session.id.clone(), packet))
            .await
            .expect("send");
        let _ = session.returns.recv().await.expect("return");
    }

    let expected = assertion(row, "snapshot");
    let snapshot = handle.snapshot().await;
    assert_eq!(snapshot.exits.len(), 1, "[{}] exit count", row.id);
    assert_eq!(
        snapshot.exits[0].exit_id.0,
        row.expect.exit_id.as_deref().unwrap_or("echo")
    );
    assert_eq!(snapshot.exits[0].send_count, expected.send_count.unwrap());
    assert_eq!(
        snapshot.exits[0].success_count,
        expected.success_count.unwrap()
    );
    assert_eq!(
        snapshot.exits[0].failure_count,
        expected.failure_count.unwrap()
    );
    assert_eq!(
        snapshot.exits[0].payload_bytes_total,
        expected.payload_bytes_total.unwrap()
    );
    assert_calls(row, &counters);
    handle.shutdown().await;
}

async fn execute_poll_stream(row: &FixtureRow) {
    let (bus, _counters) = build_plugin_bus(row).await;
    let port = bus.port();
    let handle = bus.spawn();
    let mut session = port.open_session(endpoint(&row.input.target)).await;
    session
        .submit
        .send(Frame::data(
            session.id.clone(),
            0,
            endpoint(&row.input.target),
            Bytes::from_static(b"request"),
        ))
        .await
        .expect("send");

    let expected = assertion(row, "poll_returns_continue");
    let mut events = Vec::new();
    for _ in 0..expected.payloads.len() {
        events.push(
            timeout(Duration::from_millis(200), session.returns.recv())
                .await
                .expect("event arrives")
                .expect("event"),
        );
    }
    assert_payloads(row, events, &expected.payloads);
    handle.shutdown().await;
}

fn assert_payloads(row: &FixtureRow, events: Vec<ReturnEvent>, expected: &[String]) {
    let got = events
        .into_iter()
        .map(|event| match event {
            ReturnEvent::Data { payload, .. } => {
                String::from_utf8(payload.to_vec()).expect("utf8 payload")
            }
            other => panic!("[{}] expected Data, got {:?}", row.id, other),
        })
        .collect::<Vec<_>>();
    assert_eq!(got, expected, "[{}] payloads", row.id);
}

fn close_reason(value: &str) -> CloseReason {
    match value {
        "TtlExpired" => CloseReason::TtlExpired,
        other => CloseReason::Other(other.into()),
    }
}

async fn execute_datagram(row: &FixtureRow) {
    let mut events = None;
    let (bus, counters) = if row.case == "dispatch.datagram.closed_shape_matches_opened_shape" {
        let observed = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
        let mut builder = BusBuilder::new()
            .scheduler(Box::new(First))
            .add_observer(Box::new(RecordingObserver {
                events: observed.clone(),
            }));
        let mut counters = PluginCounters::new();
        for egress in &row.input.egresses {
            let behavior = behavior_for(row, egress, &mut counters);
            builder = builder.add_egress(TestEgress::boxed(&egress.id, caps(egress), behavior));
        }
        events = Some(observed);
        (builder.build().await, counters)
    } else {
        build_plugin_bus(row).await
    };

    let port = bus.port();
    let handle = bus.spawn();
    let datagram = row.input.datagram.as_ref().expect("datagram scenario");
    let mut request = BusSessionRequest::datagram(endpoint(
        datagram.open_target.as_ref().unwrap_or(&row.input.target),
    ));
    if let Some(hint) = &datagram.schedule_hint {
        request.schedule_hint = ScheduleHint::FanOut { k: hint.fanout_k };
    }
    let mut session = port.open_datagram(request).await.expect("open datagram");

    for send in &datagram.sends {
        session
            .send_to(endpoint(&send.target), Bytes::from(send.payload.clone()))
            .await
            .expect("send datagram");
    }

    match row.case.as_str() {
        "dispatch.datagram.preserves_one_call_one_datagram" => {
            let (_source, payload) = session.recv_from().await.expect("recv");
            assert_eq!(
                vec![String::from_utf8(payload.to_vec()).expect("utf8")],
                row.expect.datagram_assertions.payloads
            );
        }
        "dispatch.datagram.reports_source_from_send_to_target" => {
            let (source, payload) = session.recv_from().await.expect("recv");
            assert_eq!(
                Some(source.to_string()),
                row.expect.datagram_assertions.expected_recv_source
            );
            assert_eq!(
                vec![String::from_utf8(payload.to_vec()).expect("utf8")],
                row.expect.datagram_assertions.payloads
            );
        }
        "dispatch.datagram.unsupported_probe_falls_back_without_empty_send"
        | "dispatch.datagram.replicate_stays_frame_router" => {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        "dispatch.datagram.fixed_target_skips_scheduler_after_open" => {}
        "dispatch.datagram.closed_shape_matches_opened_shape" => {
            if datagram.close_after_send {
                session.close().await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        _ => panic!("[{}] unsupported datagram case", row.id),
    }

    assert_calls(row, &counters);
    if let Some(want) = row.expect.datagram_assertions.frame_sends {
        let got = first_usize_count(&counters.frame_sends);
        assert_eq!(got, want, "[{}] frame_sends", row.id);
    }
    if let Some(want) = row.expect.datagram_assertions.direct_sends {
        let got = first_usize_count(&counters.direct_sends);
        assert_eq!(got, want, "[{}] direct_sends", row.id);
    }
    if let Some(observed) = events {
        let evs = observed.lock().expect("events");
        assert_eq!(
            core_shape(&evs, CoreEventId::FlowOpened),
            row.expect.datagram_assertions.flow_opened_shape
        );
        assert_eq!(
            core_shape(&evs, CoreEventId::FlowClosed),
            row.expect.datagram_assertions.flow_closed_shape
        );
    }
    handle.shutdown().await;
}

fn first_usize_count(map: &BTreeMap<String, Arc<AtomicUsize>>) -> u64 {
    map.values()
        .next()
        .map(|value| value.load(Ordering::SeqCst) as u64)
        .unwrap_or(0)
}

struct RecordingObserver {
    events: Arc<std::sync::Mutex<Vec<BusEvent>>>,
}

impl mesh_bus_core::ObserverPlugin for RecordingObserver {
    fn on_event(&self, event: &BusEvent) {
        self.events.lock().expect("events").push(event.clone());
    }
}

fn core_shape(events: &[BusEvent], id: CoreEventId) -> Option<u8> {
    events.iter().find_map(|event| match event {
        BusEvent::Core(env) if env.type_id == EventTypeId::Core(id) => env.payload.0.shape,
        _ => None,
    })
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
