use super::*;

pub(super) fn load_rows() -> Vec<FixtureRow> {
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

pub(super) async fn execute_route_group(row: &FixtureRow) {
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

pub(super) async fn execute_stream(row: &FixtureRow) {
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

pub(super) async fn execute_datagram(row: &FixtureRow) {
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
