use super::dispatch_forwarder::{
    ForwarderOpenOutcome, apply_pin_with_hysteresis, dispatch_forwarder_frame,
    try_open_forwarder_datagram, try_open_forwarder_stream, valid_order,
};
use super::dispatch_observation::{
    close_flow_if_open, publish_flow_opened, publish_path_io_error, record_dispatch,
};
use super::dispatch_return::{send_return, send_return_with_packet_id};
use crate::kernel::forwarder::{
    DatagramForwarderProbeOutcome, DataplaneShape, FlowCounters, ForwarderDatagramState,
    ForwarderStreamState, TransformRequirements,
};
use crate::kernel::observation::ObservationBus;
use crate::{
    CloseReason, EgressPlugin, ExitId, ExitResult, FlowId, FlowSemantics, Frame, FrameKind,
    PacketId, RankContext, ReturnEvent, ReturnSemantics, ScheduleDecision, ScheduleHint,
    SchedulerPlugin,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub(super) struct DispatchRuntime {
    pub egresses: Arc<Vec<Box<dyn EgressPlugin>>>,
    pub compiled_candidates: Arc<crate::kernel::compiled::CompiledCandidates>,
    pub scheduler: Arc<dyn SchedulerPlugin>,
    pub observation_bus: Arc<ObservationBus>,
    pub flow_counters: Arc<dashmap::DashMap<FlowId, Arc<FlowCounters>>>,
    pub flow_states: Arc<dashmap::DashMap<FlowId, FlowState>>,
    pub forwarder_streams: Arc<dashmap::DashMap<crate::SessionId, ForwarderStreamState>>,
    pub forwarder_datagrams: Arc<dashmap::DashMap<crate::SessionId, ForwarderDatagramState>>,
    pub probe_channels: Arc<
        dashmap::DashMap<
            crate::SessionId,
            tokio::sync::oneshot::Sender<DatagramForwarderProbeOutcome>,
        >,
    >,
    pub flow_pins: Arc<Mutex<HashMap<FlowId, usize>>>,
    pub packet_returns: Arc<Mutex<HashSet<(FlowId, PacketId)>>>,
    pub active_stream_polls: Arc<Mutex<HashMap<(crate::SessionId, usize), JoinHandle<()>>>>,
    pub health_snapshot: Arc<crate::kernel::health_snapshot::HealthPublisher>,
    pub exit_stats: Arc<dashmap::DashMap<String, ExitRuntimeStats>>,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub(super) struct FlowState {
    pub shape: DataplaneShape,
    pub sink_idx: usize,
    pub exit_id: ExitId,
    pub counters: Arc<FlowCounters>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ExitRuntimeStats {
    pub send_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub last_rtt_ms: u64,
    pub payload_bytes_total: u64,
}

pub(super) async fn dispatch(
    mut frame: Frame,
    return_tx: tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: DispatchRuntime,
) {
    if frame.ttl == 0 {
        let _ = return_tx
            .send(ReturnEvent::Closed {
                reason: CloseReason::TtlExpired,
            })
            .await;
        return;
    }
    frame.ttl = frame.ttl.saturating_sub(1);

    if matches!(frame.kind, FrameKind::Close | FrameKind::Cancel) {
        if let Some(idx) = runtime.flow_pins.lock().await.remove(&frame.flow_id) {
            runtime.egresses[idx].close(&frame.session_id).await;
        }
        abort_session_polls(&runtime, &frame.session_id).await;
        runtime.forwarder_datagrams.remove(&frame.session_id);
        runtime.forwarder_streams.remove(&frame.session_id);
        close_flow_if_open(
            &runtime,
            &frame.flow_id,
            CloseReason::SessionClosed,
            frame.session_id.clone(),
        )
        .await;
        runtime
            .packet_returns
            .lock()
            .await
            .retain(|(flow_id, _)| flow_id != &frame.flow_id);
        let _ = return_tx
            .send(ReturnEvent::Closed {
                reason: CloseReason::SessionClosed,
            })
            .await;
        return;
    }

    if !matches!(frame.kind, FrameKind::Open) {
        if let Some(state) = runtime.flow_states.get(&frame.flow_id).map(|s| s.clone()) {
            if state.shape == DataplaneShape::Forwarder {
                dispatch_forwarder_frame(frame, state, return_tx, runtime).await;
                return;
            }
        }
    }

    let (candidates, candidate_map) = healthy_candidates(
        &runtime,
        frame.flow_semantics,
        frame.route_group.as_deref(),
        frame.target_sink.as_deref(),
    );
    let ctx = RankContext::from(&frame);
    let decision = schedule_frame(&frame, &candidates, &ctx, &runtime).await;
    match decision {
        ScheduleDecision::Ordered(mut order) => {
            order = map_candidate_order(order, &candidate_map);
            if let Some(pinned) = runtime.flow_pins.lock().await.get(&frame.flow_id).copied() {
                if !snapshot_unhealthy(&runtime, &runtime.egresses[pinned].id().0) {
                    apply_pin_with_hysteresis(
                        &mut order,
                        pinned,
                        &runtime.egresses,
                        runtime.scheduler.as_ref(),
                        &candidates,
                        &ctx,
                        0.20,
                    );
                }
            }
            dispatch_ordered(frame, order, return_tx, runtime).await;
        }
        ScheduleDecision::Replicate(mut order) => {
            order = map_candidate_order(order, &candidate_map);
            if let Some(pinned) = runtime.flow_pins.lock().await.get(&frame.flow_id).copied() {
                if !snapshot_unhealthy(&runtime, &runtime.egresses[pinned].id().0) {
                    apply_pin_with_hysteresis(
                        &mut order,
                        pinned,
                        &runtime.egresses,
                        runtime.scheduler.as_ref(),
                        &candidates,
                        &ctx,
                        0.20,
                    );
                }
            }
            frame.return_semantics = ReturnSemantics::PacketDedup;
            dispatch_replicate(frame, order, return_tx, runtime).await;
        }
    }
}

async fn schedule_frame(
    frame: &Frame,
    candidates: &[ExitId],
    ctx: &RankContext,
    runtime: &DispatchRuntime,
) -> ScheduleDecision {
    if frame.flow_semantics == FlowSemantics::Datagram {
        if let ScheduleHint::FanOut { k } = frame.schedule_hint {
            let n = k.min(candidates.len());
            return ScheduleDecision::Replicate((0..n).collect());
        }
    }
    runtime.scheduler.schedule(candidates, ctx)
}

fn snapshot_unhealthy(runtime: &DispatchRuntime, exit_id: &str) -> bool {
    runtime.health_snapshot.load().unhealthy.contains(exit_id)
}

fn healthy_candidates(
    runtime: &DispatchRuntime,
    flow_semantics: FlowSemantics,
    route_group: Option<&str>,
    target_sink: Option<&str>,
) -> (Vec<ExitId>, Vec<usize>) {
    let snap = runtime.health_snapshot.load();
    let bucket = runtime.compiled_candidates.bucket(flow_semantics);
    let matches = |c: &crate::kernel::compiled::CompiledCandidate| -> bool {
        if let Some(sink) = target_sink {
            if c.exit_id.0 != sink {
                return false;
            }
        }
        match route_group {
            Some(group) => c.groups.iter().any(|g| g == group),
            None => true,
        }
    };
    let mut candidates = Vec::new();
    let mut map = Vec::new();
    for c in bucket.iter() {
        if !matches(c) {
            continue;
        }
        if !snap.unhealthy.contains(&c.exit_id.0) {
            candidates.push(c.exit_id.clone());
            map.push(c.egress_idx);
        }
    }
    if candidates.is_empty() {
        if route_group.is_some() || target_sink.is_some() {
            return (Vec::new(), Vec::new());
        }
        return bucket
            .iter()
            .filter(|c| matches(c))
            .map(|c| (c.exit_id.clone(), c.egress_idx))
            .collect::<Vec<_>>()
            .into_iter()
            .unzip();
    }
    (candidates, map)
}

fn map_candidate_order(order: Vec<usize>, candidate_map: &[usize]) -> Vec<usize> {
    order
        .into_iter()
        .filter_map(|idx| candidate_map.get(idx).copied())
        .collect()
}

async fn dispatch_ordered(
    mut frame: Frame,
    order: Vec<usize>,
    return_tx: tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: DispatchRuntime,
) {
    let order = valid_order(order, runtime.egresses.len());
    let mut last_failure = None;
    for idx in order {
        let exit = &runtime.egresses[idx];
        frame.path_trace.push(exit.id().0.clone());
        let shape = if matches!(frame.kind, FrameKind::Open) {
            DataplaneShape::derive(
                frame.flow_semantics,
                frame.return_semantics,
                1,
                runtime.egresses[idx].capabilities(),
                &TransformRequirements::default(),
            )
        } else {
            DataplaneShape::FrameRouter
        };
        if matches!(frame.kind, FrameKind::Open) && shape == DataplaneShape::Forwarder {
            match try_open_forwarder_stream(&frame, idx, shape, &return_tx, &runtime).await {
                ForwarderOpenOutcome::Handled => return,
                ForwarderOpenOutcome::Failed(event) => {
                    last_failure = Some(event);
                    continue;
                }
                ForwarderOpenOutcome::Unsupported => {}
            }
        }
        if matches!(frame.kind, FrameKind::Open) && shape == DataplaneShape::DatagramForwarder {
            match try_open_forwarder_datagram(&frame, idx, shape, &return_tx, &runtime).await {
                DatagramForwarderProbeOutcome::Handled => return,
                DatagramForwarderProbeOutcome::Fallback => {
                    if let Some((_, tx)) = runtime.probe_channels.remove(&frame.session_id) {
                        let _ = tx.send(DatagramForwarderProbeOutcome::Fallback);
                    }
                    return;
                }
                DatagramForwarderProbeOutcome::Failed(event) => {
                    last_failure = Some(event);
                    continue;
                }
            }
        }
        let result = exit.send(frame.clone()).await;
        record_dispatch(&runtime, &result, frame.payload.len() as u64);
        if result.success {
            let return_event = open_return_event(&frame, &result);
            runtime
                .flow_pins
                .lock()
                .await
                .insert(frame.flow_id.clone(), idx);
            if matches!(frame.kind, FrameKind::Open) {
                let counters = runtime
                    .flow_counters
                    .entry(frame.flow_id.clone())
                    .or_insert_with(|| Arc::new(FlowCounters::new()))
                    .clone();
                runtime.flow_states.insert(
                    frame.flow_id.clone(),
                    FlowState {
                        shape,
                        sink_idx: idx,
                        exit_id: result.exit_id.clone(),
                        counters: counters.clone(),
                    },
                );
                publish_flow_opened(&runtime, &frame, &result, shape).await;
            } else if let Some(counters) = runtime.flow_counters.get(&frame.flow_id) {
                counters
                    .field(crate::kernel::forwarder::Direction::Up)
                    .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
            }
            ensure_stream_poll(&frame, idx, return_tx.clone(), runtime.clone()).await;
            if !matches!(return_event, ReturnEvent::Idle) || matches!(frame.kind, FrameKind::Open) {
                send_return(&return_tx, &runtime, &frame, return_event).await;
            }
            return;
        }
        publish_path_io_error(&runtime, &frame, &result, true);
        last_failure = Some(result.return_event);
    }
    // Signal probe waiter if all candidates failed (probe_rx would otherwise block forever)
    if let Some((_, tx)) = runtime.probe_channels.remove(&frame.session_id) {
        let _ = tx.send(DatagramForwarderProbeOutcome::Failed(
            last_failure.clone().unwrap_or(ReturnEvent::Closed {
                reason: CloseReason::NoUsableExit,
            }),
        ));
    }
    let _ = return_tx
        .send(match last_failure {
            Some(ReturnEvent::Closed { reason }) => ReturnEvent::Closed { reason },
            _ => ReturnEvent::Closed {
                reason: CloseReason::NoUsableExit,
            },
        })
        .await;
}

fn open_return_event(frame: &Frame, result: &ExitResult) -> ReturnEvent {
    if matches!(frame.kind, FrameKind::Open) {
        return ReturnEvent::Connected {
            exit_id: result.exit_id.clone(),
            local_endpoint: result.local_endpoint.clone(),
            rtt_ms: result.rtt_ms,
        };
    }
    result.return_event.clone()
}

async fn abort_session_polls(runtime: &DispatchRuntime, session_id: &crate::SessionId) {
    let mut polls = runtime.active_stream_polls.lock().await;
    let stale: Vec<_> = polls
        .keys()
        .filter(|(sid, _)| sid == session_id)
        .cloned()
        .collect();
    for k in stale {
        if let Some(h) = polls.remove(&k) {
            h.abort();
        }
    }
}

async fn ensure_stream_poll(
    frame: &Frame,
    idx: usize,
    return_tx: tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: DispatchRuntime,
) {
    if !matches!(
        frame.flow_semantics,
        FlowSemantics::ByteStream | FlowSemantics::Datagram
    ) {
        return;
    }
    let key = (frame.session_id.clone(), idx);
    let polls_map = runtime.active_stream_polls.clone();
    let mut polls = polls_map.lock().await;
    if polls.contains_key(&key) {
        return;
    }
    let session_id = frame.session_id.clone();
    let flow_id = frame.flow_id.clone();
    let return_frame = frame.clone();
    let task_key = key.clone();
    let handle = tokio::spawn(async move {
        loop {
            if runtime.shutdown.load(Ordering::SeqCst) {
                break;
            }
            match runtime.egresses[idx].poll(&session_id).await {
                ReturnEvent::Idle => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
                ReturnEvent::Closed { reason } => {
                    close_flow_if_open(&runtime, &flow_id, reason.clone(), session_id.clone())
                        .await;
                    let _ = return_tx.send(ReturnEvent::Closed { reason }).await;
                    break;
                }
                event => {
                    let packet_id = match &event {
                        ReturnEvent::Data { seq, .. }
                            if return_frame.flow_semantics == FlowSemantics::Datagram =>
                        {
                            PacketId(*seq)
                        }
                        _ => return_frame.packet_id,
                    };
                    if !send_return_with_packet_id(
                        &return_tx,
                        &runtime,
                        &return_frame,
                        event,
                        packet_id,
                    )
                    .await
                    {
                        break;
                    }
                }
            }
        }
        runtime.active_stream_polls.lock().await.remove(&task_key);
    });
    polls.insert(key, handle);
    drop(polls);
}

async fn dispatch_replicate(
    frame: Frame,
    order: Vec<usize>,
    return_tx: tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: DispatchRuntime,
) {
    let order = valid_order(order, runtime.egresses.len());
    if order.is_empty() {
        let _ = return_tx
            .send(ReturnEvent::Closed {
                reason: CloseReason::NoUsableExit,
            })
            .await;
        return;
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel(order.len());
    for idx in order.iter().copied() {
        let egresses = runtime.egresses.clone();
        let tx = tx.clone();
        let mut replica = frame.clone();
        replica.path_trace.push(egresses[idx].id().0.clone());
        tokio::spawn(async move {
            let payload_bytes = replica.payload.len() as u64;
            let result = egresses[idx].send(replica).await;
            let _ = tx.send((idx, payload_bytes, result)).await;
        });
    }
    drop(tx);
    let mut returned = false;
    while let Some((idx, payload_bytes, result)) = rx.recv().await {
        record_dispatch(&runtime, &result, payload_bytes);
        if !result.success {
            publish_path_io_error(&runtime, &frame, &result, false);
        }
        if result.success {
            ensure_stream_poll(&frame, idx, return_tx.clone(), runtime.clone()).await;
            if !returned {
                runtime
                    .flow_pins
                    .lock()
                    .await
                    .insert(frame.flow_id.clone(), idx);
                if !matches!(result.return_event, ReturnEvent::Idle)
                    || matches!(frame.kind, FrameKind::Open)
                {
                    send_return(&return_tx, &runtime, &frame, result.return_event.clone()).await;
                }
                returned = true;
            }
        }
    }
    if !returned {
        let _ = return_tx
            .send(ReturnEvent::Closed {
                reason: CloseReason::NoUsableExit,
            })
            .await;
    }
}
