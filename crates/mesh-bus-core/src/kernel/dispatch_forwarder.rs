use super::dispatch::{DispatchRuntime, FlowState};
use super::dispatch_observation::{
    close_flow_if_open, publish_flow_opened, publish_path_io_error, record_dispatch,
};
use super::dispatch_return::send_return;
use crate::kernel::forwarder::{
    DatagramForwarderProbeOutcome, DataplaneShape, FlowCounters, ForwarderClose,
    ForwarderDatagramState, ForwarderStreamState, ForwarderTransport, OpenedForwarderTransport,
};
use crate::{
    CloseReason, EgressPlugin, ExitId, ExitResult, Frame, FrameKind, RankContext, ReturnEvent,
    SchedulerPlugin, TcpSpliceAccounting, TcpSpliceDirection,
};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub(super) enum ForwarderOpenOutcome {
    Handled,
    Failed(ReturnEvent),
    Unsupported,
}

pub(super) async fn try_open_forwarder_stream(
    frame: &Frame,
    idx: usize,
    shape: DataplaneShape,
    return_tx: &tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: &DispatchRuntime,
) -> ForwarderOpenOutcome {
    if !matches!(frame.kind, FrameKind::Open) || shape != DataplaneShape::Forwarder {
        return ForwarderOpenOutcome::Unsupported;
    }

    let exit = &runtime.egresses[idx];
    match exit.open_forwarder_stream(frame).await {
        Some(Ok(opened)) => {
            let result = ExitResult {
                exit_id: exit.id().clone(),
                success: true,
                rtt_ms: opened.rtt_ms,
                local_endpoint: opened.local_endpoint.clone(),
                return_event: ReturnEvent::Connected {
                    exit_id: exit.id().clone(),
                    local_endpoint: opened.local_endpoint,
                    rtt_ms: opened.rtt_ms,
                },
            };
            record_dispatch(runtime, &result, frame.payload.len() as u64);
            runtime
                .flow_pins
                .lock()
                .await
                .insert(frame.flow_id.clone(), idx);
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
            let flow_states_c = runtime.flow_states.clone();
            let flow_counters_c = runtime.flow_counters.clone();
            let flow_pins_c = runtime.flow_pins.clone();
            let flow_id_c = frame.flow_id.clone();
            let close = Arc::new(ForwarderClose::new(
                runtime.observation_bus.clone(),
                frame.flow_id.clone(),
                frame.session_id.clone(),
                result.exit_id.clone(),
                runtime.clock.clone(),
                Arc::new(move || {
                    let flow_states_c = flow_states_c.clone();
                    let flow_counters_c = flow_counters_c.clone();
                    let flow_pins_c = flow_pins_c.clone();
                    let flow_id_c = flow_id_c.clone();
                    Box::pin(async move {
                        flow_pins_c.lock().await.remove(&flow_id_c);
                        flow_states_c.remove(&flow_id_c);
                        flow_counters_c.remove(&flow_id_c);
                    })
                }),
                DataplaneShape::Forwarder,
            ));
            runtime.forwarder_streams.insert(
                frame.session_id.clone(),
                ForwarderStreamState {
                    transport: match opened.transport {
                        OpenedForwarderTransport::Halves { send, recv } => {
                            ForwarderTransport::Halves {
                                send: tokio::sync::Mutex::new(send),
                                recv: tokio::sync::Mutex::new(recv),
                                counters,
                                close,
                            }
                        }
                        OpenedForwarderTransport::TcpSplice(splice) => {
                            let accounting =
                                Arc::new(ForwarderSpliceAccounting { counters, close });
                            ForwarderTransport::TcpSplice(splice.with_accounting(accounting))
                        }
                    },
                },
            );
            publish_flow_opened(runtime, frame, &result, shape).await;
            send_return(return_tx, runtime, frame, result.return_event.clone()).await;
            ForwarderOpenOutcome::Handled
        }
        Some(Err(reason)) => {
            let result = ExitResult {
                exit_id: exit.id().clone(),
                success: false,
                rtt_ms: 0,
                local_endpoint: None,
                return_event: ReturnEvent::Closed {
                    reason: close_from_disconnect(reason),
                },
            };
            record_dispatch(runtime, &result, frame.payload.len() as u64);
            publish_path_io_error(runtime, frame, &result, true);
            ForwarderOpenOutcome::Failed(result.return_event)
        }
        None => ForwarderOpenOutcome::Unsupported,
    }
}

struct ForwarderSpliceAccounting {
    counters: Arc<FlowCounters>,
    close: Arc<ForwarderClose>,
}

#[async_trait]
impl TcpSpliceAccounting for ForwarderSpliceAccounting {
    fn add_bytes(&self, direction: TcpSpliceDirection, bytes: u64) {
        let direction = match direction {
            TcpSpliceDirection::Up => crate::kernel::forwarder::Direction::Up,
            TcpSpliceDirection::Down => crate::kernel::forwarder::Direction::Down,
        };
        self.counters
            .field(direction)
            .fetch_add(bytes, Ordering::Relaxed);
    }

    async fn close_once(&self, reason: CloseReason) {
        self.close.close_once(reason).await;
    }
}

pub(super) async fn dispatch_forwarder_frame(
    frame: Frame,
    state: FlowState,
    return_tx: tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: DispatchRuntime,
) {
    let result = runtime.egresses[state.sink_idx].send(frame.clone()).await;
    record_dispatch(&runtime, &result, frame.payload.len() as u64);
    if result.success {
        state
            .counters
            .field(crate::kernel::forwarder::Direction::Up)
            .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
        let event = result.return_event.clone();
        if !matches!(event, ReturnEvent::Idle) {
            send_return(&return_tx, &runtime, &frame, event).await;
        }
        return;
    }

    publish_path_io_error(&runtime, &frame, &result, true);
    let reason = match result.return_event.clone() {
        ReturnEvent::Closed { reason } => reason,
        _ => CloseReason::Other("send failed".into()),
    };
    close_flow_if_open(
        &runtime,
        &frame.flow_id,
        reason.clone(),
        frame.session_id.clone(),
    )
    .await;
    let _ = return_tx.send(ReturnEvent::Closed { reason }).await;
}

pub(super) async fn try_open_forwarder_datagram(
    frame: &Frame,
    idx: usize,
    shape: DataplaneShape,
    _return_tx: &tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: &DispatchRuntime,
) -> DatagramForwarderProbeOutcome {
    if !matches!(frame.kind, FrameKind::Open) || shape != DataplaneShape::DatagramForwarder {
        return DatagramForwarderProbeOutcome::Fallback;
    }

    let exit = &runtime.egresses[idx];
    match exit.open_forwarder_datagram(frame).await {
        Some(Ok(opened)) => {
            let result = ExitResult {
                exit_id: exit.id().clone(),
                success: true,
                rtt_ms: opened.rtt_ms,
                local_endpoint: opened.local_endpoint.clone(),
                return_event: ReturnEvent::Connected {
                    exit_id: exit.id().clone(),
                    local_endpoint: opened.local_endpoint,
                    rtt_ms: opened.rtt_ms,
                },
            };
            record_dispatch(runtime, &result, 0);
            runtime
                .flow_pins
                .lock()
                .await
                .insert(frame.flow_id.clone(), idx);
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
            let flow_states_c = runtime.flow_states.clone();
            let flow_counters_c = runtime.flow_counters.clone();
            let flow_pins_c = runtime.flow_pins.clone();
            let flow_id_c = frame.flow_id.clone();
            let close = Arc::new(ForwarderClose::new(
                runtime.observation_bus.clone(),
                frame.flow_id.clone(),
                frame.session_id.clone(),
                result.exit_id.clone(),
                runtime.clock.clone(),
                Arc::new(move || {
                    let flow_states_c = flow_states_c.clone();
                    let flow_counters_c = flow_counters_c.clone();
                    let flow_pins_c = flow_pins_c.clone();
                    let flow_id_c = flow_id_c.clone();
                    Box::pin(async move {
                        flow_pins_c.lock().await.remove(&flow_id_c);
                        flow_states_c.remove(&flow_id_c);
                        flow_counters_c.remove(&flow_id_c);
                    })
                }),
                DataplaneShape::DatagramForwarder,
            ));
            runtime.forwarder_datagrams.insert(
                frame.session_id.clone(),
                ForwarderDatagramState {
                    transport: opened.transport,
                    counters,
                    close,
                    fixed_target: frame.target.clone(),
                },
            );
            publish_flow_opened(runtime, frame, &result, shape).await;
            // Probe result communicated through private probe_channels; never via ReturnEvent.
            if let Some((_, tx)) = runtime.probe_channels.remove(&frame.session_id) {
                let _ = tx.send(DatagramForwarderProbeOutcome::Handled);
            }
            DatagramForwarderProbeOutcome::Handled
        }
        Some(Err(reason)) => {
            let result = ExitResult {
                exit_id: exit.id().clone(),
                success: false,
                rtt_ms: 0,
                local_endpoint: None,
                return_event: ReturnEvent::Closed {
                    reason: close_from_disconnect(reason),
                },
            };
            record_dispatch(runtime, &result, 0);
            publish_path_io_error(runtime, frame, &result, true);
            DatagramForwarderProbeOutcome::Failed(result.return_event)
        }
        None => DatagramForwarderProbeOutcome::Fallback,
    }
}

fn close_from_disconnect(reason: crate::DisconnectReason) -> CloseReason {
    match reason {
        crate::DisconnectReason::ConnectionRefused => CloseReason::ConnectionRefused,
        crate::DisconnectReason::NetworkUnreachable => CloseReason::NetworkUnreachable,
        crate::DisconnectReason::HostUnreachable => CloseReason::HostUnreachable,
        crate::DisconnectReason::TtlExpired => CloseReason::TtlExpired,
        crate::DisconnectReason::TimedOut => CloseReason::TimedOut,
        crate::DisconnectReason::UpstreamEof => CloseReason::UpstreamEof,
        crate::DisconnectReason::ConnectionReset => CloseReason::ConnectionReset,
        crate::DisconnectReason::NotConnected => CloseReason::NotConnected,
        crate::DisconnectReason::NoUsableExit => CloseReason::NoUsableExit,
        crate::DisconnectReason::SessionClosed => CloseReason::SessionClosed,
        crate::DisconnectReason::ReaderClosed => CloseReason::ReaderClosed,
        crate::DisconnectReason::AddressNotSupported => CloseReason::AddressNotSupported,
        crate::DisconnectReason::Other(s) => CloseReason::Other(s),
    }
}

pub(super) fn apply_pin_with_hysteresis(
    order: &mut Vec<usize>,
    pinned: usize,
    egresses: &[Box<dyn EgressPlugin>],
    scheduler: &dyn SchedulerPlugin,
    candidates: &[ExitId],
    ctx: &RankContext,
    tau: f64,
) {
    let Some(pos) = order.iter().position(|idx| *idx == pinned) else {
        return;
    };
    if order.len() <= 1 {
        let idx = order.remove(pos);
        order.insert(0, idx);
        return;
    }
    let Some(best_alt_idx) = order.iter().copied().find(|i| *i != pinned) else {
        return;
    };
    let pin_score = scheduler.score_for(&egresses[pinned].id().clone(), candidates, ctx);
    let alt_score = scheduler.score_for(&egresses[best_alt_idx].id().clone(), candidates, ctx);
    if (pin_score as f64) < (1.0 + tau) * (alt_score as f64) {
        let idx = order.remove(pos);
        order.insert(0, idx);
    }
}

pub(super) fn valid_order(order: Vec<usize>, egress_count: usize) -> Vec<usize> {
    let mut seen = HashSet::new();
    order
        .into_iter()
        .filter(|idx| *idx < egress_count && seen.insert(*idx))
        .collect()
}
