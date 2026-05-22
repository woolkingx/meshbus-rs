use std::sync::Arc;

use crate::{
    CloseReason, ExitResult, FlowId, Frame, Measurement, ReturnEvent,
    kernel::forwarder::{
        DataplaneShape, LIFECYCLE_CLOSE_TOTAL_DEADLINE, LIFECYCLE_OPEN_TOTAL_DEADLINE,
    },
    kernel::observation::{CoreEventId, EventPayload, EventPayloadInner, EventTypeId},
};

use super::dispatch::DispatchRuntime;

pub(super) fn record_dispatch(runtime: &DispatchRuntime, result: &ExitResult, payload_bytes: u64) {
    let measurement = Measurement {
        exit_id: result.exit_id.clone(),
        at_ms: (runtime.clock)(),
        rtt_ms: result.rtt_ms,
        payload_bytes,
        jitter_ms: None,
        throughput_bps: None,
        success: result.success,
    };
    update_exit_stats(runtime, &measurement);
}

pub(super) async fn publish_flow_opened(
    runtime: &DispatchRuntime,
    frame: &Frame,
    result: &ExitResult,
    shape: DataplaneShape,
) {
    let payload = EventPayload(Arc::new(EventPayloadInner {
        flow_id_text: Some(frame.flow_id.0.clone()),
        session_id_text: Some(frame.session_id.0.clone()),
        exit_id: Some(result.exit_id.0.clone()),
        selected_exit: Some(result.exit_id.0.clone()),
        route_group: frame.route_group.clone(),
        target_sink: frame.target_sink.clone(),
        packet_id: Some(frame.packet_id.0),
        payload_bytes: frame.payload.len() as u64,
        rtt_ms: result.rtt_ms,
        success: Some(true),
        shape: Some(shape_tag(shape)),
        at_ms: (runtime.clock)(),
        ..Default::default()
    }));
    let _ = runtime
        .observation_bus
        .publish_reliable(
            EventTypeId::Core(CoreEventId::FlowOpened),
            payload,
            LIFECYCLE_OPEN_TOTAL_DEADLINE,
        )
        .await;
}

pub(super) fn publish_path_io_error(
    runtime: &DispatchRuntime,
    frame: &Frame,
    result: &ExitResult,
    terminal: bool,
) {
    let close_reason = match &result.return_event {
        ReturnEvent::Closed { reason } => Some(format!("{reason:?}")),
        _ => None,
    };
    runtime.observation_bus.publish(
        EventTypeId::Core(CoreEventId::PathIoError),
        EventPayload(Arc::new(EventPayloadInner {
            flow_id_text: Some(frame.flow_id.0.clone()),
            session_id_text: Some(frame.session_id.0.clone()),
            exit_id: Some(result.exit_id.0.clone()),
            selected_exit: Some(result.exit_id.0.clone()),
            route_group: frame.route_group.clone(),
            target_sink: frame.target_sink.clone(),
            packet_id: Some(frame.packet_id.0),
            payload_bytes: frame.payload.len() as u64,
            rtt_ms: result.rtt_ms,
            success: Some(false),
            close_reason,
            terminal,
            at_ms: (runtime.clock)(),
            ..Default::default()
        })),
    );
}

pub(super) async fn close_flow_if_open(
    runtime: &DispatchRuntime,
    flow_id: &FlowId,
    reason: CloseReason,
    session_id: crate::SessionId,
) {
    let Some((_, state)) = runtime.flow_states.remove(flow_id) else {
        return;
    };
    runtime.flow_counters.remove(flow_id);
    let _ = runtime.flow_pins.lock().await.remove(flow_id);
    let payload = EventPayload(Arc::new(EventPayloadInner {
        flow_id_text: Some(flow_id.0.clone()),
        session_id_text: Some(session_id.0),
        exit_id: Some(state.exit_id.0.clone()),
        selected_exit: Some(state.exit_id.0),
        close_reason: Some(format!("{reason:?}")),
        success: Some(close_reason_is_success(&reason)),
        shape: Some(shape_tag(state.shape)),
        at_ms: (runtime.clock)(),
        ..Default::default()
    }));
    let _ = runtime
        .observation_bus
        .publish_reliable(
            EventTypeId::Core(CoreEventId::FlowClosed),
            payload,
            LIFECYCLE_CLOSE_TOTAL_DEADLINE,
        )
        .await;
}

fn update_exit_stats(runtime: &DispatchRuntime, measurement: &Measurement) {
    let mut entry = runtime
        .exit_stats
        .entry(measurement.exit_id.0.clone())
        .or_default();
    entry.send_count = entry.send_count.saturating_add(1);
    entry.last_rtt_ms = measurement.rtt_ms;
    entry.payload_bytes_total = entry
        .payload_bytes_total
        .saturating_add(measurement.payload_bytes);
    if measurement.success {
        entry.success_count = entry.success_count.saturating_add(1);
    } else {
        entry.failure_count = entry.failure_count.saturating_add(1);
    }
}

fn shape_tag(shape: DataplaneShape) -> u8 {
    shape.tag()
}

fn close_reason_is_success(reason: &CloseReason) -> bool {
    // UpstreamEof = remote sent FIN (normal TCP close); ReaderClosed = reader channel exhausted
    // (normal stream end). Both are graceful terminations, not errors.
    !matches!(
        reason,
        CloseReason::ConnectionRefused
            | CloseReason::NetworkUnreachable
            | CloseReason::HostUnreachable
            | CloseReason::TimedOut
            | CloseReason::NotConnected
            | CloseReason::ConnectionReset
            | CloseReason::AddressNotSupported
            | CloseReason::Other(_)
    )
}
