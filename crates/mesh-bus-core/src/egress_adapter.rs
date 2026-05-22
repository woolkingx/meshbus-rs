use crate::kernel::forwarder::{OpenedForwarderStream, OpenedForwarderTransport};
use crate::{
    BusDatagramRecvHalf, BusDatagramSendHalf, BusPathInfo, BusSessionInfo, BusSessionRequest,
    BusStreamEgress, BusStreamRecvHalf, BusStreamSendHalf, Capabilities, CloseReason,
    DisconnectReason, EgressPlugin, ExitId, ExitResult, Frame, FrameKind, Measurement, PathState,
    ReturnEvent, ScheduleHint, ScheduleMode,
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;
mod close_map;
mod datagram;
mod datagram_pending;
use close_map::close_from_disconnect;
pub(crate) use datagram::DatagramEgressAdapter;

pub(crate) struct DatagramState {
    pub(crate) send: Mutex<Box<dyn BusDatagramSendHalf>>,
    pub(crate) recv: Mutex<Box<dyn BusDatagramRecvHalf>>,
    pub(crate) pending_by_source: Mutex<datagram_pending::PendingDatagramSeqs>,
}

pub(crate) struct StreamEgressAdapter {
    inner: Box<dyn BusStreamEgress>,
    sessions: Arc<DashMap<crate::SessionId, Arc<StreamState>>>,
}

pub(crate) struct StreamState {
    send: Mutex<Box<dyn BusStreamSendHalf>>,
    recv: Mutex<Box<dyn BusStreamRecvHalf>>,
}

impl StreamEgressAdapter {
    pub(crate) fn new(inner: Box<dyn BusStreamEgress>) -> Self {
        Self {
            inner,
            sessions: Arc::new(DashMap::new()),
        }
    }

    async fn open_for_frame(
        &self,
        frame: &Frame,
    ) -> Result<(Option<mb_endpoint::Endpoint>, u64), DisconnectReason> {
        let request = request_from_frame(frame);
        let info = session_info_from_frame(frame, self.id().clone(), ScheduleMode::Ordered);
        let mut session = self.inner.open_stream(&request, info).await?;
        let connected = session.connect().await?;
        let local = connected
            .paths
            .get(connected.primary)
            .map(|path| path.local.clone());
        let rtt_ms = connected
            .paths
            .get(connected.primary)
            .map(|path| path.measurement.rtt_ms)
            .unwrap_or(0);
        let (send, recv) = session.split();
        self.sessions.insert(
            frame.session_id.clone(),
            Arc::new(StreamState {
                send: Mutex::new(send),
                recv: Mutex::new(recv),
            }),
        );
        Ok((local, rtt_ms))
    }
}

#[async_trait]
impl EgressPlugin for StreamEgressAdapter {
    fn id(&self) -> &ExitId {
        self.inner.id()
    }

    fn capabilities(&self) -> &Capabilities {
        self.inner.capabilities()
    }

    async fn open_forwarder_stream(
        &self,
        frame: &Frame,
    ) -> Option<Result<OpenedForwarderStream, DisconnectReason>> {
        let start = Instant::now();
        let request = request_from_frame(frame);
        let info = session_info_from_frame(frame, self.id().clone(), ScheduleMode::Ordered);
        let mut session = match self.inner.open_stream(&request, info).await {
            Ok(session) => session,
            Err(reason) => return Some(Err(reason)),
        };
        let connected = match session.connect().await {
            Ok(info) => info,
            Err(reason) => return Some(Err(reason)),
        };
        let local_endpoint = connected
            .paths
            .get(connected.primary)
            .map(|path| path.local.clone());
        let rtt_ms = connected
            .paths
            .get(connected.primary)
            .map(|path| path.measurement.rtt_ms)
            .filter(|rtt| *rtt > 0)
            .unwrap_or_else(|| start.elapsed().as_millis() as u64);
        let transport = match session.into_tcp_splice() {
            Ok(splice) => OpenedForwarderTransport::TcpSplice(splice),
            Err(session) => {
                let (send, recv) = session.split();
                OpenedForwarderTransport::Halves { send, recv }
            }
        };
        Some(Ok(OpenedForwarderStream {
            local_endpoint,
            rtt_ms,
            transport,
        }))
    }

    async fn send(&self, frame: Frame) -> ExitResult {
        let start = Instant::now();
        match frame.kind {
            FrameKind::Close | FrameKind::Cancel => {
                let state = self.sessions.remove(&frame.session_id).map(|(_, v)| v);
                if let Some(state) = state {
                    state
                        .send
                        .lock()
                        .await
                        .abort(DisconnectReason::SessionClosed)
                        .await;
                }
                return result(
                    self.id(),
                    true,
                    start,
                    None,
                    ReturnEvent::Closed {
                        reason: CloseReason::SessionClosed,
                    },
                );
            }
            FrameKind::ShutdownWrite => {
                let state = self.sessions.get(&frame.session_id).map(|r| r.clone());
                if let Some(state) = state {
                    state.send.lock().await.shutdown_write().await;
                }
                return result(self.id(), true, start, None, ReturnEvent::Idle);
            }
            FrameKind::Open | FrameKind::Data | FrameKind::Datagram | FrameKind::Probe => {}
        }

        let needs_open = !self.sessions.contains_key(&frame.session_id);
        let local_endpoint = if needs_open {
            match self.open_for_frame(&frame).await {
                Ok((local, open_rtt)) => {
                    if matches!(frame.kind, FrameKind::Open) {
                        return result(
                            self.id(),
                            true,
                            start,
                            local.clone(),
                            ReturnEvent::Connected {
                                exit_id: self.id().clone(),
                                local_endpoint: local,
                                rtt_ms: open_rtt,
                            },
                        );
                    }
                    local
                }
                Err(reason) => {
                    return result(
                        self.id(),
                        false,
                        start,
                        None,
                        ReturnEvent::Closed {
                            reason: close_from_disconnect(reason),
                        },
                    );
                }
            }
        } else {
            None
        };

        let state = self.sessions.get(&frame.session_id).map(|r| r.clone());
        let Some(state) = state else {
            return result(
                self.id(),
                false,
                start,
                None,
                ReturnEvent::Closed {
                    reason: CloseReason::NotConnected,
                },
            );
        };
        match state.send.lock().await.send(frame.payload).await {
            Ok(()) => result(self.id(), true, start, local_endpoint, ReturnEvent::Idle),
            Err(reason) => result(
                self.id(),
                false,
                start,
                local_endpoint,
                ReturnEvent::Closed {
                    reason: close_from_disconnect(reason),
                },
            ),
        }
    }

    async fn poll(&self, s: &crate::SessionId) -> ReturnEvent {
        let state = self.sessions.get(s).map(|r| r.clone());
        let Some(state) = state else {
            return ReturnEvent::Idle;
        };
        let mut recv = state.recv.lock().await;
        match recv.recv().await {
            Some(payload) => ReturnEvent::Data { seq: 0, payload },
            None => ReturnEvent::Closed {
                reason: recv
                    .last_error()
                    .cloned()
                    .map(close_from_disconnect)
                    .unwrap_or(CloseReason::ReaderClosed),
            },
        }
    }

    async fn probe(&self, _target: &mb_endpoint::Endpoint) -> Measurement {
        Measurement {
            exit_id: self.id().clone(),
            at_ms: 0,
            rtt_ms: 0,
            payload_bytes: 0,
            jitter_ms: None,
            throughput_bps: None,
            success: true,
        }
    }

    async fn close(&self, session_id: &crate::SessionId) {
        let state = self.sessions.remove(session_id).map(|(_, v)| v);
        if let Some(state) = state {
            state
                .send
                .lock()
                .await
                .abort(DisconnectReason::SessionClosed)
                .await;
        }
    }
}

pub(super) fn request_from_frame(frame: &Frame) -> BusSessionRequest {
    BusSessionRequest {
        target: frame.target.clone(),
        flow_semantics: frame.flow_semantics,
        traffic_class: frame.traffic_class,
        deadline_ms: frame.deadline_ms,
        policy_ref: frame.policy_ref.clone(),
        return_semantics: frame.return_semantics,
        schedule_hint: frame.schedule_hint,
        source_key: frame.source_key.clone(),
        target_key: frame.target_key.clone(),
        route_group: frame.route_group.clone(),
        target_sink: frame.target_sink.clone(),
    }
}

pub(super) fn session_info_from_frame(
    frame: &Frame,
    exit_id: ExitId,
    schedule_mode: ScheduleMode,
) -> BusSessionInfo {
    BusSessionInfo {
        session_id: frame.session_id.clone(),
        flow_id: frame.flow_id.clone(),
        schedule_mode: match frame.schedule_hint {
            ScheduleHint::FanOut { .. } => ScheduleMode::Replicate,
            ScheduleHint::Stripe { .. } => ScheduleMode::Stripe,
            ScheduleHint::Auto | ScheduleHint::SinglePath => schedule_mode,
        },
        paths: vec![BusPathInfo {
            exit_id: exit_id.clone(),
            local: frame.target.clone(),
            remote: frame.target.clone(),
            measurement: Measurement {
                exit_id,
                at_ms: 0,
                rtt_ms: 0,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            },
            state: PathState::Connecting,
        }],
        primary: 0,
        path_trace: frame.path_trace.iter().cloned().map(ExitId).collect(),
        started_at_ms: 0,
    }
}

pub(super) fn result(
    exit_id: &ExitId,
    success: bool,
    start: Instant,
    local_endpoint: Option<mb_endpoint::Endpoint>,
    return_event: ReturnEvent,
) -> ExitResult {
    ExitResult {
        exit_id: exit_id.clone(),
        success,
        rtt_ms: start.elapsed().as_millis() as u64,
        local_endpoint,
        return_event,
    }
}
