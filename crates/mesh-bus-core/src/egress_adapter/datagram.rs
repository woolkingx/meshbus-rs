use super::close_map::close_from_disconnect;
use super::datagram_pending::{
    PendingDatagramSeqs, datagram_key, pop_pending_seq, remove_pending_seq,
};
use super::{DatagramState, request_from_frame, result, session_info_from_frame};
use crate::kernel::forwarder::{ForwarderDatagramTransport, OpenedForwarderDatagram};
use crate::{
    BusDatagramEgress, Capabilities, CloseReason, DisconnectReason, EgressPlugin, ExitId,
    ExitResult, Frame, FrameKind, Measurement, ReturnEvent, ScheduleMode,
};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;

pub(crate) struct DatagramEgressAdapter {
    pub(super) inner: Box<dyn BusDatagramEgress>,
    pub(super) sessions: Arc<DashMap<crate::SessionId, Arc<DatagramState>>>,
    pub(super) open_lock: Mutex<()>,
}

impl DatagramEgressAdapter {
    pub(crate) fn new(inner: Box<dyn BusDatagramEgress>) -> Self {
        Self {
            inner,
            sessions: Arc::new(DashMap::new()),
            open_lock: Mutex::new(()),
        }
    }

    async fn open_for_datagram(&self, frame: &Frame) -> Result<(), CloseReason> {
        let request = request_from_frame(frame);
        let info = session_info_from_frame(frame, self.id().clone(), ScheduleMode::Ordered);
        let session = self
            .inner
            .open_datagram(&request, info)
            .await
            .map_err(close_from_disconnect)?;
        let (send, recv) = session.split();
        self.sessions.insert(
            frame.session_id.clone(),
            Arc::new(DatagramState {
                send: Mutex::new(send),
                recv: Mutex::new(recv),
                pending_by_source: Mutex::new(PendingDatagramSeqs::new()),
            }),
        );
        Ok(())
    }
}

#[async_trait]
impl EgressPlugin for DatagramEgressAdapter {
    fn id(&self) -> &ExitId {
        self.inner.id()
    }

    fn capabilities(&self) -> &Capabilities {
        self.inner.capabilities()
    }

    async fn open_forwarder_datagram(
        &self,
        frame: &Frame,
    ) -> Option<Result<OpenedForwarderDatagram, DisconnectReason>> {
        let start = Instant::now();
        let request = request_from_frame(frame);
        let info = session_info_from_frame(frame, self.id().clone(), ScheduleMode::Ordered);
        let session = match self.inner.open_datagram(&request, info).await {
            Ok(s) => s,
            Err(reason) => return Some(Err(reason)),
        };
        let rtt_ms = start.elapsed().as_millis() as u64;
        let (send, recv) = session.split();
        Some(Ok(OpenedForwarderDatagram {
            local_endpoint: None,
            rtt_ms,
            transport: ForwarderDatagramTransport {
                send: Mutex::new(send),
                recv: Mutex::new(recv),
            },
        }))
    }

    async fn send(&self, frame: Frame) -> ExitResult {
        let start = Instant::now();
        if matches!(frame.kind, FrameKind::Close | FrameKind::Cancel) {
            if let Some((_, state)) = self.sessions.remove(&frame.session_id) {
                state.send.lock().await.close().await;
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

        if !self.sessions.contains_key(&frame.session_id) {
            let _open_guard = self.open_lock.lock().await;
            if !self.sessions.contains_key(&frame.session_id) {
                if let Err(reason) = self.open_for_datagram(&frame).await {
                    return result(
                        self.id(),
                        false,
                        start,
                        None,
                        ReturnEvent::Closed { reason },
                    );
                }
            }
        }

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

        {
            let mut pending = state.pending_by_source.lock().await;
            pending
                .entry(datagram_key(&frame.target))
                .or_default()
                .push_back(frame.seq);
        }

        if let Err(err) = state
            .send
            .lock()
            .await
            .send_to(frame.target.clone(), frame.payload.clone())
            .await
        {
            remove_pending_seq(&*state, &frame.target, frame.seq).await;
            return result(
                self.id(),
                false,
                start,
                None,
                ReturnEvent::Closed {
                    reason: match err {
                        crate::SendError::PayloadTooLarge => CloseReason::AddressNotSupported,
                        crate::SendError::AddressNotSupported => CloseReason::AddressNotSupported,
                        crate::SendError::BufferFull => CloseReason::TimedOut,
                        crate::SendError::Closed => CloseReason::SessionClosed,
                    },
                },
            );
        }

        result(self.id(), true, start, None, ReturnEvent::Idle)
    }

    async fn poll(&self, s: &crate::SessionId) -> ReturnEvent {
        let state = self.sessions.get(s).map(|r| r.clone());
        let Some(state) = state else {
            return ReturnEvent::Idle;
        };
        let mut recv = state.recv.lock().await;
        match recv.recv_from().await {
            Some((source, payload)) => {
                let seq = pop_pending_seq(&*state, &source).await.unwrap_or(0);
                ReturnEvent::Data { seq, payload }
            }
            None => ReturnEvent::Closed {
                reason: recv
                    .last_error()
                    .cloned()
                    .map(close_from_disconnect)
                    .unwrap_or(CloseReason::UpstreamEof),
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
        if let Some((_, state)) = self.sessions.remove(session_id) {
            state.send.lock().await.close().await;
        }
    }
}
