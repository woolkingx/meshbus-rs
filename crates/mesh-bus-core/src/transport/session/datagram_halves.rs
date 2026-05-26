use crate::{
    CloseReason, Frame, ReturnEvent, SessionId,
    kernel::forwarder::{
        DatagramForwarderProbeOutcome, FlowCounters, ForwarderClose, ForwarderDatagramState,
    },
    transport::session::types::{
        BusDatagramRecvHalf, BusDatagramSendHalf, BusDatagramSession, BusSessionInfo,
        BusSessionRequest, DisconnectReason, SendError,
    },
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::collections::HashMap;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::{Mutex, mpsc, oneshot};

use super::data_handle::{apply_request, convert_close_reason};

pub(super) struct DatagramShared {
    pub pending_sources: Mutex<HashMap<u64, Endpoint>>,
    pub request: BusSessionRequest,
    pub max_payload_bytes: usize,
}

pub(crate) struct InternalDatagramSession {
    pub(super) submit: mpsc::Sender<Frame>,
    pub(super) session_id: crate::SessionId,
    pub(super) returns: mpsc::Receiver<ReturnEvent>,
    pub(super) info: BusSessionInfo,
    pub(super) seq: u64,
    pub(super) shared: Arc<DatagramShared>,
    pub(crate) forwarder: Option<ForwarderDatagramState>,
    forwarder_datagrams: Arc<dashmap::DashMap<SessionId, ForwarderDatagramState>>,
    probe_done: bool,
    probe_channels:
        Arc<dashmap::DashMap<SessionId, oneshot::Sender<DatagramForwarderProbeOutcome>>>,
}

struct ProbeGuard {
    map: Arc<dashmap::DashMap<SessionId, oneshot::Sender<DatagramForwarderProbeOutcome>>>,
    key: SessionId,
    armed: bool,
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        if self.armed {
            self.map.remove(&self.key);
        }
    }
}

impl InternalDatagramSession {
    pub(crate) fn new(
        inner: crate::kernel::session_handle::SessionHandle,
        request: BusSessionRequest,
        info: BusSessionInfo,
        max_payload_bytes: usize,
    ) -> Self {
        Self {
            submit: inner.submit,
            session_id: inner.id,
            returns: inner.returns,
            forwarder_datagrams: inner.forwarder_datagrams,
            probe_channels: inner.probe_channels,
            info,
            seq: 0,
            shared: Arc::new(DatagramShared {
                pending_sources: Mutex::new(HashMap::new()),
                request,
                max_payload_bytes,
            }),
            forwarder: None,
            probe_done: false,
        }
    }
}

#[async_trait]
impl BusDatagramSession for InternalDatagramSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        // Direct forwarder mode: use the established direct half
        if let Some(ref fwd) = self.forwarder {
            if target != fwd.fixed_target {
                return Err(SendError::AddressNotSupported);
            }
            let len = payload.len() as u64;
            let result = fwd
                .transport
                .send
                .lock()
                .await
                .send_to(target, payload)
                .await;
            if result.is_ok() {
                fwd.counters
                    .field(crate::kernel::forwarder::Direction::Up)
                    .fetch_add(len, Ordering::Relaxed);
            }
            return result;
        }

        // Undecided: try datagram forwarder probe on first eligible send
        if !self.probe_done
            && target == self.shared.request.target
            && !matches!(
                self.shared.request.schedule_hint,
                crate::ScheduleHint::FanOut { .. }
            )
        {
            self.probe_done = true;
            let (probe_tx, probe_rx) = oneshot::channel();
            self.probe_channels
                .insert(self.session_id.clone(), probe_tx);
            let mut probe_guard = ProbeGuard {
                map: self.probe_channels.clone(),
                key: self.session_id.clone(),
                armed: true,
            };
            let mut probe = Frame::open(self.session_id.clone(), target.clone());
            apply_request(&mut probe, &self.shared.request);
            if self.submit.send(probe).await.is_err() {
                return Err(SendError::Closed);
            }
            match probe_rx.await {
                Ok(DatagramForwarderProbeOutcome::Handled) => {
                    if let Some((_, state)) = self.forwarder_datagrams.remove(&self.session_id) {
                        self.forwarder = Some(state);
                        let fwd = self.forwarder.as_ref().unwrap();
                        let len = payload.len() as u64;
                        let result = fwd
                            .transport
                            .send
                            .lock()
                            .await
                            .send_to(target, payload)
                            .await;
                        if result.is_ok() {
                            fwd.counters
                                .field(crate::kernel::forwarder::Direction::Up)
                                .fetch_add(len, Ordering::Relaxed);
                        }
                        probe_guard.armed = false;
                        return result;
                    }
                    // Handled but no direct state: fall through to FrameRouter
                }
                Ok(DatagramForwarderProbeOutcome::Failed(_)) => return Err(SendError::Closed),
                Ok(DatagramForwarderProbeOutcome::Fallback) | Err(_) => {}
            }
        } else if !self.probe_done {
            // Target differs from request target: skip probe, use FrameRouter always
            self.probe_done = true;
        }

        // FrameRouter path
        datagram_send(
            &self.shared,
            &self.submit,
            &self.session_id,
            &mut self.seq,
            target,
            payload,
        )
        .await
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        if let Some(ref fwd) = self.forwarder {
            return match fwd.transport.recv.lock().await.recv_from().await {
                Some((source, payload)) => {
                    fwd.counters
                        .field(crate::kernel::forwarder::Direction::Down)
                        .fetch_add(payload.len() as u64, Ordering::Relaxed);
                    Some((source, payload))
                }
                None => None,
            };
        }
        loop {
            match self.returns.recv().await {
                Some(ReturnEvent::Data { seq, payload }) => {
                    let source = self
                        .shared
                        .pending_sources
                        .lock()
                        .await
                        .remove(&seq)
                        .unwrap_or_else(|| self.shared.request.target.clone());
                    return Some((source, payload));
                }
                Some(ReturnEvent::Connected { .. }) => continue,
                Some(ReturnEvent::Idle) => continue,
                Some(ReturnEvent::Closed { .. }) | None => return None,
            }
        }
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        self.shared.max_payload_bytes
    }

    async fn close(&mut self) {
        if let Some(fwd) = self.forwarder.take() {
            fwd.transport.send.into_inner().close().await;
            fwd.close.close_once(CloseReason::SessionClosed).await;
            self.forwarder_datagrams.remove(&self.session_id);
            return;
        }
        let mut frame = Frame::close(
            self.session_id.clone(),
            self.seq,
            self.shared.request.target.clone(),
        );
        apply_request(&mut frame, &self.shared.request);
        let _ = self.submit.send(frame).await;
    }

    fn split(self: Box<Self>) -> (Box<dyn BusDatagramSendHalf>, Box<dyn BusDatagramRecvHalf>) {
        let session = *self;
        if let Some(fwd) = session.forwarder {
            return make_direct_datagram_forwarder_halves(fwd);
        }
        let shared = session.shared;
        let send_half = InternalDatagramSendHalf {
            submit: session.submit,
            session_id: session.session_id,
            shared: shared.clone(),
            seq: session.seq,
        };
        let recv_half = InternalDatagramRecvHalf {
            returns: session.returns,
            shared,
            last_error: None,
        };
        (Box::new(send_half), Box::new(recv_half))
    }
}

pub(crate) struct InternalDatagramSendHalf {
    submit: mpsc::Sender<Frame>,
    session_id: crate::SessionId,
    shared: Arc<DatagramShared>,
    seq: u64,
}

#[async_trait]
impl BusDatagramSendHalf for InternalDatagramSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        datagram_send(
            &self.shared,
            &self.submit,
            &self.session_id,
            &mut self.seq,
            target,
            payload,
        )
        .await
    }

    async fn close(&mut self) {
        let mut frame = Frame::close(
            self.session_id.clone(),
            self.seq,
            self.shared.request.target.clone(),
        );
        apply_request(&mut frame, &self.shared.request);
        let _ = self.submit.send(frame).await;
    }
}

async fn datagram_send(
    shared: &DatagramShared,
    submit: &mpsc::Sender<Frame>,
    session_id: &SessionId,
    seq: &mut u64,
    target: Endpoint,
    payload: Bytes,
) -> Result<(), SendError> {
    if payload.len() > shared.max_payload_bytes {
        return Err(SendError::PayloadTooLarge);
    }
    let frame_seq = *seq;
    *seq = (*seq).saturating_add(1);
    shared
        .pending_sources
        .lock()
        .await
        .insert(frame_seq, target.clone());
    let mut frame = Frame::datagram(session_id.clone(), frame_seq, target, payload);
    apply_request(&mut frame, &shared.request);
    submit.send(frame).await.map_err(|_| SendError::Closed)
}

pub(crate) struct InternalDatagramRecvHalf {
    returns: mpsc::Receiver<ReturnEvent>,
    shared: Arc<DatagramShared>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl BusDatagramRecvHalf for InternalDatagramRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        loop {
            match self.returns.recv().await {
                Some(ReturnEvent::Data { seq, payload }) => {
                    let source = self
                        .shared
                        .pending_sources
                        .lock()
                        .await
                        .remove(&seq)
                        .unwrap_or_else(|| self.shared.request.target.clone());
                    return Some((source, payload));
                }
                Some(ReturnEvent::Connected { .. }) | Some(ReturnEvent::Idle) => continue,
                Some(ReturnEvent::Closed { reason }) => {
                    self.last_error = Some(convert_close_reason(reason));
                    return None;
                }
                None => {
                    self.last_error = Some(DisconnectReason::ReaderClosed);
                    return None;
                }
            }
        }
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

// ── Direct datagram forwarder halves ─────────────────────────────────────────

struct DirectDatagramForwarderSendHalf {
    inner: Box<dyn BusDatagramSendHalf>,
    fixed_target: Endpoint,
    counters: Arc<FlowCounters>,
    close: Arc<ForwarderClose>,
}

struct DirectDatagramForwarderRecvHalf {
    inner: Box<dyn BusDatagramRecvHalf>,
    counters: Arc<FlowCounters>,
    close: Arc<ForwarderClose>,
}

#[async_trait]
impl BusDatagramSendHalf for DirectDatagramForwarderSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        if target != self.fixed_target {
            return Err(SendError::AddressNotSupported);
        }
        let len = payload.len() as u64;
        let result = self.inner.send_to(target, payload).await;
        if result.is_ok() {
            self.counters.bytes_out.fetch_add(len, Ordering::Relaxed);
        }
        result
    }

    async fn close(&mut self) {
        self.inner.close().await;
        self.close.close_once(CloseReason::SessionClosed).await;
    }
}

#[async_trait]
impl BusDatagramRecvHalf for DirectDatagramForwarderRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        match self.inner.recv_from().await {
            Some((source, payload)) => {
                self.counters
                    .bytes_in
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                Some((source, payload))
            }
            None => {
                let reason = self
                    .inner
                    .last_error()
                    .cloned()
                    .map(disconnect_to_close)
                    .unwrap_or(CloseReason::ReaderClosed);
                self.close.close_once(reason).await;
                None
            }
        }
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.inner.last_error()
    }
}

fn disconnect_to_close(reason: DisconnectReason) -> CloseReason {
    match reason {
        DisconnectReason::ConnectionRefused => CloseReason::ConnectionRefused,
        DisconnectReason::NetworkUnreachable => CloseReason::NetworkUnreachable,
        DisconnectReason::HostUnreachable => CloseReason::HostUnreachable,
        DisconnectReason::TtlExpired => CloseReason::TtlExpired,
        DisconnectReason::TimedOut => CloseReason::TimedOut,
        DisconnectReason::UpstreamEof => CloseReason::UpstreamEof,
        DisconnectReason::ConnectionReset => CloseReason::ConnectionReset,
        DisconnectReason::NotConnected => CloseReason::NotConnected,
        DisconnectReason::NoUsableExit => CloseReason::NoUsableExit,
        DisconnectReason::SessionClosed => CloseReason::SessionClosed,
        DisconnectReason::ReaderClosed => CloseReason::ReaderClosed,
        DisconnectReason::QueueFull => CloseReason::ConnectionReset,
        DisconnectReason::AddressNotSupported => CloseReason::AddressNotSupported,
        DisconnectReason::Other(s) => CloseReason::Other(s),
    }
}

pub(crate) fn make_direct_datagram_forwarder_halves(
    state: ForwarderDatagramState,
) -> (Box<dyn BusDatagramSendHalf>, Box<dyn BusDatagramRecvHalf>) {
    let send_inner = state.transport.send.into_inner();
    let recv_inner = state.transport.recv.into_inner();
    let counters = state.counters;
    let close = state.close;
    let fixed_target = state.fixed_target;
    (
        Box::new(DirectDatagramForwarderSendHalf {
            inner: send_inner,
            fixed_target,
            counters: counters.clone(),
            close: close.clone(),
        }),
        Box::new(DirectDatagramForwarderRecvHalf {
            inner: recv_inner,
            counters,
            close,
        }),
    )
}
