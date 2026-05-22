use crate::{
    CloseReason, ExitId, FlowId, FlowSemantics, Frame, ReturnEvent, ReturnSemantics,
    kernel::forwarder::{ForwarderStreamState, ForwarderTransport},
    kernel::session_handle::SessionHandle,
    transport::session::types::{
        BusPathInfo, BusSessionInfo, BusSessionRequest, BusStreamRecvHalf, BusStreamSendHalf,
        BusStreamSession, DisconnectReason, PathState, TcpSpliceSession,
    },
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::collections::VecDeque;
use tokio::sync::mpsc;

use crate::transport::forwarding::{ScheduleHint, ScheduleMode};
use crate::transport::session::direct_forwarder_halves::make_direct_forwarder_halves;
use crate::transport::session::tcp_splice_compat::halves_from_tcp_splice;

pub(crate) struct InternalStreamSession {
    inner: SessionHandle,
    request: BusSessionRequest,
    info: BusSessionInfo,
    last_error: Option<DisconnectReason>,
    pending: VecDeque<Bytes>,
    forwarder: Option<ForwarderStreamState>,
    seq: u64,
}

impl InternalStreamSession {
    pub(crate) fn new(
        inner: SessionHandle,
        request: BusSessionRequest,
        info: BusSessionInfo,
    ) -> Self {
        Self {
            inner,
            request,
            info,
            last_error: None,
            pending: VecDeque::new(),
            forwarder: None,
            seq: 0,
        }
    }

    fn request_frame(&self, mut frame: Frame) -> Frame {
        apply_request(&mut frame, &self.request);
        frame
    }

    fn record_connected_path(
        &mut self,
        exit_id: ExitId,
        local_endpoint: Option<Endpoint>,
        rtt_ms: u64,
    ) {
        let Some(local) = local_endpoint else {
            return;
        };
        self.info.paths.clear();
        self.info.paths.push(BusPathInfo {
            exit_id: exit_id.clone(),
            local,
            remote: self.request.target.clone(),
            measurement: crate::Measurement {
                exit_id,
                at_ms: 0,
                rtt_ms,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            },
            state: PathState::Active,
        });
        self.info.primary = 0;
    }
}

#[async_trait]
impl BusStreamSession for InternalStreamSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        let frame = self.request_frame(Frame::open(
            self.inner.id.clone(),
            self.request.target.clone(),
        ));
        self.inner
            .submit
            .send(frame)
            .await
            .map_err(|_| DisconnectReason::SessionClosed)?;
        match self.inner.returns.recv().await {
            Some(ReturnEvent::Connected {
                exit_id,
                local_endpoint,
                rtt_ms,
            }) => {
                self.record_connected_path(exit_id, local_endpoint, rtt_ms);
                self.forwarder = self
                    .inner
                    .forwarder_streams
                    .remove(&self.inner.id)
                    .map(|(_, v)| v);
                Ok(&self.info)
            }
            Some(ReturnEvent::Idle) => Ok(&self.info),
            Some(ReturnEvent::Data { payload, .. }) => {
                self.pending.push_back(payload);
                Ok(&self.info)
            }
            Some(ReturnEvent::Closed { reason }) => {
                let reason = convert_close_reason(reason);
                self.last_error = Some(reason.clone());
                Err(reason)
            }
            None => {
                self.last_error = Some(DisconnectReason::ReaderClosed);
                Err(DisconnectReason::ReaderClosed)
            }
        }
    }

    fn split(self: Box<Self>) -> (Box<dyn BusStreamSendHalf>, Box<dyn BusStreamRecvHalf>) {
        let session = *self;
        if let Some(forwarder) = session.forwarder {
            if let ForwarderTransport::Halves {
                send,
                recv,
                counters,
                close,
            } = forwarder.transport
            {
                return make_direct_forwarder_halves(
                    send.into_inner(),
                    recv.into_inner(),
                    counters,
                    close,
                );
            }
            if let ForwarderTransport::TcpSplice(splice) = forwarder.transport {
                if let Some(halves) = halves_from_tcp_splice(splice) {
                    return halves;
                }
            }
        }
        let sender = InternalStreamSendHalf {
            submit: session.inner.submit.clone(),
            session_id: session.inner.id.clone(),
            request: session.request,
            seq: session.seq,
        };
        let receiver = InternalStreamRecvHalf {
            returns: session.inner.returns,
            pending: session.pending,
            last_error: session.last_error,
        };
        (Box::new(sender), Box::new(receiver))
    }

    fn into_tcp_splice(self: Box<Self>) -> Result<TcpSpliceSession, Box<dyn BusStreamSession>> {
        let mut session = *self;
        if let Some(forwarder) = session.forwarder.take() {
            if let ForwarderTransport::TcpSplice(splice) = forwarder.transport {
                return Ok(splice);
            }
            session.forwarder = Some(forwarder);
        }
        Err(Box::new(session))
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        self.last_error = Some(reason);
        let frame = self.request_frame(Frame::close(
            self.inner.id.clone(),
            self.seq,
            self.request.target.clone(),
        ));
        let _ = self.inner.submit.send(frame).await;
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

pub(crate) struct InternalStreamSendHalf {
    submit: mpsc::Sender<Frame>,
    session_id: crate::SessionId,
    request: BusSessionRequest,
    seq: u64,
}

#[async_trait]
impl BusStreamSendHalf for InternalStreamSendHalf {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        let seq = self.seq;
        self.seq = self.seq.saturating_add(1);
        let mut frame = Frame::data(
            self.session_id.clone(),
            seq,
            self.request.target.clone(),
            payload,
        );
        apply_request(&mut frame, &self.request);
        self.submit
            .send(frame)
            .await
            .map_err(|_| DisconnectReason::SessionClosed)
    }

    async fn shutdown_write(&mut self) {
        let mut frame = Frame::shutdown_write(
            self.session_id.clone(),
            self.seq,
            self.request.target.clone(),
        );
        apply_request(&mut frame, &self.request);
        let _ = self.submit.send(frame).await;
    }

    async fn abort(&mut self, _reason: DisconnectReason) {
        let mut frame = Frame::close(
            self.session_id.clone(),
            self.seq,
            self.request.target.clone(),
        );
        apply_request(&mut frame, &self.request);
        let _ = self.submit.send(frame).await;
    }
}

pub(crate) struct InternalStreamRecvHalf {
    returns: mpsc::Receiver<ReturnEvent>,
    pending: VecDeque<Bytes>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl BusStreamRecvHalf for InternalStreamRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        if let Some(payload) = self.pending.pop_front() {
            return Some(payload);
        }
        loop {
            match self.returns.recv().await {
                Some(ReturnEvent::Connected { .. }) => continue,
                Some(ReturnEvent::Data { payload, .. }) => return Some(payload),
                Some(ReturnEvent::Idle) => continue,
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

pub(super) fn convert_close_reason(reason: CloseReason) -> DisconnectReason {
    match reason {
        CloseReason::TtlExpired => DisconnectReason::TtlExpired,
        CloseReason::SessionClosed => DisconnectReason::SessionClosed,
        CloseReason::NoUsableExit => DisconnectReason::NoUsableExit,
        CloseReason::ConnectionRefused => DisconnectReason::ConnectionRefused,
        CloseReason::NetworkUnreachable => DisconnectReason::NetworkUnreachable,
        CloseReason::HostUnreachable => DisconnectReason::HostUnreachable,
        CloseReason::TimedOut => DisconnectReason::TimedOut,
        CloseReason::NotConnected => DisconnectReason::NotConnected,
        CloseReason::ConnectionReset => DisconnectReason::ConnectionReset,
        CloseReason::UpstreamEof => DisconnectReason::UpstreamEof,
        CloseReason::ReaderClosed => DisconnectReason::ReaderClosed,
        CloseReason::AddressNotSupported => DisconnectReason::AddressNotSupported,
        CloseReason::Other(s) => DisconnectReason::Other(s),
    }
}

pub(crate) fn session_info_for(
    handle: &SessionHandle,
    request: &BusSessionRequest,
) -> BusSessionInfo {
    BusSessionInfo {
        session_id: handle.id.clone(),
        // L5 carries the L4-owned flow identity (data-ontology: L5 re-exposes,
        // does not author). Derivation is the single L4 mint; full
        // Open-return-channel plumbing is the documented follow-up.
        flow_id: FlowId::mint_for(&handle.id, &request.target),
        schedule_mode: schedule_mode_for(request),
        paths: Vec::new(),
        primary: 0,
        path_trace: Vec::new(),
        started_at_ms: 0,
    }
}

fn schedule_mode_for(request: &BusSessionRequest) -> ScheduleMode {
    match request.schedule_hint {
        ScheduleHint::FanOut { .. } => ScheduleMode::Replicate,
        ScheduleHint::Stripe { .. } => ScheduleMode::Stripe,
        ScheduleHint::Auto | ScheduleHint::SinglePath => ScheduleMode::Ordered,
    }
}

pub(crate) fn apply_request(frame: &mut Frame, request: &BusSessionRequest) {
    frame.traffic_class = request.traffic_class;
    frame.policy_ref.clone_from(&request.policy_ref);
    frame.deadline_ms = request.deadline_ms;
    frame.schedule_hint = request.schedule_hint;
    frame.flow_semantics = request.flow_semantics;
    frame.return_semantics = request.return_semantics;
    frame.source_key.clone_from(&request.source_key);
    frame.target_key.clone_from(&request.target_key);
    frame.route_group.clone_from(&request.route_group);
    frame.target_sink.clone_from(&request.target_sink);
}

pub(crate) fn validate_stream_request(request: &BusSessionRequest) -> Result<(), DisconnectReason> {
    if request.flow_semantics != FlowSemantics::ByteStream {
        return Err(DisconnectReason::AddressNotSupported);
    }
    if request.return_semantics != ReturnSemantics::Direct {
        return Err(DisconnectReason::AddressNotSupported);
    }
    if matches!(
        request.schedule_hint,
        ScheduleHint::FanOut { .. } | ScheduleHint::Stripe { .. }
    ) {
        return Err(DisconnectReason::AddressNotSupported);
    }
    Ok(())
}

pub(crate) fn validate_datagram_request(
    request: &BusSessionRequest,
) -> Result<(), DisconnectReason> {
    if request.flow_semantics != FlowSemantics::Datagram {
        return Err(DisconnectReason::AddressNotSupported);
    }
    if request.return_semantics == ReturnSemantics::SequenceReorder {
        return Err(DisconnectReason::AddressNotSupported);
    }
    if matches!(request.schedule_hint, ScheduleHint::FanOut { k: 0 }) {
        return Err(DisconnectReason::AddressNotSupported);
    }
    if matches!(request.schedule_hint, ScheduleHint::Stripe { .. }) {
        return Err(DisconnectReason::AddressNotSupported);
    }
    Ok(())
}
