use super::session_handle::SessionHandle;
use crate::{
    DisconnectReason, Frame, ReturnEvent, SessionId,
    kernel::forwarder::{
        DatagramForwarderProbeOutcome, ForwarderDatagramState, ForwarderStreamState,
    },
    kernel::observation::{EventPayload, EventTypeId, ObservationBus},
    transport::session::data_handle::{
        InternalStreamSession, session_info_for, validate_datagram_request, validate_stream_request,
    },
    transport::session::datagram_halves::InternalDatagramSession,
    transport::session::types::{BusDatagramSession, BusSessionRequest, BusStreamSession},
};
use mb_endpoint::Endpoint;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
pub struct BusPort {
    pub(crate) submit_tx: mpsc::Sender<(
        Frame,
        SessionId,
        mpsc::Sender<ReturnEvent>,
        oneshot::Sender<()>,
    )>,
    pub(crate) next_session_id: Arc<AtomicU64>,
    pub(crate) supports_stream: bool,
    pub(crate) supports_datagram: bool,
    pub(crate) forwarder_streams: Arc<dashmap::DashMap<SessionId, ForwarderStreamState>>,
    pub(crate) forwarder_datagrams: Arc<dashmap::DashMap<SessionId, ForwarderDatagramState>>,
    pub(crate) probe_channels: Arc<
        dashmap::DashMap<SessionId, tokio::sync::oneshot::Sender<DatagramForwarderProbeOutcome>>,
    >,
    pub(crate) observation_bus: Arc<ObservationBus>,
}

impl BusPort {
    pub fn supports_stream(&self) -> bool {
        self.supports_stream
    }

    pub fn supports_datagram(&self) -> bool {
        self.supports_datagram
    }

    pub fn publish_observation(&self, type_id: EventTypeId, payload: EventPayload) {
        self.observation_bus.publish(type_id, payload);
    }

    /// Raw Frame-level session. Part of the published owner-test data contract (0.4.39).
    /// Runtime application participants must use `open_stream`/`open_datagram` instead.
    pub async fn open_session(&self, target: Endpoint) -> SessionHandle {
        let n = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let id = SessionId(format!("s-{n}"));
        let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(64);
        let (return_tx, return_rx) = mpsc::channel::<ReturnEvent>(64);
        let submit_tx = self.submit_tx.clone();
        let id_clone = id.clone();
        tokio::spawn(async move {
            let _ = target;
            while let Some(frame) = frame_rx.recv().await {
                let (done_tx, done_rx) = oneshot::channel();
                if submit_tx
                    .send((frame, id_clone.clone(), return_tx.clone(), done_tx))
                    .await
                    .is_err()
                {
                    break;
                }
                if done_rx.await.is_err() {
                    break;
                }
            }
        });
        SessionHandle {
            id,
            submit: frame_tx,
            returns: return_rx,
            forwarder_streams: self.forwarder_streams.clone(),
            forwarder_datagrams: self.forwarder_datagrams.clone(),
            probe_channels: self.probe_channels.clone(),
        }
    }

    pub async fn open_stream(
        &self,
        request: BusSessionRequest,
    ) -> Result<Box<dyn BusStreamSession>, DisconnectReason> {
        validate_stream_request(&request)?;
        let handle = self.open_session(request.target.clone()).await;
        let info = session_info_for(&handle, &request);
        Ok(Box::new(InternalStreamSession::new(handle, request, info)))
    }

    pub async fn open_datagram(
        &self,
        request: BusSessionRequest,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        validate_datagram_request(&request)?;
        if !self.supports_datagram {
            return Err(DisconnectReason::HostUnreachable);
        }
        let handle = self.open_session(request.target.clone()).await;
        let info = session_info_for(&handle, &request);
        Ok(Box::new(InternalDatagramSession::new(
            handle, request, info, 65_507,
        )))
    }
}
