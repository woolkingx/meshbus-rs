use crate::{
    Frame, ReturnEvent, SessionId,
    kernel::forwarder::{
        DatagramForwarderProbeOutcome, ForwarderDatagramState, ForwarderStreamState,
    },
};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Raw Frame-level session handle. Part of the published owner-test data contract (0.4.39).
/// Runtime application participants must use `BusPort::open_stream`/`open_datagram` instead.
pub struct SessionHandle {
    pub id: SessionId,
    pub submit: mpsc::Sender<Frame>,
    pub returns: mpsc::Receiver<ReturnEvent>,
    pub(crate) forwarder_streams: Arc<dashmap::DashMap<SessionId, ForwarderStreamState>>,
    pub(crate) forwarder_datagrams: Arc<dashmap::DashMap<SessionId, ForwarderDatagramState>>,
    pub(crate) probe_channels: Arc<
        dashmap::DashMap<SessionId, tokio::sync::oneshot::Sender<DatagramForwarderProbeOutcome>>,
    >,
}
