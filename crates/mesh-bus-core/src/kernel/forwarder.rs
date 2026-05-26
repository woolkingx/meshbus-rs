use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use crate::{
    BusStreamRecvHalf, BusStreamSendHalf, Capabilities, CloseReason, ExitId, FlowId, FlowSemantics,
    ReturnSemantics, SessionId, TcpSpliceSession,
    kernel::observation::{
        CoreEventId, EventPayload, EventPayloadInner, EventTypeId, ObservationBus,
    },
};
use std::time::Duration;
use tokio::sync::Mutex;

pub const LIFECYCLE_OPEN_TOTAL_DEADLINE: Duration = Duration::from_millis(10);
pub const LIFECYCLE_CLOSE_TOTAL_DEADLINE: Duration = Duration::from_millis(50);
pub(crate) type ForwarderCloseCleanup =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

#[cfg(test)]
pub(crate) fn noop_forwarder_close_cleanup() -> ForwarderCloseCleanup {
    Arc::new(|| Box::pin(async {}))
}

/// Outcome of a successful `EgressPlugin::open_forwarder_stream` call.
/// Published as part of the owner-test data contract (0.4.39).
pub struct OpenedForwarderStream {
    pub local_endpoint: Option<mb_endpoint::Endpoint>,
    pub rtt_ms: u64,
    pub transport: OpenedForwarderTransport,
}

/// Transport variant returned by `open_forwarder_stream`.
pub enum OpenedForwarderTransport {
    Halves {
        send: Box<dyn BusStreamSendHalf>,
        recv: Box<dyn BusStreamRecvHalf>,
    },
    TcpSplice(TcpSpliceSession),
}

pub(crate) struct ForwarderStreamState {
    pub transport: ForwarderTransport,
}

pub(crate) enum ForwarderTransport {
    Halves {
        send: Mutex<Box<dyn BusStreamSendHalf>>,
        recv: Mutex<Box<dyn BusStreamRecvHalf>>,
        counters: Arc<FlowCounters>,
        close: Arc<ForwarderClose>,
    },
    TcpSplice(TcpSpliceSession),
}

pub(crate) struct ForwarderClose {
    observation_bus: Arc<ObservationBus>,
    flow_id: FlowId,
    session_id: SessionId,
    exit_id: ExitId,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    closed: AtomicBool,
    on_close: ForwarderCloseCleanup,
    shape: DataplaneShape,
}

impl ForwarderClose {
    pub(crate) fn new(
        observation_bus: Arc<ObservationBus>,
        flow_id: FlowId,
        session_id: SessionId,
        exit_id: ExitId,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        on_close: ForwarderCloseCleanup,
        shape: DataplaneShape,
    ) -> Self {
        Self {
            observation_bus,
            flow_id,
            session_id,
            exit_id,
            clock,
            closed: AtomicBool::new(false),
            on_close,
            shape,
        }
    }

    pub(crate) async fn close_once(&self, reason: CloseReason) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        (self.on_close)().await;
        let payload = EventPayload(Arc::new(EventPayloadInner {
            flow_id_text: Some(self.flow_id.0.clone()),
            session_id_text: Some(self.session_id.0.clone()),
            exit_id: Some(self.exit_id.0.clone()),
            selected_exit: Some(self.exit_id.0.clone()),
            close_reason: Some(format!("{reason:?}")),
            success: Some(close_reason_is_success(&reason)),
            shape: Some(self.shape.tag()),
            at_ms: (self.clock)(),
            ..Default::default()
        }));
        let _ = self
            .observation_bus
            .publish_reliable(
                EventTypeId::Core(CoreEventId::FlowClosed),
                payload,
                LIFECYCLE_CLOSE_TOTAL_DEADLINE,
            )
            .await;
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Direction {
    Up,
    Down,
}

#[derive(Debug)]
pub struct FlowCounters {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

#[derive(Clone, Debug, Default)]
pub struct FlowCountersSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Default for FlowCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowCounters {
    pub fn new() -> Self {
        Self {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }

    pub fn field(&self, dir: Direction) -> &AtomicU64 {
        match dir {
            Direction::Up => &self.bytes_out,
            Direction::Down => &self.bytes_in,
        }
    }

    pub fn snapshot(&self) -> FlowCountersSnapshot {
        FlowCountersSnapshot {
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }
}

/// Outcome of a successful `EgressPlugin::open_forwarder_datagram` call.
/// Published as part of the owner-test data contract (0.4.39).
pub struct OpenedForwarderDatagram {
    pub local_endpoint: Option<mb_endpoint::Endpoint>,
    pub rtt_ms: u64,
    pub transport: ForwarderDatagramTransport,
}

/// Transport variant returned by `open_forwarder_datagram`.
pub struct ForwarderDatagramTransport {
    pub send: Mutex<Box<dyn crate::BusDatagramSendHalf>>,
    pub recv: Mutex<Box<dyn crate::BusDatagramRecvHalf>>,
}

pub(crate) struct ForwarderDatagramState {
    pub transport: ForwarderDatagramTransport,
    pub counters: Arc<FlowCounters>,
    pub close: Arc<ForwarderClose>,
    pub fixed_target: mb_endpoint::Endpoint,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataplaneShape {
    Forwarder,
    DatagramForwarder,
    FrameRouter,
}

/// Internal probe outcome: communicated via per-session oneshot, never via ReturnEvent.
pub(crate) enum DatagramForwarderProbeOutcome {
    Handled,
    Fallback,
    Failed(crate::ReturnEvent),
}

#[derive(Default, Clone, Debug)]
pub struct TransformRequirements {
    pub steps: Vec<&'static str>,
}

impl TransformRequirements {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
    pub fn with(step: &'static str) -> Self {
        Self { steps: vec![step] }
    }
}

impl DataplaneShape {
    pub fn tag(self) -> u8 {
        match self {
            Self::Forwarder => 0,
            Self::FrameRouter => 1,
            Self::DatagramForwarder => 2,
        }
    }

    pub fn derive(
        flow_semantics: FlowSemantics,
        return_semantics: ReturnSemantics,
        realized_paths_at_open: usize,
        sink_caps: &Capabilities,
        transform_reqs: &TransformRequirements,
    ) -> Self {
        if realized_paths_at_open != 1 || !transform_reqs.is_empty() {
            return Self::FrameRouter;
        }
        match flow_semantics {
            FlowSemantics::ByteStream
                if return_semantics == ReturnSemantics::Direct && sink_caps.supports_stream =>
            {
                Self::Forwarder
            }
            FlowSemantics::Datagram
                if matches!(
                    return_semantics,
                    ReturnSemantics::Direct | ReturnSemantics::PacketDedup
                ) && sink_caps.supports_datagram =>
            {
                Self::DatagramForwarder
            }
            _ => Self::FrameRouter,
        }
    }
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

#[cfg(test)]
#[path = "forwarder_tests.rs"]
mod forwarder_tests;
