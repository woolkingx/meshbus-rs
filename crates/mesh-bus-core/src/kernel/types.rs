use crate::SessionId;
use thiserror::Error;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BusEvent {
    SessionOpened(SessionId),
    SessionClosed { id: SessionId, reason: String },
    Core(crate::kernel::observation::EventEnvelope),
    Observation(crate::kernel::observation::EventEnvelope),
}

#[derive(Debug, Error)]
pub enum BusError {
    #[error("no scheduler registered")]
    NoScheduler,
    #[error("no egress registered")]
    NoEgress,
    #[error("session not found: {0:?}")]
    SessionNotFound(crate::SessionId),
    #[error("channel closed")]
    ChannelClosed,
    #[error("shutdown drain timed out")]
    DrainTimeout,
    #[error("invalid observation registry: {0:?}")]
    InvalidObservationRegistry(Vec<String>),
}
