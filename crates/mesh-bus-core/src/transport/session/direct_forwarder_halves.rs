use crate::{
    BusStreamRecvHalf, BusStreamSendHalf, CloseReason, DisconnectReason,
    kernel::forwarder::{FlowCounters, ForwarderClose},
};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub(super) fn make_direct_forwarder_halves(
    send: Box<dyn BusStreamSendHalf>,
    recv: Box<dyn BusStreamRecvHalf>,
    counters: Arc<FlowCounters>,
    close: Arc<ForwarderClose>,
) -> (Box<dyn BusStreamSendHalf>, Box<dyn BusStreamRecvHalf>) {
    (
        Box::new(DirectForwarderSendHalf {
            inner: send,
            counters: counters.clone(),
            close: close.clone(),
        }),
        Box::new(DirectForwarderRecvHalf {
            inner: recv,
            counters,
            close,
        }),
    )
}

struct DirectForwarderSendHalf {
    inner: Box<dyn BusStreamSendHalf>,
    counters: Arc<FlowCounters>,
    close: Arc<ForwarderClose>,
}

#[async_trait]
impl BusStreamSendHalf for DirectForwarderSendHalf {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        let len = payload.len() as u64;
        self.inner.send(payload).await?;
        self.counters
            .field(crate::kernel::forwarder::Direction::Up)
            .fetch_add(len, Ordering::Relaxed);
        Ok(())
    }

    async fn shutdown_write(&mut self) {
        self.inner.shutdown_write().await;
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        self.inner.abort(reason.clone()).await;
        self.close.close_once(close_from_disconnect(reason)).await;
    }
}

struct DirectForwarderRecvHalf {
    inner: Box<dyn BusStreamRecvHalf>,
    counters: Arc<FlowCounters>,
    close: Arc<ForwarderClose>,
}

#[async_trait]
impl BusStreamRecvHalf for DirectForwarderRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        let payload = self.inner.recv().await;
        match payload {
            Some(payload) => {
                self.counters
                    .field(crate::kernel::forwarder::Direction::Down)
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                Some(payload)
            }
            None => {
                let reason = self
                    .inner
                    .last_error()
                    .cloned()
                    .unwrap_or(DisconnectReason::UpstreamEof);
                self.close.close_once(close_from_disconnect(reason)).await;
                None
            }
        }
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.inner.last_error()
    }
}

fn close_from_disconnect(reason: DisconnectReason) -> CloseReason {
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
        DisconnectReason::AddressNotSupported => CloseReason::AddressNotSupported,
        DisconnectReason::Other(s) => CloseReason::Other(s),
    }
}
