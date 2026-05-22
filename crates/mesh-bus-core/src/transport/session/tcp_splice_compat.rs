use crate::{
    BusStreamRecvHalf, BusStreamSendHalf, CloseReason, DisconnectReason, TcpSpliceAccounting,
    TcpSpliceDirection, TcpSpliceSession,
};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub(super) fn halves_from_tcp_splice(
    splice: TcpSpliceSession,
) -> Option<(Box<dyn BusStreamSendHalf>, Box<dyn BusStreamRecvHalf>)> {
    let accounting = splice.accounting();
    let std_stream = splice.into_std();
    let _ = std_stream.set_nonblocking(true);
    let stream = tokio::net::TcpStream::from_std(std_stream).ok()?;
    let (reader, writer) = stream.into_split();
    Some((
        Box::new(DirectTcpSpliceCompatSendHalf {
            writer,
            accounting: accounting.clone(),
        }),
        Box::new(DirectTcpSpliceCompatRecvHalf {
            reader,
            accounting,
            last_error: None,
        }),
    ))
}

struct DirectTcpSpliceCompatSendHalf {
    writer: OwnedWriteHalf,
    accounting: Option<Arc<dyn TcpSpliceAccounting>>,
}

#[async_trait]
impl BusStreamSendHalf for DirectTcpSpliceCompatSendHalf {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        let len = payload.len() as u64;
        self.writer
            .write_all(&payload)
            .await
            .map_err(disconnect_reason_from_io)?;
        if let Some(accounting) = &self.accounting {
            accounting.add_bytes(TcpSpliceDirection::Up, len);
        }
        Ok(())
    }

    async fn shutdown_write(&mut self) {
        let _ = self.writer.shutdown().await;
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        if let Some(accounting) = &self.accounting {
            accounting.close_once(close_from_disconnect(reason)).await;
        }
    }
}

struct DirectTcpSpliceCompatRecvHalf {
    reader: OwnedReadHalf,
    accounting: Option<Arc<dyn TcpSpliceAccounting>>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl BusStreamRecvHalf for DirectTcpSpliceCompatRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        let mut buf = vec![0u8; 16 * 1024];
        match self.reader.read(&mut buf).await {
            Ok(0) => {
                self.last_error = Some(DisconnectReason::UpstreamEof);
                if let Some(accounting) = &self.accounting {
                    accounting.close_once(CloseReason::UpstreamEof).await;
                }
                None
            }
            Ok(n) => {
                if let Some(accounting) = &self.accounting {
                    accounting.add_bytes(TcpSpliceDirection::Down, n as u64);
                }
                Some(Bytes::copy_from_slice(&buf[..n]))
            }
            Err(e) => {
                let reason = disconnect_reason_from_io(e);
                self.last_error = Some(reason.clone());
                if let Some(accounting) = &self.accounting {
                    accounting.close_once(close_from_disconnect(reason)).await;
                }
                None
            }
        }
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
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

fn disconnect_reason_from_io(err: std::io::Error) -> DisconnectReason {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => DisconnectReason::ConnectionRefused,
        std::io::ErrorKind::TimedOut => DisconnectReason::TimedOut,
        std::io::ErrorKind::NotConnected => DisconnectReason::NotConnected,
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
            DisconnectReason::ConnectionReset
        }
        std::io::ErrorKind::UnexpectedEof => DisconnectReason::UpstreamEof,
        _ => DisconnectReason::Other(err.to_string()),
    }
}
