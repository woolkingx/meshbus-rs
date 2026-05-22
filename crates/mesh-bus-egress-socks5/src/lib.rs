//! SOCKS5 egress factory. CONNECT is exposed as one L4 stream session.

mod udp;
mod upstream;

pub use udp::Socks5UdpEgress;
pub use upstream::Socks5UpstreamAuth;

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{Reply, encode_connect_request};
use mesh_bus_core::{
    BusPathInfo, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason, ExitId,
    Measurement, PathState, StreamEgress, StreamRecvHalf, StreamSendHalf, StreamSession,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use upstream::{
    disconnect_from_reply, disconnect_reason, endpoint_from_socket_addr, negotiate_auth,
    read_reply_frame_atyp, timed_io,
};

pub struct Socks5Egress {
    id: ExitId,
    caps: Capabilities,
    upstream: String,
    timeout: Duration,
    auth: Option<Arc<Socks5UpstreamAuth>>,
}

impl Socks5Egress {
    pub fn new(id: ExitId, upstream: String, timeout: Duration) -> Self {
        Self {
            id,
            caps: Capabilities {
                protocol: "socks5".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: Vec::new(),
            },
            upstream,
            timeout,
            auth: None,
        }
    }

    /// Tag this egress with route_group labels (see [`TcpEgress::with_groups`]).
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.caps.groups = groups;
        self
    }

    /// Authenticate to the upstream SOCKS5 proxy with RFC1929 user/pass.
    pub fn with_auth(mut self, auth: Socks5UpstreamAuth) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }
}

#[async_trait]
impl StreamEgress for Socks5Egress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn open_stream(
        &self,
        request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        Ok(Box::new(Socks5StreamSession {
            exit_id: self.id.clone(),
            upstream: self.upstream.clone(),
            target: request.target.clone(),
            timeout: self.timeout,
            auth: self.auth.clone(),
            info,
            writer: None,
            returns: None,
            last_error: None,
        }))
    }
}

struct Socks5StreamSession {
    exit_id: ExitId,
    upstream: String,
    target: Endpoint,
    timeout: Duration,
    auth: Option<Arc<Socks5UpstreamAuth>>,
    info: BusSessionInfo,
    writer: Option<OwnedWriteHalf>,
    returns: Option<mpsc::Receiver<Result<Bytes, DisconnectReason>>>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl StreamSession for Socks5StreamSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        let (stream, local) = open_socks5(
            &self.upstream,
            &self.target,
            self.timeout,
            self.auth.as_deref(),
        )
        .await?;
        let (reader, writer) = stream.into_split();
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(read_returns(reader, tx));
        self.info.paths.clear();
        self.info.paths.push(BusPathInfo {
            exit_id: self.exit_id.clone(),
            local,
            remote: self.target.clone(),
            measurement: Measurement {
                exit_id: self.exit_id.clone(),
                at_ms: 0,
                rtt_ms: 0,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            },
            state: PathState::Active,
        });
        self.info.primary = 0;
        self.writer = Some(writer);
        self.returns = Some(rx);
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        let session = *self;
        (
            Box::new(Socks5SendHalf {
                writer: session.writer,
                timeout: session.timeout,
            }),
            Box::new(Socks5RecvHalf {
                returns: session.returns,
                last_error: session.last_error,
            }),
        )
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        self.last_error = Some(reason);
        self.writer.take();
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

struct Socks5SendHalf {
    writer: Option<OwnedWriteHalf>,
    timeout: Duration,
}

#[async_trait]
impl StreamSendHalf for Socks5SendHalf {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        let writer = self.writer.as_mut().ok_or(DisconnectReason::NotConnected)?;
        tokio::time::timeout(self.timeout, writer.write_all(&payload))
            .await
            .map_err(|_| DisconnectReason::TimedOut)?
            .map_err(disconnect_reason)
    }

    async fn shutdown_write(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = writer.shutdown().await;
        }
        self.writer.take();
    }

    async fn abort(&mut self, _reason: DisconnectReason) {
        self.writer.take();
    }
}

struct Socks5RecvHalf {
    returns: Option<mpsc::Receiver<Result<Bytes, DisconnectReason>>>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl StreamRecvHalf for Socks5RecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        let returns = self.returns.as_mut()?;
        match returns.recv().await {
            Some(Ok(payload)) => Some(payload),
            Some(Err(reason)) => {
                self.last_error = Some(reason);
                None
            }
            None => {
                self.last_error = Some(DisconnectReason::ReaderClosed);
                None
            }
        }
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

async fn open_socks5(
    upstream: &str,
    target: &Endpoint,
    timeout: Duration,
    auth: Option<&Socks5UpstreamAuth>,
) -> Result<(TcpStream, Endpoint), DisconnectReason> {
    let mut stream = timed_io(timeout, TcpStream::connect(upstream)).await?;
    negotiate_auth(&mut stream, timeout, auth).await?;
    timed_io(timeout, stream.write_all(&encode_connect_request(target))).await?;
    let reply = read_reply_frame_atyp(&mut stream, timeout).await?;
    if reply.reply != Reply::Succeeded {
        return Err(disconnect_from_reply(reply.reply));
    }
    let local = reply.endpoint.unwrap_or_else(|| {
        endpoint_from_socket_addr(
            stream
                .local_addr()
                .expect("connected TCP stream has local addr"),
        )
    });
    Ok((stream, local))
}

async fn read_returns(
    mut reader: OwnedReadHalf,
    tx: mpsc::Sender<Result<Bytes, DisconnectReason>>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                let _ = tx.send(Err(DisconnectReason::UpstreamEof)).await;
                break;
            }
            Ok(n) => {
                if tx
                    .send(Ok(Bytes::copy_from_slice(&buf[..n])))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(disconnect_reason(e))).await;
                break;
            }
        }
    }
}
