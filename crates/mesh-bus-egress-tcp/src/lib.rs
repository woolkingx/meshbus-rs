//! TCP egress factory. Each L4 stream session owns one TCP connection.

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_socket_tune::{SocketBufferConfig, connect_tcp};
use mesh_bus_core::{
    BusPathInfo, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason, ExitId,
    Measurement, PathState, StreamEgress, StreamRecvHalf, StreamSendHalf, StreamSession,
    TcpSpliceSession,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

pub struct TcpEgress {
    id: ExitId,
    caps: Capabilities,
    timeout: Duration,
    socket_buffers: SocketBufferConfig,
    fixed_target: Option<Endpoint>,
}

impl TcpEgress {
    pub fn new(id: ExitId, timeout: Duration) -> Self {
        Self {
            id,
            caps: Capabilities {
                protocol: "tcp".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: Vec::new(),
            },
            timeout,
            socket_buffers: SocketBufferConfig::default(),
            fixed_target: None,
        }
    }

    /// Pin the dial endpoint. When set, `open_stream` connects to this endpoint
    /// and ignores `request.target`; the request target stays as service-intent
    /// metadata only. Used by service-sink egress for reverse stream service.
    pub fn with_fixed_target(mut self, target: Endpoint) -> Self {
        self.fixed_target = Some(target);
        self
    }

    /// Tag this egress with route_group labels. A session whose
    /// `BusSessionRequest.route_group` is `Some(g)` reaches this egress only if
    /// `g` appears in `groups`. Empty groups means the egress accepts only
    /// untagged sessions (`route_group: None`).
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.caps.groups = groups;
        self
    }

    pub fn with_socket_buffers(mut self, config: SocketBufferConfig) -> Self {
        self.socket_buffers = config;
        self
    }
}

#[async_trait]
impl StreamEgress for TcpEgress {
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
        let target = self
            .fixed_target
            .clone()
            .unwrap_or_else(|| request.target.clone());
        Ok(Box::new(TcpStreamSession::new(
            self.id.clone(),
            target,
            self.timeout,
            self.socket_buffers,
            info,
        )))
    }
}

struct TcpStreamSession {
    exit_id: ExitId,
    target: Endpoint,
    timeout: Duration,
    socket_buffers: SocketBufferConfig,
    info: BusSessionInfo,
    stream: Option<TcpStream>,
    writer: Option<OwnedWriteHalf>,
    returns: Option<mpsc::Receiver<Result<Bytes, DisconnectReason>>>,
    last_error: Option<DisconnectReason>,
}

impl TcpStreamSession {
    fn new(
        exit_id: ExitId,
        target: Endpoint,
        timeout: Duration,
        socket_buffers: SocketBufferConfig,
        info: BusSessionInfo,
    ) -> Self {
        Self {
            exit_id,
            target,
            timeout,
            socket_buffers,
            info,
            stream: None,
            writer: None,
            returns: None,
            last_error: None,
        }
    }
}

#[async_trait]
impl StreamSession for TcpStreamSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        let addr = format!("{}:{}", self.target.host(), self.target.port());
        let stream = tokio::time::timeout(self.timeout, connect_tcp(&addr, self.socket_buffers))
            .await
            .map_err(|_| DisconnectReason::TimedOut)?
            .map_err(disconnect_reason)?;
        let _ = stream.set_nodelay(true);
        let local = endpoint_from_socket_addr(
            stream
                .local_addr()
                .map_err(|e| DisconnectReason::Other(e.to_string()))?,
        );
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
        self.stream = Some(stream);
        Ok(&self.info)
    }

    fn into_tcp_splice(self: Box<Self>) -> Result<TcpSpliceSession, Box<dyn StreamSession>> {
        let mut session = *self;
        if let Some(stream) = session.stream.take() {
            match stream.into_std() {
                Ok(stream) => return Ok(TcpSpliceSession::new(stream)),
                Err(e) => session.last_error = Some(DisconnectReason::Other(e.to_string())),
            }
        }
        Err(Box::new(session))
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        let mut session = *self;
        if let Some(stream) = session.stream.take() {
            let (reader, writer) = stream.into_split();
            let (tx, rx) = mpsc::channel(256);
            tokio::spawn(read_returns(reader, tx));
            session.writer = Some(writer);
            session.returns = Some(rx);
        }
        (
            Box::new(TcpSendHalf {
                writer: session.writer,
                timeout: session.timeout,
            }),
            Box::new(TcpRecvHalf {
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

struct TcpSendHalf {
    writer: Option<OwnedWriteHalf>,
    timeout: Duration,
}

#[async_trait]
impl StreamSendHalf for TcpSendHalf {
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

struct TcpRecvHalf {
    returns: Option<mpsc::Receiver<Result<Bytes, DisconnectReason>>>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl StreamRecvHalf for TcpRecvHalf {
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

fn endpoint_from_socket_addr(addr: std::net::SocketAddr) -> Endpoint {
    Endpoint::new(addr.ip().to_string(), addr.port()).expect("socket address is a valid endpoint")
}

fn disconnect_reason(err: std::io::Error) -> DisconnectReason {
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
