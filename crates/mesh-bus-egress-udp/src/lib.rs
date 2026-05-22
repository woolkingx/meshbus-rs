//! UDP egress factory. Persistent socket per session; send_to fires without waiting for response.

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_socket_tune::{SocketBufferConfig, apply_udp_socket_buffers};
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramRecvHalf,
    DatagramSendHalf, DatagramSession, DisconnectReason, ExitId, SendError,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;

const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

pub struct UdpEgress {
    id: ExitId,
    caps: Capabilities,
    timeout: Duration,
    socket_buffers: SocketBufferConfig,
    fixed_target: Option<Endpoint>,
}

impl UdpEgress {
    pub fn new(id: ExitId, timeout: Duration) -> Self {
        Self {
            id,
            caps: Capabilities {
                protocol: "udp".into(),
                supports_stream: false,
                supports_datagram: true,
                max_payload_bytes: Some(MAX_UDP_PAYLOAD_BYTES as u64),
                groups: Vec::new(),
            },
            timeout,
            socket_buffers: SocketBufferConfig::default(),
            fixed_target: None,
        }
    }

    /// Tag this egress with route_group labels (see TcpEgress::with_groups).
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.caps.groups = groups;
        self
    }

    pub fn with_socket_buffers(mut self, config: SocketBufferConfig) -> Self {
        self.socket_buffers = config;
        self
    }

    /// Force all outgoing datagrams to a configured service endpoint. The
    /// request target remains intent metadata and is not used for socket send.
    pub fn with_fixed_target(mut self, target: Endpoint) -> Self {
        self.fixed_target = Some(target);
        self
    }
}

#[async_trait]
impl DatagramEgress for UdpEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    fn max_payload_bytes(&self) -> usize {
        MAX_UDP_PAYLOAD_BYTES
    }

    async fn open_datagram(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn DatagramSession>, DisconnectReason> {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| DisconnectReason::ConnectionRefused)?;
        apply_udp_socket_buffers(&sock, self.socket_buffers)
            .map_err(|_| DisconnectReason::ConnectionRefused)?;
        let (closed_tx, closed_rx) = watch::channel(false);
        Ok(Box::new(UdpDatagramSession {
            info,
            timeout: self.timeout,
            socket: Arc::new(sock),
            closed_tx,
            closed_rx,
            fixed_target: self.fixed_target.clone(),
        }))
    }
}

struct UdpDatagramSession {
    info: BusSessionInfo,
    timeout: Duration,
    socket: Arc<UdpSocket>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    fixed_target: Option<Endpoint>,
}

#[async_trait]
impl DatagramSession for UdpDatagramSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        udp_send(
            &self.socket,
            self.timeout,
            &self.closed_tx,
            self.fixed_target.as_ref().unwrap_or(&target),
            payload,
        )
        .await
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        let mut last_error = None;
        udp_recv(
            &self.socket,
            &mut self.closed_rx,
            Some(self.timeout),
            &mut last_error,
        )
        .await
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        MAX_UDP_PAYLOAD_BYTES
    }

    async fn close(&mut self) {
        let _ = self.closed_tx.send(true);
    }

    fn split(self: Box<Self>) -> (Box<dyn DatagramSendHalf>, Box<dyn DatagramRecvHalf>) {
        let session = *self;
        let socket = session.socket;
        let send = UdpDatagramSendHalf {
            socket: socket.clone(),
            timeout: session.timeout,
            closed: session.closed_tx,
            fixed_target: session.fixed_target,
        };
        let recv = UdpDatagramRecvHalf {
            socket,
            closed: session.closed_rx,
            last_error: None,
        };
        (Box::new(send), Box::new(recv))
    }
}

struct UdpDatagramSendHalf {
    socket: Arc<UdpSocket>,
    timeout: Duration,
    closed: watch::Sender<bool>,
    fixed_target: Option<Endpoint>,
}

#[async_trait]
impl DatagramSendHalf for UdpDatagramSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        udp_send(
            &self.socket,
            self.timeout,
            &self.closed,
            self.fixed_target.as_ref().unwrap_or(&target),
            payload,
        )
        .await
    }

    async fn close(&mut self) {
        let _ = self.closed.send(true);
    }
}

struct UdpDatagramRecvHalf {
    socket: Arc<UdpSocket>,
    closed: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl DatagramRecvHalf for UdpDatagramRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        udp_recv(&self.socket, &mut self.closed, None, &mut self.last_error).await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

async fn udp_send(
    socket: &UdpSocket,
    timeout: Duration,
    closed: &watch::Sender<bool>,
    target: &Endpoint,
    payload: Bytes,
) -> Result<(), SendError> {
    if *closed.borrow() {
        return Err(SendError::Closed);
    }
    if payload.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(SendError::PayloadTooLarge);
    }
    let addr = format!("{}:{}", target.host(), target.port());
    tokio::time::timeout(timeout, socket.send_to(&payload, &addr))
        .await
        .map_err(|_| SendError::Closed)?
        .map_err(|_| SendError::Closed)?;
    Ok(())
}

async fn udp_recv(
    socket: &UdpSocket,
    closed: &mut watch::Receiver<bool>,
    timeout: Option<Duration>,
    last_error: &mut Option<DisconnectReason>,
) -> Option<(Endpoint, Bytes)> {
    if *closed.borrow() {
        return None;
    }
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD_BYTES];
    tokio::select! {
        _ = closed.changed() => None,
        result = async {
            loop {
                let result = if let Some(timeout) = timeout {
                    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                        Ok(result) => result,
                        Err(_) => return None,
                    }
                } else {
                    socket.recv_from(&mut buf).await
                };
                match result {
                    Ok((n, peer)) => {
                        let ep = match Endpoint::new(peer.ip().to_string(), peer.port()) {
                            Ok(ep) => ep,
                            Err(e) => {
                                tracing::warn!(
                                    target: "mesh_bus.egress.udp",
                                    "drop malformed datagram from {peer}: {e}"
                                );
                                continue;
                            }
                        };
                        buf.truncate(n);
                        return Some((ep, Bytes::from(buf)));
                    }
                    Err(e) => {
                        *last_error = Some(DisconnectReason::Other(e.to_string()));
                        return None;
                    }
                }
            }
        } => result,
    }
}
