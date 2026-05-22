//! SOCKS5 UDP ASSOCIATE egress. One DatagramSession owns a local UDP relay
//! socket plus the retained TCP control connection that keeps the association
//! alive (RFC1928). Reuses the shared upstream handshake helpers.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    Reply, decode_udp_datagram, encode_udp_associate_request, encode_udp_datagram,
};
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramRecvHalf,
    DatagramSendHalf, DatagramSession, DisconnectReason, ExitId, SendError,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, watch};

use crate::upstream::{
    Socks5UpstreamAuth, disconnect_from_reply, disconnect_reason, endpoint_from_socket_addr,
    negotiate_auth, read_reply_frame_atyp, timed_io,
};

const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

/// Retained TCP control connection. Dropping the inner stream terminates the
/// UDP association per RFC1928.
type Control = Arc<Mutex<Option<TcpStream>>>;

pub struct Socks5UdpEgress {
    id: ExitId,
    caps: Capabilities,
    upstream: String,
    timeout: Duration,
    auth: Option<Arc<Socks5UpstreamAuth>>,
}

impl Socks5UdpEgress {
    pub fn new(id: ExitId, upstream: String, timeout: Duration) -> Self {
        Self {
            id,
            caps: Capabilities {
                protocol: "socks5-udp".into(),
                supports_stream: false,
                supports_datagram: true,
                max_payload_bytes: Some(MAX_UDP_PAYLOAD_BYTES as u64),
                groups: Vec::new(),
            },
            upstream,
            timeout,
            auth: None,
        }
    }

    /// Tag this egress with route_group labels (see TcpEgress::with_groups).
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
impl DatagramEgress for Socks5UdpEgress {
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
        let (socket, control) =
            open_socks5_udp(&self.upstream, self.timeout, self.auth.as_deref()).await?;
        let (closed_tx, closed_rx) = watch::channel(false);
        Ok(Box::new(Socks5UdpSession {
            info,
            timeout: self.timeout,
            socket: Arc::new(socket),
            control: Arc::new(Mutex::new(Some(control))),
            closed_tx,
            closed_rx,
            recv_buf: vec![0u8; MAX_UDP_PAYLOAD_BYTES],
        }))
    }
}

struct Socks5UdpSession {
    info: BusSessionInfo,
    timeout: Duration,
    socket: Arc<UdpSocket>,
    control: Control,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    recv_buf: Vec<u8>,
}

#[async_trait]
impl DatagramSession for Socks5UdpSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        relay_send(&self.socket, self.timeout, &self.closed_tx, target, payload).await
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        let mut last_error = None;
        relay_recv(
            &self.socket,
            &mut self.closed_rx,
            &mut self.recv_buf,
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
        drop_control(&self.control).await;
        let _ = self.closed_tx.send(true);
    }

    fn split(self: Box<Self>) -> (Box<dyn DatagramSendHalf>, Box<dyn DatagramRecvHalf>) {
        let session = *self;
        let socket = session.socket;
        let send = Socks5UdpSendHalf {
            socket: socket.clone(),
            timeout: session.timeout,
            closed: session.closed_tx,
            control: session.control.clone(),
        };
        let recv = Socks5UdpRecvHalf {
            socket,
            closed: session.closed_rx,
            control: session.control,
            recv_buf: session.recv_buf,
            last_error: None,
        };
        (Box::new(send), Box::new(recv))
    }
}

struct Socks5UdpSendHalf {
    socket: Arc<UdpSocket>,
    timeout: Duration,
    closed: watch::Sender<bool>,
    control: Control,
}

#[async_trait]
impl DatagramSendHalf for Socks5UdpSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        relay_send(&self.socket, self.timeout, &self.closed, target, payload).await
    }

    async fn close(&mut self) {
        drop_control(&self.control).await;
        let _ = self.closed.send(true);
    }
}

struct Socks5UdpRecvHalf {
    socket: Arc<UdpSocket>,
    closed: watch::Receiver<bool>,
    // Held only to keep the Arc<TcpStream> alive: the RFC1928 association must
    // survive as long as the recv half can still receive relayed replies.
    #[allow(dead_code)]
    control: Control,
    recv_buf: Vec<u8>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl DatagramRecvHalf for Socks5UdpRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        relay_recv(
            &self.socket,
            &mut self.closed,
            &mut self.recv_buf,
            &mut self.last_error,
        )
        .await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

async fn drop_control(control: &Control) {
    let mut guard = control.lock().await;
    *guard = None;
}

async fn relay_send(
    socket: &UdpSocket,
    timeout: Duration,
    closed: &watch::Sender<bool>,
    target: Endpoint,
    payload: Bytes,
) -> Result<(), SendError> {
    if *closed.borrow() {
        return Err(SendError::Closed);
    }
    if payload.len() > MAX_UDP_PAYLOAD_BYTES {
        return Err(SendError::PayloadTooLarge);
    }
    let wrapped = encode_udp_datagram(&target, &payload);
    tokio::time::timeout(timeout, socket.send(&wrapped))
        .await
        .map_err(|_| SendError::Closed)?
        .map_err(|_| SendError::Closed)?;
    Ok(())
}

// A malformed or FRAG-rejected relay datagram is dropped and receiving
// continues (RFC1928 datagram drop semantics); only a closed session or a
// socket error ends the recv half. `buf` is the recv half's reusable buffer so
// there is no per-datagram 65 KB allocation.
async fn relay_recv(
    socket: &UdpSocket,
    closed: &mut watch::Receiver<bool>,
    buf: &mut [u8],
    last_error: &mut Option<DisconnectReason>,
) -> Option<(Endpoint, Bytes)> {
    loop {
        if *closed.borrow() {
            return None;
        }
        let n = tokio::select! {
            _ = closed.changed() => return None,
            result = socket.recv(buf) => match result {
                Ok(n) => n,
                Err(e) => {
                    *last_error = Some(DisconnectReason::Other(e.to_string()));
                    return None;
                }
            },
        };
        let mut frame = BytesMut::from(&buf[..n]);
        if let Ok(dg) = decode_udp_datagram(&mut frame) {
            return Some((dg.target, dg.payload));
        }
    }
}

async fn open_socks5_udp(
    upstream: &str,
    timeout: Duration,
    auth: Option<&Socks5UpstreamAuth>,
) -> Result<(UdpSocket, TcpStream), DisconnectReason> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(disconnect_reason)?;
    let local = socket.local_addr().map_err(disconnect_reason)?;
    let local_ep = endpoint_from_socket_addr(local);
    let mut control = timed_io(timeout, TcpStream::connect(upstream)).await?;
    negotiate_auth(&mut control, timeout, auth).await?;
    timed_io(
        timeout,
        control.write_all(&encode_udp_associate_request(&local_ep)),
    )
    .await?;
    let reply = read_reply_frame_atyp(&mut control, timeout).await?;
    if reply.reply != Reply::Succeeded {
        return Err(disconnect_from_reply(reply.reply));
    }
    let relay = resolve_relay(reply.endpoint, &control)?;
    socket
        .connect(format!("{}:{}", relay.host(), relay.port()))
        .await
        .map_err(disconnect_reason)?;
    Ok((socket, control))
}

fn resolve_relay(bnd: Option<Endpoint>, control: &TcpStream) -> Result<Endpoint, DisconnectReason> {
    let bnd = bnd.ok_or_else(|| {
        DisconnectReason::Other("udp associate reply missing BND endpoint".into())
    })?;
    let unspecified = bnd
        .host()
        .parse::<IpAddr>()
        .map(|ip| ip.is_unspecified())
        .unwrap_or(false);
    if !unspecified {
        return Ok(bnd);
    }
    let peer = control.peer_addr().map_err(disconnect_reason)?;
    Endpoint::new(peer.ip().to_string(), bnd.port())
        .map_err(|e| DisconnectReason::Other(format!("relay endpoint: {e}")))
}
