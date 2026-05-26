//! HTTP/1.1 CONNECT / forward-proxy ingress adapter.

mod event_build;
mod verdict_apply;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_proto_http_proxy::{HttpProxyError, RequestHead, RequestKind, parse_request_head};
use mb_socket_tune::{SocketBufferConfig, apply_tcp_stream_buffers};
use mesh_bus_core::{BusError, BusPort, BusSessionRequest, IngressPlugin, StreamSession};
pub use mesh_bus_pipeline_hooks::runtime::PipelineRuntime;
use mesh_bus_pipeline_hooks::runtime::run_pipeline_event;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::event_build::build_http_proxy_event;
use crate::verdict_apply::{PipelineOutcome, apply_verdict};

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Clone, Default)]
pub struct BasicAuth {
    users: HashMap<String, String>,
}

impl BasicAuth {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.users.insert(username.into(), password.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    fn verify_header(&self, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        let Some(encoded) = header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))
        else {
            return false;
        };
        self.users.iter().any(|(user, pass)| {
            let expected = base64_encode(format!("{user}:{pass}").as_bytes());
            constant_time_eq(encoded.as_bytes(), expected.as_bytes())
        })
    }
}

pub struct HttpConnectIngress {
    listener: TcpListener,
    pipeline: Option<Arc<PipelineRuntime>>,
    auth: Option<Arc<BasicAuth>>,
    handshake_timeout: Duration,
    max_header_bytes: usize,
    max_connections: usize,
    socket_buffers: SocketBufferConfig,
}

impl HttpConnectIngress {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            pipeline: None,
            auth: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            socket_buffers: SocketBufferConfig::default(),
        }
    }

    pub fn with_pipeline(mut self, runtime: PipelineRuntime) -> Self {
        self.pipeline = Some(Arc::new(runtime));
        self
    }

    pub fn with_auth_basic(mut self, auth: BasicAuth) -> Self {
        self.auth = if auth.is_empty() {
            None
        } else {
            Some(Arc::new(auth))
        };
        self
    }

    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    pub fn with_max_header_bytes(mut self, bytes: usize) -> Self {
        self.max_header_bytes = bytes;
        self
    }

    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    pub fn with_socket_buffers(mut self, config: SocketBufferConfig) -> Self {
        self.socket_buffers = config;
        self
    }
}

#[async_trait]
impl IngressPlugin for HttpConnectIngress {
    fn name(&self) -> &str {
        "http-connect-ingress"
    }

    async fn run(self: Box<Self>, port: BusPort) -> Result<(), BusError> {
        let sem = Arc::new(Semaphore::new(self.max_connections));
        loop {
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let (sock, peer) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "mesh_bus.ingress.http_connect", error = %e, "accept_error");
                    drop(permit);
                    tokio::time::sleep(DEFAULT_ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            let _ = apply_tcp_stream_buffers(&sock, self.socket_buffers);
            let cfg = ConnConfig {
                pipeline: self.pipeline.clone(),
                auth: self.auth.clone(),
                handshake_timeout: self.handshake_timeout,
                max_header_bytes: self.max_header_bytes,
            };
            let port = port.clone();
            tokio::spawn(async move {
                handle_conn(sock, peer, port, cfg).await;
                drop(permit);
            });
        }
        Ok(())
    }
}

struct ConnConfig {
    pipeline: Option<Arc<PipelineRuntime>>,
    auth: Option<Arc<BasicAuth>>,
    handshake_timeout: Duration,
    max_header_bytes: usize,
}

struct ParsedConn {
    head: RequestHead,
    buffered: Bytes,
}

async fn handle_conn(mut sock: TcpStream, peer: SocketAddr, port: BusPort, cfg: ConnConfig) {
    let parsed = match tokio::time::timeout(
        cfg.handshake_timeout,
        read_request_head(&mut sock, cfg.max_header_bytes),
    )
    .await
    {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(err)) => {
            write_error(&mut sock, response_for_parse_error(&err)).await;
            return;
        }
        Err(_) => {
            write_error(
                &mut sock,
                "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n",
            )
            .await;
            return;
        }
    };
    if let Some(auth) = cfg.auth.as_deref() {
        if !auth.verify_header(parsed.head.proxy_authorization.as_deref()) {
            write_error(
                &mut sock,
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"mesh-bus\"\r\nConnection: close\r\n\r\n",
            )
            .await;
            return;
        }
    }
    let request = match decide_request(peer, &parsed.head, cfg.pipeline).await {
        Some(request) => request,
        None => {
            write_error(
                &mut sock,
                "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
            )
            .await;
            return;
        }
    };
    let mut session = match port.open_stream(request).await {
        Ok(session) => session,
        Err(_) => {
            write_error(
                &mut sock,
                "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
            )
            .await;
            return;
        }
    };
    if session.connect().await.is_err() {
        write_error(
            &mut sock,
            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
        )
        .await;
        return;
    }
    let first_upstream = match parsed.head.kind {
        RequestKind::Connect => {
            if sock
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            parsed.buffered
        }
        RequestKind::ForwardHttp { .. } => {
            let mut bytes =
                Vec::with_capacity(parsed.head.forwarded_head.len() + parsed.buffered.len());
            bytes.extend_from_slice(&parsed.head.forwarded_head);
            bytes.extend_from_slice(&parsed.buffered);
            Bytes::from(bytes)
        }
    };
    relay(sock, session, first_upstream).await;
}

async fn read_request_head(
    sock: &mut TcpStream,
    max_header_bytes: usize,
) -> Result<ParsedConn, HttpProxyError> {
    let mut buf = BytesMut::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        match parse_request_head(&buf, max_header_bytes)? {
            Some(head) => {
                let buffered = buf.split_off(head.consumed).freeze();
                return Ok(ParsedConn { head, buffered });
            }
            None => {}
        }
        let n = sock
            .read(&mut chunk)
            .await
            .map_err(|_| HttpProxyError::Incomplete)?;
        if n == 0 {
            return Err(HttpProxyError::Incomplete);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn decide_request(
    peer: SocketAddr,
    head: &RequestHead,
    pipeline: Option<Arc<PipelineRuntime>>,
) -> Option<BusSessionRequest> {
    let base = BusSessionRequest::stream(head.target.clone());
    let Some(runtime) = pipeline else {
        return Some(base);
    };
    let operation = match head.kind {
        RequestKind::Connect => "http_connect_open",
        RequestKind::ForwardHttp { .. } => "http_forward_open",
    };
    let event = build_http_proxy_event(peer, &head.target, operation);
    let run = match run_pipeline_event(runtime, event).await {
        Ok(run) => run,
        Err(err) => {
            tracing::warn!(target: "mesh_bus.ingress.http_connect", error = %err, "pipeline_runtime_error");
            return None;
        }
    };
    match apply_verdict(&run.verdict, &run.event, base) {
        PipelineOutcome::Allow { request } => Some(request),
        PipelineOutcome::Deny { reason } => {
            tracing::info!(target: "mesh_bus.ingress.http_connect", %peer, target = %head.target, pipeline_reject = %reason, "http_proxy_denied");
            None
        }
        PipelineOutcome::Drop => None,
    }
}

async fn relay(mut sock: TcpStream, session: Box<dyn StreamSession>, first_upstream: Bytes) {
    let (mut send_half, mut recv_half) = session.split();
    let (mut rd, mut wr) = sock.split();

    let returns_task = async {
        while let Some(payload) = recv_half.recv().await {
            if wr.write_all(&payload).await.is_err() {
                break;
            }
        }
    };

    let send_task = async {
        if !first_upstream.is_empty() && send_half.send(first_upstream).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if send_half
                .send(Bytes::copy_from_slice(&buf[..n]))
                .await
                .is_err()
            {
                break;
            }
        }
        send_half.shutdown_write().await;
    };

    tokio::join!(returns_task, send_task);
}

async fn write_error(sock: &mut TcpStream, response: &str) {
    let _ = sock.write_all(response.as_bytes()).await;
}

fn response_for_parse_error(err: &HttpProxyError) -> &'static str {
    match err {
        HttpProxyError::UnsupportedMethod(_) => {
            "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n"
        }
        _ => "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for i in 0..max {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod lib_tests;
