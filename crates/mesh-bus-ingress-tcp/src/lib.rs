//! Plain TCP ingress plugin. Maps one accepted socket to one L4 stream
//! session. When a `PipelineRuntime` is attached the runtime decides the
//! session shape before `port.open_stream`; otherwise the fixed-target,
//! splice-capable fast path runs with no pipeline overhead.

mod event_build;
mod verdict_apply;

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_socket_tune::{SocketBufferConfig, apply_tcp_stream_buffers};
use mesh_bus_core::{BusError, BusPort, BusSessionRequest, IngressPlugin};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::event_build::build_direct_stream_event;
use crate::verdict_apply::{PipelineOutcome, apply_verdict};
pub use mesh_bus_pipeline_hooks::runtime::PipelineRuntime;
use mesh_bus_pipeline_hooks::runtime::run_pipeline_event;

const DEFAULT_ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

pub struct TcpIngress {
    listener: TcpListener,
    target: Endpoint,
    socket_buffers: SocketBufferConfig,
    pipeline: Option<Arc<PipelineRuntime>>,
    max_connections: usize,
}

impl TcpIngress {
    pub fn new(listener: TcpListener, target: Endpoint) -> Self {
        Self {
            listener,
            target,
            socket_buffers: SocketBufferConfig::default(),
            pipeline: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    pub fn with_socket_buffers(mut self, config: SocketBufferConfig) -> Self {
        self.socket_buffers = config;
        self
    }

    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    pub fn with_pipeline(mut self, runtime: PipelineRuntime) -> Self {
        self.pipeline = Some(Arc::new(runtime));
        self
    }
}

#[async_trait]
impl IngressPlugin for TcpIngress {
    fn name(&self) -> &str {
        "tcp-ingress"
    }

    async fn run(self: Box<Self>, port: BusPort) -> Result<(), BusError> {
        let accept_backoff = DEFAULT_ACCEPT_BACKOFF;
        let sem = Arc::new(Semaphore::new(self.max_connections));
        loop {
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let (sock, peer) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "mesh_bus.ingress.tcp", error = %e, "accept_error");
                    drop(permit);
                    tokio::time::sleep(accept_backoff).await;
                    continue;
                }
            };
            let _ = apply_tcp_stream_buffers(&sock, self.socket_buffers);
            let port = port.clone();
            let target = self.target.clone();
            let pipeline = self.pipeline.clone();
            tokio::spawn(async move {
                handle_conn(sock, peer, port, target, pipeline).await;
                drop(permit);
            });
        }
        Ok(())
    }
}

async fn handle_conn(
    sock: TcpStream,
    peer: SocketAddr,
    port: BusPort,
    target: Endpoint,
    pipeline: Option<Arc<PipelineRuntime>>,
) {
    let Some(request) = decide_request(peer, &target, pipeline).await else {
        return;
    };
    let Ok(mut session) = port.open_stream(request).await else {
        return;
    };
    if session.connect().await.is_err() {
        return;
    }
    relay(sock, session).await;
}

async fn decide_request(
    peer: SocketAddr,
    target: &Endpoint,
    pipeline: Option<Arc<PipelineRuntime>>,
) -> Option<BusSessionRequest> {
    let base = BusSessionRequest::stream(target.clone());
    let Some(runtime) = pipeline else {
        return Some(base);
    };
    let event = build_direct_stream_event(peer, target);
    let run = match run_pipeline_event(runtime, event).await {
        Ok(run) => run,
        Err(err) => {
            tracing::warn!(
                target: "mesh_bus.ingress.tcp",
                error = %err,
                "pipeline_runtime_error:direct_stream"
            );
            return None;
        }
    };
    match apply_verdict(&run.verdict, &run.event, base) {
        PipelineOutcome::Allow { request } => Some(request),
        PipelineOutcome::Deny { reason } => {
            tracing::info!(
                target: "mesh_bus.ingress.tcp",
                %peer,
                target = %target,
                pipeline_reject = %reason,
                "direct_stream_denied_by_pipeline"
            );
            None
        }
        PipelineOutcome::Drop => {
            tracing::debug!(
                target: "mesh_bus.ingress.tcp",
                %peer,
                target = %target,
                "direct_stream_dropped_by_pipeline"
            );
            None
        }
    }
}

async fn relay(mut sock: TcpStream, session: Box<dyn mesh_bus_core::StreamSession>) {
    let session = match session.into_tcp_splice() {
        Ok(splice) => {
            let _ = mb_splice::splice_tcp_streams(sock, splice).await;
            return;
        }
        Err(fallback) => fallback,
    };
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
