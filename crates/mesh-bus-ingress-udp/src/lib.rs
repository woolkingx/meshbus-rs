//! UDP ingress plugin. Accepts datagrams from multiple peers concurrently.
//!
//! Each peer gets a dedicated `UdpPeerSession` that holds the send half of a
//! split `DatagramSession`. A separate response pump task holds the recv half
//! and writes egress responses back to the peer socket.
//!
//! When a `PipelineRuntime` is attached the runtime decides the datagram
//! session shape once per new peer before `port.open_datagram`; otherwise the
//! fixed-target fast path runs with no pipeline overhead.

mod event_build;
mod verdict_apply;

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_socket_tune::{SocketBufferConfig, apply_udp_socket_buffers};
use mesh_bus_core::{
    BusDatagramRecvHalf, BusDatagramSendHalf, BusError, BusPort, BusSessionRequest, IngressPlugin,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::event_build::build_direct_datagram_event;
use crate::verdict_apply::{PipelineOutcome, apply_verdict};
pub use mesh_bus_pipeline_hooks::runtime::PipelineRuntime;
use mesh_bus_pipeline_hooks::runtime::run_pipeline_event;

const MAX_UDP_PEER_SESSIONS: usize = 1024;
const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

pub struct UdpIngress {
    socket: UdpSocket,
    target: Endpoint,
    socket_buffers: SocketBufferConfig,
    pipeline: Option<Arc<PipelineRuntime>>,
    max_peer_sessions: usize,
}

impl UdpIngress {
    pub fn new(socket: UdpSocket, target: Endpoint) -> Self {
        Self {
            socket,
            target,
            socket_buffers: SocketBufferConfig::default(),
            pipeline: None,
            max_peer_sessions: MAX_UDP_PEER_SESSIONS,
        }
    }

    pub fn with_socket_buffers(mut self, config: SocketBufferConfig) -> Self {
        self.socket_buffers = config;
        self
    }

    pub fn with_max_peer_sessions(mut self, max: usize) -> Self {
        self.max_peer_sessions = max.max(1);
        self
    }

    pub fn with_pipeline(mut self, runtime: PipelineRuntime) -> Self {
        self.pipeline = Some(Arc::new(runtime));
        self
    }
}

async fn decide_request(
    peer: SocketAddr,
    target: &Endpoint,
    pipeline: Option<Arc<PipelineRuntime>>,
) -> Option<BusSessionRequest> {
    let base = BusSessionRequest::datagram(target.clone());
    let Some(runtime) = pipeline else {
        return Some(base);
    };
    let event = build_direct_datagram_event(peer, target);
    let run = match run_pipeline_event(runtime, event).await {
        Ok(run) => run,
        Err(err) => {
            tracing::warn!(
                target: "mesh_bus.ingress.udp",
                error = %err,
                "pipeline_runtime_error:direct_datagram"
            );
            return None;
        }
    };
    match apply_verdict(&run.verdict, &run.event, base) {
        PipelineOutcome::Allow { request } => Some(request),
        PipelineOutcome::Deny { reason } => {
            tracing::info!(
                target: "mesh_bus.ingress.udp",
                %peer,
                target = %target,
                pipeline_reject = %reason,
                "direct_datagram_denied_by_pipeline"
            );
            None
        }
        PipelineOutcome::Drop => {
            tracing::debug!(
                target: "mesh_bus.ingress.udp",
                %peer,
                target = %target,
                "direct_datagram_dropped_by_pipeline"
            );
            None
        }
    }
}

struct UdpPeerSession {
    send: Mutex<Box<dyn BusDatagramSendHalf>>,
    pump: JoinHandle<()>,
}

impl UdpPeerSession {
    async fn close(&self) {
        self.pump.abort();
        self.send.lock().await.close().await;
    }
}

fn spawn_response_pump(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut recv: Box<dyn BusDatagramRecvHalf>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some((_source, payload)) = recv.recv_from().await {
            let _ = socket.send_to(&payload, peer).await;
        }
    })
}

#[async_trait]
impl IngressPlugin for UdpIngress {
    fn name(&self) -> &str {
        "udp-ingress"
    }

    async fn run(self: Box<Self>, port: BusPort) -> Result<(), BusError> {
        let _ = apply_udp_socket_buffers(&self.socket, self.socket_buffers);
        let socket = Arc::new(self.socket);
        let mut peer_sessions: HashMap<SocketAddr, Arc<UdpPeerSession>> = HashMap::new();
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD_BYTES];

        loop {
            let (n, peer) = socket
                .recv_from(&mut buf)
                .await
                .map_err(|_| BusError::ChannelClosed)?;
            let payload = Bytes::copy_from_slice(&buf[..n]);

            let session = if let Some(s) = peer_sessions.get(&peer) {
                s.clone()
            } else {
                let Some(request) = decide_request(peer, &self.target, self.pipeline.clone()).await
                else {
                    continue;
                };
                let Ok(ds) = port.open_datagram(request).await else {
                    continue;
                };
                let (send, recv) = ds.split();
                let pump = spawn_response_pump(socket.clone(), peer, recv);
                let ps = Arc::new(UdpPeerSession {
                    send: Mutex::new(send),
                    pump,
                });
                if peer_sessions.len() >= self.max_peer_sessions {
                    if let Some(evict_peer) = peer_sessions.keys().next().copied() {
                        if let Some(evicted) = peer_sessions.remove(&evict_peer) {
                            evicted.close().await;
                        }
                    }
                }
                peer_sessions.insert(peer, ps.clone());
                ps
            };

            let _ = session
                .send
                .lock()
                .await
                .send_to(self.target.clone(), payload)
                .await;
        }
    }
}
