//! SOCKS5 ingress plugin. CONNECT maps to byte streams; UDP ASSOCIATE maps to datagrams.

mod access;
pub mod action_apply;
mod auth;
pub mod bind;
mod connect;
pub mod event_build;
pub mod rule_ctx_build;
mod udp_assoc;
pub mod verdict_apply;

use async_trait::async_trait;
use mb_proto_socks5::Command;
use mb_rule::{RuleChain, RuleSetRegistry};
use mb_socket_tune::{SocketBufferConfig, apply_tcp_stream_buffers};
use mesh_bus_core::{BusError, BusPort, IngressPlugin};
pub use mesh_bus_pipeline_hooks::runtime::PipelineRuntime;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

pub use crate::action_apply::validate_rule_policy_actions;
pub use crate::auth::AuthConfig;
use crate::auth::{Handshake, read_handshake};
use crate::connect::pipe_connect;
use crate::udp_assoc::udp_associate;

/// Whether this build can negotiate the SOCKS5 GSSAPI auth method (0x01).
///
/// GSSAPI is gated behind the default-off `gssapi` cargo feature and has no
/// authenticator backend in any shipped build, so this is `false` unless the
/// crate is compiled with `--features gssapi`. The greeting negotiation never
/// selects GSSAPI; a GSSAPI-only client takes the RFC1928 0x05 0xff
/// no-acceptable-methods path. This is the documented full-RFC posture.
pub const GSSAPI_SUPPORTED: bool = cfg!(feature = "gssapi");

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_UDP_FORWARD_CONCURRENCY: usize = 64;

#[derive(Clone)]
pub struct RulePolicy {
    pub(crate) chain: Arc<RuleChain>,
    pub(crate) registry: Arc<RuleSetRegistry>,
}

impl RulePolicy {
    pub fn new(chain: RuleChain, registry: RuleSetRegistry) -> Self {
        Self {
            chain: Arc::new(chain),
            registry: Arc::new(registry),
        }
    }
}

pub struct Socks5Ingress {
    listener: TcpListener,
    policy: Option<RulePolicy>,
    pipeline: Option<Arc<PipelineRuntime>>,
    auth: Option<Arc<AuthConfig>>,
    handshake_timeout: Duration,
    accept_backoff: Duration,
    max_connections: usize,
    udp_forward_concurrency: usize,
    socket_buffers: SocketBufferConfig,
}

impl Socks5Ingress {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            policy: None,
            pipeline: None,
            auth: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            accept_backoff: DEFAULT_ACCEPT_BACKOFF,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            udp_forward_concurrency: DEFAULT_UDP_FORWARD_CONCURRENCY,
            socket_buffers: SocketBufferConfig::default(),
        }
    }

    pub fn with_rule_policy(mut self, policy: RulePolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_pipeline(mut self, runtime: PipelineRuntime) -> Self {
        self.pipeline = Some(Arc::new(runtime));
        self
    }

    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = if auth.is_empty() {
            None
        } else {
            Some(Arc::new(auth))
        };
        self
    }

    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    pub fn with_accept_backoff(mut self, d: Duration) -> Self {
        self.accept_backoff = d;
        self
    }

    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    pub fn with_udp_forward_concurrency(mut self, n: usize) -> Self {
        self.udp_forward_concurrency = n;
        self
    }

    pub fn with_socket_buffers(mut self, config: SocketBufferConfig) -> Self {
        self.socket_buffers = config;
        self
    }
}

#[async_trait]
impl IngressPlugin for Socks5Ingress {
    fn name(&self) -> &str {
        "socks5-ingress"
    }

    async fn run(self: Box<Self>, port: BusPort) -> Result<(), BusError> {
        let policy = self.policy.clone();
        let pipeline = self.pipeline.clone();
        let auth = self.auth.clone();
        let handshake_timeout = self.handshake_timeout;
        let accept_backoff = self.accept_backoff;
        let udp_forward_concurrency = self.udp_forward_concurrency;
        let socket_buffers = self.socket_buffers;
        let sem = Arc::new(Semaphore::new(self.max_connections));
        loop {
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let (sock, peer) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "mesh_bus.ingress.socks5", error = %e, "accept_error");
                    drop(permit);
                    tokio::time::sleep(accept_backoff).await;
                    continue;
                }
            };
            let _ = sock.set_nodelay(true);
            if let Err(e) = apply_tcp_stream_buffers(&sock, socket_buffers) {
                tracing::warn!(
                    target: "mesh_bus.ingress.socks5",
                    %peer,
                    error = %e,
                    "socket_buffer_tune_failed"
                );
            }
            let port = port.clone();
            let policy = policy.clone();
            let pipeline = pipeline.clone();
            let auth = auth.clone();
            tokio::spawn(async move {
                handle_conn(
                    sock,
                    peer,
                    port,
                    policy,
                    pipeline,
                    auth,
                    handshake_timeout,
                    udp_forward_concurrency,
                )
                .await;
                drop(permit);
            });
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    mut sock: TcpStream,
    peer: SocketAddr,
    port: BusPort,
    policy: Option<RulePolicy>,
    pipeline: Option<Arc<PipelineRuntime>>,
    auth: Option<Arc<AuthConfig>>,
    handshake_timeout: Duration,
    udp_forward_concurrency: usize,
) {
    let handshake = match tokio::time::timeout(
        handshake_timeout,
        read_handshake(&mut sock, auth.as_deref()),
    )
    .await
    {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::debug!(target: "mesh_bus.ingress.socks5", %peer, "handshake_aborted");
            return;
        }
        Err(_) => {
            tracing::warn!(target: "mesh_bus.ingress.socks5", %peer, "handshake_timeout");
            return;
        }
    };
    let Handshake {
        request,
        authenticated_user,
    } = handshake;
    match request.command {
        Command::Connect => {
            pipe_connect(
                sock,
                peer,
                port,
                request.endpoint,
                policy,
                pipeline,
                authenticated_user,
                handshake_timeout,
            )
            .await
        }
        Command::UdpAssociate => {
            udp_associate(
                sock,
                peer,
                port,
                request.endpoint,
                policy,
                pipeline,
                authenticated_user,
                udp_forward_concurrency,
            )
            .await
        }
        Command::Bind => {
            bind::bind_command(
                sock,
                peer,
                request.endpoint,
                policy,
                pipeline,
                authenticated_user,
                handshake_timeout,
            )
            .await
        }
    }
}
