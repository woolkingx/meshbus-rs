//! SOCKS5 ingress plugin. CONNECT maps to byte streams; UDP ASSOCIATE maps to datagrams.

pub mod action_apply;
pub mod bind;
pub mod event_build;
pub mod rule_ctx_build;
pub mod verdict_apply;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    CodecError, Command, Method, Reply, USER_PASS_STATUS_FAILURE, USER_PASS_STATUS_SUCCESS,
    decode_greeting, decode_request, decode_udp_datagram, decode_user_pass_request, encode_reply,
    encode_reply_with_endpoint, encode_udp_datagram, encode_user_pass_reply,
};
use mb_rule::{RuleChain, RuleSetRegistry};
use mb_socket_tune::{SocketBufferConfig, apply_tcp_stream_buffers};
use mesh_bus_core::kernel::Verdict;
use mesh_bus_core::{
    BusDatagramRecvHalf, BusDatagramSendHalf, BusError, BusPort, BusSessionInfo, BusSessionRequest,
    DisconnectReason, IngressPlugin, StreamSession,
};
pub use mesh_bus_pipeline_hooks::runtime::PipelineRuntime;
use mesh_bus_pipeline_hooks::runtime::run_pipeline_event;

use crate::action_apply::{ApplyOutcome, action_label, apply_decision, schedule_hint_label};
use crate::event_build::{build_connect_event, build_udp_packet_event};
use crate::rule_ctx_build::{build_connect_ctx, build_udp_associate_ctx, build_udp_packet_ctx};
use crate::verdict_apply::{PipelineOutcome, apply_verdict};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Semaphore};

pub use crate::action_apply::validate_rule_policy_actions;

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
const MAX_UDP_TARGET_SESSIONS: usize = 256;

#[derive(Debug, Clone)]
struct AccessTrace {
    matched_rule_id: String,
    matched_rule_index: String,
    default_used: bool,
    action: String,
    route_group: String,
    schedule_hint: String,
}

fn log_connect_open(
    peer: SocketAddr,
    target: &Endpoint,
    authenticated_user: Option<&str>,
    trace: Option<&AccessTrace>,
) {
    let user = authenticated_user.unwrap_or("-");
    match trace {
        Some(t) => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            target = %target,
            authenticated_user = %user,
            matched_rule_id = %t.matched_rule_id,
            matched_rule_index = %t.matched_rule_index,
            default_used = t.default_used,
            action = %t.action,
            route_group = %t.route_group,
            schedule_hint = %t.schedule_hint,
            "connect_open"
        ),
        None => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            target = %target,
            authenticated_user = %user,
            "connect_open"
        ),
    }
}

fn log_flow_opened(
    peer: SocketAddr,
    target: &Endpoint,
    info: &BusSessionInfo,
    trace: Option<&AccessTrace>,
) {
    let primary = info.paths.get(info.primary);
    let selected_exit = primary.map(|path| path.exit_id.0.as_str()).unwrap_or("-");
    let route_group = trace.map(|t| t.route_group.as_str()).unwrap_or("-");
    let schedule_hint = trace.map(|t| t.schedule_hint.as_str()).unwrap_or("-");
    tracing::info!(
        target: "mesh_bus.ingress.socks5",
        %peer,
        target = %target,
        flow_id = %info.flow_id.0,
        packet_id = 0u64,
        exit_id = %selected_exit,
        selected_exit = %selected_exit,
        route_group = %route_group,
        schedule_hint = %schedule_hint,
        candidate_count = info.paths.len() as u64,
        success = true,
        "flow_opened"
    );
}

fn log_udp_associate_open(
    peer: SocketAddr,
    declared_peer: &Endpoint,
    authenticated_user: Option<&str>,
    trace: Option<&AccessTrace>,
) {
    let user = authenticated_user.unwrap_or("-");
    match trace {
        Some(t) => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            declared_peer = %declared_peer,
            authenticated_user = %user,
            matched_rule_id = %t.matched_rule_id,
            matched_rule_index = %t.matched_rule_index,
            default_used = t.default_used,
            action = %t.action,
            route_group = %t.route_group,
            schedule_hint = %t.schedule_hint,
            "udp_associate_open"
        ),
        None => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            declared_peer = %declared_peer,
            authenticated_user = %user,
            "udp_associate_open"
        ),
    }
}

fn socks5_source_key(peer: &SocketAddr) -> String {
    peer.ip().to_string()
}

fn socks5_target_key(target: &Endpoint) -> String {
    let host = target.host();
    let normalized = match host.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => host.to_ascii_lowercase(),
    };
    format!("{normalized}:{}", target.port())
}

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

#[derive(Clone, Default)]
pub struct AuthConfig {
    users: HashMap<String, String>,
}

impl AuthConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.users.insert(username.into(), password.into());
        self
    }

    pub fn insert(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }

    pub fn verify(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .is_some_and(|stored| stored.as_str() == password)
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
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

struct Handshake {
    request: mb_proto_socks5::Request,
    authenticated_user: Option<String>,
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

async fn read_handshake(sock: &mut TcpStream, auth: Option<&AuthConfig>) -> Option<Handshake> {
    let mut buf = BytesMut::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        let n = match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        match decode_greeting(&mut buf) {
            Ok(greeting) => {
                let required_method = if auth.is_some() {
                    Method::UserPass
                } else {
                    Method::NoAuth
                };
                if !greeting.methods.contains(&required_method) {
                    if !GSSAPI_SUPPORTED && greeting.methods.contains(&Method::GssApi) {
                        tracing::debug!(
                            target: "mesh_bus.ingress.socks5",
                            "socks5_gssapi_unsupported"
                        );
                    }
                    let _ = sock.write_all(&[0x05, 0xff]).await;
                    return None;
                }
                let selected = match required_method {
                    Method::NoAuth => 0x00u8,
                    Method::UserPass => 0x02u8,
                    _ => unreachable!("required_method is constrained above"),
                };
                if sock.write_all(&[0x05, selected]).await.is_err() {
                    return None;
                }
                break;
            }
            Err(CodecError::Incomplete) => {}
            Err(_) => return None,
        }
    }

    let authenticated_user = match auth {
        Some(auth) => Some(run_user_pass_subnegotiation(sock, &mut buf, auth).await?),
        None => None,
    };

    loop {
        match decode_request(&mut buf) {
            Ok(request) => {
                return Some(Handshake {
                    request,
                    authenticated_user,
                });
            }
            Err(CodecError::Incomplete) => {}
            Err(_) => return None,
        }
        let n = match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn run_user_pass_subnegotiation(
    sock: &mut TcpStream,
    buf: &mut BytesMut,
    auth: &AuthConfig,
) -> Option<String> {
    let mut chunk = [0u8; 512];
    loop {
        match decode_user_pass_request(buf) {
            Ok(req) => {
                let username = match std::str::from_utf8(&req.username) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        let _ = sock
                            .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                            .await;
                        return None;
                    }
                };
                let password = match std::str::from_utf8(&req.password) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = sock
                            .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                            .await;
                        return None;
                    }
                };
                if !auth.verify(&username, password) {
                    let _ = sock
                        .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                        .await;
                    return None;
                }
                if sock
                    .write_all(&encode_user_pass_reply(USER_PASS_STATUS_SUCCESS))
                    .await
                    .is_err()
                {
                    return None;
                }
                return Some(username);
            }
            Err(mb_proto_socks5::CodecError::Incomplete) => {
                let n = match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(_) => {
                let _ = sock
                    .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                    .await;
                return None;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn pipe_connect(
    mut sock: TcpStream,
    peer: SocketAddr,
    port: BusPort,
    target: Endpoint,
    policy: Option<RulePolicy>,
    pipeline: Option<Arc<PipelineRuntime>>,
    authenticated_user: Option<String>,
    handshake_timeout: Duration,
) {
    let base = BusSessionRequest::stream(target.clone())
        .with_source_key(socks5_source_key(&peer))
        .with_target_key(socks5_target_key(&target));

    let (request, trace_fields) = if let Some(runtime) = pipeline.clone() {
        let event = build_connect_event(peer, &target, authenticated_user.as_deref());
        let run = match run_pipeline_event(runtime, event).await {
            Ok(run) => run,
            Err(err) => {
                tracing::warn!(
                    target: "mesh_bus.ingress.socks5",
                    error = %err,
                    "pipeline_runtime_error:connect"
                );
                let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
                return;
            }
        };
        match apply_verdict(&run.verdict, &run.event, base.clone()) {
            PipelineOutcome::Allow { request, .. } => {
                let action_lbl = match &run.verdict {
                    Verdict::Accept(_) => "allow".to_string(),
                    _ => "unknown".to_string(),
                };
                let route_group = request.route_group.clone().unwrap_or_else(|| "-".into());
                let hint = schedule_hint_label(&request.schedule_hint);
                (
                    request,
                    Some(AccessTrace {
                        matched_rule_id: "-".into(),
                        matched_rule_index: "-".into(),
                        default_used: false,
                        action: action_lbl,
                        route_group,
                        schedule_hint: hint,
                    }),
                )
            }
            PipelineOutcome::Deny { reason } => {
                tracing::info!(
                    target: "mesh_bus.ingress.socks5",
                    %peer,
                    target = %target,
                    pipeline_reject = %reason,
                    "connect_denied_by_pipeline"
                );
                let _ = sock
                    .write_all(&encode_reply(Reply::ConnectionNotAllowed))
                    .await;
                return;
            }
            PipelineOutcome::Drop => {
                tracing::debug!(
                    target: "mesh_bus.ingress.socks5",
                    %peer,
                    target = %target,
                    "connect_dropped_by_pipeline"
                );
                return;
            }
        }
    } else {
        match policy {
            Some(policy) => {
                let ctx = build_connect_ctx(peer, &target, authenticated_user.as_deref());
                let decision = mb_rule::evaluate_with_trace(&policy.chain, &ctx, &policy.registry);
                let action_lbl = action_label(&decision.action);
                let rule_id = decision.trace.rule_id.clone().unwrap_or_else(|| "-".into());
                let rule_index = decision
                    .trace
                    .rule_index
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".into());
                let default_used = decision.trace.default_used;
                match apply_decision(decision, base) {
                    ApplyOutcome::Allow(req) => {
                        let route_group = req.route_group.clone().unwrap_or_else(|| "-".into());
                        let hint = schedule_hint_label(&req.schedule_hint);
                        (
                            req,
                            Some(AccessTrace {
                                matched_rule_id: rule_id,
                                matched_rule_index: rule_index,
                                default_used,
                                action: action_lbl,
                                route_group,
                                schedule_hint: hint,
                            }),
                        )
                    }
                    ApplyOutcome::Deny => {
                        tracing::info!(
                            target: "mesh_bus.ingress.socks5",
                            %peer,
                            target = %target,
                            matched_rule_id = %rule_id,
                            matched_rule_index = %rule_index,
                            default_used,
                            action = %action_lbl,
                            "connect_denied_by_rule"
                        );
                        let _ = sock
                            .write_all(&encode_reply(Reply::ConnectionNotAllowed))
                            .await;
                        return;
                    }
                }
            }
            None => (base, None),
        }
    };

    let mut session = match port.open_stream(request).await {
        Ok(session) => session,
        Err(reason) => {
            tracing::warn!(
                target: "mesh_bus.ingress.socks5",
                %peer,
                target = %target,
                reason = ?reason,
                "connect_open_stream_failed"
            );
            let _ = sock
                .write_all(&encode_reply(reply_for_disconnect(&reason)))
                .await;
            return;
        }
    };

    let session_info = match tokio::time::timeout(handshake_timeout, session.connect()).await {
        Ok(Ok(info)) => info.clone(),
        Ok(Err(reason)) => {
            tracing::warn!(
                target: "mesh_bus.ingress.socks5",
                %peer,
                target = %target,
                reason = ?reason,
                "connect_session_failed"
            );
            let _ = sock
                .write_all(&encode_reply(reply_for_disconnect(&reason)))
                .await;
            return;
        }
        Err(_) => {
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
    };
    let bind_endpoint = session_info
        .paths
        .get(session_info.primary)
        .map(|path| path.local.clone());

    let reply = bind_endpoint
        .as_ref()
        .map(|endpoint| encode_reply_with_endpoint(Reply::Succeeded, endpoint))
        .unwrap_or_else(|| encode_reply(Reply::Succeeded));
    if sock.write_all(&reply).await.is_err() {
        return;
    }

    log_connect_open(
        peer,
        &target,
        authenticated_user.as_deref(),
        trace_fields.as_ref(),
    );
    log_flow_opened(peer, &target, &session_info, trace_fields.as_ref());
    let flow_id = session_info.flow_id.0;
    let started = Instant::now();

    match try_splice_tcp_connect(sock, session).await {
        SpliceConnect::Closed {
            stats,
            close_reason,
        } => {
            tracing::info!(
                target: "mesh_bus.ingress.socks5",
                %peer,
                flow_id = %flow_id,
                bytes_up = stats.bytes_up,
                bytes_down = stats.bytes_down,
                duration_ms = started.elapsed().as_millis() as u64,
                close_reason,
                "connect_close"
            );
            return;
        }
        SpliceConnect::Fallback {
            sock: fallback_sock,
            session: fallback_session,
        } => {
            sock = fallback_sock;
            session = fallback_session;
        }
    }

    // bytes_up/bytes_down are only needed in the fallback (non-splice) path.
    let bytes_up = Arc::new(AtomicU64::new(0));
    let bytes_down = Arc::new(AtomicU64::new(0));

    let (mut send_half, mut recv_half) = session.split();
    let (mut rd, mut wr) = sock.into_split();

    let mut returns_task = {
        let bytes_down = bytes_down.clone();
        tokio::spawn(async move {
            while let Some(payload) = recv_half.recv().await {
                bytes_down.fetch_add(payload.len() as u64, Ordering::Relaxed);
                if wr.write_all(&payload).await.is_err() {
                    break;
                }
            }
            "return_closed"
        })
    };

    let mut send_task = {
        let bytes_up = bytes_up.clone();
        tokio::spawn(async move {
            let mut data = vec![0u8; 16 * 1024];
            loop {
                let n = match rd.read(&mut data).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                if send_half
                    .send(Bytes::copy_from_slice(&data[..n]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            send_half.shutdown_write().await;
            "client_closed"
        })
    };

    let close_reason = tokio::select! {
        result = &mut returns_task => {
            send_task.abort();
            let _ = send_task.await;
            join_close_reason(result, "return_closed", "return_task_failed")
        },
        result = &mut send_task => {
            returns_task.abort();
            let _ = returns_task.await;
            join_close_reason(result, "client_closed", "send_task_failed")
        },
    };

    tracing::info!(
        target: "mesh_bus.ingress.socks5",
        %peer,
        flow_id = %flow_id,
        bytes_up = bytes_up.load(Ordering::Relaxed),
        bytes_down = bytes_down.load(Ordering::Relaxed),
        duration_ms = started.elapsed().as_millis() as u64,
        close_reason,
        "connect_close"
    );
}

enum SpliceConnect {
    Closed {
        stats: mb_splice::SpliceStats,
        close_reason: &'static str,
    },
    Fallback {
        sock: TcpStream,
        session: Box<dyn StreamSession>,
    },
}

#[cfg(target_os = "linux")]
async fn try_splice_tcp_connect(sock: TcpStream, session: Box<dyn StreamSession>) -> SpliceConnect {
    match session.into_tcp_splice() {
        Ok(splice) => match mb_splice::splice_tcp_streams(sock, splice).await {
            Ok(stats) => SpliceConnect::Closed {
                stats,
                close_reason: "splice_closed",
            },
            Err(e) => {
                tracing::warn!(
                    target: "mesh_bus.ingress.socks5",
                    error = %e,
                    "splice_failed"
                );
                SpliceConnect::Closed {
                    stats: mb_splice::SpliceStats::default(),
                    close_reason: "splice_error",
                }
            }
        },
        Err(session) => SpliceConnect::Fallback { sock, session },
    }
}

#[cfg(not(target_os = "linux"))]
async fn try_splice_tcp_connect(sock: TcpStream, session: Box<dyn StreamSession>) -> SpliceConnect {
    SpliceConnect::Fallback { sock, session }
}

fn join_close_reason(
    result: Result<&'static str, tokio::task::JoinError>,
    ok: &'static str,
    err: &'static str,
) -> &'static str {
    match result {
        Ok(reason) => reason,
        Err(_) => {
            tracing::warn!(
                target: "mesh_bus.ingress.socks5",
                expected_close_reason = ok,
                "connect_direction_task_failed"
            );
            err
        }
    }
}

fn reply_for_disconnect(reason: &DisconnectReason) -> Reply {
    match reason {
        DisconnectReason::ConnectionRefused => Reply::ConnectionRefused,
        DisconnectReason::NetworkUnreachable => Reply::NetworkUnreachable,
        DisconnectReason::HostUnreachable
        | DisconnectReason::NoUsableExit
        | DisconnectReason::NotConnected => Reply::HostUnreachable,
        DisconnectReason::TimedOut | DisconnectReason::TtlExpired => Reply::TtlExpired,
        _ => Reply::GeneralFailure,
    }
}

#[allow(clippy::too_many_arguments)]
async fn udp_associate(
    mut sock: TcpStream,
    peer: SocketAddr,
    port: BusPort,
    declared_peer: Endpoint,
    policy: Option<RulePolicy>,
    pipeline: Option<Arc<PipelineRuntime>>,
    authenticated_user: Option<String>,
    udp_forward_concurrency: usize,
) {
    let trace_fields = if pipeline.is_some() {
        None
    } else if let Some(ref policy) = policy {
        let ctx = build_udp_associate_ctx(peer, &declared_peer, authenticated_user.as_deref());
        let decision = mb_rule::evaluate_with_trace(&policy.chain, &ctx, &policy.registry);
        let action_lbl = action_label(&decision.action);
        let rule_id = decision.trace.rule_id.clone().unwrap_or_else(|| "-".into());
        let rule_index = decision
            .trace
            .rule_index
            .map(|i| i.to_string())
            .unwrap_or_else(|| "-".into());
        let default_used = decision.trace.default_used;
        match apply_decision(decision, BusSessionRequest::datagram(declared_peer.clone())) {
            ApplyOutcome::Allow(req) => Some(AccessTrace {
                matched_rule_id: rule_id,
                matched_rule_index: rule_index,
                default_used,
                action: action_lbl,
                route_group: req.route_group.clone().unwrap_or_else(|| "-".into()),
                schedule_hint: schedule_hint_label(&req.schedule_hint),
            }),
            ApplyOutcome::Deny => {
                tracing::info!(
                    target: "mesh_bus.ingress.socks5",
                    %peer,
                    declared_peer = %declared_peer,
                    matched_rule_id = %rule_id,
                    matched_rule_index = %rule_index,
                    default_used,
                    action = %action_lbl,
                    "udp_associate_denied_by_rule"
                );
                let _ = sock
                    .write_all(&encode_reply(Reply::ConnectionNotAllowed))
                    .await;
                return;
            }
        }
    } else {
        None
    };
    log_udp_associate_open(
        peer,
        &declared_peer,
        authenticated_user.as_deref(),
        trace_fields.as_ref(),
    );
    if !port.supports_datagram() {
        let _ = sock.write_all(&encode_reply(Reply::HostUnreachable)).await;
        return;
    }
    let bind_addr = udp_bind_addr(&sock);
    let relay = match UdpSocket::bind(bind_addr).await {
        Ok(relay) => relay,
        Err(_) => {
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
    };
    let relay_addr = match relay.local_addr() {
        Ok(addr) => addr,
        Err(_) => {
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
    };
    let bind_ep = Endpoint::new(relay_addr.ip().to_string(), relay_addr.port())
        .expect("socket local addr is a valid endpoint");
    if sock
        .write_all(&encode_reply_with_endpoint(Reply::Succeeded, &bind_ep))
        .await
        .is_err()
    {
        return;
    }

    let relay = Arc::new(relay);
    let association = match UdpAssociation::new(
        port,
        declared_peer,
        policy,
        pipeline,
        authenticated_user.clone(),
    ) {
        Some(association) => association,
        None => {
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
    };
    let relay_task = tokio::spawn(run_udp_relay(
        relay.clone(),
        association,
        udp_forward_concurrency,
    ));

    let mut drain = [0u8; 1];
    loop {
        match sock.read(&mut drain).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    relay_task.abort();
}

fn udp_bind_addr(sock: &TcpStream) -> SocketAddr {
    let ip = sock
        .local_addr()
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    SocketAddr::new(ip, 0)
}

#[derive(Clone)]
struct UdpAssociation {
    port: BusPort,
    peer: SocketAddr,
    sessions: Arc<Mutex<HashMap<String, Arc<UdpTargetSession>>>>,
    policy: Option<RulePolicy>,
    pipeline: Option<Arc<PipelineRuntime>>,
    authenticated_user: Option<String>,
}

struct UdpTargetSession {
    send: Mutex<Box<dyn BusDatagramSendHalf>>,
    pump: tokio::task::JoinHandle<()>,
}

impl UdpAssociation {
    fn new(
        port: BusPort,
        declared_peer: Endpoint,
        policy: Option<RulePolicy>,
        pipeline: Option<Arc<PipelineRuntime>>,
        authenticated_user: Option<String>,
    ) -> Option<Self> {
        let ip: IpAddr = declared_peer.host().parse().ok()?;
        let peer = SocketAddr::new(ip, declared_peer.port());
        Some(Self {
            port,
            peer,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            policy,
            pipeline,
            authenticated_user,
        })
    }

    fn owns_peer(&self, peer: SocketAddr) -> bool {
        // RFC1928 §4: 0.0.0.0:0 or [::]:0 means accept any source (wildcard hint)
        if self.peer.port() == 0 || self.peer.ip().is_unspecified() {
            return true;
        }
        peer == self.peer
    }

    async fn session_for(
        &self,
        target: &Endpoint,
        relay: Arc<UdpSocket>,
        peer: SocketAddr,
    ) -> Option<Arc<UdpTargetSession>> {
        let key = target.to_string();
        if let Some(session) = self.sessions.lock().await.get(&key).cloned() {
            return Some(session);
        }

        let base = BusSessionRequest::datagram(target.clone())
            .with_source_key(socks5_source_key(&self.peer))
            .with_target_key(socks5_target_key(target));

        let request = if let Some(runtime) = self.pipeline.clone() {
            let event =
                build_udp_packet_event(self.peer, target, self.authenticated_user.as_deref());
            let run = match run_pipeline_event(runtime, event).await {
                Ok(run) => run,
                Err(err) => {
                    tracing::warn!(
                        target: "mesh_bus.ingress.socks5",
                        target = %target,
                        error = %err,
                        "pipeline_runtime_error:udp_packet"
                    );
                    return None;
                }
            };
            match apply_verdict(&run.verdict, &run.event, base) {
                PipelineOutcome::Allow { request, .. } => {
                    tracing::debug!(
                        target: "mesh_bus.ingress.socks5",
                        target = %target,
                        action = "allow",
                        "udp_packet_allow:pkt"
                    );
                    request
                }
                PipelineOutcome::Deny { reason } => {
                    tracing::debug!(
                        target: "mesh_bus.ingress.socks5",
                        target = %target,
                        pipeline_reject = %reason,
                        "udp_packet_denied_by_pipeline:pkt"
                    );
                    return None;
                }
                PipelineOutcome::Drop => {
                    tracing::debug!(
                        target: "mesh_bus.ingress.socks5",
                        target = %target,
                        "udp_packet_dropped_by_pipeline"
                    );
                    return None;
                }
            }
        } else {
            match &self.policy {
                Some(policy) => {
                    let ctx =
                        build_udp_packet_ctx(self.peer, target, self.authenticated_user.as_deref());
                    let decision =
                        mb_rule::evaluate_with_trace(&policy.chain, &ctx, &policy.registry);
                    let action_lbl = action_label(&decision.action);
                    let rule_id = decision.trace.rule_id.clone().unwrap_or_else(|| "-".into());
                    match apply_decision(decision, base) {
                        ApplyOutcome::Allow(req) => {
                            tracing::debug!(
                                target: "mesh_bus.ingress.socks5",
                                target = %target,
                                matched_rule_id = %rule_id,
                                action = %action_lbl,
                                "udp_packet_allow:pkt"
                            );
                            req
                        }
                        ApplyOutcome::Deny => {
                            tracing::debug!(
                                target: "mesh_bus.ingress.socks5",
                                target = %target,
                                matched_rule_id = %rule_id,
                                action = %action_lbl,
                                "udp_packet_denied_by_rule:pkt"
                            );
                            return None;
                        }
                    }
                }
                None => base,
            }
        };

        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(&key).cloned() {
            return Some(session);
        }

        let session = self.port.open_datagram(request).await.ok()?;
        let (send_half, recv_half) = session.split();

        // Spawn per-target response pump: reads from recv half and sends encoded
        // SOCKS5 UDP datagrams back to the client peer.
        let target_clone = target.clone();
        let pump = tokio::spawn(run_udp_response_pump(relay, peer, target_clone, recv_half));
        let slot = Arc::new(UdpTargetSession {
            send: Mutex::new(send_half),
            pump,
        });

        // Evict one entry when the session table is full so it does not grow
        // unbounded; the evicted entry's response pump holds its own clones and
        // must be aborted explicitly, not left to Arc drop.
        if sessions.len() >= MAX_UDP_TARGET_SESSIONS {
            if let Some(evict_key) = sessions.keys().next().cloned() {
                if let Some(evicted) = sessions.remove(&evict_key) {
                    evicted.pump.abort();
                }
            }
        }
        sessions.insert(key, slot.clone());
        Some(slot)
    }
}

async fn run_udp_relay(
    relay: Arc<UdpSocket>,
    association: UdpAssociation,
    udp_forward_concurrency: usize,
) {
    let sem = Arc::new(Semaphore::new(udp_forward_concurrency));
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let mut buf = vec![0u8; 65_507];
    loop {
        while tasks.try_join_next().is_some() {}
        let (n, peer) = match relay.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(target: "mesh_bus.ingress.socks5", error = %e, "udp_recv_error");
                break;
            }
        };
        if !association.owns_peer(peer) {
            continue;
        }
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let packet = Bytes::copy_from_slice(&buf[..n]);
        let relay = relay.clone();
        let association = association.clone();
        tasks.spawn(async move {
            forward_udp_packet(relay, association, peer, packet).await;
            drop(permit);
        });
    }
    tasks.shutdown().await;
}

async fn forward_udp_packet(
    relay: Arc<UdpSocket>,
    association: UdpAssociation,
    peer: SocketAddr,
    packet: Bytes,
) {
    let mut buf = BytesMut::from(&packet[..]);
    let datagram = match decode_udp_datagram(&mut buf) {
        Ok(datagram) => datagram,
        Err(_) => return,
    };
    let Some(session) = association.session_for(&datagram.target, relay, peer).await else {
        return;
    };
    let _ = session
        .send
        .lock()
        .await
        .send_to(datagram.target, datagram.payload)
        .await;
}

async fn run_udp_response_pump(
    relay: Arc<UdpSocket>,
    peer: SocketAddr,
    target: Endpoint,
    mut recv: Box<dyn BusDatagramRecvHalf>,
) {
    while let Some((source, payload)) = recv.recv_from().await {
        // Use the source endpoint returned by the recv half (seq mapping preserves it).
        // Fall back to the session target when source is unspecified.
        let effective_source = if source.host() == "0.0.0.0" || source.host() == "::" {
            target.clone()
        } else {
            source
        };
        let reply = encode_udp_datagram(&effective_source, &payload);
        if let Err(e) = relay.send_to(&reply, peer).await {
            tracing::debug!(
                target: "mesh_bus.ingress.socks5",
                error = %e,
                peer = %peer,
                "udp_pump_send_to_client_error"
            );
        }
    }
}
