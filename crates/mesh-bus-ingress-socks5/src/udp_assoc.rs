//! SOCKS5 UDP ASSOCIATE datagram adaptation.

use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    Reply, decode_udp_datagram, encode_reply, encode_reply_with_endpoint, encode_udp_datagram,
};
use mesh_bus_core::{BusDatagramRecvHalf, BusDatagramSendHalf, BusPort, BusSessionRequest};
use mesh_bus_pipeline_hooks::runtime::run_pipeline_event;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, Semaphore};

use crate::access::{AccessTrace, log_udp_associate_open, socks5_source_key, socks5_target_key};
use crate::action_apply::{ApplyOutcome, action_label, apply_decision, schedule_hint_label};
use crate::event_build::build_udp_packet_event;
use crate::rule_ctx_build::{build_udp_associate_ctx, build_udp_packet_ctx};
use crate::verdict_apply::{PipelineOutcome, apply_verdict};
use crate::{PipelineRuntime, RulePolicy};

const MAX_UDP_TARGET_SESSIONS: usize = 256;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn udp_associate(
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
