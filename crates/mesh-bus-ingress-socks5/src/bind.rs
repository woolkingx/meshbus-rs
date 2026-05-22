//! SOCKS5 BIND local-relay command.
//!
//! BIND is a client-facing local-relay command, not a bus egress session. The
//! adapter opens a local TCP listener, sends the listener endpoint as the first
//! RFC1928 reply, accepts exactly one inbound peer (v1 single-accept), sends the
//! accepted peer endpoint as the second reply, then bidirectionally copies bytes
//! between the original SOCKS5 control TCP and the accepted peer TCP. No
//! `BusSessionRequest` is opened: BIND is policy/pipeline gated for
//! Allow/Deny/Drop/Fail only and the projected request is discarded.

use mb_endpoint::Endpoint;
use mb_proto_socks5::{Reply, encode_reply, encode_reply_with_endpoint};
use mesh_bus_core::BusSessionRequest;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::PipelineRuntime;
use crate::RulePolicy;
use crate::action_apply::{ApplyOutcome, apply_decision};
use crate::event_build::build_bind_event;
use crate::rule_ctx_build::build_bind_ctx;
use crate::verdict_apply::{PipelineOutcome, apply_verdict};
use mesh_bus_pipeline_hooks::runtime::run_pipeline_event;

enum BindGate {
    Allow,
    Deny,
    Drop,
    Fail,
}

async fn gate(
    peer: SocketAddr,
    declared: &Endpoint,
    policy: &Option<RulePolicy>,
    pipeline: &Option<Arc<PipelineRuntime>>,
    authenticated_user: Option<&str>,
) -> BindGate {
    let base = BusSessionRequest::stream(declared.clone());
    if let Some(runtime) = pipeline.clone() {
        let event = build_bind_event(peer, declared, authenticated_user);
        let run = match run_pipeline_event(runtime, event).await {
            Ok(run) => run,
            Err(err) => {
                tracing::warn!(
                    target: "mesh_bus.ingress.socks5",
                    error = %err,
                    "pipeline_runtime_error:bind"
                );
                return BindGate::Fail;
            }
        };
        match apply_verdict(&run.verdict, &run.event, base) {
            PipelineOutcome::Allow { .. } => BindGate::Allow,
            PipelineOutcome::Deny { .. } => BindGate::Deny,
            PipelineOutcome::Drop => BindGate::Drop,
        }
    } else {
        match policy {
            Some(policy) => {
                let ctx = build_bind_ctx(peer, declared, authenticated_user);
                let decision = mb_rule::evaluate_with_trace(&policy.chain, &ctx, &policy.registry);
                match apply_decision(decision, base) {
                    ApplyOutcome::Allow(_) => BindGate::Allow,
                    ApplyOutcome::Deny => BindGate::Deny,
                }
            }
            None => BindGate::Allow,
        }
    }
}

// Wrong-peer rejection is IP-only because the connecting peer source port is
// ephemeral. The SOCKS5 codec rejects a zero declared port, so only the
// IP-shaped cases remain: unspecified declared IP or a non-IP hostname accepts
// any source; a specific declared IP requires the connecting IP to match.
fn peer_ip_allowed(declared: &Endpoint, connecting: IpAddr) -> bool {
    match declared.host().parse::<IpAddr>() {
        Ok(decl_ip) => decl_ip.is_unspecified() || decl_ip == connecting,
        Err(_) => true,
    }
}

fn endpoint_from_sockaddr(addr: SocketAddr) -> Option<Endpoint> {
    Endpoint::new(addr.ip().to_string(), addr.port()).ok()
}

fn bind_listen_addr(sock: &TcpStream) -> SocketAddr {
    let ip = sock
        .local_addr()
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    SocketAddr::new(ip, 0)
}

async fn run_bind_relay(
    mut sock: TcpStream,
    peer: SocketAddr,
    declared: Endpoint,
    accept_timeout: Duration,
) {
    let listener = match TcpListener::bind(bind_listen_addr(&sock)).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::warn!(target: "mesh_bus.ingress.socks5", %peer, error = %err, "bind_listener_failed");
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
    };
    let first = match listener.local_addr().ok().and_then(endpoint_from_sockaddr) {
        Some(ep) => encode_reply_with_endpoint(Reply::Succeeded, &ep),
        None => {
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
    };
    if sock.write_all(&first).await.is_err() {
        return;
    }

    let (mut inbound, inbound_addr) = match tokio::time::timeout(accept_timeout, listener.accept())
        .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(err)) => {
            tracing::warn!(target: "mesh_bus.ingress.socks5", %peer, error = %err, "bind_accept_failed");
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
        Err(_) => {
            tracing::info!(target: "mesh_bus.ingress.socks5", %peer, "bind_accept_timeout");
            let _ = sock.write_all(&encode_reply(Reply::TtlExpired)).await;
            return;
        }
    };

    if !peer_ip_allowed(&declared, inbound_addr.ip()) {
        tracing::info!(target: "mesh_bus.ingress.socks5", %peer, connecting = %inbound_addr, "bind_wrong_peer");
        let _ = sock
            .write_all(&encode_reply(Reply::ConnectionNotAllowed))
            .await;
        return;
    }

    let second = match endpoint_from_sockaddr(inbound_addr) {
        Some(ep) => encode_reply_with_endpoint(Reply::Succeeded, &ep),
        None => encode_reply(Reply::Succeeded),
    };
    if sock.write_all(&second).await.is_err() {
        return;
    }

    match tokio::io::copy_bidirectional(&mut sock, &mut inbound).await {
        Ok((c2p, p2c)) => tracing::debug!(
            target: "mesh_bus.ingress.socks5", %peer,
            client_to_peer = c2p, peer_to_client = p2c, "bind_relay_closed"
        ),
        Err(err) => tracing::debug!(
            target: "mesh_bus.ingress.socks5", %peer, error = %err, "bind_relay_error"
        ),
    }
}

pub async fn bind_command(
    mut sock: TcpStream,
    peer: SocketAddr,
    declared: Endpoint,
    policy: Option<RulePolicy>,
    pipeline: Option<Arc<PipelineRuntime>>,
    authenticated_user: Option<String>,
    accept_timeout: Duration,
) {
    match gate(
        peer,
        &declared,
        &policy,
        &pipeline,
        authenticated_user.as_deref(),
    )
    .await
    {
        BindGate::Allow => {}
        BindGate::Deny => {
            tracing::info!(target: "mesh_bus.ingress.socks5", %peer, "bind_denied");
            let _ = sock
                .write_all(&encode_reply(Reply::ConnectionNotAllowed))
                .await;
            return;
        }
        BindGate::Drop => {
            tracing::debug!(target: "mesh_bus.ingress.socks5", %peer, "bind_dropped");
            return;
        }
        BindGate::Fail => {
            let _ = sock.write_all(&encode_reply(Reply::GeneralFailure)).await;
            return;
        }
    }
    run_bind_relay(sock, peer, declared, accept_timeout).await;
}
