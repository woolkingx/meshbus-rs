//! SOCKS5 CONNECT stream adaptation.

use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{Reply, encode_reply, encode_reply_with_endpoint};
use mesh_bus_core::kernel::Verdict;
use mesh_bus_core::{BusPort, BusSessionRequest, DisconnectReason, StreamSession};
use mesh_bus_pipeline_hooks::runtime::run_pipeline_event;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::access::{
    AccessTrace, log_connect_open, log_flow_opened, socks5_source_key, socks5_target_key,
};
use crate::action_apply::{ApplyOutcome, action_label, apply_decision, schedule_hint_label};
use crate::event_build::build_connect_event;
use crate::rule_ctx_build::build_connect_ctx;
use crate::verdict_apply::{PipelineOutcome, apply_verdict};
use crate::{PipelineRuntime, RulePolicy};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn pipe_connect(
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
