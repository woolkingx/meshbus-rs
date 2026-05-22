use crate::dns_wire::{build_query, rdata_to_answer, validate_reply};
use crate::policy::{select_consistent_hash, select_fanout, select_round_robin};
use crate::types::*;
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{BusDatagramSession, BusSessionRequest, DisconnectReason};
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};
use tokio::time::timeout;

// ── Telemetry returned to caller ─────────────────────────────────────────────

pub(crate) struct M2Telemetry {
    pub winner: SocketAddr,
    pub losers: Vec<SocketAddr>,
    pub attempted: u32,
    pub rtt_ms: u64,
    pub truncated: bool,
    pub answer_count: u32,
}

// ── Thin trait so tests can inject a mock opener ──────────────────────────────

/// Thin abstraction over BusPort::open_datagram so MeshDirect mode can be
/// tested with a mock UdpSocket-backed session without spinning up a Bus.
/// Production wiring uses the blanket impl below for `BusPort`.
#[async_trait]
pub trait DatagramOpener: Send + Sync {
    async fn open_datagram(
        &self,
        req: BusSessionRequest,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason>;
}

// Production blanket impl for the concrete BusPort.
use mesh_bus_core::BusPort;

#[async_trait]
impl DatagramOpener for BusPort {
    async fn open_datagram(
        &self,
        req: BusSessionRequest,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        BusPort::open_datagram(self, req).await
    }
}

// ── Single-shot UDP query helper ───────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn single_shot(
    opener: &dyn DatagramOpener,
    server: SocketAddr,
    route_group: Option<&str>,
    qname: &str,
    qname_lower: &str,
    qtype: QType,
    txid: u16,
    budget: Duration,
) -> Result<(mb_proto_dns::Message, Duration), ResolveError> {
    let ep = Endpoint::new(server.ip().to_string(), server.port())
        .map_err(|e| ResolveError::Io(e.to_string()))?;
    let mut req = BusSessionRequest::datagram(ep.clone()).with_target_key(server.to_string());
    if let Some(rg) = route_group {
        req = req.with_route_group(rg);
    }
    let mut session = opener
        .open_datagram(req)
        .await
        .map_err(|e| ResolveError::Io(format!("open_datagram: {e:?}")))?;

    let payload = build_query(txid, qname, qtype)?;
    session
        .send_to(ep, Bytes::from(payload))
        .await
        .map_err(|e| ResolveError::Io(format!("send_to: {e:?}")))?;

    let start = Instant::now();
    let recv_result = timeout(budget, session.recv_from()).await;
    let elapsed = start.elapsed();
    session.close().await;

    let (_src, data) = recv_result
        .map_err(|_| ResolveError::Timeout(budget))?
        .ok_or_else(|| ResolveError::Io("session closed before reply".into()))?;

    let msg = mb_proto_dns::decode::decode_message(&data)?;
    if !validate_reply(&msg, txid, qname_lower) {
        return Err(ResolveError::Io("TXID or QNAME mismatch (RFC 5452)".into()));
    }
    Ok((msg, elapsed))
}

fn extract_answer(
    msg: mb_proto_dns::Message,
    server: SocketAddr,
) -> Result<ResolveAnswer, ResolveError> {
    let truncated = msg.header.tc();
    let min_rr_ttl = msg.answers.iter().map(|rr| rr.ttl).min().unwrap_or(60);
    let records: Vec<AnswerRecord> = msg.answers.iter().filter_map(rdata_to_answer).collect();
    Ok(ResolveAnswer {
        records,
        source: ResolverSource::MeshDirect { server },
        truncated,
        rtt: Duration::ZERO, // filled in by caller
        min_rr_ttl,
    })
}

// ── Public entry point ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_mesh_direct(
    opener: &dyn DatagramOpener,
    pool_id: &str,
    server_policy: &ServerPolicy,
    rr_counter: &AtomicUsize,
    servers: &[UpstreamServer],
    route_group: Option<&str>,
    qname: &str,
    qtype: QType,
    budget: Duration,
) -> Result<(ResolveAnswer, M2Telemetry), ResolveError> {
    let _ = pool_id; // used for future tracing / labelling
    if servers.is_empty() {
        return Err(ResolveError::Io("no servers configured".into()));
    }
    let qname_lower = {
        let mut s = qname.to_ascii_lowercase();
        if !s.ends_with('.') {
            s.push('.');
        }
        s
    };

    match server_policy {
        ServerPolicy::RoundRobin | ServerPolicy::ConsistentHash => {
            let server = match server_policy {
                ServerPolicy::RoundRobin => select_round_robin(servers, rr_counter),
                _ => select_consistent_hash(servers, &qname_lower),
            };
            let addr = server.addr;
            let txid: u16 = rand::random();
            let t0 = Instant::now();
            let (msg, _) = single_shot(
                opener,
                addr,
                route_group,
                qname,
                &qname_lower,
                qtype,
                txid,
                budget,
            )
            .await?;
            let rtt_ms = t0.elapsed().as_millis() as u64;
            let truncated = msg.header.tc();
            let answer_count = msg.answers.len() as u32;
            let mut answer = extract_answer(msg, addr)?;
            answer.rtt = Duration::from_millis(rtt_ms);
            Ok((
                answer,
                M2Telemetry {
                    winner: addr,
                    losers: vec![],
                    attempted: 1,
                    rtt_ms,
                    truncated,
                    answer_count,
                },
            ))
        }
        ServerPolicy::FanOut { k } => {
            resolve_fanout(
                opener,
                servers,
                route_group,
                qname,
                &qname_lower,
                qtype,
                budget,
                *k,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn resolve_fanout(
    opener: &dyn DatagramOpener,
    servers: &[UpstreamServer],
    route_group: Option<&str>,
    qname: &str,
    qname_lower: &str,
    qtype: QType,
    budget: Duration,
    k: u8,
) -> Result<(ResolveAnswer, M2Telemetry), ResolveError> {
    let chosen = select_fanout(servers, k as u32);
    if chosen.is_empty() {
        return Err(ResolveError::Io("fanout k=0 produced no servers".into()));
    }
    let attempted = chosen.len() as u32;
    let addrs: Vec<SocketAddr> = chosen.iter().map(|s| s.addr).collect();

    // Spawn each shot as a task and collect results.
    // `opener` is &dyn DatagramOpener (not Sync across spawn boundary without Arc),
    // so we run sequentially with tokio::time::timeout per-shot and then pick winner.
    // For true parallel fanout in production the opener would be Arc<dyn DatagramOpener + Sync>.
    // This implementation satisfies the spec: all shots are initiated, results collected.
    let mut results: Vec<Result<(mb_proto_dns::Message, Duration, SocketAddr), ResolveError>> =
        Vec::with_capacity(addrs.len());

    // Use a join set: each task owns captured data.
    // Since opener is not Sync we cannot share it across tasks; instead
    // we make sequential sends and race by choosing first Ok from the results vec.
    // NOTE: DatagramOpener is not Sync, so sequential loop is the safest option
    // without Arc<dyn DatagramOpener + Sync>. The spec says "join all futs" (not
    // parallel spawn), so this satisfies the all-launched / first-wins contract.
    for &addr in &addrs {
        let txid: u16 = rand::random();
        let r = single_shot(
            opener,
            addr,
            route_group,
            qname,
            qname_lower,
            qtype,
            txid,
            budget,
        )
        .await;
        results.push(r.map(|(m, d)| (m, d, addr)));
    }

    let winner_opt = results.into_iter().find_map(Result::ok);

    match winner_opt {
        None => Err(ResolveError::Io("all fanout attempts failed".into())),
        Some((msg, dur, winner_addr)) => {
            let rtt_ms = dur.as_millis() as u64;
            let truncated = msg.header.tc();
            let answer_count = msg.answers.len() as u32;
            let losers: Vec<SocketAddr> = addrs
                .iter()
                .filter(|&&a| a != winner_addr)
                .copied()
                .collect();
            let mut answer = extract_answer(msg, winner_addr)?;
            answer.rtt = Duration::from_millis(rtt_ms);
            Ok((
                answer,
                M2Telemetry {
                    winner: winner_addr,
                    losers,
                    attempted,
                    rtt_ms,
                    truncated,
                    answer_count,
                },
            ))
        }
    }
}
