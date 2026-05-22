use crate::dns_wire::{build_query, rdata_to_answer, validate_reply};
use crate::policy::{select_consistent_hash, select_fanout, select_round_robin};
use crate::types::*;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_dns::framing::{try_read_tcp_frame, write_tcp_frame};
use mesh_bus_core::{
    BusSessionRequest, BusStreamRecvHalf, BusStreamSendHalf, BusStreamSession, DisconnectReason,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::timeout;

// ── Telemetry returned to caller ─────────────────────────────────────────────

pub(crate) struct M1Telemetry {
    pub winner: SocketAddr,
    pub losers: Vec<SocketAddr>,
    pub attempted: u32,
    pub rtt_ms: u64,
    pub truncated: bool,
    pub answer_count: u32,
}

// ── Thin trait so tests can inject a mock opener ──────────────────────────────

/// Thin abstraction over BusPort::open_stream so Tunneled mode can be tested
/// with a mock framed-channel-backed session without spinning up a Bus.
/// Production wiring uses the blanket impl below for `BusPort`.
#[async_trait]
pub trait StreamOpener: Send + Sync {
    async fn open_stream(
        &self,
        req: BusSessionRequest,
    ) -> Result<Box<dyn BusStreamSession>, DisconnectReason>;
}

use mesh_bus_core::BusPort;

#[async_trait]
impl StreamOpener for BusPort {
    async fn open_stream(
        &self,
        req: BusSessionRequest,
    ) -> Result<Box<dyn BusStreamSession>, DisconnectReason> {
        BusPort::open_stream(self, req).await
    }
}

// ── Per-(server, route_group) connection cache ────────────────────────────────

type CacheKey = (SocketAddr, Option<String>);

pub(crate) struct CachedConn {
    send: Box<dyn BusStreamSendHalf>,
    recv: Box<dyn BusStreamRecvHalf>,
    rx_buf: BytesMut,
}

#[derive(Default)]
pub(crate) struct ConnCache {
    entries: Mutex<HashMap<CacheKey, Arc<Mutex<CachedConn>>>>,
}

impl ConnCache {
    pub fn new() -> Self {
        Self::default()
    }

    async fn get_or_open(
        &self,
        opener: &dyn StreamOpener,
        server: SocketAddr,
        route_group: Option<&str>,
    ) -> Result<Arc<Mutex<CachedConn>>, ResolveError> {
        let key: CacheKey = (server, route_group.map(|s| s.to_string()));
        {
            let entries = self.entries.lock().await;
            if let Some(c) = entries.get(&key) {
                return Ok(c.clone());
            }
        }

        let ep = Endpoint::new(server.ip().to_string(), server.port())
            .map_err(|e| ResolveError::Io(e.to_string()))?;
        let mut req = BusSessionRequest::stream(ep).with_target_key(server.to_string());
        if let Some(rg) = route_group {
            req = req.with_route_group(rg);
        }
        let mut session = opener
            .open_stream(req)
            .await
            .map_err(|e| ResolveError::Io(format!("open_stream: {e:?}")))?;
        session
            .connect()
            .await
            .map_err(|e| ResolveError::Io(format!("stream connect: {e:?}")))?;
        let (send, recv) = session.split();
        let conn = Arc::new(Mutex::new(CachedConn {
            send,
            recv,
            rx_buf: BytesMut::with_capacity(4096),
        }));

        let mut entries = self.entries.lock().await;
        // Another caller may have inserted between our read and write; honor theirs.
        if let Some(existing) = entries.get(&key) {
            return Ok(existing.clone());
        }
        entries.insert(key, conn.clone());
        Ok(conn)
    }

    async fn evict(&self, server: SocketAddr, route_group: Option<&str>) {
        let key: CacheKey = (server, route_group.map(|s| s.to_string()));
        let mut entries = self.entries.lock().await;
        entries.remove(&key);
    }
}

// ── Single-shot TCP query helper ──────────────────────────────────────────────

/// Pulls one framed RFC 7766 reply from `recv`, accumulating into `rx_buf` until
/// `try_read_tcp_frame` returns Some. Returns Err on stream close before a full frame.
async fn read_one_frame(
    recv: &mut Box<dyn BusStreamRecvHalf>,
    rx_buf: &mut BytesMut,
) -> Result<Bytes, ResolveError> {
    loop {
        if let Some(frame) = try_read_tcp_frame(rx_buf) {
            return Ok(frame);
        }
        match recv.recv().await {
            Some(chunk) => rx_buf.extend_from_slice(&chunk),
            None => {
                return Err(ResolveError::Io("stream closed before full frame".into()));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn single_shot_tcp(
    opener: &dyn StreamOpener,
    cache: &ConnCache,
    server: SocketAddr,
    route_group: Option<&str>,
    qname: &str,
    qname_lower: &str,
    qtype: QType,
    txid: u16,
    budget: Duration,
) -> Result<(mb_proto_dns::Message, Duration), ResolveError> {
    let conn = cache.get_or_open(opener, server, route_group).await?;
    let payload = build_query(txid, qname, qtype)?;
    let mut framed = BytesMut::with_capacity(payload.len() + 2);
    write_tcp_frame(&mut framed, &payload);

    let start = Instant::now();
    let send_recv = async {
        let mut guard = conn.lock().await;
        let CachedConn { send, recv, rx_buf } = &mut *guard;
        send.send(framed.freeze())
            .await
            .map_err(|e| ResolveError::Io(format!("stream send: {e:?}")))?;
        read_one_frame(recv, rx_buf).await
    };
    let frame_result = timeout(budget, send_recv).await;
    let elapsed = start.elapsed();

    let data = match frame_result {
        Err(_) => {
            cache.evict(server, route_group).await;
            return Err(ResolveError::Timeout(budget));
        }
        Ok(Err(e)) => {
            cache.evict(server, route_group).await;
            return Err(e);
        }
        Ok(Ok(d)) => d,
    };

    let msg = mb_proto_dns::decode::decode_message(&data)?;
    if !validate_reply(&msg, txid, qname_lower) {
        // RFC 5452 mismatch on TCP indicates a desynced stream — evict so the
        // next query reopens.
        cache.evict(server, route_group).await;
        return Err(ResolveError::Io("TXID or QNAME mismatch (RFC 5452)".into()));
    }
    Ok((msg, elapsed))
}

fn extract_answer(msg: mb_proto_dns::Message, server: SocketAddr) -> ResolveAnswer {
    let truncated = msg.header.tc();
    let min_rr_ttl = msg.answers.iter().map(|rr| rr.ttl).min().unwrap_or(60);
    let records: Vec<AnswerRecord> = msg.answers.iter().filter_map(rdata_to_answer).collect();
    ResolveAnswer {
        records,
        source: ResolverSource::Tunneled { server },
        truncated,
        rtt: Duration::ZERO,
        min_rr_ttl,
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_tunneled(
    opener: &dyn StreamOpener,
    cache: &ConnCache,
    pool_id: &str,
    server_policy: &ServerPolicy,
    rr_counter: &AtomicUsize,
    servers: &[UpstreamServer],
    route_group: Option<&str>,
    qname: &str,
    qtype: QType,
    budget: Duration,
) -> Result<(ResolveAnswer, M1Telemetry), ResolveError> {
    let _ = pool_id;
    if servers.is_empty() {
        return Err(ResolveError::Io("no servers configured".into()));
    }
    let qname_lower = crate::dns_wire::normalize_qname(qname);

    match server_policy {
        ServerPolicy::RoundRobin | ServerPolicy::ConsistentHash => {
            let server = match server_policy {
                ServerPolicy::RoundRobin => select_round_robin(servers, rr_counter),
                _ => select_consistent_hash(servers, &qname_lower),
            };
            let addr = server.addr;
            let txid: u16 = rand::random();
            let t0 = Instant::now();
            let (msg, _) = single_shot_tcp(
                opener,
                cache,
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
            let mut answer = extract_answer(msg, addr);
            answer.rtt = Duration::from_millis(rtt_ms);
            Ok((
                answer,
                M1Telemetry {
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
            resolve_fanout_tcp(
                opener,
                cache,
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
async fn resolve_fanout_tcp(
    opener: &dyn StreamOpener,
    cache: &ConnCache,
    servers: &[UpstreamServer],
    route_group: Option<&str>,
    qname: &str,
    qname_lower: &str,
    qtype: QType,
    budget: Duration,
    k: u8,
) -> Result<(ResolveAnswer, M1Telemetry), ResolveError> {
    let chosen = select_fanout(servers, k as u32);
    if chosen.is_empty() {
        return Err(ResolveError::Io("fanout k=0 produced no servers".into()));
    }
    let attempted = chosen.len() as u32;
    let addrs: Vec<SocketAddr> = chosen.iter().map(|s| s.addr).collect();

    let mut results: Vec<Result<(mb_proto_dns::Message, Duration, SocketAddr), ResolveError>> =
        Vec::with_capacity(addrs.len());
    for &addr in &addrs {
        let txid: u16 = rand::random();
        let r = single_shot_tcp(
            opener,
            cache,
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
            let mut answer = extract_answer(msg, winner_addr);
            answer.rtt = Duration::from_millis(rtt_ms);
            Ok((
                answer,
                M1Telemetry {
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
