use crate::m1::{ConnCache, M1Telemetry, StreamOpener, resolve_tunneled};
use crate::m2::{DatagramOpener, M2Telemetry, resolve_mesh_direct};
use crate::m3::resolve_system;
use crate::rule::{build_rule_ctx, project_decision};
use crate::signals::{emit_access_log, fresh_signals, record_rule_decision};
use crate::types::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use thiserror::Error;

pub(crate) fn is_special_use_localhost(qname_lower: &str) -> bool {
    qname_lower == "localhost." || qname_lower.ends_with(".localhost.")
}

pub(crate) fn is_special_use_invalid_or_reserved(qname_lower: &str) -> bool {
    qname_lower.ends_with(".invalid.")
        || qname_lower.ends_with(".test.")
        || qname_lower.ends_with(".example.")
        || qname_lower == "invalid."
        || qname_lower == "test."
        || qname_lower == "example."
}

pub(crate) fn is_rfc6303_reverse(qname_lower: &str) -> bool {
    const RANGES: &[&str] = &[
        "10.in-addr.arpa.",
        "168.192.in-addr.arpa.",
        "254.169.in-addr.arpa.",
        "d.f.ip6.arpa.",
        "c.f.ip6.arpa.",
    ];
    if RANGES.iter().any(|r| qname_lower.ends_with(r)) {
        return true;
    }
    for n in 16u8..=31 {
        if qname_lower.ends_with(&format!(".{n}.172.in-addr.arpa."))
            || qname_lower.ends_with(&format!("{n}.172.in-addr.arpa."))
        {
            return true;
        }
    }
    false
}

#[async_trait]
pub trait ResolverHandle: Send + Sync + 'static {
    async fn resolve(
        &self,
        req: ResolveRequest,
    ) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)>;
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("resolver requires at least one pool")]
    NoPool,
    #[error("duplicate pool id: {0}")]
    DuplicatePool(String),
    #[error("unsupported upstream scheme for tunneled pool {0} (only tcp allowed)")]
    UnsupportedTunneledScheme(String),
    #[error("unsupported upstream scheme for mesh-direct pool {0} (only udp allowed)")]
    UnsupportedMeshDirectScheme(String),
    #[error("system-mode pool {0} must not declare servers")]
    SystemModeHasServers(String),
}

#[derive(Default)]
pub struct ResolverBuilder {
    pools: Vec<Pool>,
    default_pool: Option<String>,
    rule_chain: Option<Arc<mb_rule::RuleChain>>,
    rule_sets: Option<Arc<mb_rule::RuleSetRegistry>>,
    opener: Option<Arc<dyn DatagramOpener>>,
    stream_opener: Option<Arc<dyn StreamOpener>>,
    default_query_timeout: Option<Duration>,
    cache: Option<Arc<crate::cache::DnsCache>>,
}

impl ResolverBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pool(mut self, p: Pool) -> Self {
        self.pools.push(p);
        self
    }

    pub fn with_default_pool(mut self, id: impl Into<String>) -> Self {
        self.default_pool = Some(id.into());
        self
    }

    pub fn with_rule_chain(
        mut self,
        chain: Arc<mb_rule::RuleChain>,
        sets: Arc<mb_rule::RuleSetRegistry>,
    ) -> Self {
        self.rule_chain = Some(chain);
        self.rule_sets = Some(sets);
        self
    }

    /// Inject a DatagramOpener for MeshDirect mode. In production this is an
    /// `Arc<BusPort>`; tests inject a mock that wraps a local UdpSocket.
    pub fn with_datagram_opener(mut self, opener: Arc<dyn DatagramOpener>) -> Self {
        self.opener = Some(opener);
        self
    }

    /// Inject a StreamOpener for Tunneled mode. In production this is an
    /// `Arc<BusPort>`; tests inject a mock backed by an in-memory framed channel.
    pub fn with_stream_opener(mut self, opener: Arc<dyn StreamOpener>) -> Self {
        self.stream_opener = Some(opener);
        self
    }

    /// Default per-query budget for MeshDirect / Tunneled modes (B3/B4).
    pub fn with_query_timeout(mut self, t: Duration) -> Self {
        self.default_query_timeout = Some(t);
        self
    }

    /// Inject a DnsCache for pre-lookup short-circuit and post-resolve write-back.
    pub fn with_cache(mut self, cache: Arc<crate::cache::DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.pools.is_empty() {
            return Err(ConfigError::NoPool);
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.pools {
            if !seen.insert(&p.id) {
                return Err(ConfigError::DuplicatePool(p.id.clone()));
            }
            match &p.mode {
                PoolMode::SystemMode => {
                    if !p.servers.is_empty() {
                        return Err(ConfigError::SystemModeHasServers(p.id.clone()));
                    }
                }
                PoolMode::MeshDirect { .. } => {
                    for s in &p.servers {
                        if !matches!(s.scheme, UpstreamScheme::Udp) {
                            return Err(ConfigError::UnsupportedMeshDirectScheme(p.id.clone()));
                        }
                    }
                }
                PoolMode::Tunneled { .. } => {
                    for s in &p.servers {
                        if !matches!(s.scheme, UpstreamScheme::Tcp) {
                            return Err(ConfigError::UnsupportedTunneledScheme(p.id.clone()));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn build(self) -> Result<Resolver, ConfigError> {
        self.validate()?;
        let mut rr_counters: HashMap<String, Arc<AtomicUsize>> = HashMap::new();
        for p in &self.pools {
            rr_counters.insert(p.id.clone(), Arc::new(AtomicUsize::new(0)));
        }
        let pools = self
            .pools
            .into_iter()
            .map(|p| (p.id.clone(), p))
            .collect::<HashMap<_, _>>();
        Ok(Resolver {
            pools,
            default_pool: self.default_pool,
            rule_chain: self.rule_chain,
            rule_sets: self.rule_sets,
            opener: self.opener,
            stream_opener: self.stream_opener,
            conn_cache: Arc::new(ConnCache::new()),
            rr_counters,
            query_timeout: self.default_query_timeout.unwrap_or(Duration::from_secs(3)),
            cache: self.cache,
        })
    }
}

pub struct Resolver {
    pub(crate) pools: HashMap<String, Pool>,
    pub(crate) default_pool: Option<String>,
    pub(crate) rule_chain: Option<Arc<mb_rule::RuleChain>>,
    pub(crate) rule_sets: Option<Arc<mb_rule::RuleSetRegistry>>,
    pub(crate) opener: Option<Arc<dyn DatagramOpener>>,
    pub(crate) stream_opener: Option<Arc<dyn StreamOpener>>,
    pub(crate) conn_cache: Arc<ConnCache>,
    pub(crate) rr_counters: HashMap<String, Arc<AtomicUsize>>,
    pub(crate) query_timeout: Duration,
    pub(crate) cache: Option<Arc<crate::cache::DnsCache>>,
}

// Manual Debug impl: dyn DatagramOpener has no Debug bound.
impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("pools", &self.pools.keys().collect::<Vec<_>>())
            .field("default_pool", &self.default_pool)
            .field("opener", &self.opener.as_ref().map(|_| "<opener>"))
            .field("query_timeout", &self.query_timeout)
            .finish()
    }
}

fn normalize_qname(qname: &str) -> String {
    let mut s = qname.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

fn localhost_records(qtype: QType) -> Vec<AnswerRecord> {
    match qtype {
        QType::A => vec![AnswerRecord::A(std::net::Ipv4Addr::LOCALHOST)],
        QType::Aaaa => vec![AnswerRecord::Aaaa(std::net::Ipv6Addr::LOCALHOST)],
        _ => vec![
            AnswerRecord::A(std::net::Ipv4Addr::LOCALHOST),
            AnswerRecord::Aaaa(std::net::Ipv6Addr::LOCALHOST),
        ],
    }
}

#[async_trait]
impl ResolverHandle for Resolver {
    async fn resolve(
        &self,
        req: ResolveRequest,
    ) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
        let qname_lower = normalize_qname(&req.qname);

        // RFC 2181 / 2308 — cache is the fastest path; runs before special-use.
        if let Some(cache) = &self.cache {
            let key = crate::cache::CacheKey {
                qname: qname_lower.clone(),
                qtype: req.qtype,
            };
            if let Some(hit) = cache.lookup(&key) {
                if hit.is_fresh() {
                    use crate::cache::Lookup;
                    let mut sig = fresh_signals(&qname_lower, "cache");
                    sig.answer_count = hit.records().len() as u32;
                    sig.winner_exit = WinnerExit::System;
                    emit_access_log(&sig, "mesh_bus.resolver.open");
                    return match hit {
                        Lookup::Positive { records, .. } => Ok((
                            ResolveAnswer {
                                records,
                                source: ResolverSource::System,
                                truncated: false,
                                rtt: std::time::Duration::ZERO,
                                min_rr_ttl: 0,
                            },
                            sig,
                        )),
                        Lookup::Negative { .. } => Err((ResolveError::NxDomain, sig)),
                    };
                }
            }
        }

        // Cache for write-back after upstream resolve.
        let cache_for_write = self.cache.clone();

        // RFC 6761 / 6303 short-circuits — bypass rule chain
        if is_special_use_localhost(&qname_lower) {
            let mut sig = fresh_signals(&qname_lower, "(special-use:localhost)");
            sig.winner_exit = WinnerExit::System;
            emit_access_log(&sig, "mesh_bus.resolver.open");
            return Ok((
                ResolveAnswer {
                    records: localhost_records(req.qtype),
                    source: ResolverSource::System,
                    truncated: false,
                    rtt: std::time::Duration::ZERO,
                    min_rr_ttl: 60,
                },
                sig,
            ));
        }

        if is_special_use_invalid_or_reserved(&qname_lower) {
            let mut sig = fresh_signals(&qname_lower, "(special-use:nxdomain)");
            sig.winner_exit = WinnerExit::System;
            emit_access_log(&sig, "mesh_bus.resolver.open");
            return Err((ResolveError::NxDomain, sig));
        }

        if is_rfc6303_reverse(&qname_lower) {
            let mut sig = fresh_signals(&qname_lower, "(rfc6303:system)");
            sig.winner_exit = WinnerExit::System;
            let result = resolve_system(&req.qname, req.qtype).await;
            match result {
                Ok(a) => {
                    sig.resolver_rtt_ms = a.rtt.as_millis() as u64;
                    sig.answer_count = a.records.len() as u32;
                    sig.truncated = a.truncated;
                    emit_access_log(&sig, "mesh_bus.resolver.open");
                    return Ok((a, sig));
                }
                Err(e) => {
                    emit_access_log(&sig, "mesh_bus.resolver.open");
                    return Err((e, sig));
                }
            };
        }

        // Rule chain evaluation
        let reg = mb_rule::RuleSetRegistry::default();
        let proj = if let Some(chain) = &self.rule_chain {
            let ctx = build_rule_ctx(&req);
            let reg_ref = self.rule_sets.as_deref().unwrap_or(&reg);
            let dec = mb_rule::evaluate_with_trace(chain, &ctx, reg_ref);
            let p = project_decision(&dec);
            let mut sig_tmp = fresh_signals(&qname_lower, "");
            record_rule_decision(&mut sig_tmp, &dec);
            if p.denied {
                sig_tmp.pool = "(denied)".into();
                emit_access_log(&sig_tmp, "mesh_bus.resolver.denied");
                return Err((ResolveError::Denied, sig_tmp));
            }
            (p, sig_tmp)
        } else {
            let sig_tmp = fresh_signals(&qname_lower, "");
            (crate::rule::Projection::default(), sig_tmp)
        };

        let (projection, mut sig) = proj;

        // Resolve pool name
        let pool_name = projection
            .pool
            .as_deref()
            .or(self.default_pool.as_deref())
            .unwrap_or("(none)");

        sig.pool = pool_name.to_string();
        if sig.schedule_hint.is_empty() {
            sig.schedule_hint = projection.schedule_hint_label.clone();
            if sig.schedule_hint.is_empty() {
                sig.schedule_hint = "ordered".into();
            }
        }

        let pool = match self.pools.get(pool_name) {
            Some(p) => p,
            None => {
                emit_access_log(&sig, "mesh_bus.resolver.open");
                return Err((ResolveError::PoolNotFound(pool_name.to_string()), sig));
            }
        };

        match &pool.mode {
            PoolMode::SystemMode => {
                let result = resolve_system(&req.qname, req.qtype).await;
                sig.winner_exit = WinnerExit::System;
                match result {
                    Ok(mut a) => {
                        a.source = ResolverSource::System;
                        sig.resolver_rtt_ms = a.rtt.as_millis() as u64;
                        sig.answer_count = a.records.len() as u32;
                        sig.truncated = a.truncated;
                        if let Some(c) = &cache_for_write {
                            let ttl = Duration::from_secs(a.min_rr_ttl.max(1) as u64);
                            c.put_positive(
                                crate::cache::CacheKey {
                                    qname: qname_lower.clone(),
                                    qtype: req.qtype,
                                },
                                a.records.clone(),
                                ttl,
                            );
                        }
                        emit_access_log(&sig, "mesh_bus.resolver.open");
                        Ok((a, sig))
                    }
                    Err(e) => {
                        emit_access_log(&sig, "mesh_bus.resolver.open");
                        Err((e, sig))
                    }
                }
            }
            PoolMode::MeshDirect { server_policy } => {
                let opener = match self.opener.as_ref() {
                    Some(o) => o.clone(),
                    None => {
                        emit_access_log(&sig, "mesh_bus.resolver.open");
                        return Err((
                            ResolveError::Io(
                                "MeshDirect pool requires DatagramOpener (use ResolverBuilder::with_datagram_opener)".into(),
                            ),
                            sig,
                        ));
                    }
                };
                let counter = self
                    .rr_counters
                    .get(pool_name)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
                let route_group = projection.route_group.as_deref();
                let result = resolve_mesh_direct(
                    opener.as_ref(),
                    pool_name,
                    server_policy,
                    &counter,
                    &pool.servers,
                    route_group,
                    &req.qname,
                    req.qtype,
                    self.query_timeout,
                )
                .await;
                let cache_key = crate::cache::CacheKey {
                    qname: qname_lower.clone(),
                    qtype: req.qtype,
                };
                apply_m2_result(result, sig, cache_for_write.as_deref(), cache_key)
            }
            PoolMode::Tunneled { server_policy } => {
                let opener = match self.stream_opener.as_ref() {
                    Some(o) => o.clone(),
                    None => {
                        emit_access_log(&sig, "mesh_bus.resolver.open");
                        return Err((
                            ResolveError::Io(
                                "Tunneled pool requires StreamOpener (use ResolverBuilder::with_stream_opener)".into(),
                            ),
                            sig,
                        ));
                    }
                };
                let counter = self
                    .rr_counters
                    .get(pool_name)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
                let route_group = projection.route_group.as_deref();
                let result = resolve_tunneled(
                    opener.as_ref(),
                    self.conn_cache.as_ref(),
                    pool_name,
                    server_policy,
                    &counter,
                    &pool.servers,
                    route_group,
                    &req.qname,
                    req.qtype,
                    self.query_timeout,
                )
                .await;
                let cache_key = crate::cache::CacheKey {
                    qname: qname_lower.clone(),
                    qtype: req.qtype,
                };
                apply_m1_result(result, sig, cache_for_write.as_deref(), cache_key)
            }
        }
    }
}

/// Populate signals from an M2 result and emit the access log.
#[allow(clippy::result_large_err)]
fn apply_m2_result(
    result: Result<(ResolveAnswer, M2Telemetry), ResolveError>,
    sig: ResolutionSignals,
    cache: Option<&crate::cache::DnsCache>,
    cache_key: crate::cache::CacheKey,
) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
    let result = result.map(|(a, t)| {
        (
            a,
            TelemetryCommon {
                winner: t.winner,
                losers: t.losers,
                attempted: t.attempted,
                rtt_ms: t.rtt_ms,
                truncated: t.truncated,
                answer_count: t.answer_count,
            },
        )
    });
    apply_telemetry(result, sig, cache, cache_key, |w| {
        ResolverSource::MeshDirect { server: w }
    })
}

/// Populate signals from an M1 result and emit the access log.
#[allow(clippy::result_large_err)]
fn apply_m1_result(
    result: Result<(ResolveAnswer, M1Telemetry), ResolveError>,
    sig: ResolutionSignals,
    cache: Option<&crate::cache::DnsCache>,
    cache_key: crate::cache::CacheKey,
) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
    let result = result.map(|(a, t)| {
        (
            a,
            TelemetryCommon {
                winner: t.winner,
                losers: t.losers,
                attempted: t.attempted,
                rtt_ms: t.rtt_ms,
                truncated: t.truncated,
                answer_count: t.answer_count,
            },
        )
    });
    apply_telemetry(result, sig, cache, cache_key, |w| {
        ResolverSource::Tunneled { server: w }
    })
}

struct TelemetryCommon {
    winner: std::net::SocketAddr,
    losers: Vec<std::net::SocketAddr>,
    attempted: u32,
    rtt_ms: u64,
    truncated: bool,
    answer_count: u32,
}

#[allow(clippy::result_large_err)]
fn apply_telemetry(
    result: Result<(ResolveAnswer, TelemetryCommon), ResolveError>,
    mut sig: ResolutionSignals,
    cache: Option<&crate::cache::DnsCache>,
    cache_key: crate::cache::CacheKey,
    source_of: impl FnOnce(std::net::SocketAddr) -> ResolverSource,
) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
    match result {
        Ok((mut answer, tel)) => {
            answer.source = source_of(tel.winner);
            sig.resolver_rtt_ms = tel.rtt_ms;
            sig.answer_count = tel.answer_count;
            sig.truncated = tel.truncated;
            sig.attempted = tel.attempted;
            sig.winner_exit = if tel.losers.is_empty() {
                WinnerExit::SinglePath { server: tel.winner }
            } else {
                WinnerExit::FanOut {
                    winner: tel.winner,
                    losers: tel.losers,
                }
            };
            if let Some(c) = cache {
                let ttl = Duration::from_secs(answer.min_rr_ttl.max(1) as u64);
                c.put_positive(cache_key, answer.records.clone(), ttl);
            }
            emit_access_log(&sig, "mesh_bus.resolver.open");
            Ok((answer, sig))
        }
        Err(e) => {
            emit_access_log(&sig, "mesh_bus.resolver.open");
            Err((e, sig))
        }
    }
}
