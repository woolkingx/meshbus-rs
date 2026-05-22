//! Runtime: assembles the bus from config and spawns ingress listeners.
//!
//! Config schema + parse/validate live in `config`. This module owns the
//! plugin wiring + the async `run()` entry point that bridges config into
//! the live bus.

mod config;
mod config_validate;
mod pipeline;

pub use config::{
    AuthCfg, AuthUserCfg, Config, DnsCacheCfg, EgressCfg, GeoIpCfg, GeositeCfg, HealthCfg,
    IngressCfg, LoadBalanceModeCfg, LogFormat, LoggingCfg, MeshSecPeerCfg, MeshSecProfileCfg,
    MetricsCfg, NodeCfg, OperatorAuthCfg, OperatorCfg, PeerCfg, PipelineCfg, PipelineSourceCfg,
    SchedulerCfg, Socks5UpstreamAuthCfg, TrafficClassCfg, parse_config, validate_config,
};
pub use pipeline::{build_pipeline_runtime, selected_pipeline_source_index};

use anyhow::anyhow;
use mb_endpoint::Endpoint;
use mb_socket_tune::SocketBufferConfig;
use mesh_bus_core::ExitId;
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use mesh_bus_core::{BusBuilder, BusHandle, IngressPlugin};
use mesh_bus_egress_mesh_peer_udp::MeshPeerUdpEgress;
use mesh_bus_egress_service::{ServiceTcpEgress, ServiceUdpEgress};
use mesh_bus_egress_socks5::{Socks5Egress, Socks5UdpEgress, Socks5UpstreamAuth};
use mesh_bus_egress_tcp::TcpEgress;
use mesh_bus_egress_udp::UdpEgress;
use mesh_bus_ingress_http_connect::{BasicAuth, HttpConnectIngress};
use mesh_bus_ingress_mesh_peer_udp::MeshPeerUdpIngress;
use mesh_bus_ingress_socks5::Socks5Ingress;
use mesh_bus_ingress_tcp::TcpIngress;
use mesh_bus_ingress_udp::UdpIngress;
use mesh_bus_observer_metrics::CounterObserver;
use mesh_bus_observer_prometheus::PrometheusTextfileObserver;
use mesh_bus_scheduler_cake::CakeScheduler;
use mesh_bus_scheduler_loadbalance::LoadBalanceScheduler;
use mesh_bus_scheduler_replicate::ReplicateScheduler;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpListener;

pub fn validate_legacy_rule_policy_actions(chain: &mb_rule::RuleChain) -> anyhow::Result<()> {
    mesh_bus_ingress_socks5::validate_rule_policy_actions(chain).map_err(|e| anyhow!("{e}"))
}

/// Run config-file preflight checks that require the operator config
/// directory. This is the shared owner path for CLI `check` and Operator API
/// config-check.
pub fn preflight_config(cfg: &Config, base_dir: &Path) -> anyhow::Result<()> {
    validate_rule_chains(cfg, base_dir)?;
    if cfg.pipeline.is_some() {
        build_pipeline_runtime(cfg, base_dir).map_err(|e| anyhow!("pipeline check: {e}"))?;
    }
    Ok(())
}

pub fn status_text(cfg: &Config) -> String {
    let mut text = format!(
        "scheduler={} ingresses={} egresses={} logging={}/{} metrics={}",
        cfg.scheduler.name(),
        cfg.ingresses.len(),
        cfg.egresses.len(),
        cfg.logging.level,
        cfg.logging.format.name(),
        cfg.metrics.as_ref().map(MetricsCfg::name).unwrap_or("none")
    );
    for egress in &cfg.egresses {
        text.push_str(&format!(
            "\nexit={} wan={} priority={} send_count=0 success_count=0 failure_count=0 last_rtt_ms=0 payload_bytes_total=0",
            egress.id(),
            egress.wan_id(),
            egress.priority()
        ));
    }
    text
}

fn resolve_config_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn validate_rule_chains(cfg: &Config, base_dir: &Path) -> anyhow::Result<()> {
    let pipeline_source_index = selected_pipeline_source_index(cfg)?;
    for (idx, ingress) in cfg.ingresses.iter().enumerate() {
        if pipeline_source_index == Some(idx) {
            continue;
        }
        if let IngressCfg::Socks5 {
            rule_chain_path: Some(path),
            ..
        } = ingress
        {
            let p = resolve_config_path(base_dir, Path::new(path));
            if !p.exists() {
                return Err(anyhow!("rule_chain_path not found: {}", p.display()));
            }
            let body = std::fs::read_to_string(&p)
                .map_err(|e| anyhow!("read rule_chain_path {}: {e}", p.display()))?;
            let (chain, mut rulesets) = mb_rule::parse_chain_and_rulesets_yaml(&body)
                .map_err(|e| anyhow!("parse rule_chain {}: {e:?}", p.display()))?;
            mb_rule::validate(&chain, &rulesets)
                .map_err(|e| anyhow!("validate rule_chain {}: {e}", p.display()))?;
            validate_legacy_rule_policy_actions(&chain)
                .map_err(|e| anyhow!("validate legacy RulePolicy {}: {e}", p.display()))?;
            if let Some(chain_dir) = p.parent() {
                for rs in &mut rulesets {
                    if let mb_rule::types::RulesetSource::Local { path } = &mut rs.source {
                        if path.is_relative() {
                            *path = chain_dir.join(&*path);
                        }
                    }
                }
            }
            mb_rule::RuleSetRegistry::load(&rulesets)
                .map_err(|e| anyhow!("load rule_sets {}: {e:?}", p.display()))?;
        }
    }
    Ok(())
}

/// Assemble and start the Bus from config, spawn all ingress listeners.
/// Returns a [`BusHandle`] the caller uses to shut down.
///
/// `base_dir` is the directory holding the operator YAML file; relative
/// paths in `pipeline:` and legacy `ingress.rule_chain_path` resolve
/// against it.
pub async fn run(cfg: Config, base_dir: &Path) -> anyhow::Result<BusHandle> {
    let pipeline_source_index = pipeline::selected_pipeline_source_index(&cfg)?;
    let pipeline_runtime = if cfg.pipeline.is_some() {
        let rt = build_pipeline_runtime(&cfg, base_dir)?;
        tracing::info!(
            target: "mesh_bus.runtime",
            "pipeline_runtime_attached"
        );
        Some(rt)
    } else {
        None
    };
    let weights = egress_weights(&cfg.egresses);
    let wan_labels = egress_wan_labels(&cfg.egresses);
    let peer_labels = egress_peer_labels(cfg.node.as_ref(), &cfg.egresses);
    let meshsec_boot_salt: [u8; 4] = rand::random();
    let meshsec_open_keys = cfg.meshsec_open_keys();
    let meshsec_local_node_id = cfg.node.as_ref().map(|n| n.id.clone());
    let meshsec_seal_contexts: std::collections::HashMap<
        String,
        mb_proto_mesh::MeshSecSealContext,
    > = cfg
        .peers
        .iter()
        .filter_map(|p| {
            cfg.meshsec_seal_context(&p.id, meshsec_boot_salt)
                .map(|c| (p.id.clone(), c))
        })
        .collect();
    let scheduler: Box<dyn mesh_bus_core::SchedulerPlugin> = match cfg.scheduler {
        SchedulerCfg::Cake { .. } => Box::new(CakeScheduler::new()),
        SchedulerCfg::Replicate { .. } => Box::new(ReplicateScheduler::new()),
        SchedulerCfg::LoadBalance {
            mode,
            sticky_ttl_secs,
        } => Box::new(
            LoadBalanceScheduler::with_sticky_ttl_ms(
                mode.into(),
                sticky_ttl_secs.saturating_mul(1_000),
            )
            .with_weights(weights),
        ),
    };
    let mut builder = BusBuilder::new()
        .scheduler(scheduler)
        .health_policy(cfg.health.into())
        .add_observer(Box::new(CounterObserver::new()));
    if let Some(metrics) = cfg.metrics {
        match metrics {
            MetricsCfg::PrometheusTextfile { path, labels } => {
                builder = builder.add_observer(Box::new(
                    PrometheusTextfileObserver::new(path)
                        .with_wan_labels(wan_labels)
                        .with_peer_labels(peer_labels)
                        .with_static_labels(labels),
                ));
            }
            MetricsCfg::PrometheusHttp { listen, labels } => {
                let listener = TcpListener::bind(&listen)
                    .await
                    .map_err(|e| anyhow!("bind metrics {listen}: {e}"))?;
                let observer = PrometheusTextfileObserver::http()
                    .with_wan_labels(wan_labels)
                    .with_peer_labels(peer_labels)
                    .with_static_labels(labels);
                tokio::spawn(observer.clone().serve_http(listener));
                builder = builder.add_observer(Box::new(observer));
            }
        }
    }

    for e in &cfg.egresses {
        match e {
            EgressCfg::Tcp {
                id,
                groups,
                timeout_ms,
                socket_recv_buffer_bytes,
                socket_send_buffer_bytes,
                ..
            } => {
                builder = builder.add_stream_egress(Box::new(
                    TcpEgress::new(ExitId(id.clone()), Duration::from_millis(*timeout_ms))
                        .with_groups(groups.clone())
                        .with_socket_buffers(SocketBufferConfig::new(
                            *socket_recv_buffer_bytes,
                            *socket_send_buffer_bytes,
                        )),
                ));
            }
            EgressCfg::Socks5 {
                id,
                upstream,
                groups,
                timeout_ms,
                ..
            } => {
                builder = builder.add_stream_egress(Box::new(
                    Socks5Egress::new(
                        ExitId(id.clone()),
                        upstream.clone(),
                        Duration::from_millis(*timeout_ms),
                    )
                    .with_groups(groups.clone()),
                ));
            }
            EgressCfg::Udp {
                id,
                groups,
                timeout_ms,
                socket_recv_buffer_bytes,
                socket_send_buffer_bytes,
                ..
            } => {
                builder = builder.add_datagram_egress(Box::new(
                    UdpEgress::new(ExitId(id.clone()), Duration::from_millis(*timeout_ms))
                        .with_groups(groups.clone())
                        .with_socket_buffers(SocketBufferConfig::new(
                            *socket_recv_buffer_bytes,
                            *socket_send_buffer_bytes,
                        )),
                ));
            }
            EgressCfg::Socks5Udp {
                id,
                upstream,
                groups,
                timeout_ms,
                auth,
                ..
            } => {
                let mut egress = Socks5UdpEgress::new(
                    ExitId(id.clone()),
                    upstream.clone(),
                    Duration::from_millis(*timeout_ms),
                )
                .with_groups(groups.clone());
                if let Some(auth) = auth {
                    egress = egress.with_auth(Socks5UpstreamAuth {
                        username: auth.username.clone().into_bytes(),
                        password: auth.password.clone().into_bytes(),
                    });
                }
                builder = builder.add_datagram_egress(Box::new(egress));
            }
            EgressCfg::MeshPeerUdp {
                id,
                peer_id,
                peer,
                groups,
                timeout_ms,
                ..
            } => {
                let peer_addr = parse_socket_addr(peer)?;
                let mut egress = MeshPeerUdpEgress::new(
                    ExitId(id.clone()),
                    peer_addr,
                    Duration::from_millis(*timeout_ms),
                )
                .with_groups(groups.clone())
                .with_native_event_mode(e.native_event_mode());
                let (mode, fanout, probe_budget) = e.delivery_policy();
                egress = egress.with_delivery_policy(mode, fanout, probe_budget);
                if let Some(ctx) = meshsec_seal_contexts.get(peer_id) {
                    egress = egress.with_meshsec(ctx.clone());
                }
                builder = builder.add_stream_egress(Box::new(egress.clone().as_stream_adapter()));
                builder = builder.add_datagram_egress(Box::new(egress.as_datagram_adapter()));
            }
            EgressCfg::ServiceTcp {
                id,
                service_id,
                groups,
                connect,
                timeout_ms,
                ..
            } => {
                let connect_ep = _parse_endpoint(connect)?;
                builder = builder.add_stream_egress(Box::new(
                    ServiceTcpEgress::new(
                        ExitId(id.clone()),
                        service_id.clone(),
                        connect_ep,
                        Duration::from_millis(*timeout_ms),
                    )
                    .with_groups(groups.clone()),
                ));
            }
            EgressCfg::ServiceUdp {
                id,
                service_id,
                groups,
                connect,
                timeout_ms,
                socket_recv_buffer_bytes,
                socket_send_buffer_bytes,
                ..
            } => {
                let connect_ep = _parse_endpoint(connect)?;
                builder = builder.add_datagram_egress(Box::new(
                    ServiceUdpEgress::new(
                        ExitId(id.clone()),
                        service_id.clone(),
                        connect_ep,
                        Duration::from_millis(*timeout_ms),
                    )
                    .with_groups(groups.clone())
                    .with_socket_buffers(SocketBufferConfig::new(
                        *socket_recv_buffer_bytes,
                        *socket_send_buffer_bytes,
                    )),
                ));
            }
        }
    }

    let bus = builder
        .try_build()
        .await
        .map_err(|e| anyhow!("bus build: {e:?}"))?;
    let port = bus.port();
    let handle = bus.spawn();

    for (ingress_idx, i) in cfg.ingresses.into_iter().enumerate() {
        let port = port.clone();
        match i {
            IngressCfg::Socks5 {
                listen,
                rule_chain_path,
                auth,
                handshake_timeout_ms,
                accept_backoff_ms,
                max_connections,
                udp_forward_concurrency,
                socket_recv_buffer_bytes,
                socket_send_buffer_bytes,
            } => {
                let listener = TcpListener::bind(&listen)
                    .await
                    .map_err(|e| anyhow!("bind {listen}: {e}"))?;
                let mut ingress = Socks5Ingress::new(listener);
                if let Some(ms) = handshake_timeout_ms {
                    ingress = ingress.with_handshake_timeout(Duration::from_millis(ms));
                }
                if let Some(ms) = accept_backoff_ms {
                    ingress = ingress.with_accept_backoff(Duration::from_millis(ms));
                }
                if let Some(n) = max_connections {
                    ingress = ingress.with_max_connections(n);
                }
                if let Some(n) = udp_forward_concurrency {
                    ingress = ingress.with_udp_forward_concurrency(n);
                }
                ingress = ingress.with_socket_buffers(SocketBufferConfig::new(
                    socket_recv_buffer_bytes,
                    socket_send_buffer_bytes,
                ));
                if let Some(auth_cfg) = auth {
                    let mut ac = mesh_bus_ingress_socks5::AuthConfig::new();
                    for u in &auth_cfg.users {
                        ac.insert(u.name.clone(), u.password.clone());
                    }
                    let user_count = auth_cfg.users.len();
                    ingress = ingress.with_auth(ac);
                    tracing::info!(
                        target: "mesh_bus.runtime",
                        users = user_count,
                        "socks5_auth_enabled"
                    );
                }
                if pipeline_source_index == Some(ingress_idx) {
                    let rt = pipeline_runtime.clone().ok_or_else(|| {
                        anyhow!("pipeline source index selected but pipeline runtime is missing")
                    })?;
                    if rule_chain_path.is_some() {
                        tracing::info!(
                            target: "mesh_bus.runtime",
                            "pipeline_runtime_supersedes_ingress_rule_chain_path"
                        );
                    }
                    ingress = ingress.with_pipeline(rt);
                } else if let Some(path) = rule_chain_path {
                    let chain_path = resolve_config_path(base_dir, Path::new(&path));
                    let body = std::fs::read_to_string(&chain_path).map_err(|e| {
                        anyhow!("read rule_chain_path {}: {e}", chain_path.display())
                    })?;
                    let (chain, mut rulesets) = mb_rule::parse_chain_and_rulesets_yaml(&body)
                        .map_err(|e| anyhow!("parse rule_chain {}: {e:?}", chain_path.display()))?;
                    mb_rule::validate(&chain, &rulesets).map_err(|e| {
                        anyhow!("validate rule_chain {}: {e}", chain_path.display())
                    })?;
                    validate_legacy_rule_policy_actions(&chain).map_err(|e| {
                        anyhow!("validate legacy RulePolicy {}: {e}", chain_path.display())
                    })?;
                    let chain_dir = chain_path.parent().map(PathBuf::from);
                    if let Some(base) = chain_dir.as_deref() {
                        for rs in &mut rulesets {
                            if let mb_rule::types::RulesetSource::Local { path: p } = &mut rs.source
                            {
                                if p.is_relative() {
                                    *p = base.join(&*p);
                                }
                            }
                        }
                    }
                    let registry = mb_rule::RuleSetRegistry::load(&rulesets)
                        .map_err(|e| anyhow!("load rule_sets {}: {e:?}", chain_path.display()))?;
                    let policy = mesh_bus_ingress_socks5::RulePolicy::new(chain, registry);
                    ingress = ingress.with_rule_policy(policy);
                    tracing::info!(
                        target: "mesh_bus.runtime",
                        path = %chain_path.display(),
                        rule_sets = rulesets.len(),
                        "socks5_rule_chain_loaded"
                    );
                }
                let plugin: Box<dyn IngressPlugin> = Box::new(ingress);
                tokio::spawn(async move {
                    let _ = plugin.run(port).await;
                });
            }
            IngressCfg::Tcp {
                listen,
                target,
                socket_recv_buffer_bytes,
                socket_send_buffer_bytes,
                ..
            } => {
                let listener = TcpListener::bind(&listen)
                    .await
                    .map_err(|e| anyhow!("bind {listen}: {e}"))?;
                let ep = _parse_endpoint(&target)?;
                let mut ingress = TcpIngress::new(listener, ep).with_socket_buffers(
                    SocketBufferConfig::new(socket_recv_buffer_bytes, socket_send_buffer_bytes),
                );
                if pipeline_source_index == Some(ingress_idx) {
                    let rt = pipeline_runtime.clone().ok_or_else(|| {
                        anyhow!("pipeline source index selected but pipeline runtime is missing")
                    })?;
                    ingress = ingress.with_pipeline(rt);
                }
                let plugin: Box<dyn IngressPlugin> = Box::new(ingress);
                tokio::spawn(async move {
                    let _ = plugin.run(port).await;
                });
            }
            IngressCfg::HttpConnect {
                listen,
                auth,
                handshake_timeout_ms,
                max_header_bytes,
                max_connections,
                socket_recv_buffer_bytes,
                socket_send_buffer_bytes,
            } => {
                let listener = TcpListener::bind(&listen)
                    .await
                    .map_err(|e| anyhow!("bind {listen}: {e}"))?;
                let mut ingress = HttpConnectIngress::new(listener).with_socket_buffers(
                    SocketBufferConfig::new(socket_recv_buffer_bytes, socket_send_buffer_bytes),
                );
                if let Some(ms) = handshake_timeout_ms {
                    ingress = ingress.with_handshake_timeout(Duration::from_millis(ms));
                }
                if let Some(n) = max_header_bytes {
                    ingress = ingress.with_max_header_bytes(n);
                }
                if let Some(n) = max_connections {
                    ingress = ingress.with_max_connections(n);
                }
                if let Some(auth_cfg) = auth {
                    let mut basic = BasicAuth::new();
                    for u in &auth_cfg.users {
                        basic = basic.with_user(u.name.clone(), u.password.clone());
                    }
                    let user_count = auth_cfg.users.len();
                    ingress = ingress.with_auth_basic(basic);
                    tracing::info!(
                        target: "mesh_bus.runtime",
                        users = user_count,
                        "http_connect_auth_enabled"
                    );
                }
                if pipeline_source_index == Some(ingress_idx) {
                    let rt = pipeline_runtime.clone().ok_or_else(|| {
                        anyhow!("pipeline source index selected but pipeline runtime is missing")
                    })?;
                    ingress = ingress.with_pipeline(rt);
                }
                let plugin: Box<dyn IngressPlugin> = Box::new(ingress);
                tokio::spawn(async move {
                    let _ = plugin.run(port).await;
                });
            }
            IngressCfg::Udp {
                listen,
                target,
                socket_recv_buffer_bytes,
                socket_send_buffer_bytes,
                ..
            } => {
                let socket = tokio::net::UdpSocket::bind(&listen)
                    .await
                    .map_err(|e| anyhow!("bind {listen}: {e}"))?;
                let ep = _parse_endpoint(&target)?;
                let mut ingress = UdpIngress::new(socket, ep).with_socket_buffers(
                    SocketBufferConfig::new(socket_recv_buffer_bytes, socket_send_buffer_bytes),
                );
                if pipeline_source_index == Some(ingress_idx) {
                    let rt = pipeline_runtime.clone().ok_or_else(|| {
                        anyhow!("pipeline source index selected but pipeline runtime is missing")
                    })?;
                    ingress = ingress.with_pipeline(rt);
                }
                let plugin: Box<dyn IngressPlugin> = Box::new(ingress);
                tokio::spawn(async move {
                    let _ = plugin.run(port).await;
                });
            }
            IngressCfg::MeshPeerUdp {
                listen,
                native_event_mode,
            } => {
                let packet_loop = UdpPacketLoop::bind(parse_socket_addr(&listen)?)
                    .await
                    .map_err(|e| anyhow!("bind mesh peer udp {listen}: {e}"))?;
                let mut ingress = MeshPeerUdpIngress::new(packet_loop)
                    .with_native_event_mode(native_event_mode.to_proto());
                if let Some(node_id) = &meshsec_local_node_id {
                    if !meshsec_open_keys.is_empty() {
                        ingress =
                            ingress.with_meshsec_keys(node_id.clone(), meshsec_open_keys.clone());
                    }
                }
                let plugin: Box<dyn IngressPlugin> = Box::new(ingress);
                tokio::spawn(async move {
                    let _ = plugin.run(port).await;
                });
            }
        }
    }

    Ok(handle)
}

fn egress_weights(egresses: &[EgressCfg]) -> HashMap<String, u32> {
    egresses
        .iter()
        .map(|egress| (egress.id().to_string(), egress.priority()))
        .collect()
}

fn egress_wan_labels(egresses: &[EgressCfg]) -> HashMap<String, String> {
    egresses
        .iter()
        .map(|egress| (egress.id().to_string(), egress.wan_id().to_string()))
        .collect()
}

/// Static per-sink observability labels: node_id for every sink when node
/// config is present, plus peer_id/path_id/hop_count for configured
/// mesh-peer egress sinks (hop_count=1 for a direct adjacent peer).
pub fn egress_peer_labels(
    node: Option<&NodeCfg>,
    egresses: &[EgressCfg],
) -> HashMap<String, BTreeMap<String, String>> {
    let node_id = node.map(|n| n.id.clone());
    egresses
        .iter()
        .filter_map(|egress| {
            let mut m = BTreeMap::new();
            if let Some(nid) = &node_id {
                m.insert("node_id".to_string(), nid.clone());
            }
            if let Some(peer_id) = egress.peer_id() {
                m.insert("peer_id".to_string(), peer_id.to_string());
                m.insert("path_id".to_string(), egress.id().to_string());
                m.insert("hop_count".to_string(), "1".to_string());
            }
            (!m.is_empty()).then(|| (egress.id().to_string(), m))
        })
        .collect()
}

fn _parse_endpoint(s: &str) -> anyhow::Result<Endpoint> {
    Endpoint::parse(s).map_err(|e| anyhow!("bad endpoint {s}: {e}"))
}

fn parse_socket_addr(s: &str) -> anyhow::Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .map_err(|e| anyhow!("bad socket addr {s}: {e}"))
}
