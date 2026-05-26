use crate::config::{
    Config, EgressCfg, IngressCfg, MeshSecKeyRoleCfg, MetricsCfg, OperatorAuthCfg, OperatorCfg,
    PeerCfg, SchedulerCfg,
};
use anyhow::anyhow;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;

const METADATA_NAMESPACES: &[&str] = &["net", "transport", "policy", "auth", "trace", "ext"];

pub fn validate_config(cfg: &Config) -> anyhow::Result<()> {
    if cfg.ingresses.is_empty() {
        return Err(anyhow!("at least one ingress is required"));
    }
    if cfg.egresses.is_empty() {
        return Err(anyhow!("at least one egress is required"));
    }
    validate_logging(cfg)?;
    validate_health(cfg)?;
    validate_scheduler(cfg)?;
    validate_metrics(cfg)?;
    validate_operator(cfg)?;
    validate_mesh_identity(cfg)?;
    validate_meshsec_peer_uniqueness(cfg)?;
    for ingress in &cfg.ingresses {
        validate_ingress(ingress)?;
    }
    validate_mesh_peer_udp_wan_requires_meshsec(cfg)?;
    let mut ids = HashSet::new();
    for egress in &cfg.egresses {
        let id = egress.id();
        if id.is_empty() {
            return Err(anyhow!("egress id must not be empty"));
        }
        reject_invalid_id_shape(id, "egress id", "SinkId")?;
        validate_egress(egress, id)?;
        if !ids.insert(id) {
            return Err(anyhow!("duplicate egress id: {id}"));
        }
        if egress.raw_priority() == 0 {
            return Err(anyhow!("egress {id} priority must be >= 1"));
        }
        if egress.timeout_ms() == 0 {
            return Err(anyhow!("egress {id} timeout_ms must be >= 1"));
        }
    }
    if matches!(cfg.scheduler, SchedulerCfg::Replicate { .. }) && cfg.egresses.len() < 2 {
        tracing::warn!("scheduler=Replicate has fewer than two egresses; fan-out is single-path");
    }
    if let Some(pipeline) = &cfg.pipeline {
        reject_empty_path(
            pipeline.rule_chain_path.as_deref(),
            "pipeline rule_chain_path",
        )?;
        reject_empty_path(
            pipeline.rule_chain_forward.as_deref(),
            "pipeline rule_chain_forward",
        )?;
        reject_empty_path(
            pipeline.rule_chain_resolver.as_deref(),
            "pipeline rule_chain_resolver",
        )?;
        if let Some(geoip) = &pipeline.geoip {
            reject_empty_path(geoip.country_path.as_deref(), "pipeline geoip.country_path")?;
            reject_empty_path(geoip.asn_path.as_deref(), "pipeline geoip.asn_path")?;
            if geoip.country_path.is_none() || geoip.asn_path.is_none() {
                return Err(anyhow!(
                    "pipeline geoip requires both country_path and asn_path"
                ));
            }
        }
        if let Some(geosite) = &pipeline.geosite {
            reject_empty_path(geosite.path.as_deref(), "pipeline geosite.path")?;
            if geosite.path.is_none() {
                return Err(anyhow!("pipeline geosite.path is required"));
            }
        }
        reject_empty_str(pipeline.source.id.as_deref(), "pipeline source id")?;
        if let Some(id) = &pipeline.source.id {
            reject_invalid_id_shape(id, "pipeline source id", "SourceId")?;
        }
        reject_empty_str(Some(&pipeline.source.kind), "pipeline source kind")?;
        if pipeline.source.kind != "application/source" {
            return Err(anyhow!(
                "pipeline source kind must be application/source, got {}",
                pipeline.source.kind
            ));
        }
        if pipeline.forward_rule_chain_path().is_none() {
            return Err(anyhow!(
                "pipeline requires rule_chain_forward or legacy rule_chain_path"
            ));
        }
        if let Some(idx) = pipeline.source.ingress_index {
            let ingress = cfg
                .ingresses
                .get(idx)
                .ok_or_else(|| anyhow!("pipeline source ingress_index {idx} is out of range"))?;
            if ingress.pipeline_source_kind() != Some(pipeline.source.kind.as_str()) {
                return Err(anyhow!(
                    "pipeline source ingress_index {idx} does not declare pipeline source kind {}",
                    pipeline.source.kind
                ));
            }
        } else {
            let matches = cfg
                .ingresses
                .iter()
                .filter(|ingress| {
                    ingress.pipeline_source_kind() == Some(pipeline.source.kind.as_str())
                })
                .count();
            match matches {
                0 => {
                    return Err(anyhow!(
                        "pipeline requires at least one ingress declaring pipeline source kind {}",
                        pipeline.source.kind
                    ));
                }
                1 => {}
                _ => {
                    return Err(anyhow!(
                        "pipeline source ingress_index is required when multiple ingresses declare pipeline source kind {}",
                        pipeline.source.kind
                    ));
                }
            }
        }
        for key in &pipeline.source.initial_writes {
            if !is_metadata_key(key) {
                return Err(anyhow!(
                    "pipeline source initial_writes contains invalid metadata key `{key}`"
                ));
            }
            let head = key.split('.').next().unwrap_or("");
            if matches!(head, "policy" | "transport") {
                return Err(anyhow!(
                    "pipeline source initial_writes `{key}` targets reserved lower-layer namespace `{head}`; per docs/handbook/spec/data-ontology.schema.json#metadata_namespace_ownership only net|auth|trace|ext are operator-writable at ingress (source_initial_writes_allowed=true)"
                ));
            }
        }
    }
    Ok(())
}

fn validate_mesh_identity(cfg: &Config) -> anyhow::Result<()> {
    if let Some(node) = &cfg.node {
        reject_empty_str(Some(&node.id), "node id")?;
        reject_invalid_id_shape(&node.id, "node id", "NodeId")?;
    }
    let mut peer_ids = HashSet::new();
    let mut peer_node_ids = HashSet::new();
    for peer in &cfg.peers {
        reject_empty_str(Some(&peer.id), "peer id")?;
        reject_empty_str(Some(&peer.node_id), "peer node_id")?;
        reject_invalid_id_shape(&peer.id, "peer id", "PeerId")?;
        reject_invalid_id_shape(&peer.node_id, "peer node_id", "NodeId")?;
        if !peer_ids.insert(peer.id.as_str()) {
            return Err(anyhow!("duplicate peer id: {}", peer.id));
        }
        if cfg
            .node
            .as_ref()
            .is_some_and(|node| node.id == peer.node_id)
        {
            return Err(anyhow!("duplicate node_id: {}", peer.node_id));
        }
        if !peer_node_ids.insert(peer.node_id.as_str()) {
            return Err(anyhow!("duplicate node_id: {}", peer.node_id));
        }
        if peer.route_groups.iter().any(|group| group.is_empty()) {
            return Err(anyhow!(
                "peer {} route_groups contains empty label",
                peer.id
            ));
        }
        if peer.meshsec.is_some() {
            if cfg.node.is_none() {
                return Err(anyhow!(
                    "peer {} has meshsec but top-level node.id is missing",
                    peer.id
                ));
            }
            validate_meshsec_keys(peer)?;
        }
    }
    for egress in &cfg.egresses {
        let Some(peer_id) = egress.peer_id() else {
            continue;
        };
        let peer = cfg
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .ok_or_else(|| {
                anyhow!(
                    "egress {} references unknown peer_id {peer_id}",
                    egress.id()
                )
            })?;
        validate_peer_route_groups(egress, peer)?;
    }
    Ok(())
}

fn validate_meshsec_keys(peer: &PeerCfg) -> anyhow::Result<()> {
    let meshsec = peer.meshsec.as_ref().expect("caller checked meshsec");
    match (&meshsec.static_key_hex, meshsec.keyring.is_empty()) {
        (Some(hex), true) => {
            validate_meshsec_hex(peer, "static_key_hex", hex)?;
            Ok(())
        }
        (None, false) => validate_meshsec_keyring(peer),
        (Some(_), false) => Err(anyhow!(
            "peer {} meshsec must use either static_key_hex or keyring, not both",
            peer.id
        )),
        (None, true) => Err(anyhow!(
            "peer {} meshsec requires static_key_hex or keyring",
            peer.id
        )),
    }
}

fn validate_meshsec_keyring(peer: &PeerCfg) -> anyhow::Result<()> {
    let meshsec = peer.meshsec.as_ref().expect("caller checked meshsec");
    let Some(active_key_id) = meshsec.active_key_id.as_ref() else {
        return Err(anyhow!(
            "peer {} meshsec keyring requires active_key_id",
            peer.id
        ));
    };
    if active_key_id.is_empty() {
        return Err(anyhow!(
            "peer {} meshsec active_key_id must not be empty",
            peer.id
        ));
    }
    let mut ids = std::collections::HashSet::new();
    let mut active_found = false;
    for key in &meshsec.keyring {
        if key.id.is_empty() {
            return Err(anyhow!("peer {} meshsec key id must not be empty", peer.id));
        }
        if !ids.insert(key.id.as_str()) {
            return Err(anyhow!(
                "peer {} meshsec keyring duplicate key id {}",
                peer.id,
                key.id
            ));
        }
        validate_meshsec_hex(
            peer,
            &format!("keyring[{}].static_key_hex", key.id),
            &key.static_key_hex,
        )?;
        if key.id == *active_key_id {
            if !matches!(key.role, MeshSecKeyRoleCfg::Active) {
                return Err(anyhow!(
                    "peer {} meshsec active_key_id {} must reference a key with role active",
                    peer.id,
                    active_key_id
                ));
            }
            active_found = true;
        }
    }
    if !active_found {
        return Err(anyhow!(
            "peer {} meshsec active_key_id {} is not present in keyring",
            peer.id,
            active_key_id
        ));
    }
    Ok(())
}

fn validate_meshsec_hex(peer: &PeerCfg, field: &str, hex: &str) -> anyhow::Result<()> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "peer {} meshsec {field} must be exactly 64 hex characters",
            peer.id
        ));
    }
    Ok(())
}

fn validate_meshsec_peer_uniqueness(cfg: &Config) -> anyhow::Result<()> {
    let mut udp_egress_count: HashMap<&str, usize> = HashMap::new();
    for egress in &cfg.egresses {
        if let EgressCfg::MeshPeerUdp { peer_id, .. } = egress {
            *udp_egress_count.entry(peer_id.as_str()).or_insert(0) += 1;
        }
    }
    for peer in &cfg.peers {
        if peer.meshsec.is_none() {
            continue;
        }
        if udp_egress_count.get(peer.id.as_str()).copied().unwrap_or(0) >= 2 {
            return Err(anyhow!(
                "peer {} carries meshsec and is bound by more than one mesh_peer_udp egress; \
                 a shared MeshSec K_tx must not reuse a counter nonce across egresses (fail-closed)",
                peer.id
            ));
        }
    }
    Ok(())
}

fn validate_mesh_peer_udp_wan_requires_meshsec(cfg: &Config) -> anyhow::Result<()> {
    let has_meshsec_peer = cfg.peers.iter().any(|peer| peer.meshsec.is_some());
    for ingress in &cfg.ingresses {
        let IngressCfg::MeshPeerUdp { listen, .. } = ingress else {
            continue;
        };
        let addr = parse_mesh_peer_udp_listen(listen)?;
        if addr.ip().is_loopback() {
            continue;
        }
        if !has_meshsec_peer {
            return Err(anyhow!(
                "MeshPeerUdp ingress {listen} requires MeshSec when binding a non-loopback address; add peers[].meshsec or bind loopback for debug-clear"
            ));
        }
    }
    Ok(())
}

fn validate_peer_route_groups(egress: &EgressCfg, peer: &PeerCfg) -> anyhow::Result<()> {
    if peer.route_groups.is_empty() {
        return Ok(());
    }
    for group in egress.groups() {
        if !peer.route_groups.iter().any(|allowed| allowed == group) {
            return Err(anyhow!(
                "egress {} unknown peer route_group `{group}` for peer {}",
                egress.id(),
                peer.id
            ));
        }
    }
    Ok(())
}

fn parse_mesh_peer_udp_listen(listen: &str) -> anyhow::Result<SocketAddr> {
    listen
        .parse::<SocketAddr>()
        .map_err(|e| anyhow!("MeshPeerUdp ingress listen must be a socket address: {listen}: {e}"))
}

fn validate_logging(cfg: &Config) -> anyhow::Result<()> {
    match cfg.logging.level.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(anyhow!(
            "logging level must be one of trace, debug, info, warn, error"
        )),
    }
}

fn validate_metrics(cfg: &Config) -> anyhow::Result<()> {
    match &cfg.metrics {
        Some(MetricsCfg::PrometheusTextfile { path, labels }) => {
            reject_empty_str(Some(path), "metrics PrometheusTextfile path")?;
            validate_prometheus_label_names(labels.keys())
        }
        Some(MetricsCfg::PrometheusHttp { listen, labels }) => {
            reject_empty_str(Some(listen), "metrics PrometheusHttp listen")?;
            validate_prometheus_label_names(labels.keys())
        }
        None => Ok(()),
    }
}

fn validate_operator(cfg: &Config) -> anyhow::Result<()> {
    match &cfg.operator {
        Some(OperatorCfg::LocalHttp { listen, auth }) => {
            reject_empty_str(Some(listen), "operator LocalHttp listen")?;
            let addr: SocketAddr = listen.parse().map_err(|e| {
                anyhow!("operator LocalHttp listen must be a socket address: {listen}: {e}")
            })?;
            if !addr.ip().is_loopback() {
                return Err(anyhow!(
                    "operator LocalHttp listen must be loopback-only for M0, got {listen}"
                ));
            }
            if let Some(OperatorAuthCfg::BearerTokenFile { path }) = auth {
                if path.as_os_str().is_empty() {
                    return Err(anyhow!(
                        "operator LocalHttp auth BearerTokenFile path must not be empty"
                    ));
                }
            }
            Ok(())
        }
        None => Ok(()),
    }
}

fn validate_health(cfg: &Config) -> anyhow::Result<()> {
    if cfg.health.failure_threshold == 0 {
        return Err(anyhow!("health failure_threshold must be >= 1"));
    }
    if cfg.health.recovery_window_ms == 0 {
        return Err(anyhow!("health recovery_window_ms must be >= 1"));
    }
    if cfg.health.probe_after_ms == 0 {
        return Err(anyhow!("health probe_after_ms must be >= 1"));
    }
    Ok(())
}

fn validate_scheduler(cfg: &Config) -> anyhow::Result<()> {
    match cfg.scheduler {
        SchedulerCfg::LoadBalance {
            sticky_ttl_secs: 0, ..
        } => Err(anyhow!("scheduler sticky_ttl_secs must be >= 1")),
        SchedulerCfg::LoadBalance {
            source_lease_rotate,
            ..
        } if source_lease_rotate.idle_timeout_secs == 0 => Err(anyhow!(
            "scheduler source_lease_rotate idle_timeout_secs must be >= 1"
        )),
        SchedulerCfg::LoadBalance {
            source_lease_rotate,
            ..
        } if source_lease_rotate.max_age_secs == 0 => Err(anyhow!(
            "scheduler source_lease_rotate max_age_secs must be >= 1"
        )),
        _ => Ok(()),
    }
}

fn validate_ingress(ingress: &IngressCfg) -> anyhow::Result<()> {
    match ingress {
        IngressCfg::Socks5 {
            listen,
            handshake_timeout_ms,
            accept_backoff_ms,
            max_connections,
            udp_forward_concurrency,
            socket_recv_buffer_bytes,
            socket_send_buffer_bytes,
            ..
        } => {
            reject_empty_str(Some(listen), "Socks5 ingress listen")?;
            reject_zero(*handshake_timeout_ms, "Socks5 ingress handshake_timeout_ms")?;
            reject_zero(*accept_backoff_ms, "Socks5 ingress accept_backoff_ms")?;
            reject_zero(*max_connections, "Socks5 ingress max_connections")?;
            reject_zero(
                *udp_forward_concurrency,
                "Socks5 ingress udp_forward_concurrency",
            )?;
            reject_zero(
                *socket_recv_buffer_bytes,
                "Socks5 ingress socket_recv_buffer_bytes",
            )?;
            reject_zero(
                *socket_send_buffer_bytes,
                "Socks5 ingress socket_send_buffer_bytes",
            )?;
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
            reject_empty_str(Some(listen), "HttpConnect ingress listen")?;
            reject_zero(
                *handshake_timeout_ms,
                "HttpConnect ingress handshake_timeout_ms",
            )?;
            reject_zero(*max_header_bytes, "HttpConnect ingress max_header_bytes")?;
            reject_zero(*max_connections, "HttpConnect ingress max_connections")?;
            reject_zero(
                *socket_recv_buffer_bytes,
                "HttpConnect ingress socket_recv_buffer_bytes",
            )?;
            reject_zero(
                *socket_send_buffer_bytes,
                "HttpConnect ingress socket_send_buffer_bytes",
            )?;
            if let Some(auth) = auth {
                for user in &auth.users {
                    reject_empty_str(Some(&user.name), "HttpConnect ingress auth user name")?;
                    reject_empty_str(
                        Some(&user.password),
                        "HttpConnect ingress auth user password",
                    )?;
                }
            }
        }
        IngressCfg::Tcp {
            listen,
            target,
            route_group,
            traffic_class: _,
            deadline_ms,
            source_label,
            socket_recv_buffer_bytes,
            socket_send_buffer_bytes,
        } => {
            reject_empty_str(Some(listen), "Tcp ingress listen")?;
            reject_empty_str(Some(target), "Tcp ingress target")?;
            reject_empty_str(route_group.as_deref(), "Tcp ingress route_group")?;
            reject_empty_str(source_label.as_deref(), "Tcp ingress source_label")?;
            reject_zero(*deadline_ms, "Tcp ingress deadline_ms")?;
            reject_zero(
                *socket_recv_buffer_bytes,
                "Tcp ingress socket_recv_buffer_bytes",
            )?;
            reject_zero(
                *socket_send_buffer_bytes,
                "Tcp ingress socket_send_buffer_bytes",
            )?;
        }
        IngressCfg::Udp {
            listen,
            target,
            route_group,
            traffic_class: _,
            deadline_ms,
            source_label,
            socket_recv_buffer_bytes,
            socket_send_buffer_bytes,
        } => {
            reject_empty_str(Some(listen), "Udp ingress listen")?;
            reject_empty_str(Some(target), "Udp ingress target")?;
            reject_empty_str(route_group.as_deref(), "Udp ingress route_group")?;
            reject_empty_str(source_label.as_deref(), "Udp ingress source_label")?;
            reject_zero(*deadline_ms, "Udp ingress deadline_ms")?;
            reject_zero(
                *socket_recv_buffer_bytes,
                "Udp ingress socket_recv_buffer_bytes",
            )?;
            reject_zero(
                *socket_send_buffer_bytes,
                "Udp ingress socket_send_buffer_bytes",
            )?;
        }
        IngressCfg::MeshPeerUdp { listen, .. } => {
            reject_empty_str(Some(listen), "MeshPeerUdp ingress listen")?;
        }
    }
    Ok(())
}

fn validate_egress(egress: &EgressCfg, id: &str) -> anyhow::Result<()> {
    if egress.wan_id().is_empty() {
        return Err(anyhow!("egress {id} wan_id must not be empty"));
    }
    if egress.groups().iter().any(|group| group.is_empty()) {
        return Err(anyhow!("egress {id} groups contains empty label"));
    }
    match egress {
        EgressCfg::Tcp {
            socket_recv_buffer_bytes,
            socket_send_buffer_bytes,
            ..
        }
        | EgressCfg::Udp {
            socket_recv_buffer_bytes,
            socket_send_buffer_bytes,
            ..
        } => {
            reject_zero(
                *socket_recv_buffer_bytes,
                &format!("egress {id} socket_recv_buffer_bytes"),
            )?;
            reject_zero(
                *socket_send_buffer_bytes,
                &format!("egress {id} socket_send_buffer_bytes"),
            )?;
        }
        EgressCfg::Socks5 { upstream, .. } => {
            reject_empty_str(Some(upstream), "Socks5 egress upstream")?;
        }
        EgressCfg::Socks5Udp { upstream, auth, .. } => {
            reject_empty_str(Some(upstream), "Socks5Udp egress upstream")?;
            if let Some(auth) = auth {
                reject_empty_str(
                    Some(&auth.username),
                    &format!("egress {id} Socks5Udp auth username"),
                )?;
                reject_empty_str(
                    Some(&auth.password),
                    &format!("egress {id} Socks5Udp auth password"),
                )?;
            }
        }
        EgressCfg::MeshPeerUdp { peer_id, peer, .. } => {
            reject_empty_str(Some(peer_id), &format!("egress {id} peer_id"))?;
            reject_empty_str(Some(peer), &format!("egress {id} peer"))?;
        }
        EgressCfg::ServiceTcp {
            service_id,
            route_group,
            connect,
            ..
        } => {
            if service_id.is_empty() {
                return Err(anyhow!("egress {id} service_id must not be empty"));
            }
            if connect.is_empty() {
                return Err(anyhow!("egress {id} connect must not be empty"));
            }
            reject_empty_str(route_group.as_deref(), &format!("egress {id} route_group"))?;
        }
        EgressCfg::ServiceUdp {
            service_id,
            route_group,
            connect,
            socket_recv_buffer_bytes,
            socket_send_buffer_bytes,
            ..
        } => {
            if service_id.is_empty() {
                return Err(anyhow!("egress {id} service_id must not be empty"));
            }
            if connect.is_empty() {
                return Err(anyhow!("egress {id} connect must not be empty"));
            }
            reject_empty_str(route_group.as_deref(), &format!("egress {id} route_group"))?;
            reject_zero(
                *socket_recv_buffer_bytes,
                &format!("egress {id} socket_recv_buffer_bytes"),
            )?;
            reject_zero(
                *socket_send_buffer_bytes,
                &format!("egress {id} socket_send_buffer_bytes"),
            )?;
        }
    }
    Ok(())
}

fn reject_empty_str(value: Option<&str>, label: &str) -> anyhow::Result<()> {
    if value == Some("") {
        return Err(anyhow!("{label} must not be empty"));
    }
    Ok(())
}

fn validate_prometheus_label_names<'a>(
    keys: impl IntoIterator<Item = &'a String>,
) -> anyhow::Result<()> {
    for key in keys {
        if !is_prometheus_label_name(key) {
            return Err(anyhow!(
                "metrics labels key `{key}` must match Prometheus label name pattern ^[A-Za-z_][A-Za-z0-9_]*$"
            ));
        }
    }
    Ok(())
}

fn is_prometheus_label_name(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn reject_invalid_id_shape(id: &str, label: &str, type_name: &str) -> anyhow::Result<()> {
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
    {
        return Err(anyhow!(
            "{label} must match {type_name} pattern ^[A-Za-z0-9_.:-]+$"
        ));
    }
    Ok(())
}

fn reject_empty_path(value: Option<&Path>, label: &str) -> anyhow::Result<()> {
    if value.is_some_and(|path| path.as_os_str().is_empty()) {
        return Err(anyhow!("{label} must not be empty"));
    }
    Ok(())
}

fn reject_zero<T>(value: Option<T>, label: &str) -> anyhow::Result<()>
where
    T: PartialEq + From<u8>,
{
    if value == Some(T::from(0)) {
        return Err(anyhow!("{label} must be >= 1"));
    }
    Ok(())
}

fn is_metadata_key(key: &str) -> bool {
    let Some((head, rest)) = key.split_once('.') else {
        return false;
    };
    METADATA_NAMESPACES.contains(&head)
        && rest.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}
