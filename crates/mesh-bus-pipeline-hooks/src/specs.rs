//! HookSpec constants for the four-hook forward pipeline.
//!
//! Each Lazy<HookSpec> mirrors the declarative specification in
//! docs/handbook/system-architecture.html.
//! KernelRegistry::verify cross-checks these against allowed_namespaces,
//! reads, writes, may_terminate, and may_accept_to to enforce kernel invariants.

use mesh_bus_core::kernel::{HookId, HookKind, HookSpec, SinkId};
use once_cell::sync::Lazy;

pub static RESOLVE_HOOK: Lazy<HookSpec> = Lazy::new(|| HookSpec {
    id: HookId::new("net.resolve_or_recover"),
    kind: HookKind::Net,
    allowed_namespaces: vec!["net.*".into(), "ext.*".into()],
    reads: vec!["net.dst_host".into(), "ext.dst_ip_primary".into()],
    writes: vec![
        "ext.dst_ips".into(),
        "ext.dst_ip_primary".into(),
        "ext.dns_rtt_ms".into(),
        "ext.resolution_mode".into(),
        "ext.geo_country".into(),
        "ext.asn".into(),
        "net.dst_host".into(),
    ],
    may_terminate: true,
    may_jump: false,
    may_jump_to: vec![],
    may_accept_to: vec![],
    side_effect_only: false,
});

pub static ENRICH_HOOK: Lazy<HookSpec> = Lazy::new(|| HookSpec {
    id: HookId::new("net.enrich_geo_asn"),
    kind: HookKind::Net,
    allowed_namespaces: vec!["ext.*".into(), "net.*".into()],
    reads: vec!["ext.dst_ips".into(), "net.dst_host".into()],
    writes: vec![
        "ext.geo_country".into(),
        "ext.asn".into(),
        "ext.geosite_tags".into(),
    ],
    may_terminate: false,
    may_jump: false,
    may_jump_to: vec![],
    may_accept_to: vec![],
    side_effect_only: false,
});

pub static RULE_HOOK: Lazy<HookSpec> = Lazy::new(|| HookSpec {
    id: HookId::new("policy.rule_chain"),
    kind: HookKind::Policy,
    allowed_namespaces: vec![
        "policy.*".into(),
        "transport.*".into(),
        "ext.*".into(),
        "net.*".into(),
        "auth.*".into(),
    ],
    reads: vec![
        "net.dst_host".into(),
        "net.dst_port".into(),
        "net.src_ip".into(),
        "net.protocol".into(),
        "auth.user".into(),
        "ext.operation".into(),
        "ext.dst_ip_primary".into(),
        "ext.geo_country".into(),
        "ext.asn".into(),
        "ext.geosite_tags".into(),
    ],
    writes: vec![
        "policy.route_group".into(),
        "transport.schedule_hint".into(),
        "transport.schedule_fanout_k".into(),
        "ext.cost_bias".into(),
    ],
    may_terminate: true,
    may_jump: false,
    may_jump_to: vec![],
    may_accept_to: vec![],
    side_effect_only: false,
});

pub fn pick_sink_hook_spec(may_accept_to: Vec<SinkId>) -> HookSpec {
    HookSpec {
        id: HookId::new("transport.pick_sink_cake"),
        kind: HookKind::Transport,
        allowed_namespaces: vec![
            "transport.*".into(),
            "net.*".into(),
            "trace.*".into(),
            "policy.*".into(),
            "ext.*".into(),
        ],
        reads: vec![
            "net.protocol".into(),
            "policy.route_group".into(),
            "ext.cost_bias".into(),
            "ext.dns_rtt_ms".into(),
            "trace.flow_id".into(),
        ],
        writes: vec![],
        may_terminate: true,
        may_jump: false,
        may_jump_to: vec![],
        may_accept_to,
        side_effect_only: false,
    }
}
