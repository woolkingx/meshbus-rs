use mesh_bus_core::kernel::{
    HookId, KernelRegistry, Pipeline, PipelineId, SinkId, SinkSpec, SourceId, SourceSpec, Wiring,
    kernel_registry_verify,
};

#[test]
fn pick_sink_hook_spec_uses_supplied_accept_sinks_only() {
    let sinks = vec![
        SinkId::new("stream-primary"),
        SinkId::new("datagram-primary"),
    ];

    let spec = mesh_bus_pipeline_hooks::specs::pick_sink_hook_spec(sinks.clone());

    assert_eq!(spec.may_accept_to, sinks);
}

#[test]
fn pick_sink_hook_spec_has_no_metadata_writes() {
    let spec = mesh_bus_pipeline_hooks::specs::pick_sink_hook_spec(vec![SinkId::new("primary")]);

    assert!(
        spec.writes.is_empty(),
        "pick_sink returns a terminal Verdict; HookTrace is runner output, not trace.* metadata"
    );
}

#[test]
fn pick_sink_hook_spec_declares_only_active_reads() {
    let spec = mesh_bus_pipeline_hooks::specs::pick_sink_hook_spec(vec![SinkId::new("primary")]);

    assert!(
        !spec.reads.iter().any(|k| k == "transport.schedule_hint"),
        "schedule_hint is reserved until pick_sink actually consumes it"
    );
}

#[test]
fn resolve_hook_spec_declares_reverse_map_enrichment_writes() {
    let writes = &mesh_bus_pipeline_hooks::specs::RESOLVE_HOOK.writes;

    assert!(
        writes.iter().any(|k| k == "ext.geo_country"),
        "reverse-map recovery can write ext.geo_country"
    );
    assert!(
        writes.iter().any(|k| k == "ext.asn"),
        "reverse-map recovery can write ext.asn"
    );
}

#[test]
fn resolve_hook_spec_declares_only_active_reads() {
    let reads = &mesh_bus_pipeline_hooks::specs::RESOLVE_HOOK.reads;

    assert!(
        !reads.iter().any(|k| k == "net.dst_port"),
        "resolve_or_recover does not read the destination port"
    );
}

#[test]
fn enrich_hook_spec_declares_geosite_hostname_read() {
    let spec = &*mesh_bus_pipeline_hooks::specs::ENRICH_HOOK;

    assert!(
        spec.allowed_namespaces.iter().any(|p| p == "net.*"),
        "geosite lookup reads net.dst_host, so net.* must be allowed"
    );
    assert!(
        spec.reads.iter().any(|k| k == "net.dst_host"),
        "geosite lookup reads net.dst_host"
    );
}

#[test]
fn rule_hook_spec_declares_schedule_hint_payload_writes() {
    let writes = &mesh_bus_pipeline_hooks::specs::RULE_HOOK.writes;

    assert!(
        writes.iter().any(|k| k == "transport.schedule_hint"),
        "rule hook must declare schedule hint label writes"
    );
    assert!(
        writes.iter().any(|k| k == "transport.schedule_fanout_k"),
        "rule hook must declare FanOut k payload writes"
    );
}

#[test]
fn pick_sink_hook_spec_declares_l4_transport_family_read() {
    let spec = mesh_bus_pipeline_hooks::specs::pick_sink_hook_spec(Vec::new());

    assert!(
        spec.allowed_namespaces.iter().any(|p| p == "net.*"),
        "pick_sink filters candidates by L4 net.protocol, so net.* must be allowed"
    );
    assert!(
        spec.reads.iter().any(|k| k == "net.protocol"),
        "pick_sink filters candidates by L4 net.protocol"
    );
}

#[test]
fn four_hook_forward_pipeline_verifies() {
    let mut reg = KernelRegistry::default();
    let pid = PipelineId::new("forward");

    reg.sources.insert(
        SourceId::new("app"),
        SourceSpec {
            id: SourceId::new("app"),
            kind: "application/source".into(),
            initial_writes: vec![
                "net.dst_host".into(),
                "net.dst_port".into(),
                "net.protocol".into(),
                "net.src_ip".into(),
                "auth.user".into(),
                "trace.flow_id".into(),
                "ext.operation".into(),
                "ext.dst_ip_primary".into(),
            ],
        },
    );
    let sink_ids = [
        SinkId::new("stream-primary"),
        SinkId::new("datagram-primary"),
    ];
    for sink in &sink_ids {
        reg.sinks.insert(
            sink.clone(),
            SinkSpec {
                id: sink.clone(),
                kind: "stream_egress".into(),
            },
        );
    }

    reg.hooks.insert(
        HookId::new("net.resolve_or_recover"),
        mesh_bus_pipeline_hooks::specs::RESOLVE_HOOK.clone(),
    );
    reg.hooks.insert(
        HookId::new("net.enrich_geo_asn"),
        mesh_bus_pipeline_hooks::specs::ENRICH_HOOK.clone(),
    );
    reg.hooks.insert(
        HookId::new("policy.rule_chain"),
        mesh_bus_pipeline_hooks::specs::RULE_HOOK.clone(),
    );
    reg.hooks.insert(
        HookId::new("transport.pick_sink_cake"),
        mesh_bus_pipeline_hooks::specs::pick_sink_hook_spec(sink_ids.to_vec()),
    );
    reg.fns.insert(
        HookId::new("net.resolve_or_recover"),
        mesh_bus_pipeline_hooks::resolve::resolve_or_recover,
    );
    reg.fns.insert(
        HookId::new("net.enrich_geo_asn"),
        mesh_bus_pipeline_hooks::geo::enrich_geo_asn,
    );
    reg.fns.insert(
        HookId::new("policy.rule_chain"),
        mesh_bus_pipeline_hooks::rule::rule_chain,
    );
    reg.fns.insert(
        HookId::new("transport.pick_sink_cake"),
        mesh_bus_pipeline_hooks::pick_sink::pick_sink_cake,
    );

    reg.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: vec![
                HookId::new("net.resolve_or_recover"),
                HookId::new("net.enrich_geo_asn"),
                HookId::new("policy.rule_chain"),
                HookId::new("transport.pick_sink_cake"),
            ],
        },
    );
    reg.wirings.push(Wiring {
        source: SourceId::new("app"),
        pipeline: pid.clone(),
    });

    let result = kernel_registry_verify(&reg);
    assert!(result.is_ok(), "verify failed: {result:?}");
}
