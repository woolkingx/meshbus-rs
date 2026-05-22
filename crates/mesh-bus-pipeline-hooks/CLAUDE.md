# mesh-bus-pipeline-hooks

mesh-bus-pipeline-hooks role:
  protocol-neutral hook implementations for the four-hook forward pipeline
  (net.resolve_or_recover -> net.enrich_geo_asn -> policy.rule_chain -> transport.pick_sink_cake);
  each hook is a sync HookFn pointer plus a declarative HookSpec;
  async upstream bridges through SharedHookCtx (Tokio runtime handle + DnsCache + GeoIpDb + GeositeDb + rule_chain/rulesets + capability-aware ExitCandidate set).

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mesh-bus-pipeline-hooks governs:
  src/context.rs    — SharedHookCtx thread-local install/current/clear + scoped guard (Tokio Handle + cache handles + GeoIpDb + GeositeDb + ExitCandidate set)
  src/ext_meta.rs   — crate-local TypedMap.ext write helper; validates local key tails via mesh-bus-core::kernel::is_valid_ext_key_tail in debug builds
  src/runtime.rs    — protocol-neutral PipelineRuntime { SharedHookCtx + verified KernelRegistry + SourceId } + run_pipeline_event helper for source adapters
  src/resolve.rs    — net.resolve_or_recover hook
  src/geo.rs        — net.enrich_geo_asn hook
  src/rule.rs       — policy.rule_chain hook (wraps mb_rule::evaluate_with_trace)
  src/pick_sink.rs  — transport.pick_sink_cake hook (wraps mb-cake)
  src/specs.rs      — HookSpec constants/builders (allowed_namespaces glob form; pick_sink may_accept_to supplied by runtime)
  tests/wiring.rs   — KernelRegistry.verify() passes with all four hooks registered
  tests/runtime.rs  — PipelineRuntime construction/run guards, including protocol-neutral SourceSpec fixture shape

mesh-bus-pipeline-hooks depends_on:
  mesh-bus-core     — kernel pipeline types
  mesh-bus-resolver — ResolverHandle (for resolve hook)
  mb-rule           — evaluate_with_trace (for rule hook)
  mb-geoip          — GeoIpDb::lookup (for geo hook)
  mb-geosite        — GeositeDb::lookup_packed (for domain-side geosite tags)
  mb-cake / mb-cost / mb-health — rank/score/window (for pick_sink hook)

mesh-bus-pipeline-hooks invariants:
  - HookFn is a sync fn-pointer; async work uses tokio::runtime::Handle::block_on through SharedHookCtx per kernel spec §4; runtime execution installs SharedHookCtx through a scoped guard so unwind paths clear thread-local state
  - HookSpec.allowed_namespaces uses glob form `<head>.*`; KernelRegistry::verify checks both reads and writes
  - HookSpec.may_accept_to lists every SinkId the hook's Accept verdict may name (verify enforces UnknownSink)
  - transport.pick_sink_cake HookSpec is built with the operator's SinkIds; protocol-neutral hook templates must not hardcode adapter-specific sink ids
  - transport.pick_sink_cake declares only reads it actively consumes, including `net.protocol` as an L4 transport-family hint; reserved fields such as transport.schedule_hint stay out of HookSpec.reads until implemented
  - pick_sink filters candidates by L4 net.protocol (`tcp` => stream, `udp` => datagram) against ExitCandidate stream/datagram capability before route_group and CAKE ranking; it rejects missing or unknown values fail-closed and never branches on adapter protocol labels such as SOCKS5/HTTP/HTTPS
  - net.resolve_or_recover declares both DNS writes and reverse-map recovery enrichment writes (`ext.geo_country`, `ext.asn`)
  - net.resolve_or_recover reads host/IP metadata only (`net.dst_host`, `ext.dst_ip_primary`); destination port is a policy input, not a resolver input
  - net.enrich_geo_asn declares both IP enrichment input (`ext.dst_ips`) and domain-side geosite input (`net.dst_host`); missing `ext.dst_ips` is a no-op, but malformed packed bytes reject fail-closed as metadata corruption
  - hook implementations write `TypedMap.ext` through src/ext_meta.rs using local key tails (`operation`, `dst_ip_primary`), never full registry metadata keys (`ext.operation`); tail validation belongs to mesh-bus-core::kernel
  - ExitCandidate.route_groups keeps all operator group labels; route_group matching is set membership, not first-label-only
  - policy.rule_chain maps L4 `net.protocol` into mb-rule `RuleCtx.network` and `ext.operation` into `RuleCtx.operation`; missing or unknown `net.protocol`, invalid `net.src_ip`, or invalid `ext.dst_ip_primary` rejects fail-closed before rule evaluation; protocol-specific operation aliases must stay in source adapters
  - policy.rule_chain projects `SetScheduleHint(auto)` as absent `transport.schedule_hint` so the downstream BusSessionRequest keeps core `ScheduleHint::Auto`; explicit fanout writes `ScheduleHintLabel::FanOut` plus `transport.schedule_fanout_k`
  - policy.rule_chain fails closed for mb-rule actions it cannot project onto its declared HookSpec writes; resolver-pool and transform intent belong to their owning hooks/planes, not the forward policy hook
  - PipelineRuntime is protocol-neutral and may be consumed by any application source adapter; construction is fail-fast and verifies KernelRegistry before attachment; fields are private behind read-only accessors; it stores SourceId, resolves the executable PipelineId through KernelRegistry.wirings at event time, and returns typed PipelineRuntimeError for worker join or kernel run failures
  - test registries must use the same generic projections as runtime assembly: `SourceSpec.kind == application/source` and capability-shaped SinkSpec.kind (`stream_egress` / `datagram_egress`), never legacy `application_ingress`, `stream`, or protocol-shaped kind strings
  - no public re-export of kernel data-plane internals (Frame/FrameKind/EgressPlugin); only kernel pipeline primitives

mesh-bus-pipeline-hooks decisions:
  - 0.2.30 (2026-05-13): policy.rule_chain now rejects unparseable net.src_ip and ext.dst_ip_primary instead of treating corrupted IP metadata as absent.
  - 0.2.29 (2026-05-13): net.enrich_geo_asn now rejects malformed ext.dst_ips fail-closed instead of silently continuing without geo/asn enrichment.
  - 0.2.28 (2026-05-13): policy.rule_chain now rejects missing or unknown net.protocol before evaluating rules, matching pick_sink L4 transport-family fail-closed behavior.

handbook:
  ../../docs/handbook/index.html
