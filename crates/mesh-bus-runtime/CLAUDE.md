# mesh-bus-runtime


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-runtime governs:
  src/lib.rs — status_text, run (plugin wiring + ingress spawn + pipeline attach)
  src/config.rs — Config, PipelineCfg, PipelineSourceCfg, GeoIpCfg, LoggingCfg, HealthCfg, SchedulerCfg, IngressCfg, EgressCfg, AuthCfg, MetricsCfg, parse_config, pipeline_source_kind, pipeline_sink_kind
  src/config_validate.rs — validate_config + runtime operator-shape guards shared by parse_config and pipeline assembly
  src/pipeline.rs — build_pipeline_runtime: parameterize the selected application adapter's pipeline profile from operator YAML (source projection + source wiring + chain + geoip/geosite + resolver + profile registry with kernel_registry_verify gate)
  schema.json — operator YAML schema; must mirror Config/PipelineCfg/IngressCfg/EgressCfg surface
  tests/config.rs — parse round-trips, strict unknown-field guards, schema-surface guard, bus assembly smoke test
  tests/pipeline_assembly.rs — build_pipeline_runtime green path + source projection + sink registration + pick_sink may_accept_to injection + candidate groups/capabilities + kernel_registry_verify + missing-chain error

mesh-bus-runtime depends_on:
  mesh-bus-core — BusBuilder, BusHandle, IngressPlugin, ExitId, KernelRegistry, kernel_registry_verify
  mesh-bus-ingress-socks5 — Socks5Ingress application source adapter
  mesh-bus-ingress-tcp — TcpIngress
  mesh-bus-ingress-udp — UdpIngress
  mesh-bus-ingress-mesh-peer-udp — MeshPeerUdpIngress
  mesh-bus-egress-tcp — TcpEgress
  mesh-bus-egress-service — ServiceTcpEgress (native direct reverse stream service sink)
  mesh-bus-egress-udp — UdpEgress
  mesh-bus-egress-mesh-peer-udp — MeshPeerUdpEgress
  mesh-bus-egress-socks5 — Socks5Egress, Socks5UdpEgress, Socks5UpstreamAuth
  mesh-bus-scheduler-cake — CakeScheduler
  mesh-bus-scheduler-replicate — ReplicateScheduler
  mesh-bus-scheduler-loadbalance — LoadBalanceScheduler
  mesh-bus-observer-metrics — CounterObserver
  mesh-bus-observer-prometheus — PrometheusTextfileObserver and HTTP /metrics server
  mesh-bus-pipeline-hooks — PipelineRuntime, SharedHookCtx, ExitCandidate, specs::{RESOLVE_HOOK, ENRICH_HOOK, RULE_HOOK, pick_sink_hook_spec}, fn impls
  mesh-bus-resolver — ResolverBuilder, ResolverHandle, DnsCache, Pool, PoolMode
  mb-geoip — GeoIpDb (open + empty fallback for absent runtime config)
  mb-geosite — GeositeDb (open + empty fallback for absent runtime config)
  mb-endpoint — Endpoint
  mb-health — HealthPolicy
  mb-socket-tune — SocketBufferConfig bridge for optional SO_RCVBUF/SO_SNDBUF plugin knobs
  serde_yaml — YAML deserialization
  anyhow — error propagation

mesh-bus-runtime invariants:
  - runtime assembles L4 forwarding-plane plugins from YAML but does not parse protocol payloads
  - runtime is composition and verification glue, not a universal pipeline DSL; each application source adapter owns its pipeline profile/template, while operator YAML supplies parameters, selected source projection, data paths, and egress candidates
  - scheduler selection changes routing behavior; protocol interpretation remains in ingress/egress plugins
  - parse_config validates production-shape mistakes before bind/run, including duplicate egress ids and empty ingress/egress lists
  - health config maps to the shared HealthPolicy schema and mb-health runtime logic
  - metrics config is observer wiring only; it cannot feed back into routing decisions
  - metrics static label keys must be valid Prometheus label names and are rejected during parse_config validation
  - egress wan_id is an observability label; egress groups are L4 route-group candidate labels; egress priority is load-balance weight
  - peer observability labels are derived from config only: node_id from node.id for every sink, and peer_id/path_id/hop_count from each mesh-peer egress (path_id=egress id, hop_count=1 for a direct adjacent peer); runtime never reads Mesh Protocol payload to build them
  - egress priority follows schema minimum 1 at parse/validate time; priority=0 is rejected, not silently clamped into operator intent
  - status_text prints one exit row per configured egress with zeroed counters for pre-run dry status
  - Replicate with fewer than two egresses is valid but warned because fan-out degenerates into single-path dispatch
  - logging config is data only; CLI decides how to install tracing subscriber
  - runtime may depend on protocol plugins because it is composition code, not the core forwarding plane
  - schema.json is part of the operator contract and must stay in lockstep with serde config structs, including metadata spelling and validator-level collection minimums
  - schema minimums/minLength/enums/patterns for logging level, health, scheduler sticky TTL, ingress knobs, adapter endpoints, egress id/wan_id/groups/priority/timeout, metrics path/listen, pipeline paths, and pipeline source id/kind are enforced during parse/validate; invalid operator knobs reject instead of falling through to runtime interpretation
  - socket buffer knobs are optional operator hints (`socket_recv_buffer_bytes`, `socket_send_buffer_bytes`) and default to kernel autotuning; runtime only maps them into plugin builders and never infers BDP itself
  - egress id is the operator projection of SinkId and must match the core SinkId shape (`^[A-Za-z0-9_.:-]+$`) before pipeline assembly registers sinks or pick_sink may_accept_to targets
  - top-level pipeline block supersedes legacy ingress.rule_chain_path only for the source adapter selected by `pipeline.source`; unselected ingresses keep their own legacy/no-policy path
  - pipeline source registration is derived from configured `ingresses[]` as `ingress:N`, not hardcoded to a protocol name
  - `pipeline.source` is the operator-owned SourceSpec projection: id/initial_writes are data; id is an opaque SourceId that must match the core shape (`^[A-Za-z0-9_.:-]+$`) and runtime must not inspect protocol tokens inside it; kind is fixed to `application/source`, and runtime validates selected source adapters through `IngressCfg::pipeline_source_kind()` rather than protocol names
  - `pipeline.source.initial_writes` must use the same MetadataKey shape as mesh-bus-core registry schema and must satisfy every HookSpec.read in the selected adapter's pipeline profile; `kernel_registry_verify` is the startup gate for missing source writes
  - `parse_config` rejects `pipeline.source.ingress_index` when it is out of range or points at an ingress whose `pipeline_source_kind()` does not match `pipeline.source.kind`; runtime assembly keeps the same check as a second line of defense
  - if more than one ingress declares the requested `pipeline.source.kind`, `pipeline.source.ingress_index` is required; runtime must reject ambiguous default source selection instead of silently choosing the first matching adapter
  - `pipeline.source.ingress_index` selects exactly one runtime source adapter for PipelineRuntime attachment; PipelineRuntime::new verifies KernelRegistry, carries that SourceId, and resolves PipelineId via KernelRegistry.wirings; unselected ingresses keep their own legacy/no-policy path
  - every pipeline-source-capable ingress arm (Socks5, Tcp, Udp) attaches the built PipelineRuntime via the adapter's `with_pipeline` when selected and fails closed if the runtime is missing; an arm that advertises `pipeline_source_kind()` but skips attachment is a wiring bug, not a fast-path
  - `EgressCfg::ServiceTcp.route_group` is an operator single-label alias folded into `groups` exactly once in `parse_config`; runtime registration and pipeline candidate construction both read `EgressCfg::groups()` only, so there is no second route-group source to drift
  - service-sink connect endpoint is operator config dialed by the data plane; `request.target` is service-intent metadata only and is never used for the service dial; no L7 route parsing enters core or scheduler
  - pipeline sink registration derives SinkSpec.kind from `EgressCfg::pipeline_sink_kind()` (single-valued closed-vocab registry metadata) and stream/datagram candidate bits from `EgressCfg::pipeline_capability_bits()`, not from a pipeline-builder-local protocol match or global default; the two are independent surfaces
  - pick_sink HookSpec may_accept_to is built from configured egress SinkIds during pipeline assembly; runtime must not depend on hook-library default sink ids
  - PipelineRuntime candidates preserve all egress groups and stream/datagram capability bits; pick_sink filters by L4 transport-family metadata (`net.protocol`) before accepting a sink, never by adapter protocol label
  - configured pipeline data paths are startup gates: absent geoip/geosite config uses empty DBs; a present `geoip` block must include both `country_path` and `asn_path`; a present `geosite` block must include `path`; configured files must open successfully or runtime assembly fails
  - forward pipeline rule chains are startup-gated against the selected pipeline profile's HookSpec write surface; resolver-pool and transform actions are rejected before runtime attachment when that profile cannot project them
  - legacy `ingress.rule_chain_path` RulePolicy loading is startup-gated through the SOCKS5 adapter action-surface validator; unsupported resolver-pool, transform, cost-bias, or future actions reject instead of starting with traffic-time surprises
  - legacy `ingress.rule_chain_path` fallback is an operator-owned config path and resolves relative to the config file directory via `run(cfg, base_dir)`, then local ruleset paths resolve relative to that chain file

mesh-bus-runtime decisions:
  - 0.1.75 (2026-05-18): DDTR M2 — `tests/config.rs` 2797→898 LOC; config cases moved to 108 `tests/fixtures/config/*.yaml` data fixtures driven by `tests/config_fixture_runner.rs` over the REAL `parse_config`/`run` (no mock runtime). `Config` derives only Debug+Deserialize (no Serialize), so field assertions use the `expect.debug_contains` substring arm against `format!("{cfg:?}")` (the proven fallback). Part of the data-driven test-reduction plan close-out (root `mesh-bus` 0.4.40; ledger docs/plan/2026-05-18-ddtr-audit.md). cargo test --workspace 0 failed.
  - 0.1.74 (2026-05-18): native plan M7 — `EgressCfg::MeshPeerUdp` gained `delivery_mode` (`DeliveryModeCfg` steer/stripe/replicate/repair/probe, `to_proto()` → `mb_proto_mesh::DeliveryMode`, default steer so existing configs are byte-for-byte unchanged), `replicate_fanout` (schema 1..=4, default 2), and `probe_budget` (schema ≥0, default 4). `EgressCfg::delivery_policy()` returns `(mode, fanout, probe_budget)` and the runtime MeshPeerUdp arm plumbs it via `MeshPeerUdpEgress::with_delivery_policy`. schema.json mirrors the three fields on the egress object. Policy is a per-egress delivery-coordinate concern only; runtime never parses Mesh Protocol payload to build it. Proven by runtime config parse tests + e2e `mesh_peer_secure_udp_{replicate_dedup,stripe_reorder,repair_gap}`.
  - 0.1.73 (2026-05-16): `EgressCfg::pipeline_capability_bits()` decoupled from `pipeline_sink_kind()` (M7). Current active runtime variants expose Tcp/Socks5/ServiceTcp as stream-only and Socks5Udp/Udp/MeshPeerUdp as datagram-only; any future dual-transport sink must declare candidate bits at its own owner boundary instead of inferring them from `SinkSpec.kind`.

handbook:
  ../../docs/handbook/index.html
