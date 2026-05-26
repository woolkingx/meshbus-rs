# mesh-bus

mesh-bus governs:
  crates/mesh-bus-core
  crates/mesh-bus-schema
  crates/mesh-bus-ingress-*
  crates/mesh-bus-egress-*
  crates/mesh-bus-scheduler-*
  crates/mesh-bus-observer-*
  crates/mesh-bus-runtime
  crates/mesh-bus-bin
  tests/CLAUDE.md

mesh-bus depends_on:
  lib/mb-* (pure algorithms and protocol codecs)

mesh-bus extends:
  docs/handbook/index.html
  docs/handbook/system-architecture.html
  docs/handbook/dataplane-observation.html
  docs/handbook/mesh-protocol.html
  docs/handbook/direct-proxy.html
  docs/handbook/operator-plane.html
  docs/handbook/transport.html

mesh-bus thesis:
  - runtime substrate is shaped like TCP/IP (kernel + transport substrate + application participants); OSI L4/L5/L6/L7 is the ownership map that prevents code from leaking across module boundaries
  - two complementary planes share the kernel: an event-pipeline control plane that decides where each session goes, and a frame-runtime data plane that moves the bytes once the decision is made
  - event-pipeline (control plane): ingress builds Event{payload, meta: TypedMap}; a wired Pipeline runs sync HookFns (net.resolve_or_recover → net.enrich_geo_asn → policy.rule_chain → transport.pick_sink_cake); the terminal Verdict::Accept(SinkId) names the egress; KernelRegistry::verify() enforces 26 error classes (UnknownSource, UnknownWiringPipeline, DuplicateWiringSource, MissingSourceWiring, RegistryIdentityMismatch, InvalidSourceId, InvalidSinkId, InvalidPipelineId, InvalidHookId, InvalidSourceKind, InvalidSinkKind, MissingHookFn, UnknownHookFn, InvalidAcceptDeclaration, InvalidJumpDeclaration, InvalidMetadataKey, InvalidNamespacePattern, NamespaceViolation read|write, UnknownSink, etc.) at load time
  - frame-runtime (data plane): once a session is accepted, kernel forwards opaque Frame.payload bytes through the transport substrate (L4 forwarding + L5 session + L6 transform); dispatch obeys flow_semantics / return_semantics / target_sink and consults mb-health::ExitHealthTable; algorithms live in plugins
  - transport substrate is reusable infrastructure with no L7 protocol awareness; kernel + transport together form mesh-bus-core
  - L4 forwarding owns metadata routing, capability matching, scheduling, and dispatch (incl. target_sink pin from Verdict::Accept)
  - L5 session owns generic session identity, flow identity, affinity labels, lifecycle, path metadata, fan-in/dedup, future reassembly/migration
  - L6 transform owns protocol-agnostic payload transforms such as fragmentation, checksum, compression, encryption, parity, and object/message presentation; algorithms live in plugins, not in core
  - application participants (L7) translate external protocol syntax into bus semantics; they are stitchers of L6 codec + L5 control + L4 transport that drive `run_pipeline` for the decision and consume the Bus L5 session surface for the data
  - it is not a reverse proxy, API gateway, or L7 service mesh; nearest shapes are IP router, OVS, nftables — not Envoy or sing-box

mesh-bus invariants:
  - kernel-opacity: kernel never names an application-participant identifier; runtime application participants never name a kernel data-plane internal type (FrameKind/EgressPlugin/SchedulerPlugin/ScheduleDecision/RankContext) for routing or runtime wiring. EXCEPTION (0.4.39, user-consented per DDTR D-M7.2; test-form wording reconciled per D-M7.3): the dispatch Frame→ReturnEvent boundary is a PUBLISHED owner-contract test boundary — `Frame` + its constructors, the dispatch entry, `EgressPlugin`/`SchedulerPlugin`, `ReturnEvent` are public solely so service composition / owner-contract tests can drive the real dispatch service over its public boundary (dispatch is a SERVICE that crosses Frame/scheduler/egress/health/observation owners, not a single-schema data owner; a JSON fixture interpreter would fabricate a fake data-owner = forbidden anti-pattern); this is a test/boundary contract, not a license for application participants to drive the kernel data plane directly at runtime
  - mesh-bus-core is kernel + transport substrate only; core crates must never depend on L7 protocol crates or protocol parser crates
  - Frame.payload is opaque bytes to the bus; routing and scheduling must inspect metadata only
  - transport substrate participates in the bus execution graph through typed metadata and explicit transform outputs; protocol-specific parsers never leak into kernel or transport
  - L7 protocol decode/encode belongs only in application participants (ingress/egress/resolver adapters)
  - Routing decisions may use flow_id, target, traffic_class, ttl, deadline_ms, policy_ref, schedule_hint, flow_semantics, return_semantics, and path metadata; they must not inspect URL, host header, HTTP method, RPC method, body, SNI, or protocol-specific fields
  - New L7 protocol support is implemented as a plugin pair or edge adapter, not as a branch in mesh-bus-core

mesh-bus primitives:
  - Event { payload: Bytes, meta: TypedMap } — mesh-bus-core::kernel::event (executable substrate unit)
  - TypedMap (fixed hot struct: net/transport/policy/auth/trace + SmallMap ext) — mesh-bus-core::kernel::metadata; `is_valid_ext_key_tail` is the core-owned validator reused by hook/adapter crates
  - Hook = sync HookFn fn-pointer + declarative HookSpec — mesh-bus-core::kernel::registry; HookSpec.allowed_namespaces is strict glob `<head>.*` over dotted metadata keys; HookSpec.may_accept_to lists every SinkId Accept may name; registry-aware execution rejects HookFn Accept/Jump targets not declared by the HookSpec
  - Pipeline { id, hooks: Vec<HookId> } + Wiring (source → pipeline) — mesh-bus-core::kernel::pipeline
  - Verdict (Continue / Jump(pipeline) / Accept(sink) / Reject / Drop) — mesh-bus-core::kernel::verdict; PipelineId is control-flow, SinkId is terminal target
  - KernelRegistry (sources / sinks / hooks / pipelines / wirings / fns) + verify() (26 error classes) — mesh-bus-core::kernel::registry; SourceId/SinkId/PipelineId/HookId share the kernel id shape `^[A-Za-z0-9_.:-]+$`; SourceSpec.kind is generic `application/source`, SinkSpec.kind is capability-shaped `stream_egress` or `datagram_egress`
  - SharedHookCtx (tokio Handle + DnsCache + GeoIpDb + GeositeDb + rule_chain/rulesets + capability-aware ExitCandidate set) — mesh-bus-pipeline-hooks::context; async upstream bridges via block_on per kernel spec §4
  - PipelineRuntime (SharedHookCtx + verified KernelRegistry + SourceId) — mesh-bus-pipeline-hooks::runtime; protocol-neutral execution bundle consumed by source adapters; construction verifies KernelRegistry, fields stay private behind read-only accessors, execution resolves SourceId through KernelRegistry.wirings, and runtime failures return typed errors
  - Four-hook forward pipeline (net.resolve_or_recover → net.enrich_geo_asn → policy.rule_chain → transport.pick_sink_cake) — mesh-bus-pipeline-hooks
  - ext.operation — protocol-neutral source operation metadata consumed by policy hooks; protocol-specific aliases are adapter compatibility fields only
  - Frame-runtime substrate (FlowSemantics, ReturnSemantics, TTL guard, flow_pin, replicate dedup) — mesh-bus-core::kernel runtime/dispatch; crate-internal data plane behind L4 session/factory traits
  - SOCKS5 L7 edge adapter — first application source adapter instance; mb-proto-socks5 + mesh-bus-ingress-socks5 project protocol traffic into the protocol-neutral pipeline runtime

mesh-bus extension-rule:
  - feature requires payload parsing or L7 inspection in core → ingress/egress plugin or edge adapter
  - feature uses only L4 metadata → core, scheduler, or observer is fair game
  - feature uses generic session identity, affinity, path proof, fan-in, or reassembly → L5 session plane
  - feature transforms opaque payload shape (fragment, compress, encrypt, checksum, parity) → L6 transform plane with schema first
  - new L7 protocol → new plugin pair, never a branch in core

mesh-bus testing-rule:
  - tests follow `data -> schema -> module owner test -> integration -> product e2e`; write the owner/module test before using e2e to prove composition
  - module tests live with the module code and schema; root `tests/` is only the shared testing guide and composition policy
  - e2e must stay small and hard: it proves already-tested modules compose, not codec/crypto/reorder/schema/parser edge cases
  - avoid large fake runtime / fake mesh / fake protocol helpers; such tests indicate a missing data owner or boundary contract

mesh-bus roadmap:
  - use `docs/handbook/index.html` as the topologic/logic schema spine; `schema.json` owns data/structure schema, and plans/code/tests derive from those owners
  - keep CLAUDE.md as execution rules/keypoints/navigation only; keep Markdown plans as action plans only
  - fix UDP ingress head-of-line by spawning per datagram
  - bind UDP ingress sessions by client peer when protocol needs flow affinity
  - keep adjacent-peer, transport-neutral Mesh Protocol semantics in `docs/handbook/mesh-protocol.html`; mesh-peer plugins are delivery substrates or edge adapters
  - make native direct forward/reverse paths the product skeleton: compatibility protocols remain edge plugins, while direct sources and services project intent into L4/L5 bus sessions without extra protocol translation
  - harden direct forward + direct reverse + single-node data movement baselines before optimizing mesh protocol transport, multi-hop, striping, or reorder
  - use `docs/handbook/direct-proxy.html` as the source-of-truth before selecting direct proxy implementation slices
  - add ScheduleDecision::Striping
  - implement SequenceReorder only for ByteStream + Striping

mesh-bus perf-backlog:
  - P1 enterprise CPU tuning: expose `runtime.worker_threads: Option<usize>` in config and a per-ingress accept-pool size; default keeps tokio num_cpus. Trigger: multi-tenant box where bus must yield cores to other services, or 8+ core host where uncapped worker pool causes cross-socket contention. Not needed for single-host personal deploys.
  - P1 splice follow-up: direct Forwarder TCP splice landed for Linux TCP ingress/SOCKS5 ingress + TCP egress. Current implementation uses blocking splice workers per direction over a pipe pair. Use `cargo test -p mb-splice --test relay_matrix --release -- --ignored --nocapture --test-threads=1` to compare direct echo, std copy, Tokio copy_bidirectional, blocking splice, and nonblocking poll-splice before changing the mesh fast path.
  - P2 socket buffer tuning follow-up: optional SO_SNDBUF / SO_RCVBUF config exists for TCP/SOCKS5/UDP ingress and TCP/UDP egress. Loopback tests did not show a stable gain over kernel autotuning, so defaults remain unset. Future WAN work should auto-size from measured BDP instead of hardcoding a large buffer.
  - P2 io_uring submission batching: replace per-chunk read/write with submission-queue batches on Linux; complementary to splice, applies to non-splice-able egresses.
  - P2 sockmap offload: register the accepted ingress fd and connected egress fd into a BPF sockmap and let the kernel forward bytes without userspace involvement; gate stays ByteStream + Direct + single pinned stream path.
  - P3 T2 XDP / T3 HW offload: research-only; needs route_group + capability metadata projected into BPF map shape first.

mesh-bus decisions:
  - 0.4.55 (2026-05-26): Coding structure gate is now release-prep owned: durable Rust tests live outside production logic, module `CLAUDE.md` files route to schema/test contracts instead of embedding long proof code, `tools/audit-coding-structure.mjs` guards inline-test and oversized-file drift, and `tools/flowgraph.mjs` emits boundary edges for data/control-flow readback.
  - 0.4.54 (2026-05-22): Public GitHub name is `meshbus-rs`; product family remains MeshBus, protocol is MeshBus Protocol, security layer is MeshSec, and current implemented CLI remains `mesh-bus`. GitHub Markdown files are landing/contribution gates only; handbook remains the architecture/spec truth.
  - 0.4.53 (2026-05-22): CLAUDE design-boundary guards are now mechanically enforced. Handbook gate R8 fails hard when any `crates/lib/tests/**/CLAUDE.md` lacks exactly one `design-rule:` block, so local boot cards cannot drift away from the handbook topology/schema ownership boundary silently.
