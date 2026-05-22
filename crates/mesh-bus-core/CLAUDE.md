# mesh-bus-core

mesh-bus-core role:
  kernel + transport substrate — TCP/IP-shaped runtime + OSI L4/L5/L6 reusable substrate; never names an L7 protocol identifier

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mesh-bus-core governs:
  src/lib.rs — public router types (ExitId, SessionId, FlowId, PacketId, TrafficClass, Capabilities, Measurement, ExitResult, snapshots) plus crate-internal Frame/FrameKind/EgressPlugin data plane; re-exports from kernel/ and transport/
  src/kernel/ — bus runtime / dispatch / registry / observation spine (schema.json, types.rs, data_handle.rs, builder.rs, port.rs, registry.rs, runtime.rs, dispatch.rs, dispatch_observation.rs, session_handle.rs, health_snapshot.rs, metrics_observer.rs, health_observer.rs, forwarder.rs, observation/, tests.rs)
  src/egress_adapter.rs — StreamEgress/DatagramEgress factory adapters into the internal Frame runtime
  src/transport/ — reusable substrate (L4 forwarding + L5 session + L6 transform)
  src/transport/forwarding/ — L4 forwarding-plane data (schema.json, types.rs, data_handle.rs, tests.rs)
  src/transport/session/ — L5 session domain (schema.json, types.rs, data_handle.rs, direct_forwarder_halves.rs, tcp_splice_compat.rs, tests.rs)
  src/transport/transform/ — L6 transform domain skeleton
  src/transport/path_stats.rs — PathStatsProvider trait (per-flow PathStats pull surface)
  src/transport/link_evidence.rs — LinkEvidence L4 scheduler-evidence projection from PathStats + lock-free per-neighbor immutable snapshot (arc-swap copy-on-write)
  src/transport/udp_loop/ — L4 UDP packet-loop substrate (mod.rs packet-oriented surface, socket.rs tokio UdpSocket I/O, queue.rs in/out datagram queues); payload-opaque, owns no MeshFrame/mb-proto-mesh knowledge
  src/*_tests.rs — internal runtime/router tests that may inspect crate-private Frame
  tests/session_surface.rs — external public-surface guard; raw Frame channel must not be public
  tests/kernel_invariant.rs — kernel + transport substrate invariant: manifest + src/ contain no L7 protocol identifier
  tests/boundary_guard.rs — domain layout (kernel/ + transport/{forwarding,session,transform}) + public surface + retired-shim + algorithm-free + LOC-cap guards

mesh-bus-core depends_on:
  mesh-bus-schema
  mb-endpoint
  tokio
  async-trait
  bytes
  thiserror
  tracing
  mb-health

mesh-bus-core extends:
  ../../docs/handbook/system-architecture.html
  ../../docs/handbook/dataplane-observation.html

mesh-bus-core protocol-semantics:
  - FlowSemantics::ByteStream — TCP-like; Ordered dispatch returns Direct; future striping requires SequenceReorder
  - FlowSemantics::Datagram — UDP-like; replicate uses PacketDedup on return
  - FlowSemantics::Message — message-oriented; ordering policy is plugin-defined
  - ReturnSemantics::Direct — emit each successful return
  - ReturnSemantics::PacketDedup — at most one return per (flow_id, packet_id)
  - ReturnSemantics::SequenceReorder — reserved for ByteStream + Striping; not implemented in core

mesh-bus-core invariants:
  - mesh-bus-core is kernel + transport substrate (L4 forwarding + L5 session + L6 transform); it must not import or depend on SOCKS, HTTP, TLS, RPC, QUIC, or other L7 protocol crates
  - kernel-opacity: kernel source must never name an application-participant identifier; participants must never name a kernel data-plane internal type (Frame/FrameKind/EgressPlugin/SchedulerPlugin/ScheduleDecision/RankContext); enforced by tests/kernel_invariant.rs + per-adapter tests/application_boundary.rs
  - L6 transform substrate carries metadata + validation only; algorithm execution lives in plugins, not in transport/transform/
  - Frame.payload is opaque bytes; core may copy, forward, dedup, or reorder payload bytes, but must not parse them
  - core may route by typed metadata and generic session semantics (session_id, flow_id, source_key, target_key, path_trace, return_semantics), but must not derive those semantics from protocol payloads
  - Frame.flow_semantics is generic L4 flow-shape metadata for capability matching and dispatch placement, not protocol-level semantics or an L7 policy input
  - L6 payload transforms are explicit external planes; core can forward transformed opaque bytes and metadata, but transform algorithms do not live in core
  - L7 protocol handling belongs in ingress/egress plugin crates
  - SchedulerPlugin and runtime dispatch can use packet metadata only: flow_id, target, traffic_class, ttl, deadline_ms, policy_ref, schedule_hint, flow_semantics, return_semantics, source_key, target_key, and path_trace
  - SessionRequest::source_key and SessionRequest::target_key are opaque ingress-supplied keys (e.g. client_ip; eTLD+1 of dst_host) that propagate through Frame and RankContext; the scheduler decides which keys its mode consumes, the bus never inspects the strings
  - dispatch health is shared by all schedulers through mb-health::ExitHealthTable; after repeated failures an exit is temporarily filtered, then re-admitted for probe after policy delay
  - Measurement includes payload_bytes so observers can expose traffic counters without parsing payload
  - BusHandle::shutdown drains already accepted in-flight dispatches before returning
  - BusHandle::snapshot requests an in-process runtime snapshot through the command channel and reports per-exit counters
  - runtime control commands must stay responsive while dispatch admission is back-pressured
  - ByteStream returns are stream-shaped: after an ordered dispatch succeeds, core keeps polling the pinned egress for upstream bytes until close/shutdown/client-drop
  - TcpSpliceSession is an optional L5 transport optimization surface for already-connected TCP stream sessions; it never exposes Frame/FrameKind and must fall back to normal StreamSendHalf/StreamRecvHalf semantics when not consumed by an ingress
  - CONNECT/Open failure reasons are typed CloseReason values and must not be collapsed into generic no-usable-exit when reporting to ingress
  - successful Open returns Connected metadata so L4Session can populate SessionInfo.paths with selected exit and local endpoint
  - Frame, FrameKind, EgressPlugin, SessionHandle, and BusPort::open_session are crate-internal; external ingress/egress crates must use L4 session/factory traits
  - runtime dispatch candidates must match Frame.flow_semantics against egress capabilities before scheduler ordering
  - ordered load-balancing is flow-level: scheduler picks the first exit for a new flow, then flow_pins keep that flow on the successful exit
  - tests/kernel_invariant.rs enforces the dependency part of this invariant
  - route_group is L4 candidate-filter metadata (string label) and is never a PipelineId; PipelineId is event-kernel control flow (Verdict::Jump target). They live in different namespaces and verify() rejects cross-confusion at registry load.
  - KernelRegistry wiring is closed-world, total, and single-valued: every SourceSpec has exactly one Wiring, and every Wiring.source and Wiring.pipeline must resolve to registered SourceSpec/Pipeline entries.
  - KernelRegistry keyed maps are identity-closed: SourceSpec/SinkSpec/HookSpec/Pipeline embedded ids must equal their BTreeMap keys.
  - SourceId, SinkId, PipelineId, and HookId share the kernel id shape `^[A-Za-z0-9_.:-]+$`; KernelRegistry verify rejects slash/whitespace/symbol ids before graph checks.
  - KernelRegistry kind vocabulary is closed and generic: SourceSpec.kind is `application/source`; SinkSpec.kind is `stream_egress` or `datagram_egress`.
  - HookFn is a sync fn-pointer; async upstream from hooks must bridge through SharedHookCtx.tokio.block_on per kernel spec §4; no async-trait or boxed-future in the kernel hook surface; every pipeline hook must have a registered HookFn at verify time, and every registered HookFn must have a HookSpec.
  - HookSpec.may_jump_to is legal only when may_jump=true; may_jump only satisfies PipelineDoesNotTerminate when may_jump_to is nonempty and targets verify; empty jump declarations do not make a pipeline terminal.
  - SourceSpec.initial_writes and HookSpec reads/writes must be concrete dotted metadata keys under net|transport|policy|auth|trace|ext; key segments are ASCII alnum or underscore only, and invalid keys fail verify before read-satisfaction checks.
  - HookSpec.allowed_namespaces entries must be schema-valid NamespacePattern values (`<head>.*` for known metadata heads), even when the hook currently declares no reads/writes.
  - HookSpec.allowed_namespaces uses glob form `<head>.*` where head ∈ {net, transport, policy, auth, trace, ext}; verify checks both reads and writes against strict `head.` prefixes and reports NamespaceViolation { side: "read" | "write" }.
  - HookSpec.may_accept_to is legal only when may_terminate=true; it lists every SinkId Verdict::Accept may name, and UnknownSink fires when a listed sink is not registered.
  - run_pipeline_with_registry enforces each HookFn's returned Accept/Jump target against the hook's declared may_accept_to/may_jump_to before recording HookTrace; undeclared runtime targets fail closed as PipelineRunError.
  - run_pipeline_with_registry records HookTrace entries in KernelCtx; richer fields stay in adapter/dispatch access logs.
  - Datagram returns are packet-shaped: BusDatagramSendHalf and BusDatagramRecvHalf progress independently; core maps returned datagram payloads to the original target by packet seq rather than FIFO ordering.
  - UdpPacketLoop is the L4 UDP delivery substrate: it owns the tokio UdpSocket, outbound/inbound datagram queues, packet timestamps, peer endpoint, and PathStats updates; it treats every datagram body as opaque bytes and must not parse, encode, or decode MeshFrame or any mb-proto-mesh wire structure (peer crates keep MeshFrame encode/decode).

mesh-bus-core layer-mapping:
  - src IP / port — L4 — core owns as BusSessionRequest.source_key (opaque label)
  - dst host / port — L4 — core owns as BusSessionRequest.target_key (opaque label)
  - FlowId / PacketId — L4 — core owns and mints; FlowId is opaque (FlowId::mint_for hashes session_id+target, no cleartext L7 host) and authored only in the L4 data plane; L5 session_info carries it, never authors; routing keys
  - exit candidate set / health filtering — L4 — core dispatch
  - selected exit / path_trace — L4 — core dispatch output
  - ScheduleHint (Ordered / FanOut) — L4 — core scheduler input
  - route_group — L4 — core candidate filter; plugin projects in via action_apply
  - TTL / deadline / traffic_class — L4 — core scheduler input
  - flow_pin (sticky exit per flow) — L4 — core runtime state
  - rate limit / quota / shaping — L4 — CAKE scheduler concern (HTB shaping + fair queueing + AQM), not a separate admission feature
  - bus session open/close lifecycle — L5 — core owns via BusStreamSession / BusDatagramSession
  - SessionInfo.paths (selected exit + local endpoint) — L5 — core Open success metadata
  - DisconnectReason / CloseReason — L5 — core typed closure reasons
  - bus session ↔ flow correspondence — L5 — core; flow_id is sub-key inside session
  - Frame.payload bytes — L6 transport substrate — core carries opaque bytes and transform metadata; application adapters/proto-codecs own external wire syntax parsing and encoding
  - TLS wrap — L6 — plugin (future mesh-bus-ingress-tls); encoding transform
  - gzip / compression — L6 — plugin-internal encoding transform
  - JSON / protobuf / MessagePack — L6 — plugin-internal encoding
  - charset / base64 — L6 — plugin-internal encoding
  - "open a stream to host:port" intent — L7 — ingress plugin intent
  - "open a datagram channel for this client" intent — L7 — ingress plugin intent
  - request-method semantics / cookie / token — L7 — plugin intent / app state
  - RuleCtx fields (dst_host, src_ip, etc.) — L7 projection — application adapter/proto-codec supplies to mb-rule; core sees only typed metadata
  - Rule Action (Allow / Deny / SetRouteGroup / SetScheduleHint) — L7 → L4 projection — verdict_apply (or action_apply) in plugin projects to core vocabulary
  - auth credentials (user/pass / GSSAPI / token) — L7 (app state) — ingress plugin; authenticated username may enter RuleCtx
  - striping / fragmentation metadata — L4 transport extension owned by core transport/transform/ (carries metadata + validation only; algorithm execution lives in plugins)
  - Pipeline / Hook / KernelRegistry — kernel control-plane substrate — mesh-bus-core::kernel (Event/TypedMap/Verdict primitives + run_pipeline executor with MAX_JUMP_DEPTH=32)
  - ObservationRegistry / ObservationBus / SubscriberStatusTable — kernel observation substrate (verified at boot) — mesh-bus-core::kernel::observation
  - DataplaneShape derivation + FlowCounters — L4 forwarding shape decision + per-flow byte counters — mesh-bus-core::kernel::forwarder
  - PathStatsProvider trait — L4/L5 telemetry pull surface (separate from EgressPlugin) — mesh-bus-core::transport::path_stats
  - LinkEvidence / LinkEvidenceSnapshot — L4 scheduler evidence projected from PathStats (srtt/rttvar/delivery_ratio/loss_burst/reorder_score/pmtu/queue_delay/cost_weight); soft TTL-expirable per-neighbor evidence kept separate from durable configured-peer identity; lock-free hot-path read via arc-swap copy-on-write — mesh-bus-core::transport::link_evidence
  - UdpPacketLoop — L4 UDP delivery substrate (datagram-oriented, payload-opaque, owns tokio UdpSocket + in/out queues + packet timestamps + PathStats updates) — mesh-bus-core::transport::udp_loop

mesh-bus-core decisions:
  - 0.4.40 (2026-05-18): DDTR M7 closed via ontological correction (plan D-M7.3). Dispatch is a SERVICE (it crosses Frame / scheduler decision / EgressPlugin behavior / ExitHealthTable / ObservationBus) — not a single-schema data owner — so its owner-contract artifact is a composition test over the REAL public `BusBuilder` dispatch boundary, never a JSON fixture interpreter (which would fabricate a fake data-owner = the forbidden fake-runtime/fake-scheduler anti-pattern in testing-rule). 15 dispatch cases kept in `tests/dispatch_contract.rs` (9) + `tests/dispatch_datagram.rs` (6); the 14 copy-pasted fake `EgressPlugin`/`SchedulerPlugin`/`ObserverPlugin` collapsed into ONE shared parameterized `tests/dispatch_double.rs::TestEgress` (behavior enum) + reused `First`/`RecordingScheduler`; two-file LOC 1326→915; 15 decorative non-conformant JSON deleted; dead `test-fixture.schema.json` `+dispatch` reverted. `runtime_tests.rs`/`datagram_session_tests.rs` residue re-affirmed as doctrine-sanctioned irreducible-timing (concurrency/shutdown-drain/dedup wall-clock), stays inline. The 0.4.39 public `Frame` boundary is unchanged; only the test-form wording was reconciled. `cargo test --workspace` 0 failed; session_surface/boundary_guard/kernel_invariant green; commits 40191ec/82d0759.
  - 0.4.38 (2026-05-18): native plan M6 — `transport/link_evidence.rs` lands `LinkEvidence` (8 schema `link_evidence_v1` fields, owner L4) projected purely from `PathStats` via `LinkEvidence::from_path_stats` (srtt/rttvar=rtt_us/rttvar_us; queue_delay=pacing_delay_us; pmtu=pmtu; loss_burst=drops; delivery_ratio=1/(1+failures) heuristic where failures=send_errors+drops+queue_full_drops; reorder_score=0 no send-side evidence; cost_weight=srtt+4·rttvar+loss penalty — RTO-shaped, documented heuristic, observation not route truth). `LinkEvidenceSnapshot` keeps a durable configured-peer identity vector that evidence expiry never deletes, separate from soft TTL-expirable per-neighbor evidence stored behind `arc_swap::ArcSwap` copy-on-write (control-path swaps, hot-path `candidate_mouths`/`evidence_for` read lock-free, no global mutex await). No new core dep (arc-swap already workspace+core); no mb-proto-mesh dep added — wire `LinkSample` stays in the codec crate, decoupled. Proven by `udp_loop` tests `link_evidence_projects_path_stats_into_schema_shape` + `evidence_expiry_removes_mouth_but_keeps_configured_identity`.
  - 0.4.37 (2026-05-17): FlowId is opaque, minted only via L4-owned FlowId::mint_for; L5 session_info carries it (does not author). Closes data-ontology F2 at functional-equivalent affinity; Open-return-channel plumbing is a documented follow-up.
