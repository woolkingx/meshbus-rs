# mesh-bus-core.kernel


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  schema.json — data contract for Bus/BusHandle/BusPort/BusBuilder/Registry/BusEvent/BusError/SessionHandle/RuntimeSnapshot
  types.rs — BusEvent, BusError
  data_handle.rs — umbrella re-exports for Bus, BusHandle, BusBuilder, BusPort, Registry, and kernel pipeline primitives
  builder.rs — BusBuilder assembly
  port.rs — BusPort (open_session crate-internal, open_stream/open_datagram public)
  registry.rs — Frame-runtime Registry (egress/scheduler/observer); distinct from KernelRegistry
  runtime.rs — Bus + BusHandle runtime
  dispatch.rs — runtime dispatch loop and per-session ordered handling; first-flow dispatch derives DataplaneShape and pins flow state
  dispatch_observation.rs — core observation emission and exit-runtime stats updates for dispatch
  session_handle.rs — crate-internal SessionHandle bridging L4 facade to runtime
  health_snapshot.rs — lockless ArcSwap publisher of the unhealthy-exit set for dispatch hot path
  metrics_observer.rs — always-on observer that sources BusSnapshot.dispatch_success/failure/bytes_sent
  health_observer.rs — always-on observer that owns ExitHealthTable + publishes HealthSnapshot
  observation/ — routed ObservationBus, EventEnvelope, CoreEventId/ObsEventId, registry verification, subscriber status, and probe counters
  forwarder.rs — DataplaneShape, FlowCounters, TransformRequirements, and lifecycle publish deadlines
  tests.rs — kernel-local smoke

kernel owns:
  bus runtime assembly, Frame-runtime registry, port, builder, dispatch, command path, shutdown, snapshot,
  plus the event-pipeline kernel primitives (Event / TypedMap / Hook / Pipeline / Verdict / KernelRegistry).

kernel pipeline_substrate:
  event/    — Event { payload: Bytes, meta: TypedMap } + HookTrace per-hook entry
  metadata/ — TypedMap (fixed hot struct: net/transport/policy/auth/trace + SmallMap ext) + MetaValue
  pipeline/ — Pipeline { id, hooks: Vec<HookId> } + Wiring + run_pipeline executor (MAX_JUMP_DEPTH=32)
  registry/ — KernelRegistry (sources/sinks/hooks/pipelines/wirings/fns) + HookFn fn-pointer alias + HookSpec (glob allowed_namespaces, may_accept_to) + verify() (26 error classes)
  verdict/  — Verdict (Continue/Jump/Accept/Reject/Drop) + PipelineId/SinkId/HookId/SourceId/Reason
  Note: the on-disk path is kernel/registry/; the Rust module is exposed as `kernel_registry`
        to avoid collision with the existing kernel/registry.rs (Frame-runtime Registry).

kernel pipeline_contract:
  - HookFn is a sync fn-pointer; async upstream bridges through SharedHookCtx.tokio.block_on per spec §4; every pipeline hook must have a registered HookFn at verify time, and every registered HookFn must have a HookSpec
  - keyed registry entries are identity-closed: each SourceSpec/SinkSpec/HookSpec/Pipeline embedded id must equal its BTreeMap key
  - SourceId/SinkId/PipelineId/HookId use the same kernel id shape (`^[A-Za-z0-9_.:-]+$`) in verdict, event, pipeline, registry schemas, and verify
  - TypedMap.ext key-tail validation is a core-owned kernel contract; adapters and hook crates reuse `kernel::is_valid_ext_key_tail` instead of carrying local validator copies
  - SourceSpec.kind is fixed to `application/source`; SinkSpec.kind is capability-shaped (`stream_egress` or `datagram_egress`)
  - source wiring is total and single-valued: every SourceSpec has exactly one KernelRegistry.wirings entry
  - route_group != pipeline_id: route_group is metadata filtering sink candidates; PipelineId is Jump control flow
  - may_accept_to is legal only when may_terminate=true; may_jump_to is legal only when may_jump=true; may_jump only proves a pipeline can terminate when may_jump_to declares at least one verified target pipeline
  - HookTrace = (hook_id, verdict) is the kernel-surface trace; richer fields belong to adapter access logs
  - Spec: docs/handbook/system-architecture.html

kernel dataplane_contract:
  - first successful Open derives DataplaneShape and stores per-flow FlowState + FlowCounters
  - Forwarder-capable streams open the egress stream once and transfer egress send/recv halves to InternalStreamSession; subsequent Data chunks bypass dispatch_forwarder_frame and update FlowCounters through the per-flow Arc
  - dispatch no longer emits per-dispatch BusEvent::DispatchResult or BusEvent::DispatchFailure; it publishes CoreEventId envelopes through ObservationBus
  - ObservationBus routes by EventTypeId; subscribers receive only registered event ids instead of global broadcast fan-out
  - two always-on core observers are wired in build(): MetricsObserver (BusSnapshot source) and ExitHealthObserver (HealthSnapshot publisher)
  - scheduler feedback is plugin-owned: SchedulerPlugin::on_observation receives core envelopes, and CAKE owns its CakeFeedbackObserver compatibility adapter
  - HealthSnapshot is an ArcSwap publication: dispatch hot path takes `health_snapshot.load()` (lockless Arc clone); the ExitHealthTable lives inside ExitHealthObserver's drainer task
  - flow_pins is the sole affinity store: Mutex<HashMap<FlowId, usize>> populated on successful dispatch, drained on Close/Cancel
  - source_activity is the core-owned source lifecycle projection: successful Open increments source_key active_flows; flow close decrements it and records idle_since_ms when the count reaches zero; schedulers may read this projection through RankContext but must not infer active flow state themselves
  - exit_stats and flow counters are sharded DashMap/AtomicU64 surfaces; collect_snapshot is sync and pulls flow byte counters without event replay

kernel decisions:
  - 0.4.11 (2026-05-26): RankContext now carries core-owned SourceActivity for true source idle. Source-lease schedulers must treat idle as active_flows==0 plus idle_since_ms expiry, not as time since the last scheduling call.
  - 0.4.10 (2026-05-15): close_reason_is_success() corrected in dispatch_observation.rs and forwarder.rs. UpstreamEof (server FIN) and ReaderClosed (stream channel exhausted) removed from failure list; both are graceful TCP terminations. Fixes 50% false dispatch_failure rate in Prometheus where every successful HTTP session generated one FlowOpened(success=true) + one FlowClosed(UpstreamEof→success=false). dispatch_success_rate now reads 1.000 under normal operation.
  - 0.4.9 (2026-05-15): DatagramForwarder probe correctness fixes. Fallback now signals probe_channels oneshot (not ReturnEvent::Idle); Failed branch signals probe_channels when all ordered candidates fail so probe_rx never deadlocks. Direct datagram close uses forwarder.take() to prevent double-close; ForwarderClose::close_once() awaits on_close cleanup so direct paths remove flow_pins, flow_states, and flow_counters together. ForwarderClose::new() accepts async ForwarderCloseCleanup; datagram uses cleanup closure, stream uses no-op.
  - 0.4.2 (2026-05-14): DatagramForwarder direct path landed. dispatch_forwarder.rs gains DatagramForwarderProbeOutcome and try_open_forwarder_datagram; dispatch_ordered branches on DatagramForwarder Open frames, stores ForwarderDatagramState, and signals probe_channels on Fallback. session/datagram_halves.rs probes on first eligible send via oneshot and routes subsequent sends through forwarder_datagrams or FrameRouter.
  - 0.3.2 (2026-05-13): T0 fastpath now publishes RTT samples via bounded mpsc + background drainer; scheduler receives feedback without acquiring the scheduler mutex on the hot path.
  - 0.3.1 (2026-05-13): DispatchRuntime now publishes fast_sends/slow_sends AtomicU64 counters on BusSnapshot; fastpath hit-ratio is runtime-observable. Loopback SOCKS5 single-flow stream bench: fast_sends=19725, slow_sends=0, ratio=1.0, 109 MiB/s.
