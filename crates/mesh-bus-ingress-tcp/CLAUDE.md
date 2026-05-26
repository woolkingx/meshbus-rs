# mesh-bus-ingress-tcp


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-ingress-tcp implements:
  IngressPlugin — plain TCP source adapter

owned files:
  src/lib.rs — TcpIngress; fixed-target StreamSession fast path, plus optional PipelineRuntime decision before port.open_stream
  src/event_build.rs — direct-stream target projection into Event TypedMap (ext.operation=direct_stream_open, generic L4 metadata only)
  src/verdict_apply.rs — Verdict + post-run Event projection into BusSessionRequest (Accept→target_sink, Reject/Continue/Jump→deny, Drop→silent close)
  tests/listen.rs — end-to-end: ingress + bus + egress-tcp echo roundtrip
  tests/pipeline.rs — consumed PipelineRuntime path: deny closes client, route_group pins dispatch

local dependencies:
  mesh-bus-core — IngressPlugin, BusPort, BusSessionRequest, StreamSession split halves
  mesh-bus-pipeline-hooks — optional PipelineRuntime decision path consumed by the direct source adapter
  mb-endpoint — Endpoint (fixed target per listener)
  tokio — async TCP accept loop, split read/write

boundary rules:
  - direct source adapter: this crate is an L7-free native source; it builds protocol-neutral Event metadata and consumes the Bus L5 session surface only, never Frame/FrameKind/EgressPlugin
  - event projection fills ext.operation=direct_stream_open, net.protocol=tcp, net.dst_host or ext.dst_ip_primary, net.dst_port, net.src_ip, trace.flow_id=<peer>-><host>:<port>; no adapter protocol labels enter kernel metadata
  - PipelineRuntime, when attached via with_pipeline, is the decision source of truth: run_pipeline_event runs before port.open_stream; typed runtime errors fail closed to closing the client with no session
  - verdict projection fails closed on unterminated control flow (Continue/Jump) and on Reject; only terminal Accept(SinkId) becomes a BusSessionRequest; Drop closes the client silently
  - fast path is preserved: with no pipeline attached, TcpIngress stays fixed-target and splice-capable with no pipeline overhead

mesh-bus-ingress-tcp decisions:
  - 0.1.5 (2026-05-15): pipeline-aware direct TCP ingress landed. TcpIngress::with_pipeline(PipelineRuntime) runs run_pipeline_event before port.open_stream; src/event_build.rs projects direct-stream metadata (ext.operation=direct_stream_open), src/verdict_apply.rs projects Verdict onto BusSessionRequest (Accept→target_sink + route_group + schedule_hint; Reject/Continue/Jump deny-close; Drop silent close; runtime error fail-closed). Fast path unchanged when no pipeline attached.
  - 0.1.4 (2026-05-13): adapter-local schema root now rejects unknown fields and names StreamSendHalf::shutdown_write as the client EOF behavior instead of retired raw Frame close semantics.
  - 0.1.3 (2026-05-11): import surface aligned to canonical BusSessionRequest; deprecated SessionRequest alias no longer referenced

handbook:
  ../../docs/handbook/index.html
