# mesh-bus-ingress-udp


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-ingress-udp governs:
  src/lib.rs — UdpIngress datagram listener using DatagramSession send_to/recv_from; optional PipelineRuntime decision per new peer before port.open_datagram
  src/event_build.rs — direct-datagram peer projection into Event TypedMap (ext.operation=direct_datagram_send, generic L4 metadata only)
  src/verdict_apply.rs — Verdict + post-run Event projection into BusSessionRequest::datagram (Accept→target_sink, Reject/Continue/Jump→deny, Drop→silent skip)
  tests/listen.rs — UDP ingress to UDP egress echo behavior
  tests/schema.rs — adapter schema boundary and datagram-boundary contract guard

mesh-bus-ingress-udp depends_on:
  mesh-bus-core
  mesh-bus-pipeline-hooks — optional PipelineRuntime decision path consumed by the direct datagram source adapter
  mb-endpoint
  tokio
  async-trait
  tracing

mesh-bus-ingress-udp invariants:
  - UDP ingress is an L4 edge adapter: socket datagram to DatagramSession send_to
  - each socket recv_from maps to exactly one DatagramSession::send_to; this adapter must not split, coalesce, or parse payload boundaries
  - it sets Datagram and PacketDedup semantics but does not inspect application payload
  - any DNS, QUIC, or custom protocol parsing must live in a separate protocol-aware plugin, not here

mesh-bus-ingress-udp invariants:
  - main recv loop only calls send half; never calls recv_from on any session
  - per-peer UdpPeerSession holds send half under Mutex; plain HashMap tracks peers (single-task recv loop)
  - response pump task holds recv half and writes encoded responses back to peer socket
  - first datagram from a new peer: decide_request → open_datagram → split → spawn pump → insert into peer_sessions

mesh-bus-ingress-udp invariants:
  - direct datagram source adapter: L7-free native source; builds protocol-neutral Event metadata and consumes the Bus L5 datagram session surface only, never Frame/FrameKind/EgressPlugin
  - event projection fills ext.operation=direct_datagram_send, net.protocol=udp, net.dst_host or ext.dst_ip_primary, net.dst_port, net.src_ip, trace.flow_id=<peer>-><host>:<port>; no adapter protocol labels enter kernel metadata
  - PipelineRuntime, when attached via with_pipeline, is the decision source of truth: run_pipeline_event runs once per new peer before port.open_datagram; typed runtime errors fail closed to skipping the datagram with no session
  - verdict projection fails closed on unterminated control flow (Continue/Jump) and on Reject; only terminal Accept(SinkId) becomes a BusSessionRequest::datagram; Drop skips the datagram silently
  - fast path is preserved: with no pipeline attached, UdpIngress stays fixed-target with no pipeline overhead

mesh-bus-ingress-udp decisions:
  - 0.1.4 (2026-05-13): schema now names the UDP ingress datagram-boundary contract (`one-recv-one-send`) and guards it with tests/schema.rs
  - 0.1.5 (2026-05-14): split send loop from response pump. Per-peer UdpPeerSession holds BusDatagramSendHalf under Mutex; spawn_response_pump holds BusDatagramRecvHalf in a dedicated task. Main recv loop never blocks on egress response, enabling concurrent multi-peer and multi-datagram throughput.
  - 0.1.6 (2026-05-16): pipeline-aware direct UDP datagram forward landed (M6). UdpIngress::with_pipeline(PipelineRuntime) runs run_pipeline_event once per new peer before port.open_datagram; src/event_build.rs projects direct-datagram metadata (ext.operation=direct_datagram_send, net.protocol=udp), src/verdict_apply.rs projects Verdict onto BusSessionRequest::datagram (Accept→target_sink + route_group + schedule_hint; Reject/Continue/Jump skip; Drop silent skip; runtime error fail-closed). Fast path unchanged when no pipeline attached.

handbook:
  ../../docs/handbook/index.html
