# mesh-bus-ingress-socks5

mesh-bus-ingress-socks5 role:
  L7 adapter — first application source adapter instance; thin stitcher of L6 content + L5 control + L4 transport per layer-model §2.4
  L6 content: SOCKS5 wire format via mb-proto-socks5 (greeting/request/reply, UDP relay datagram)
  L5 control: BusPort + BusSessionRequest stream/datagram, open_stream/open_datagram, DisconnectReason, half-close
  L4 transport: opaque payload bytes flow through the bus kernel; this crate never constructs Frame/FrameKind/EgressPlugin
  the adapter parses just enough wire format to choose a session shape and feed metadata; routing/health/load-balance/dedup are L4 services it consumes, not features it owns

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mesh-bus-ingress-socks5 implements:
  IngressPlugin — SOCKS5 source adapter; an instance of the generic application-source contract, not a mesh-bus-core primitive

mesh-bus-ingress-socks5 governs:
  src/lib.rs — Socks5Ingress; greeting + CONNECT via mb-proto-socks5 to ByteStream; UDP ASSOCIATE relay to Datagram; BIND dispatched to src/bind.rs; GSSAPI_SUPPORTED gate (default-off `gssapi` cargo feature)
  src/bind.rs — SOCKS5 BIND local-relay command: policy/pipeline gate, TCP listener, two RFC1928 replies, IP-only peer match, bidirectional copy
  src/event_build.rs — SOCKS5 CONNECT, BIND, and UDP relay-packet target projection into Event TypedMap for the pipeline path; fills generic ext.operation
  src/verdict_apply.rs — Verdict + post-run Event projection into BusSessionRequest
  src/action_apply.rs — legacy RulePolicy action projection into BusSessionRequest
  src/rule_ctx_build.rs — legacy RulePolicy RuleCtx projection for CONNECT/BIND/UDP; fills generic operation plus legacy socks5_command
  schema.json — adapter-local schema metadata for the SOCKS5 application-source surface
  tests/handshake.rs / tests/udp_associate.rs — full SOCKS5 stream/datagram behavior
  tests/pipeline_connect.rs — consumed PipelineRuntime path and Accept(SinkId) pinning
  tests/access_log.rs / tests/auth.rs / tests/rule_chain.rs — decision trace, RFC1929 auth, legacy policy compatibility

mesh-bus-ingress-socks5 depends_on:
  mesh-bus-core — IngressPlugin, BusPort, StreamSession, DatagramSession, DisconnectReason
  mesh-bus-pipeline-hooks — optional PipelineRuntime decision path consumed by the source adapter
  mb-proto-socks5 — decode_greeting, decode_request, UDP relay datagram codec, encode_reply
  mb-chunker — monotonic sequence assignment
  mb-geoip / mb-geosite / mesh-bus-resolver — test fixture dependencies for SharedHookCtx in pipeline_connect
  tokio — async TCP accept loop, UDP relay socket, split read/write

mesh-bus-ingress-socks5 invariants:
  - L7 stitcher boundary: code in this crate may import mb-proto-socks5 (L6 codec) and canonical Bus* L5 session surface only; it must never reference mesh-bus-core::Frame, FrameKind, EgressPlugin, SchedulerPlugin, or any L4 internal type
  - SOCKS5 parsing is edge-only L7 adaptation; SOCKS5 code uses Bus L5 session surface (BusStreamSession/BusDatagramSession) and never raw Frame
  - live-ingress command/auth support is the `live_ingress_commands` (Connect/Bind/UdpAssociate) and `live_ingress_auth` (NoAuth/UserPass) columns of `lib/mb-proto-socks5/schema.json` `command_auth_matrix`; that matrix is the single contract source and this crate must not diverge from it
  - greeting negotiation accepts only clients that explicitly offer NoAuth (no AuthConfig) or UserPass (AuthConfig set); a client offering neither receives 0x05 0xff and is closed
  - GSSAPI (SOCKS5 method 0x01) is never negotiated: it is gated behind the default-off `gssapi` cargo feature with no authenticator backend in any shipped build; `GSSAPI_SUPPORTED` reflects that build feature; a GSSAPI-only greeting takes the documented RFC1928 0x05 0xff no-acceptable-methods reject path, a greeting that also offers a supported method negotiates that method normally
  - CONNECT opens a StreamSession, maps typed DisconnectReason to an RFC1928 REP before sending Succeeded, then attempts Linux TCP splice for splice-capable sessions before falling back to split send/recv halves
  - CONNECT fallback relay owns the accepted TCP halves with TcpStream::into_split and spawns independent upload/download direction tasks; upload keeps a 16 KiB read buffer because the 64 KiB trial regressed loopback throughput
  - CONNECT success replies use session.info().paths[primary].local as RFC1928 BND.ADDR/BND.PORT when the selected egress reports it
  - CONNECT client write EOF sends StreamSendHalf::shutdown_write and keeps the downstream read side open until upstream FIN
  - UDP ASSOCIATE maps each SOCKS5 UDP relay packet through DatagramSession::send_to/recv_from and wraps one returned datagram back into a SOCKS5 UDP relay packet
  - UDP ASSOCIATE high-throughput asynchronous response pumping: per-target send half held under Mutex inside UdpAssocTargetState; spawned recv pump holds recv half and encodes SOCKS5 UDP relay frames back to the client socket; forward path is send-only with no lockstep recv
  - PipelineRuntime forward decisions for UDP are per relay packet because only packets carry the real target; UDP ASSOCIATE control opens the relay and must not run the target-bearing forward pipeline
  - UDP ASSOCIATE accepts datagrams only from the declared UDP peer for that association
  - UDP ASSOCIATE reuses one bus session per target inside the association so flow_id affinity remains meaningful
  - PipelineRuntime, when present, is the decision source of truth and supersedes legacy RulePolicy for that ingress; the type is owned by mesh-bus-pipeline-hooks, not this adapter; typed runtime errors are logged and fail closed to protocol failure/no session
  - PipelineRuntime test fixtures must model the same generic kernel contract as runtime assembly: neutral `SourceId` such as `ingress:0`, source kind `application/source`, and stream/datagram sink kinds rather than SOCKS5-shaped registry identities
  - pipeline verdict projection fails closed on unterminated control flow (`Continue` / `Jump`); only terminal `Accept(SinkId)` can become a BusSessionRequest; `Reject` maps to protocol denial, while `Drop` remains a silent close/drop per kernel verdict semantics
  - pipeline verdict projection maps absent `transport.schedule_hint` to core `ScheduleHint::Auto`; `ScheduleHintLabel::FanOut` must preserve `transport.schedule_fanout_k`; FanOut without that payload fails closed
  - pipeline Event projection fills `ext.operation` as generic source-operation metadata (`connect`, `datagram_send`) and `net.protocol` as L4 transport family (`tcp` / `udp`) only; it must never write adapter labels or SOCKS5 control command names such as `socks5` / `udp_associate` into kernel metadata; legacy RulePolicy fills mb-rule `operation` with generic names (`connect`, `datagram_associate`, `datagram_send`), while `socks5_command` is retained only for compatibility with existing chains
  - legacy RulePolicy action projection fails closed for mb-rule actions it cannot map onto BusSessionRequest; resolver-pool, transform, and future unknown actions must not become no-op allows
  - legacy RulePolicy exposes the same action-surface validator for runtime/bin preflight; startup checks and traffic-time projection must not diverge
  - BIND is a client-facing local-relay command, not a bus egress session: the adapter opens a local TCP listener, sends the listener endpoint as the first RFC1928 reply, accepts exactly one inbound peer (v1 single-accept), sends the accepted peer endpoint as the second reply, then bidirectionally copies bytes between the original SOCKS5 control TCP and the accepted peer TCP; no BusSessionRequest is opened
  - BIND is policy/pipeline gated for Allow/Deny/Drop only; the projected BusSessionRequest from apply_verdict/apply_decision is discarded; pipeline runtime error fails closed to REP 0x01 GeneralFailure, pipeline/rule Deny replies REP 0x02 ConnectionNotAllowed, Drop closes silently
  - BIND wrong-peer rejection is IP-only because the connecting peer source port is ephemeral: unspecified declared IP or declared port 0 accepts any source; a specific declared IP requires the connecting IP to match; a declared hostname (non-IP) accepts any
  - BIND accept timeout reuses handshake_timeout; on timeout the second reply is REP 0x06 TtlExpired and the connection closes
  - CONNECT success emits adapter access logs as `connect_open` plus `flow_opened`; `flow_opened` mirrors selected exit, flow_id, route_group, schedule_hint, and success without depending on retired kernel DispatchResult events

mesh-bus-ingress-socks5 decisions:
  - 0.1.46 (2026-05-15): GSSAPI feature gate landed as the explicit full-RFC posture. SOCKS5 method 0x01 is codec-recognized but never negotiated; it is gated behind a default-off `gssapi` cargo feature with no authenticator backend, exposed as `pub const GSSAPI_SUPPORTED = cfg!(feature = "gssapi")`. A GSSAPI-only greeting takes the RFC1928 0x05 0xff no-acceptable-methods reject path (with a distinct `socks5_gssapi_unsupported` debug log); a greeting that also offers NoAuth/UserPass negotiates that method normally. Resolves the discussion gate: full RFC release is "full except an explicit, reserved, feature-gated GSSAPI capability", which is RFC1928-compliant subset behavior. Documented in schema.json `gssapi_gate` / `auth_methods` and lib/mb-proto-socks5 `gssapi_status`.
  - 0.1.45 (2026-05-15): SOCKS5 BIND landed as a client-facing local-relay command in src/bind.rs. The adapter opens a local TCP listener, sends the listener endpoint as the first RFC1928 reply, accepts exactly one inbound peer (v1 single-accept), sends the accepted peer endpoint as the second reply, then bidirectionally copies bytes between the original SOCKS5 control TCP and the accepted peer TCP. No BusSessionRequest is opened; BIND is policy/pipeline gated for Allow/Deny/Drop/Fail only and the projected request is discarded. Wrong-peer rejection is IP-only because the source port is ephemeral. Accept timeout reuses handshake_timeout and replies REP 0x06 TtlExpired; pipeline runtime error fails closed to REP 0x01.
  - 0.1.44 (2026-05-14): UDP ASSOCIATE per-target response pump landed. Each unique target inside one association gets a UdpAssocTargetState holding a BusDatagramSendHalf (Mutex) and a spawned recv pump task holding BusDatagramRecvHalf. Forward path calls send half only; recv pump encodes SOCKS5 UDP relay frames back to the client socket without blocking the forward loop.

handbook:
  ../../docs/handbook/index.html
