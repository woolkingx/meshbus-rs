# mesh-bus-resolver

mesh-bus-resolver role:
  DNS client + cache component — resolves names for pipeline hooks and other bus consumers without exposing a DNS listener or server surface
  three modes share one ResolverHandle trait: M1 tunneled (RFC 7766 over BusStreamSession), M2 mesh-direct (RFC 1035 UDP over BusDatagramSession), M3 system (libc::getaddrinfo on tokio blocking pool)
  reuses mb-rule as policy primitive; projects RuleDecision onto (pool, route_group, schedule_hint); mode-internal upstream selection is server_policy (RoundRobin / ConsistentHash / FanOut)
  emits ResolutionSignals on every answer; bus-core never imports this type
  M0 invariant: legacy SOCKS5 CONNECT-by-hostname continues unchanged without resolver policy; pipeline runtime may reach resolver through mesh-bus-pipeline-hooks

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mesh-bus-resolver governs:
  src/lib.rs — public surface (ResolverHandle trait, ResolverBuilder, re-exports from types)
  src/types.rs — Pool, PoolMode, ServerPolicy, ResolveRequest, ResolveAnswer, ResolveError, ResolverSource, ResolutionSignals, ConsumerId
  src/data_handle.rs — ResolverConfig validation, RuleChain hook, RFC 6761 special-use short-circuit, RFC 6303 PTR forwarding to M3
  src/rule.rs — build_rule_ctx(req) + apply_decision (mirrors mesh-bus-ingress-socks5/src/action_apply.rs)
  src/policy.rs — server_policy fan-in (RoundRobin counter, ConsistentHash{qname.lower}, FanOut{k} race)
  src/m1.rs — tunneled mode: per-(server, route_group) BusStreamSession cache, RFC 7766 framing
  src/m2.rs — mesh-direct: BusDatagramSession + random TXID + random source port via session affinity, RFC 5452 TXID match
  src/m3.rs — system mode: tokio spawn_blocking + libc::getaddrinfo wrapper
  src/signals.rs — ResolutionSignals builder + access-log emission (targets: mesh_bus.resolver.open, mesh_bus.resolver.denied)
  tests/{config_validate,ctx_build,rule_chain,policy,m3_system,m2_mesh_direct,m1_tunneled,signals,application_boundary}.rs

mesh-bus-resolver depends_on:
  mesh-bus-core — BusPort, BusSessionRequest, BusStreamSession, BusDatagramSession, BusSessionInfo (canonical surface only)
  mb-proto-dns — wire codec + RFC 7766 framing helpers
  mb-rule — Action, RuleCtx, evaluate_with_trace, RuleDecision
  mb-endpoint — IpAddr / SocketAddr
  tokio — runtime + spawn_blocking
  tracing — structured access logs

mesh-bus-resolver invariants:
  - this crate is an outbound DNS client/cache and resolver policy engine only; it must not bind port 53, expose a DNS listener, or become a bus ingress adapter
  - never imports mesh_bus_core::{Frame, FrameKind, EgressPlugin, SchedulerPlugin, ScheduleDecision, RankContext}
  - mesh-bus-core never depends on resolver or DNS concepts; application adapters may reach resolver through mesh-bus-pipeline-hooks when the event pipeline includes `net.resolve_or_recover`
  - decode never panics; every wire error maps to ResolveError variant
  - RFC 6761 special-use names short-circuit before any network IO:
      "localhost." -> [127.0.0.1, ::1]; "*.localhost" -> same; "*.invalid" -> NXDOMAIN; "*.test" / "*.example" -> NXDOMAIN unless an explicit override pool resolves them
  - RFC 6303 reverse zones (10.in-addr.arpa, 168.192.in-addr.arpa, 16-31.172.in-addr.arpa, 254.169.in-addr.arpa, fc/fd) forward to M3 system mode regardless of selected pool
  - M2 TXID is generated from a CSPRNG (getrandom or tokio::task_local rand); source port is randomized via per-query BusDatagramSession open (RFC 5452 §9)
  - M1 connection cache key is (server_socket_addr, route_group) so a route_group flip forces a fresh upstream connection
  - ResolverHandle trait is the only public async entry point; callers do not see modes
  - ResolutionSignals is produced for every successful or failed answer; bus-core source tree must contain zero occurrences of the identifier `ResolutionSignals`

mesh-bus-resolver decisions:
  - 0.1.5 (2026-05-13): application_boundary now guards against listener/ingress surface tokens (`TcpListener`, `UdpSocket::bind`, `IngressPlugin`) so resolver remains DNS client/cache only.
  - 0.1.4 (2026-05-13): CLAUDE role reframed from L7 edge participant to DNS client/cache component; port-53 listener/server scope is explicitly forbidden and DNS enrichment reaches runtime through pipeline hooks.
  - 0.1.3 (2026-05-12): B4 — M1 Tunneled (RFC 7766 TCP) path landed. m1.rs implements StreamOpener trait (blanket impl on BusPort), ConnCache keyed by (server_socket_addr, route_group) over `Mutex<HashMap<.., Arc<Mutex<CachedConn>>>>` so repeated queries reuse the same BusStreamSession; per-shot single_shot_tcp wraps RFC 1035 query in RFC 7766 length-prefix frame via mb_proto_dns::framing::write_tcp_frame, awaits one full reply frame via try_read_tcp_frame loop, validates TXID + QNAME (RFC 5452 + RFC 4343). Failure modes (timeout, send error, recv error, frame parse failure, TXID/QNAME mismatch) all evict the cache entry so the next call reopens. resolve_tunneled dispatches by ServerPolicy (RR/CH single shot, FanOut iterates sequentially and picks first Ok). Shared DNS wire helpers extracted from m2.rs into new dns_wire.rs module (build_query, qtype_to_dns, validate_reply, rdata_to_answer, normalize_qname) — both m1 and m2 use them. data_handle.rs Tunneled arm routes through resolve_tunneled + apply_m1_result; ResolverBuilder gains with_stream_opener(Arc<dyn StreamOpener>); Resolver holds Option<Arc<dyn StreamOpener>> + Arc<ConnCache>. apply_m2_result / apply_m1_result share inner apply_telemetry via a small TelemetryCommon shim. tests/m1_tunneled.rs (12 cases): mock backed by mpsc<Bytes> channel pair, send half decodes the framed query and writes the framed reply on the recv channel. Covers single-shot success, two-query cached connection reuse, RR cycle across 3 servers, RFC 5452 TXID + QNAME rejection, timeout, empty pool, FanOut first-wins / second-wins-when-first-silent / all-silent, missing-opener error, and ReplyThenClose to assert the cached-conn-closed path surfaces Io and the cache evicts so the subsequent call reopens. Workspace gates green.

handbook:
  ../../docs/handbook/index.html
