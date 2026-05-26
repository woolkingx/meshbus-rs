# mesh-bus-ingress-socks5

Role: L7 SOCKS5 application source adapter. It parses SOCKS5 syntax, projects
intent into protocol-neutral bus metadata/session requests, and relays opaque
bytes through the Bus L5 session surface.

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

Read first:
  - ../../docs/handbook/compatibility.html
  - ../../docs/handbook/system-architecture.html
  - ../../docs/handbook/testing-gates.html
  - schema.json
  - test.html

Owned surfaces:
  - src/lib.rs — Socks5Ingress and connection dispatch.
  - src/auth.rs — method negotiation and RFC1929 user/pass auth.
  - src/connect.rs — CONNECT stream open, reply mapping, splice/fallback relay.
  - src/udp_assoc.rs — UDP ASSOCIATE relay and per-target datagram sessions.
  - src/bind.rs — SOCKS5 BIND local relay.
  - src/event_build.rs, src/verdict_apply.rs, src/action_apply.rs, src/rule_ctx_build.rs — pipeline and legacy policy projection.
  - tests/ — RFC behavior, pipeline, access log, auth, rule, and UDP proof.

Boundary rules:
  - This crate may import mb-proto-socks5 and Bus L5 surfaces; it must not construct Frame/FrameKind/EgressPlugin.
  - CONNECT opens one StreamSession, then relays opaque bytes.
  - UDP ASSOCIATE makes the target-bearing decision per UDP relay packet, not at control open.
  - PipelineRuntime, when attached, is the decision source of truth and fails closed on typed runtime errors.
  - BIND is local relay behavior, not a BusSessionRequest egress session.

Local proof:
  - cargo test -p mesh-bus-ingress-socks5
  - cargo test -p mesh-bus-ingress-socks5 --test handshake
  - cargo test -p mesh-bus-ingress-socks5 --test udp_associate
  - cargo test -p mesh-bus-ingress-socks5 --test application_boundary

Latest decision pointers:
  - 2026-05-15: GSSAPI remains explicit default-off feature-gated unsupported negotiation.
  - 2026-05-14: UDP ASSOCIATE per-target response pump is send-only on the forward path.

handbook:
  ../../docs/handbook/index.html
