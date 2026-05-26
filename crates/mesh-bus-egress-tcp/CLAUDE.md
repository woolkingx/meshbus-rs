# mesh-bus-egress-tcp


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-egress-tcp implements:
  StreamEgress — TCP target factory; each StreamSession owns one TCP connection

owned files:
  src/lib.rs — TcpEgress factory plus per-session split send/recv halves; send writes client bytes, recv returns upstream chunks; with_fixed_target(Endpoint) pins the dial endpoint so the session ignores request.target (used by service-sink egress for reverse stream)
  tests/echo.rs — stream conformance, echo server roundtrip, large response streaming, delayed-reader backpressure smoke, and timeout failure tests

local dependencies:
  mesh-bus-core — StreamEgress, StreamSession, StreamSendHalf, StreamRecvHalf, SessionInfo
  mb-endpoint — Endpoint type
  tokio — async TCP, timeouts

mesh-bus-egress-tcp decisions:
  - 0.1.13 (2026-05-16): TcpEgress gains with_fixed_target(Endpoint). When set, open_stream dials the fixed endpoint and ignores request.target; request.target stays as service-intent metadata only. This is the DRY substrate for mesh-bus-egress-service reverse stream service sinks — no duplicated TCP session machinery.
  - 0.1.12 (2026-05-14): per-session upstream read_returns queue raised from 64 to 256 frames to reduce reader stalls while SOCKS5 CONNECT relay runs upload/download as independent spawned direction tasks. This is still bounded backpressure, not an unbounded buffer.
  - 0.1.11 (2026-05-13): TcpStreamSession now sets TCP_NODELAY on the outbound socket after connect. Loopback request/response throughput jumped ~50x because Nagle + delayed-ACK had been throttling small writes.

handbook:
  ../../docs/handbook/index.html
