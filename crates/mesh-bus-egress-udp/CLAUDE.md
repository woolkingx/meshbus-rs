# mesh-bus-egress-udp


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-egress-udp governs:
  src/lib.rs — UdpEgress DatagramEgress factory; each DatagramSession preserves one send_to/recv_from packet boundary
  tests/echo.rs — UDP datagram conformance and echo egress behavior

mesh-bus-egress-udp depends_on:
  mesh-bus-core
  mb-endpoint
  tokio
  async-trait

mesh-bus-egress-udp invariants:
  - UDP egress is an L4 edge adapter: opaque DatagramSession payload to one UDP datagram
  - fixed-target mode is service-sink plumbing only: request.target remains intent metadata, while send_to emits to the configured endpoint
  - it may measure timeout and response bytes, but must not decode application payload
  - protocol-specific UDP behavior belongs in a separate plugin layered at the edge

mesh-bus-egress-udp decisions:
  - 0.1.8 (2026-05-20): UdpEgress gains with_fixed_target(Endpoint) for UDP reverse service sinks. This preserves the one-send-one-datagram RFC768 boundary while letting ServiceUdpEgress ignore request.target and send to the configured service endpoint.
  - 0.1.7 (2026-05-14): persistent socket session and split halves. open_datagram now binds one UdpSocket once; send_to fires without waiting for response. split() consumes the session into UdpDatagramSendHalf (fire-and-forget send) + UdpDatagramRecvHalf (blocking recv loop), both backed by Arc<UdpSocket>. VecDeque pending queue and send_one helper removed.
  - 0.1.6 (2026-05-13): adapter-local schema now names the one-send-one-datagram boundary and schema tests guard datagram-only capability markers.
  - 0.1.5 (2026-05-11): UdpEgress gains with_groups(Vec<String>) builder so route_group filter membership is settable from runtime YAML
  - 0.1.4 (2026-05-11): import surface aligned to canonical Bus* names (BusSessionRequest/BusSessionInfo); deprecated aliases no longer referenced

handbook:
  ../../docs/handbook/index.html
