# mesh-bus-egress-service


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-egress-service implements:
  StreamEgress — local service sink for native direct reverse stream; a source selects a service through the normal scheduler and the data plane opens a local connector
  DatagramEgress — local service sink for native direct reverse datagram; a source selects a service through the normal scheduler and the data plane sends each datagram to the configured UDP endpoint

mesh-bus-egress-service governs:
  src/lib.rs — ServiceTcpEgress and ServiceUdpEgress: scheduler-selectable service sinks that delegate TCP/UDP session machinery to fixed-target egresses and carry a static service_id label
  schema.json — config surface: id, service_id, route_group, groups, connect, timeout_ms
  tests/service.rs — service sinks ignore request.target, use the configured connect endpoint, preserve bytes/datagram payloads, and expose service_id

mesh-bus-egress-service depends_on:
  mesh-bus-core — StreamEgress, DatagramEgress, StreamSession, DatagramSession, BusSessionRequest, BusSessionInfo, Capabilities, ExitId, DisconnectReason
  mesh-bus-egress-tcp — TcpEgress (with_fixed_target substrate; no duplicated TCP session code)
  mesh-bus-egress-udp — UdpEgress (with_fixed_target substrate; no duplicated UDP session code)
  mb-endpoint — Endpoint type

mesh-bus-egress-service invariants:
  - service connect endpoint is configured locally; request.target is service-intent metadata only and never used for the dial
  - this is L4/L5 service selection; no L7 route parsing enters core or scheduler
  - ServiceTcp capability is stream-only (supports_stream=true, supports_datagram=false); ServiceUdp capability is datagram-only (supports_stream=false, supports_datagram=true)
  - service_id is a static per-sink label from runtime config; it is never derived from payload

mesh-bus-egress-service decisions:
  - 0.1.1 (2026-05-20): ServiceUdpEgress added for MVP UDP reverse service. It wraps UdpEgress::with_fixed_target so request.target remains service-intent metadata while each send_to call remains one RFC768 datagram to the configured connect endpoint.
  - 0.1.0 (2026-05-16): crate created for M4 native direct reverse stream service. ServiceTcpEgress wraps TcpEgress::with_fixed_target so the reverse service sink reuses proven TCP session/split/splice machinery instead of duplicating ~250 lines; the only added state is the static service_id label.

handbook:
  ../../docs/handbook/index.html
