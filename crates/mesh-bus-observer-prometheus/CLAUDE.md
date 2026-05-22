# mesh-bus-observer-prometheus


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-observer-prometheus implements:
  ObserverPlugin — Prometheus textfile and HTTP exporter for core flow/path observation telemetry

mesh-bus-observer-prometheus governs:
  src/lib.rs — PrometheusTextfileObserver; writes or serves per-exit dispatch counters, RTT gauge, byte counter, success-rate gauge, optional wan_id label, and optional per-sink peer labels (node_id/peer_id/path_id/hop_count)
  schema.json — config surface: kind=PrometheusTextfile/path or kind=PrometheusHttp/listen, with Prometheus-valid static label names
  tests/schema.rs — config schema closure and static-label-name guard

mesh-bus-observer-prometheus depends_on:
  mesh-bus-core — ObserverPlugin, BusEvent, Measurement, EventEnvelope/CoreEventId

mesh-bus-observer-prometheus invariants:
  - observer is IO-only; it never affects scheduling or dispatch order
  - throughput is exported as cumulative bytes; Prometheus computes rates with rate()
  - wan_id labels come from runtime egress config and are never inferred from protocol data
  - peer labels (node_id/peer_id/path_id/hop_count) are static per configured egress sink and come from runtime node/peer config; they are never derived from Mesh Protocol payload, so core stays payload-opaque
  - node_id is emitted for every sink when node config is present; peer_id/path_id/hop_count are emitted only for configured mesh-peer egress sinks (hop_count=1 for a direct adjacent peer)
  - configured static label keys must be valid Prometheus label names (`^[A-Za-z_][A-Za-z0-9_]*$`)
  - writes use a temporary sibling file followed by rename so node_exporter never reads partial metrics
  - HTTP mode serves only GET /metrics and shares the same in-memory counters as textfile mode

mesh-bus-observer-prometheus decisions:
  - 0.1.5 (2026-05-14): Prometheus observer consumes Core FlowOpened/FlowClosed/PathIoError envelopes; legacy DispatchResult is retired
  - 0.1.6 (2026-05-15): per-sink peer labels added — with_peer_labels() carries node_id/peer_id/path_id/hop_count from runtime node/peer config into every metric family alongside wan_id; labels stay static-per-sink so the observer never parses Mesh Protocol payload
  - 0.1.7 (2026-05-17): on_event forwards only FlowOpened|PathIoError; FlowClosed is dropped because it is the terminal lifecycle of an already-counted FlowOpened (zero new bytes/RTT) and forwarding it double-counted mesh_bus_dispatch_total; success default folds to FlowOpened so dispatch_total == dispatch_success_total + dispatch_failure_total

handbook:
  ../../docs/handbook/index.html
