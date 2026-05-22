# mesh-bus-observer-metrics


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-observer-metrics implements:
  ObserverPlugin — dispatch counter

mesh-bus-observer-metrics governs:
  src/lib.rs — CounterObserver; increments per-exit counter on BusEvent::Core FlowOpened envelopes
  tests/counter.rs — two events on same exit produce count 2
  tests/schema.rs — no-runtime-config schema closure guard

mesh-bus-observer-metrics depends_on:
  mesh-bus-core — ObserverPlugin, BusEvent, EventEnvelope/CoreEventId
  tokio — async Mutex for interior mutability

mesh-bus-observer-metrics invariants:
  - observer consumes BusEvent after dispatch; it must not affect scheduling, routing, pipeline verdicts, or transport execution
  - CounterObserver has no runtime config surface; schema root is closed and construction stays CounterObserver::new()

mesh-bus-observer-metrics decisions:
  - 0.1.0 (2026-05-10): dispatch counter only; snapshot() returns a clone; no prometheus integration yet
  - 0.1.1 (2026-05-13): schema root now rejects unknown runtime config fields because CounterObserver has no runtime config surface
  - 0.1.2 (2026-05-14): CounterObserver consumes Core(FlowOpened) observation envelopes; legacy DispatchResult is retired

handbook:
  ../../docs/handbook/index.html
