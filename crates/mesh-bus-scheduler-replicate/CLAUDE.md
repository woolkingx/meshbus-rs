# mesh-bus-scheduler-replicate


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — ReplicateScheduler
  tests/replicate.rs — scheduler decision and UDP datagram replicate demo
  tests/schema.rs — schema closure and generic candidate fan-out wording guard

local dependencies:
  mesh-bus-core — SchedulerPlugin, ScheduleDecision

boundary rules:
  - scheduler decisions are metadata-only and never inspect Frame.payload
  - ReplicateScheduler is a forwarding primitive that fans out to all candidate egresses
  - datagram replicate demo proves fan-out plus PacketDedup without adding protocol knowledge to core

mesh-bus-scheduler-replicate decisions:
  - 0.1.0 (2026-05-10): always returns ScheduleDecision::Replicate over all candidates; intended as a primitive/demo scheduler, not a QoS policy engine
  - 0.1.1 (2026-05-10): module documented as an L4 forwarding-plane fan-out primitive
  - 0.1.2 (2026-05-13): schema wording now describes generic metadata-only candidate fan-out instead of narrowing Replicate to packet/datagram language

handbook:
  ../../docs/handbook/index.html
