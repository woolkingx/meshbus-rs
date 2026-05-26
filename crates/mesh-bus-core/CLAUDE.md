# mesh-bus-core

Role: kernel plus reusable L4/L5/L6 transport substrate. It carries opaque
payloads and owns routing/session/observation primitives, but never owns L7
protocol syntax.

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

Read first:
  - ../../docs/handbook/system-architecture.html
  - ../../docs/handbook/dataplane-observation.html
  - ../../docs/handbook/testing-gates.html
  - schema.json
  - test.html

Owned surfaces:
  - src/kernel/ — Event, TypedMap, Hook, Pipeline, Verdict, KernelRegistry, observation, runtime dispatch.
  - src/transport/forwarding/ — L4 capability matching, scheduling inputs, dispatch shape.
  - src/transport/session/ — L5 stream/datagram session identity, lifecycle, close reasons, path info.
  - src/transport/transform/ — L6 transform metadata and validation only.
  - src/transport/udp_loop/ — UDP packet-loop substrate, batching, PMTU, pacing, path stats.
  - src/*_tests.rs and tests/ — owner/integration proof over the real public boundary.

Boundary rules:
  - No SOCKS5, HTTP, DNS wire parsing, QUIC channel truth, URL, SNI, or app payload inspection in core.
  - Frame.payload is opaque bytes; lower owners may copy, forward, dedup, reorder, or count bytes only through declared PCI.
  - External ingress/egress crates use BusPort and L5 session/factory traits, not Frame/FrameKind runtime internals.
  - route_group is an L4 candidate-filter label, never a PipelineId.
  - UDP loop drains are packet-owner boundaries; do not reintroduce payload-aware peek/restore.

Local proof:
  - cargo test -p mesh-bus-core --lib
  - cargo test -p mesh-bus-core --test dispatch_fixture_runner
  - cargo test -p mesh-bus-core --test boundary_guard
  - node ../../tools/flowgraph.mjs --out-dir ../../artifacts/flowgraph

Latest decision pointers:
  - 2026-05-25: restore_inbound_front removed; QueueFull is the L5 typed backpressure reason.
  - 2026-05-18: dispatch proof uses the real BusBuilder boundary, not a fake JSON runtime.

handbook:
  ../../docs/handbook/index.html
