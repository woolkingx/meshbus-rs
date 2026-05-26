# mesh-bus-runtime

Role: operator config to verified runtime assembly. Runtime wires sources,
sinks, hooks, schedulers, observers, and plugins; it does not own protocol
payload semantics.

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

Read first:
  - ../../docs/handbook/system-architecture.html
  - ../../docs/handbook/operator-plane.html
  - ../../docs/handbook/production-readiness.html
  - schema.json
  - test.html

Owned surfaces:
  - src/config.rs and src/config/ — deserialized operator config shape.
  - src/config_validate.rs — startup validation and production-shape guards.
  - src/pipeline.rs — selected application source to verified PipelineRuntime.
  - src/lib.rs — run/status_text composition and plugin spawning.
  - tests/config.rs and tests/pipeline_assembly.rs — config/schema/runtime assembly proof.

Boundary rules:
  - schema.json and serde config structs must stay in lockstep.
  - Runtime may depend on protocol plugins because it composes them; core must not.
  - Pipeline source selection is operator data; ambiguous source selection fails closed.
  - Egress id is the operator projection of SinkId and must pass core id shape before registration.
  - Metrics and labels are observation/config data only; they must not feed routing decisions directly.
  - MeshPeer delivery policy is per-egress delivery-coordinate config, not Mesh Protocol payload parsing.

Local proof:
  - cargo test -p mesh-bus-runtime
  - cargo test -p mesh-bus-runtime --test config
  - cargo test -p mesh-bus-runtime --test pipeline_assembly
  - node ../../docs/handbook/handbook-gate.mjs

Latest decision pointers:
  - 2026-05-18: config proof uses fixture rows over real parse_config/run.
  - 2026-05-18: MeshPeerUdp delivery policy config defaults to steer and stays delivery-coordinate only.

handbook:
  ../../docs/handbook/index.html
