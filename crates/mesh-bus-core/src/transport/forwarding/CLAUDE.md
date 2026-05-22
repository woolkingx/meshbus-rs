# mesh-bus-core.forwarding


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
forwarding governs:
  schema.json — data contract
  types.rs — Rust projection (filled by later tasks)
  data_handle.rs — handlers (filled by later tasks)
  tests.rs — domain-local tests

forwarding owns:
  L4 metadata, capability matching, rank context, schedule decision, measurements, and path dispatch data

forwarding decisions:
  - 0.1.0 (2026-05-11): skeleton created; types/handlers move here in subsequent tasks
