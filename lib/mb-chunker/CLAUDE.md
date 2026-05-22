# mb-chunker


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mb-chunker governs:
  src/lib.rs — Chunk struct, Chunker with next_frame

mb-chunker depends_on:
  bytes — Bytes type for zero-copy payloads

mb-chunker extends:
  ../../docs/handbook/dataplane-observation.html

mb-chunker decisions:
  - 1.0.0 (2026-05-10): initial implementation — sequence assignment for stream chunks; no buffering, no protocol awareness
