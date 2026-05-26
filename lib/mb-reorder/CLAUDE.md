# mb-reorder


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — ReorderBuffer with insert, next_expected, pending_count

local dependencies:
  bytes — Bytes type for zero-copy payloads

handbook links:
  ../../docs/handbook/dataplane-observation.html

mb-reorder decisions:
  - 1.0.0 (2026-05-10): initial implementation — drops duplicates and out-of-window frames; bounded only by remote sender behavior; egress should enforce upper bound on pending_count
