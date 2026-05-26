# mb-loadbalance


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — Candidate, Wrr (weighted round-robin), Swrr (smooth WRR), ConsistentHash, StickyTable

local dependencies:
  fxhash — stable hashing across runs and Rust versions

handbook links:
  ../../docs/handbook/dataplane-observation.html

mb-loadbalance decisions:
  - 1.0.0 (2026-05-10): initial implementation — WRR, SWRR, ConsistentHash; uses FxHash for stability; no state ownership beyond algorithm cursors; renamed next() to pick() to avoid Iterator trait confusion
  - 1.0.1 (2026-05-10): add StickyTable with TTL expiry and candidate disappearance repick for flow-level sticky scheduling
