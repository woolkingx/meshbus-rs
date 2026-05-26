# mb-pool


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — ConnectionFactory trait, Pool, Pooled, PoolError, Slot

local dependencies:
  tokio — async runtime and Mutex
  async-trait — async fn in trait definitions
  thiserror — PoolError derive

handbook links:
  ../../docs/handbook/system-architecture.html

mb-pool decisions:
  - 1.0.0 (2026-05-10): initial implementation — generic per-key connection pool; idle eviction by timestamp; bounded per-key; Drop returns conn via spawned Tokio task (idiomatic Tokio pattern)
