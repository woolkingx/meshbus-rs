# mb-health


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mb-health governs:
  src/lib.rs — HealthWindow with sliding-window RTT/outcome aggregation; HealthPolicy and ExitHealthTable for per-exit dispatch health
  tests/window.rs — window aggregation and ExitHealthTable unhealthy/probe/recovery behavior

mb-health depends_on:
  std collections only

mb-health invariants:
  - shared health logic lives here, not in bus core or scheduler plugins
  - ExitHealthTable can mark exits unhealthy after repeated failures and re-admit them for probe after policy delay
  - success clears the unhealthy state so recovery is reachable

mb-health decisions:
  - 0.1.0 (2026-05-10): initial implementation — sliding-window aggregation, no allocation per sample beyond bounded deque
  - 0.1.1 (2026-05-10): HealthPolicy and ExitHealthTable added for shared exit failure/recovery logic
  - 0.1.2 (2026-05-11): HealthWindow::jitter_ms() exposes mean absolute deviation so schedulers can read jitter from the same sliding window as RTT/success
  - 0.2.0 (2026-05-13): HealthWindow gains EWMA mean/jitter (α=1/8) and a bytes window with goodput_bps; arithmetic mean and MAD retired in favor of spike-resistant estimates that ramp in ~3 RTTs.

handbook:
  ../../docs/handbook/index.html
