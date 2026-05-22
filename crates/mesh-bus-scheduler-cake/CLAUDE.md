# mesh-bus-scheduler-cake


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-scheduler-cake implements:
  SchedulerPlugin — CAKE-based exit ranking

mesh-bus-scheduler-cake governs:
  src/lib.rs — CakeScheduler; per-exit HealthWindow, mb-cake rank on feedback
  tests/cake.rs — low-RTT ranked first, unknown exits fall through
  tests/feedback_goodput.rs — goodput_bps_for + score_for live window coverage
  tests/schema.rs — schema closure and metadata-only wording guard

mesh-bus-scheduler-cake depends_on:
  mesh-bus-core — SchedulerPlugin, RankContext, ExitId, ExitResult, FlowId, TrafficClass
  mb-health — HealthWindow (sliding-window RTT and success rate)
  mb-cake — rank() pure function, ExitMetric, RankConfig
  mb-cost — Score, ScoreInputs (score_for implementation)

mesh-bus-scheduler-cake invariants:
  - CAKE ranks exits from L4 metadata and feedback windows only
  - CAKE must not inspect Frame.payload or protocol-specific fields
  - protocol-specific routing belongs in edge plugins or future metadata producers, not in this scheduler

mesh-bus-scheduler-cake decisions:
  - 0.1.8 (2026-05-14): unknown exits use an optimistic provisional RTT for exploration. This keeps CAKE convergence working when direct Forwarder streams report scheduler feedback at flow-open/lifecycle cadence instead of per Data chunk.
  - 0.1.4 (2026-05-10): scheduler documented as metadata-only ranking for the L4 forwarding plane
  - 0.1.5 (2026-05-11): jitter now sampled from HealthWindow MAD instead of hardcoded 0; mb-cake rank uses fxhash(session_id|exit_id) tiebreaker so equal-score exits no longer all collapse onto the first candidate
  - 0.1.6 (2026-05-13): schema root is closed and flow/return semantics are documented as generic L4 placement metadata, not protocol-aware policy inputs
  - 0.1.7 (2026-05-13): CakeScheduler records payload bytes into HealthWindow on feedback; score_for and goodput_bps_for expose live window state for kernel hysteresis and observability.

handbook:
  ../../docs/handbook/index.html
