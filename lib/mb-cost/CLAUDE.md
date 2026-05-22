# mb-cost


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mb-cost governs:
  src/lib.rs — ScoreInputs, Score, Score::compute

mb-cost extends:
  ../../docs/handbook/dataplane-observation.html

mb-cost decisions:
  - 1.0.0 (2026-05-10): initial implementation — pure score computation, no state, no I/O; composes ScoreInputs into Score
  - 1.1.0 (2026-05-13): ScoreInputs gains goodput_bps + capacity_bps; saturation_penalty adds 0..10_000 penalty for utilization in [0.7, 1.0]; behavior is identity when capacity_bps is None.
