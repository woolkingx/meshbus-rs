# mb-cake


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — ExitMetric, RankConfig, rank() pure function

local dependencies:
  mb-cost — Score and ScoreInputs
  mb-loadbalance — Candidate (type reference)

handbook links:
  ../../docs/handbook/dataplane-observation.html

mb-cake decisions:
  - 1.0.0 (2026-05-10): initial implementation — CAKE ranking composition over Score; pure function, no state
  - 1.1.0 (2026-05-11): rank() takes session_id; equal-score exits sort by fxhash(session_id|exit_id) so ranking is deterministic but distributes equal exits across flows instead of always picking the first
  - 1.2.0 (2026-05-13): ExitMetric carries goodput_bps + capacity_bps, passed into ScoreInputs so CAKE rank reacts to per-exit saturation as well as RTT/jitter/success.
