# mesh-bus-core.kernel.verdict


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  schema.json    — Verdict, VerdictLabel, PipelineId, SinkId, HookId, SourceId, Reason
  types.rs       — all verdict and id types
  data_handle.rs — label helpers
  tests.rs       — unit tests

verdict decisions:
  - 0.2.3 (2026-05-13): PipelineId and HookId schema now use the same kernel id shape as SourceId/SinkId (`^[A-Za-z0-9_.:-]+$`) so Jump targets and HookTrace ids reject whitespace/slash forms.
  - 0.2.2 (2026-05-13): SinkId schema now uses the same terminal id shape as SourceId (`^[A-Za-z0-9_.:-]+$`) so Verdict::Accept targets cannot contain whitespace/slash ids.
  - 0.2.1 (2026-05-13): schema.json roots at Verdict and closes Reason plus every Verdict variant object with additionalProperties=false; SourceId schema now permits runtime-derived ids such as `ingress:0` while id newtypes remain protocol-neutral.
