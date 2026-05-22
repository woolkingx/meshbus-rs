# mesh-bus-core.kernel.event


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
event governs:
  schema.json    — Event, HookTrace
  types.rs       — Event { payload: Bytes, meta: TypedMap }, HookTrace { hook_id: HookId, verdict: VerdictLabel }
  data_handle.rs — Event constructors, HookTrace recorder
  tests.rs       — unit tests

event contract:
  - schema.json roots at Event and mirrors Event { payload, meta } plus HookTrace { hook_id, verdict }: both object shapes reject unknown fields; HookTrace.hook_id uses the shared HookId shape (`^[A-Za-z0-9_.:-]+$`); Event.meta references sibling kernel/metadata TypedMap
  - HookTrace = (hook_id, verdict) is the kernel-surface trace contract. Richer per-hook fields (reads/writes/duration_us) belong to adapter access logs, not to the kernel event-pipeline primitive.

event decisions:
  - 0.2.2 (2026-05-13): HookTrace.hook_id schema now uses the shared HookId shape (`^[A-Za-z0-9_.:-]+$`) so observability artifacts cannot carry slash/whitespace hook ids.
  - 0.2.1 (2026-05-13): schema.json now roots at Event, closes Event/HookTrace object shapes, requires Event.meta, and fixes Event.meta ref to ../metadata/schema.json#/$defs/TypedMap.
  - 0.2.0 (2026-05-12): bedrock — Event { payload: Bytes, meta: TypedMap } + HookTrace { hook_id, verdict: VerdictLabel } defined; no PipelineTrace at this layer.
