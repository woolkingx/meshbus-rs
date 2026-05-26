# mesh-bus-core.kernel.pipeline


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  schema.json    — Pipeline, Wiring, PipelineRunError
  types.rs       — Pipeline { id, hooks: Vec<HookId> }, Wiring { source, pipeline }
  data_handle.rs — run_pipeline executor (resolves HookId → HookFn via closure); registry-aware facade records HookTrace
  tests.rs       — unit tests

boundary rules:
  - Pipeline.id, Pipeline.hooks, Wiring.source, and Wiring.pipeline schema use the same kernel id shape as verdict/registry (`^[A-Za-z0-9_.:-]+$`); runtime-derived ids such as `ingress:0` and dotted hook ids are valid, whitespace/slash ids are not
  - Registry-aware pipeline execution must enforce returned `Accept` and `Jump` targets against each hook's `may_accept_to` and `may_jump_to`; undeclared targets are kernel run errors, not fallback or best-effort routing

pipeline decisions:
  - 0.2.5 (2026-05-13): run_pipeline_with_registry now rejects HookFn `Accept` and `Jump` payloads that were not declared by the hook spec.
  - 0.2.4 (2026-05-13): Pipeline.id, Pipeline.hooks, and Wiring.pipeline now share the kernel id shape with verdict/registry ids.
  - 0.2.3 (2026-05-13): Wiring.source schema now matches verdict/registry SourceId shape so pipeline wiring cannot accept looser source ids than KernelRegistry.
