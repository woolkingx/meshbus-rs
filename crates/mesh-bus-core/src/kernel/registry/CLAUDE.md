# mesh-bus-core.kernel.registry


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
registry governs:
  schema.json    — KernelRegistry, HookSpec, HookFn, SourceSpec, SinkSpec, VerifyError
  types.rs       — KernelRegistry { sources, sinks, hooks, pipelines, wirings, fns } + HookFn + HookSpec { allowed_namespaces (glob), may_accept_to } + KernelCtx + SourceSpec + SinkSpec
  data_handle.rs — register ops + verify() (26 error classes: UnknownSource, UnknownWiringPipeline, DuplicateWiringSource, MissingSourceWiring, UnknownHook, MissingHookFn, UnknownHookFn, RegistryIdentityMismatch, InvalidSourceId, InvalidSinkId, InvalidPipelineId, InvalidHookId, InvalidSourceKind, InvalidSinkKind, UnknownSink, InvalidAcceptDeclaration, InvalidJumpDeclaration, UnknownPipelineJumpTarget, JumpCycle, InvalidMetadataKey, InvalidNamespacePattern, UnsatisfiedRead, NamespaceViolation, PolicyReadsPayload, SideEffectMutatesVerdict, PipelineDoesNotTerminate)
  id_shape.rs    — shared SourceId/SinkId/PipelineId/HookId shape check used by verify()
  verify_error.rs — VerifyError enum and error display strings
  tests.rs       — unit tests for all 26 verify error classes

registry contract:
  - HookFn is a sync fn-pointer; async upstream bridges through SharedHookCtx.tokio.block_on per kernel spec §4; every pipeline hook must have a registered HookFn at verify time, and every registered HookFn must have a HookSpec
  - schema.json roots at KernelRegistry and mirrors Rust spec object shape: KernelRegistry/HookSpec/SourceSpec/SinkSpec/Pipeline/Wiring reject unknown fields and require every non-optional Rust field; registry map keys use propertyNames for SourceId/SinkId/HookId/PipelineId, and HookFn is represented as a symbolic registration label because Rust stores a non-serializable fn pointer
  - keyed registry entries are identity-closed: each SourceSpec/SinkSpec/HookSpec/Pipeline embedded id must equal its BTreeMap key
  - SourceId/SinkId/PipelineId/HookId use the same kernel id shape (`^[A-Za-z0-9_.:-]+$`) in verdict, pipeline, registry schemas, and verify; invalid wiring, jump, hook, and sink ids fail before graph resolution
  - SourceSpec.kind is fixed to `application/source`; SinkSpec.kind is capability-shaped (`stream_egress` or `datagram_egress`); verify rejects unknown kind strings before graph wiring checks
  - Wiring.source and Wiring.pipeline must both resolve to registered SourceSpec/Pipeline entries; every SourceSpec has exactly one Wiring; verify rejects dangling, missing, or ambiguous graph edges before namespace analysis
  - SourceId/SinkId/PipelineId/HookId schema uses the same id-shape as verdict ids (`^[A-Za-z0-9_.:-]+$`) so runtime-derived ids such as `ingress:0`, egress ids such as `direct`, and dotted hook ids are legal while whitespace/slash ids are not schema-valid
  - SourceSpec.initial_writes and HookSpec reads/writes must name concrete dotted metadata keys under net|transport|policy|auth|trace|ext; key segments are ASCII alnum or underscore only
  - HookSpec.allowed_namespaces entries must be exactly `<head>.*` for known metadata namespace heads, even when a hook currently has no reads/writes
  - HookSpec.allowed_namespaces uses glob form `<head>.*` (e.g. `net.*`); verify checks both reads and writes against strict `head.` prefixes, so empty allowed_namespaces is not a wildcard and bare namespace heads such as `net` are invalid metadata keys
  - HookSpec.may_accept_to is legal only when may_terminate=true; it lists every SinkId Verdict::Accept(...) may name, and UnknownSink fires when a listed sink is not registered
  - may_jump_to is legal only when may_jump=true; may_jump only satisfies PipelineDoesNotTerminate when may_jump_to declares at least one verified target pipeline
  - route_group != pipeline_id: route_group is policy metadata that filters sink candidates; PipelineId is control flow (Verdict::Jump)

registry decisions:
  - 0.2.20 (2026-05-13): verify no longer treats empty HookSpec.allowed_namespaces as wildcard; any declared read/write must be covered by a namespace pattern.
  - 0.2.19 (2026-05-13): KernelRegistry schema map keys now use propertyNames tied to SourceId/SinkId/HookId/PipelineId so artifact keys cannot bypass id-shape validation.
  - 0.2.18 (2026-05-13): KernelRegistry schema and verify now reject invalid PipelineId/HookId shapes; verify errors live in verify_error.rs to keep verify logic under size limits.
