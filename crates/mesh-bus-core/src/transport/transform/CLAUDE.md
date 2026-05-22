# mesh-bus-core.transform


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
transform governs:
  schema.json — local mirror of /schemas/transform.schema.json, fragment.schema.json, reassembly.schema.json
  types.rs — TransformKind, TransformDescriptor, FragmentMetadata, ReassemblyMode, ReassemblyPolicy, TransformError
  data_handle.rs — validate_fragment metadata invariant check
  tests.rs — domain-local tests

transform owns:
  L6 transform descriptors, fragment metadata, reassembly policy, and transform metadata validators only

transform invariants:
  - core executes no transform algorithm; it only validates metadata shape
  - TransformDescriptor.policy_ref is opaque to bus; algorithm crates own its grammar
  - validate_fragment enforces total > 0, seq < total, non-empty group_id and fragment_id

transform decisions:
  - 0.1.0 (2026-05-11): skeleton created; types/handlers move here in subsequent tasks
  - 0.1.1 (2026-05-11): L6 transform domain types and validate_fragment handler added; schemas mirrored from /schemas/transform.schema.json, fragment.schema.json, reassembly.schema.json
