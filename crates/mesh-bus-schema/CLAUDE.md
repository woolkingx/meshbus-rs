# mesh-bus-schema


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — re-exports typify-generated types
  build.rs — typify codegen pipeline with external $ref rewriting, including ExitSnapshot
  schema.json — local index pointing at /schemas/
  tests/types.rs — round-trip serde verification

local dependencies:
  ../../schemas — source of truth, single direction
  typify — build-time code generator
  regress — runtime regex validation (used by ExitId pattern check)

boundary rules:
  - ../../schemas/*.schema.json is the cross-module schema authority; mesh-bus-schema/schema.json is only a closed local index and must not define local runtime shape extensions
  - build.rs may project workspace schemas into Rust types, but schema ownership remains in ../../schemas

handbook links:
  ../../docs/handbook/system-architecture.html

mesh-bus-schema decisions:
  - 1.0.3 (2026-05-10): build.rs includes ExitSnapshot for runtime status schema generation
  - 1.1.0 (2026-05-11): L6 transform schemas registered: TransformDescriptor, FragmentMetadata, ReassemblyPolicy
  - 1.1.1 (2026-05-13): mesh-bus-schema/schema.json is now a closed index and tests/schema_governance.rs guards the ../../schemas authority boundary
