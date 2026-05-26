# mb-rule

Role: pure declarative policy primitive. It evaluates DTO-shaped rule context
and returns actions; it owns no kernel, adapter, runtime, or protocol payload
truth.

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

Read first:
  - ../../docs/handbook/system-architecture.html#rule-engine
  - ../../docs/handbook/testing-gates.html
  - test.html
  - src/types.rs
  - src/data_handle.rs

Owned surfaces:
  - src/types.rs — RuleCtx, Predicate, MatchExpr, Action, RuleDecision.
  - src/evaluate.rs — first-match evaluation and trace.
  - src/data_handle.rs and src/data_handle/ — YAML parser and validator bridge.
  - tests/ — schema sync, validation, YAML, predicate, and evaluation proof.

Boundary rules:
  - Do not depend on mesh-bus-core, runtime, or adapter crates.
  - Do not inspect payload bytes or protocol wire syntax.
  - Actions describe route/schedule/transform intent; projection into BusSessionRequest belongs to consuming adapters/hooks.
  - Empty predicates, duplicate/conflicting compose actions, and unsupported shape variants fail validation.
  - YAML parser changes must preserve schema sync and validation tests.

Local proof:
  - cargo test -p mb-rule
  - cargo test -p mb-rule --test yaml
  - cargo test -p mb-rule --test schema_sync
  - cargo test -p mb-rule --test validate

Latest decision pointers:
  - Rules are DTO-level policy; kernel and adapters consume projected decisions through their own owner boundaries.
  - YAML parser lives in src/data_handle/ so parsing bulk does not bury the rule data owner.

handbook:
  ../../docs/handbook/index.html
