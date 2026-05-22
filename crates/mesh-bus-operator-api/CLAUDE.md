# mesh-bus-operator-api


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-operator-api governs:
  src/lib.rs — schema-backed M0 Operator API response builders and redaction helpers
  schema.json — request/response contract for read-only status, config-check, and effective config
  tests/m0.rs — owner tests for response shape, preflight errors, and secret redaction

mesh-bus-operator-api depends_on:
  mesh-bus-runtime — Config, parse_config, preflight_config, status projections
  serde / serde_yaml — response serialization and redacted config projection
  sha2 — stable config fingerprint

mesh-bus-operator-api invariants:
  - Operator API is a management adapter over existing owners; it must not run the bus or mutate core state.
  - M0 is read-only plus config-check only.
  - Effective config output is redacted before leaving this crate.
  - CLI/Web/remote admin clients must use this contract instead of duplicating status/config logic.

handbook:
  ../../docs/handbook/operator-plane.html

decisions:
  - 0.1.0 (2026-05-21): M0 owner crate added for API-first Operator Plane status/config-check/effective-config.
