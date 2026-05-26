# mb-endpoint


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — Endpoint type, ParseError, parse + display

local dependencies:
  thiserror

handbook links:
  ../../docs/handbook/system-architecture.html

mb-endpoint decisions:
  - 1.0.0 (2026-05-10): initial implementation — pure parser, no I/O, no panic on untrusted input, validates length <= 255 per RFC 1035, rejects port 0
