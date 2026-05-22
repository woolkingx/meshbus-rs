# mb-proto-http-proxy

mb-proto-http-proxy role:
  L6 codec — pure HTTP/1.1 proxy request-head parser and encoder; bytes-in / bytes-out; no sockets, no async runtime, no bus dependencies
  consumed only by L7 HTTP proxy ingress adapters
  never imported by mesh-bus-core or any L4/L5 module

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mb-proto-http-proxy governs:
  src/lib.rs — RequestKind, RequestHead, HttpProxyError, parse_request_head
  tests/codec.rs — RFC-shaped CONNECT authority-form, absolute-form rewrite, malformed, incomplete, and bounded-header proofs

mb-proto-http-proxy depends_on:
  bytes — immutable forwarded request-head bytes
  mb-endpoint — decoded authority endpoint
  thiserror — error enum derive

mb-proto-http-proxy invariants:
  - RFC 9110/9112 only: CONNECT target is authority-form; non-CONNECT forward proxy input must be absolute-form
  - parsing is request-head only; after CONNECT succeeds the adapter must relay opaque bytes and this crate must not inspect tunneled payload
  - forwarded HTTP request heads remove proxy-only headers before upstream relay
  - this crate must not depend on mesh-bus-core or any L4/L5 surface

mb-proto-http-proxy extends:
  ../../docs/handbook/direct-proxy.html
