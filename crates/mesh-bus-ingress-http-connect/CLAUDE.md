# mesh-bus-ingress-http-connect

mesh-bus-ingress-http-connect role:
  L7 compatibility ingress adapter for HTTP/1.1 forward proxy and CONNECT tunnel entry
  parses only RFC 9110/9112 request-head bytes, projects target intent into `BusSessionRequest::stream`, then relays opaque bytes over the bus

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

owned files:
  src/lib.rs — HttpConnectIngress, BasicAuth, handshake read, RFC response mapping, stream relay
  src/event_build.rs — protocol-neutral event metadata for optional pipeline decisions
  src/verdict_apply.rs — projection of pipeline Verdict metadata onto BusSessionRequest
  tests/handshake.rs — CONNECT, malformed, opaque tunnel payload, absolute-form rewrite, Basic auth

local dependencies:
  mb-proto-http-proxy — pure request-head parser
  mesh-bus-core — BusPort / BusSessionRequest / StreamSession
  mesh-bus-pipeline-hooks — optional event pipeline runtime
  mb-socket-tune — socket buffer knobs

boundary rules:
  - CONNECT target must be RFC 9112 authority-form; origin-form CONNECT is 400
  - HTTP absolute-form requests are compatibility mode only and are rewritten to origin-form before upstream relay
  - after CONNECT 2xx the adapter must not parse tunneled payload
  - no HTTP method, header, URL, SNI, or body field leaks into mesh-bus-core routing; only target metadata enters BusSessionRequest / pipeline metadata

handbook links:
  ../../docs/handbook/direct-proxy.html
