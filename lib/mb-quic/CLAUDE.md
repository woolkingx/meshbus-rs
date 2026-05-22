# mb-quic

mb-quic role:
  QUIC protocol library and deterministic reference data-shape owner
  sans-I/O: owns QUIC packets, frames, streams, datagrams, recovery, TLS binding, and transport parameters
  does not own Mesh Protocol session truth, route truth, peer topology, UDP sockets, or runtime wiring

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mb-quic governs:
  src/lib.rs — crate surface and errors
  src/conn.rs — QUIC connection state machine
  src/packet.rs — packet/header encoding and packet-number handling
  src/frame.rs — QUIC frame codec
  src/stream.rs — QUIC stream ID/table/reassembly data
  src/datagram.rs — QUIC datagram queue behavior
  src/recovery.rs — ACK/loss/PTO/congestion data
  src/crypto.rs — QUIC initial secrets and packet protection
  src/tls.rs — rustls QUIC TLS integration
  src/transport_params.rs — RFC 9000 transport parameters
  schema.json — protocol-library data contract summary
  test.html — owner proof contract

mb-quic invariants:
  - library only; no socket, no mesh peer runtime binding, no product topology gate
  - may be used later by a QUIC application adapter over Mesh Protocol
  - must not carry Mesh Protocol as the native mesh production substrate
  - quiche is source reference only; Quinn is not a dependency

handbook:
  ../../docs/handbook/index.html
