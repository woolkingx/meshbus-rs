# mb-proto-socks5

mb-proto-socks5 role:
  L6 codec — pure SOCKS5 wire format library; per layer-model §2.3 and §6
  contract: bytes-in / bytes-out; no sockets, no async runtime, no bus dependencies
  consumed only by L7 adapter crates (mesh-bus-ingress-socks5, mesh-bus-egress-socks5)
  never imported by the bus kernel or any L4/L5 module

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

owned files:
  src/lib.rs — Method, Command, Reply, Greeting, Request, ReplyFrame, UdpDatagram, CodecError; encode/decode functions for greeting, request, reply, reply-with-endpoint, and UDP relay datagram
  tests/codec.rs — codec roundtrips for CONNECT, UDP ASSOCIATE, reply, and UDP relay datagram

local dependencies:
  bytes — BytesMut buffer for zero-copy parsing
  mb-endpoint — Endpoint type for decoded target address
  thiserror — CodecError derive

boundary rules:
  - L6 codec scope: SOCKS5 wire format only; no sockets, no async runtime, no bus dependencies
  - Command::Connect and Command::UdpAssociate are decoded as wire facts for the L7 adapter to translate into BusSessionRequest; the codec itself emits no session/L4 metadata
  - UDP relay datagram parser supports FRAG=0 only; fragmented SOCKS5 UDP packets are rejected explicitly
  - unknown authentication methods are preserved as Method::Unknown and must never be coerced into Method::NoAuth
  - this crate must not depend on mesh-bus-core or any L4/L5 surface; depending on it would invert the layer-model dependency direction

handbook links:
  ../../docs/handbook/compatibility.html

mb-proto-socks5 decisions:
  - 0.1.9 (2026-05-15): GSSAPI contract pinned in schema.json `gssapi_status`. Method::GssApi (0x01) stays a decode-only wire token; the codec performs no GSSAPI subnegotiation. GSSAPI negotiation/rejection is owned by the L7 adapter, which gates it off behind a default-off `gssapi` cargo feature and replies RFC1928 0x05 0xff to a GSSAPI-only client.
  - 0.1.10 (2026-05-15): four-column SOCKS5 command/auth matrix pinned in schema.json `command_auth_matrix` as the single contract source: codec-recognized vs live-ingress vs live-egress-stream vs live-egress-datagram commands and per-column auth. The codec recognizes all three commands and three methods as wire facts only; ingress/egress/tests CLAUDE.md reference this matrix instead of restating it.
  - 0.1.11 (2026-05-15): `reply_frame_total_len(&[u8]) -> Result<usize, CodecError>` exposed as the single source of SOCKS5 reply-frame wire length. Given a prefix it returns the full VER REP RSV ATYP BND.ADDR BND.PORT length, or `CodecError::Incomplete` when the DOMAIN length octet is not yet available. L7 egress streaming reads use this instead of re-deriving per-ATYP sizes inline, removing the ATYP byte-length arithmetic that previously lived in mesh-bus-egress-socks5.
