# mb-proto-dns

mb-proto-dns role:
  L6 codec library — RFC 1035 §4 DNS wire format encode/decode plus RFC 7766 length-prefix framing
  pure functions over bytes::{Bytes,BytesMut}; no tokio, no mesh-bus-core, no L7 imports

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

owned files:
  src/types.rs — Name, QType, RClass, RData (A/AAAA/PTR/CNAME/TXT/OPT), Question, ResourceRecord, Message, MessageHeader, EdnsConfig, TcpDnsFrame
  src/encode.rs — encode_message, encode_query, encode_name, edns_opt_rr
  src/decode.rs — decode_message, decode_name (RFC 1035 §4.1.4 compression pointers, loop guard), decode_rr; RFC 4343 case folding via Name::as_ascii_lower()
  src/framing.rs — write_tcp_frame(BytesMut, &[u8]) / try_read_tcp_frame(&mut BytesMut) -> Option<Bytes> per RFC 7766 §8 (2-byte length prefix, big-endian)
  schema/dns_message.schema.json — JSON schema mirror of public types
  tests/encode_decode.rs — round-trip queries and answers
  tests/edns.rs — OPT pseudo-RR encode/decode with UDP payload size
  tests/framing.rs — length-prefix split-buffer reads and partial frames
  tests/compression_pointers.rs — pointer following + cycle rejection

local dependencies:
  bytes — Bytes/BytesMut buffer surface
  thiserror — DecodeError variants
  mb-endpoint — IpAddr re-use for A/AAAA payloads

boundary rules:
  - no dependency on mesh-bus-core, tokio, async-trait, or any L7 protocol crate
  - decode_name enforces a pointer-hop budget (default 16) and rejects cycles with DecodeError::CompressionLoop
  - decode_message returns DecodeError on truncation rather than partial answers; callers handle TC=1 via the parsed header.tc field
  - Name comparison is case-insensitive per RFC 4343 (ASCII only); Name::as_ascii_lower() is the canonical key
  - encode_message refuses messages with > u16::MAX label/RR counts (DecodeError::Oversize at encode site)

mb-proto-dns decisions:
  - 0.1.0 (2026-05-12): initial codec covering A/AAAA/PTR/CNAME/TXT/OPT for resolver v1; ANY/AXFR/IXFR explicitly out of scope (RFC 8482 ANY treated as opaque RR list on decode, never synthesized on encode)

handbook:
  ../../docs/handbook/index.html
