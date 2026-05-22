# mesh-bus-ingress-mesh-peer-udp

mesh-bus-ingress-mesh-peer-udp role:
  L7 mesh-peer raw UDP ingress adapter for Mesh Protocol stream/datagram re-entry
  parses Mesh Protocol frames at the peer boundary and opens normal bus stream/datagram sessions
  does not parse HTTP, SOCKS5, TLS, QUIC, DNS, or application payload

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mesh-bus-ingress-mesh-peer-udp governs:
  src/lib.rs — IngressPlugin implementation for configured adjacent peer UDP sockets
  tests/ingress.rs — local raw UDP peer to bus stream/datagram re-entry

mesh-bus-ingress-mesh-peer-udp depends_on:
  mesh-bus-core — BusPort/IngressPlugin and stream/datagram session halves
  mb-proto-mesh — Mesh Protocol wire frames + MeshEvent/DataPackage native codec
  mb-reorder — FamilyReorderState per-(peer,session) ordering for native Secure UDP events
  tokio — UDP socket runtime

mesh-bus-ingress-mesh-peer-udp invariants:
  - Mesh Protocol parsing stays in this adapter; core remains payload-opaque.
  - Raw UDP accepts stream and datagram control/data; `StreamOpen` re-enters the local bus and rejects only when local open fails.
  - `StreamData` writes to the local stream send half; the local recv pump returns opaque bytes as monotone `StreamData`.
  - Response pump is independent from send path; DatagramSend must not wait for DatagramReturn.
  - Returned datagrams preserve source endpoint through `DatagramReturn`.
  - UDP socket I/O must align with the shared L4 `UdpPacketLoop` architecture before fast-path work lands.
  - `UdpBatchRecv`, `UdpBatchSend`, `UdpGso`, `UdpGro`, `UdpPacing`, and `UdpPathMtu` are transport capabilities; they must feed path evidence without becoming route truth.
  - When a configured peer carries MeshSec, inbound datagrams are opened via `Config::meshsec_open_keys` before frame decode; AEAD-fail, tampered, or replayed datagrams are dropped fail-closed (no bus session, no reply), proven by the two-node tamper/replay e2e.
  - Two-layer decode: Layer 1 yields clear SDU + `sealed` flag (MeshSec `open_bytes` or clear loopback); Layer 2 switches on `native_event_mode` — `MeshFrame` decodes a `MeshFrame` (`decode_mesh_frame_clear` when sealed, `decode_frame` when clear), `SecureUdpNative` runs `decode_event` and demuxes by `frame_event_meta` family. Control/Observation bypass reorder; Stream/Datagram run per-(peer,session) `FamilyReorderState` and re-enter the bus only in seq order. Every native decode/family/queue failure is typed (`NativeDropReason`) and dropped fail-closed.

mesh-bus-ingress-mesh-peer-udp decisions:
  - 0.1.5 (2026-05-19): L7-over-Mesh M4 stream re-entry landed. `StreamOpen` builds a local `BusSessionRequest::stream`, opens the local bus stream, stores bounded peer stream state, and spawns a recv pump that returns local bytes as `StreamData`; inbound `StreamData` writes to the local send half, `StreamShutdownWrite` propagates half-close, and `StreamClose` aborts and removes state. Local open failures map to `StreamOpenReject` with typed close reason. Proven by `stream_open_reenters_local_bus`, `stream_open_rejects_when_local_open_fails`, `stream_data_forwards_to_local_send_half`, and `local_stream_recv_pump_returns_stream_data_to_peer`.
  - 0.1.4 (2026-05-18): native plan M7 repair feedback + replicate dedup landed. On `FamilyPushOutcome::Gap(ack)` the ingress now sends the `AckNack` back to the peer as `MeshFrame::AckNack` via the existing reply path (best-effort; a failed send-back just waits for the next gap), so a Repair-mode egress retransmits the missing seqs. Replicate dedup needs no new structure: a duplicated `DatagramOpen` is dropped by the pre-existing `sessions.contains_key` guard and a duplicated data seq lands as `FamilyReorderState::Duplicate` (event_id is `"{family}:{seq}"`, so `(peer, family_id, seq)` is the dedup identity the reorder state already enforces). The AckNack carries no route/session/channel truth and never opens/rebinds a bus session — it is L5 feedback only. Proven by e2e `mesh_peer_secure_udp_{replicate_dedup,repair_gap}`.
  - 0.1.3 (2026-05-18): receiver-mouth registry landed (master plan M5). A `(peer_addr, mouth_id)` → `MouthEntry{epoch, last_seen, ...}` map is updated purely from `PortOpen`/`PortClose` Control frames: `apply_port_open` prunes soft-TTL-expired (`MOUTH_SOFT_TTL_SECS = 30`) entries for the peer, rejects a strictly-older epoch, else upserts; `apply_port_close` removes only when the carried epoch is not stale. Make-before-break: a rotated mouth is recorded before the old close arrives, and a stale close is ignored. The registry is L7-local delivery bookkeeping — it never opens, closes, or rebinds a bus session, never touches session_id/route_group/family. Proven by `mouth_registry_tests` (initial / rotation / stale / soft-TTL prune).

handbook:
  ../../docs/handbook/index.html
