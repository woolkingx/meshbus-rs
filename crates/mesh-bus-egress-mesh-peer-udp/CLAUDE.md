# mesh-bus-egress-mesh-peer-udp

mesh-bus-egress-mesh-peer-udp role:
  L7 mesh-peer raw UDP upstream egress adapter for opaque Mesh Protocol stream/datagram forwarding
  owns UDP socket I/O and Mesh Protocol frame encode/decode at the peer boundary
  does not parse HTTP, SOCKS5, TLS, QUIC, DNS, or application payload

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

owned files:
  src/lib.rs — StreamEgress + DatagramEgress implementation for a configured adjacent peer
  src/demux.rs — per-session demux driver lifecycle and bounded inbound inbox routing
  tests/egress.rs — raw UDP peer stream/datagram frame exchange and endpoint preservation

local dependencies:
  mesh-bus-core — StreamEgress/StreamSession and DatagramEgress/DatagramSession traits only
  mb-proto-mesh — Mesh Protocol wire frames
  mb-reorder — FamilyReorderState per-(peer,family) ordering for native Secure UDP DataPackages
  mb-endpoint — Endpoint projection
  tokio — UDP socket runtime

boundary rules:
  - Supports stream and datagram as MeshPeer upstream egress; payload remains opaque.
  - `open_stream` sends `StreamOpen` and must wait for `StreamOpenAccepted`, `StreamOpenReject`, or timeout before reporting connect success; `send` sends ordered `StreamData`; `shutdown_write` and `abort` send explicit stream control frames.
  - `open_datagram` sends `DatagramOpen` when fixed target metadata exists.
  - `send_to` sends one `DatagramSend` per logical datagram and preserves target endpoint.
  - `recv_from` accepts `DatagramReturn` and preserves source endpoint.
  - UDP socket I/O must align with the shared L4 `UdpPacketLoop` architecture before fast-path work lands.
  - `UdpBatchSend`, `UdpBatchRecv`, `UdpGso`, `UdpGro`, `UdpPacing`, and `UdpPathMtu` are optional transport capabilities; they must report path evidence without changing EventBus route truth.
  - Stream reliability, ordering, retransmission policy, and close semantics belong to Mesh Protocol event-family state, not QUIC or a transport channel.
  - Inbound peer replies are drained only by the per-UdpPacketLoop demux driver (`src/demux.rs`); stream/datagram sessions consume bounded inboxes and must not call `UdpPacketLoop::drain_inbound` directly.
  - When the configured peer carries MeshSec, every outbound frame is sealed before send (debug-clear is `MAGIC`-prefixed, sealed envelopes are never `MAGIC`-prefixed); the per-frame counter nonce is hoisted to one per-egress `Arc<AtomicU64>` so a single `K_tx` never reuses a nonce across datagram sessions of one boot.
  - `native_event_mode` selects the on-wire encoding: `MeshFrame` keeps the legacy frame path byte-for-byte; `SecureUdpNative` encodes each frame as MeshEvent/DataPackage (`encode_event`) and steers it through `UdpPacketLoop` with `DeliveryMode::Steer`. Mode never alters session id, route_group, target endpoint, or the monotone per-session `next_seq`.

mesh-bus-egress-mesh-peer-udp decisions:
  - 0.1.11 (2026-05-25): demux driver lifetime is tied to the owning stream/datagram session or recv half. `DriverGuard` aborts the per-session driver on drop so closed sessions release their per-session `UdpPacketLoop` socket immediately instead of waiting for another peer packet to wake `poll_recv`. Proven by `stream_driver_drop_releases_udp_socket_without_peer_packet`, `datagram_driver_drop_releases_udp_socket_without_peer_packet`, and full `cargo test -p mesh-bus-egress-mesh-peer-udp`.
  - 0.1.10 (2026-05-25): datagram return backpressure is receiver-visible. The demux driver now maps a saturated `datagram_inbox` to `DisconnectReason::QueueFull` through an error inbox and terminates the recv half; stream open control inbox overflow terminates the driver instead of silently turning a remote ack into a timeout. Proven by `datagram_return_queue_full_sets_recv_last_error`, `datagram_close_closes_recv_half_without_local_timeout`, and the mesh-peer UDP path-contract flowgraph.
  - 0.1.9 (2026-05-25): inbound mesh-peer UDP replies now use one demux driver per `UdpPacketLoop`. The driver owns `drain_inbound`, MeshSec open/replay mutation, native `DataPackage` -> `FamilyReorderState` ordering, PortOpen/AckNack handling, and bounded session inbox routing. `wait_stream_open_ack` and consumer-side MeshSec reopen were removed, so MeshSec early `StreamData` is opened exactly once and delivered after the matching `StreamOpenAccepted`; queued data is delivered before shutdown/close EOF. Outbound queue full maps to `DisconnectReason::QueueFull`. Proven by `meshsec_stream_connect_preserves_data_that_arrives_before_open_ack`, `stream_recv_delivers_buffered_payloads_before_close`, `outbound_queue_full_maps_to_l5_queue_full`, and full `cargo test -p mesh-bus-egress-mesh-peer-udp`.
  - 0.1.8 (2026-05-24): Stream open success is remote-confirmed. `connect` sends `StreamOpen` with a random/time/counter mixed `open_token`, then waits for matching `StreamOpenAccepted` or `StreamOpenReject`; timeout maps to `DisconnectReason::TimedOut`, so a blackholed peer becomes a failed path instead of a false dispatch success. Proven by `stream_connect_requires_open_ack`, `stream_connect_ignores_stale_open_ack_token`, egress/ingress tests, product topology fixtures, and Run2 failover gate.
  - 0.1.7 (2026-05-19): Runtime adapter capability projections landed. `MeshPeerUdpEgress` remains the stream+datagram owner, but runtime registration must clone it into `as_stream_adapter()` and `as_datagram_adapter()` projections so core dispatch cannot select the stream adapter for datagram flows or the datagram adapter for stream flows. This preserves the L7-over-Mesh owner contract while keeping adapter-local flow-family truth exact.
  - 0.1.6 (2026-05-19): L7-over-Mesh M3 stream egress landed. `MeshPeerUdpEgress` now advertises stream+datagram capability and implements `StreamEgress`: `connect` emits `StreamOpen`, stream send emits monotone `StreamData`, `shutdown_write` emits `StreamShutdownWrite`, and abort emits `StreamClose`. The implementation reuses `UdpPacketLoop`, MeshSec/native-event wrapping, `DeliveryCoord`, and `EgressPolicy`; no L7 payload parsing or QUIC channel ownership is introduced. Proven by `capabilities_advertise_stream_and_datagram`, `stream_open_emits_mesh_stream_open`, `stream_send_emits_ordered_stream_data`, and `stream_close_removes_session_state`.
  - 0.1.5 (2026-05-18): native plan M7 delivery policy landed. A per-egress `EgressPolicy{mode, replicate_fanout(clamped 1..=4), probe_budget, probe_used, bounded retransmit ring (REPAIR_RING_DEPTH=64)}` is shared `Arc` alongside `DeliveryCoord` through session/send/recv halves. `send_mesh_frame` stamps `policy.policy_id()` onto every wrapped event and enqueues `send_copies()` copies — Replicate is a bounded duplicate send, every other mode sends once. Repair `remember`s each Datagram/Stream send into the ring; an inbound `MeshFrame::AckNack` retransmits only the seqs in its `missing_ranges` to the current `coord.addr()`. Steer is the default (existing configs byte-for-byte unchanged). Mode-invariant: session id, family id, seq, route_group, and target endpoint are never altered — policy changes delivery coordinates only; the receiver `FamilyReorderState` restores order. `stripe_index` (across-mouths round-robin) and the probe budget gate are test-proven contract surface; multi-mouth/probe-loop wiring is the documented D-M7.5 follow-up (egress holds one rotating coord today). Proven by `policy_tests` + e2e `mesh_peer_secure_udp_{replicate_dedup,stripe_reorder,repair_gap}`.

handbook:
  ../../docs/handbook/index.html
