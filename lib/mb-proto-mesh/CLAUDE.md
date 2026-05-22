# mb-proto-mesh

handbook:
  ../../docs/handbook/index.html

mb-proto-mesh role:
  L6 Mesh Protocol wire codec — pure frame envelope and message codec
  contract: bytes-in / bytes-out; no sockets, no async runtime, no bus dependencies
  consumed only by mesh-peer L7 adapter crates
  never imported by mesh-bus-core or scheduler crates

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mb-proto-mesh governs:
  src/lib.rs — MeshFrame, control/data message types, versioned envelope encode/decode
  schema.json — MeshSec envelope wire contract, profile constants, and crypto invariants
  tests/codec.rs — envelope, Hello, StreamOpen re-entry, datagram source preservation

mb-proto-mesh depends_on:
  bytes — Bytes/BytesMut buffer handling
  mb-endpoint — Endpoint wire projection for target/source endpoints
  serde + bincode — production binary payload encoding inside the Mesh Protocol envelope
  thiserror — CodecError derive

mb-proto-mesh invariants:
  - Codec scope only; no sockets, Tokio, runtime config, scheduler, or mesh-bus-core dependency.
  - Mesh Protocol frame payload stays opaque to core; mesh-peer adapters translate frames into BusSessionRequest.
  - Raw UDP binding may carry control/observation/datagram frames only; reliable stream data requires QUIC, TCP reference, or future mb-rudp.
  - Envelope version mismatch is explicit; silent drop is forbidden.

mb-proto-mesh decisions:
  - 0.1.8 (2026-05-18): native plan M7 wire surface. `wrap_frame_event` gained a `delivery_policy_id: &str` parameter (the only M4 caller — egress `send_mesh_frame` — updated same commit; mode-invariant: it never alters event_id/family_id/seq/semantic). `DeliveryMode` gained `policy_id()`/`from_policy_id()` (unknown id degrades to `Steer`, never route truth). Added `MeshFrame::AckNack(AckNack)` Control wire variant (msg_type 51, `frame_event_meta` → family-keyed Control seq 0) as the L5 receiver→sender feedback channel. Added pure one-XOR-parity helpers `xor_parity`/`reconstruct_missing` (recover exactly one lost chunk per generation; zero/≥2 missing → None). No schema.json change — AckNack is a control message and the codec is its wire contract (PortOpen/PortClose 0.1.6 precedent); a wire-integrated proactive `RepairFec` FEC packet is a documented follow-up. Proven by codec tests `ack_nack_roundtrips_as_family_keyed_control`, `delivery_mode_policy_id_round_trips_and_unknown_falls_back_to_steer`, `one_xor_parity_reconstructs_exactly_one_lost_chunk_per_generation`.
  - 0.1.7 (2026-05-18): added `LinkSample` struct (mirrors handbook Control-Plane `LinkSample`: source_node_id/mouth_id/epoch/seq/observed_at_ms + rtt_us/loss_permille/goodput_bps/queue_delay_us/close_count/saturated) and `MeshFrame::LinkSample(LinkSample)` wire variant (msg_type 50). `frame_event_meta` keys it by `mouth_id`, carries its own `seq`, and maps it to `EventSemantic::Observation` so it rides the existing Observation bypass-reorder native path (`native_frame_classes` already classes Observation as BestEffort/Unordered). LinkSample is best-effort scheduling evidence, never route/registry truth. No schema.json change — LinkSample is a control/observation message (not a Native Data Shape root) and the codec is its wire contract, same precedent as PortOpen/PortClose 0.1.6. Proven by codec test `link_sample_roundtrip_as_observation`.
  - 0.1.6 (2026-05-18): added `ReceiverMouth` struct (mirrors `receiver_mouth_v1`: mouth_id/udp_addr/family_filter/advertised_capacity/epoch) and `MeshFrame::PortOpen(ReceiverMouth)` + `MeshFrame::PortClose { mouth_id, epoch }` Control wire variants (msg_type 48/49). `frame_event_meta` maps both to `EventSemantic::Control` seq 0 so they ride the existing Control bypass-reorder native path; PortOpen/PortClose change delivery coordinates only and never carry session/route/channel truth. No schema.json change — `receiver_mouth_v1` was already locked at M0 and the codec is the wire contract. Proven by codec test `port_open_and_port_close_roundtrip_as_control`.
