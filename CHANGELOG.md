# Changelog

All notable user-facing changes are tracked here. Architecture and spec truth
remain in `docs/handbook/`; this file is a release-facing summary.

## Unreleased

### Added

- Added Run2 SOCKS-upstream control validation mode to
  `tests/live-run2-pool-validation.mjs`, allowing the direct upstream SOCKS5
  path to be checked separately from the MeshPeerUdp gateway-to-pool path.
- Added explicit Mesh Protocol stream-open confirmation:
  `StreamOpen` now carries an `open_token`, and peers must answer with
  `StreamOpenAccepted` or `StreamOpenReject` before an egress reports stream
  connect success.
- Added `deploy/run2-lab`, a Run2 gateway-plus-pool deployment wrapper that
  deploys pool nodes before the gateway and can run the live Run2 validation
  gate after deployment.
- Added role-specific Run2 deployment binary paths:
  the gateway defaults to `/opt/mesh-bus/bin/mesh-bus-run2`, while pool nodes
  default to `/opt/mesh-bus/bin/mesh-bus`.

### Changed

- MeshPeer UDP stream egress now treats a blackholed or stale peer open as a
  failed path instead of a successful local UDP enqueue.
- MeshPeer UDP ingress only sends `StreamOpenAccepted` after local bus stream
  re-entry succeeds; local open failure returns `StreamOpenReject`.
- Run2 live validation now records MeshSec/native drop deltas and per-exit
  movement evidence for the gateway-to-pool path.
- Run2 acceptance documentation now separates the direct SOCKS-upstream control
  gate from the MeshPeerUdp/MeshSec mesh acceptance gate.
- MeshPeerUdp Run2 example config now uses native repair mode for ordered stream
  delivery instead of relying on `secure_udp_native + steer`.

### Fixed

- Fixed native ordered stream gap handling for Run2 MeshPeerUdp paths by proving
  that `DeliveryMode::Steer` cannot repair missing stream sequences and using
  `DeliveryMode::Repair` for the Run2 mesh upstream profile.
- Fixed remote native reorder overflow surfacing: ingress now returns a terminal
  `StreamClose(ProtocolError)` for stream-family overflow instead of leaving
  the sender with a silent remote drop.
- Fixed Run2 SOCKS-upstream control validation so a custom
  `MESH_BUS_RUN2_TARGET` is mapped to the Rust live smoke target host/port,
  avoiding false-green validation against a different destination.
- Fixed gateway health ownership by guarding against treating metrics-only
  native drop observations as exit health failures.
- Fixed a live deployment class where the deploy script updated one binary path
  while systemd executed another binary. `deploy/service` now fails fast when
  `--remote-bin` does not match the target unit's `ExecStart` binary.
- Fixed false-positive Run2 validation caused by mixed gateway/pool binary ABI
  generations, which surfaced as peer-side
  `native_drop_total{reason="control_frame_decode"}`.
