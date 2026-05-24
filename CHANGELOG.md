# Changelog

All notable user-facing changes are tracked here. Architecture and spec truth
remain in `docs/handbook/`; this file is a release-facing summary.

## Unreleased

### Added

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

### Fixed

- Fixed a live deployment class where the deploy script updated one binary path
  while systemd executed another binary. `deploy/service` now fails fast when
  `--remote-bin` does not match the target unit's `ExecStart` binary.
- Fixed false-positive Run2 validation caused by mixed gateway/pool binary ABI
  generations, which surfaced as peer-side
  `native_drop_total{reason="control_frame_decode"}`.
