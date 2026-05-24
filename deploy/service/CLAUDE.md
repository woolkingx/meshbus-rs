# deploy/service

deploy/service governs:
  deploy.mjs — one-command SSH/systemd deployment and rollback adapter
  schema.json — deployment action input contract
  test.html — deployment proof contract

deploy/service depends_on:
  deploy/systemd — owns the systemd unit template
  mesh-bus-bin — owns check/run/admin CLI semantics
  mesh-bus-runtime — owns runtime YAML shape and config validation

deploy/service invariants:
  - deployment adapter owns host file movement, backup paths, restart, and service-state verification
  - deployment adapter must not encode mesh topology, route policy, peer identity, or rewrite runtime YAML
  - `remote_bin` must equal the target systemd unit's `ExecStart` binary path; otherwise deployment evidence is invalid because the service may run a different binary than the one installed
  - binary-only deployment must preserve remote config when the remote host owns service topology
  - preflight always runs remote `mesh-bus check --config` before restart
  - rollback restores backup artifacts, then reruns config preflight and service restart

deploy/service decisions:
  - 0.1.2 (2026-05-24): deploy and rollback now fail fast when `--remote-bin` does not match the systemd `ExecStart` path. Run2 live testing exposed the bug class: updating `/opt/mesh-bus/bin/mesh-bus` while `mesh-bus-run2.service` executed `/opt/mesh-bus/bin/mesh-bus-run2`.
  - 0.1.1 (2026-05-21): add `--preserve-remote-config` after live deploy proved binary and remote service config have different lifecycles on 10.36.
  - 0.1.0 (2026-05-21): service deployment adapter introduced for MVP service substrate hardening; rollback is artifact-level restore, not topology mutation.
