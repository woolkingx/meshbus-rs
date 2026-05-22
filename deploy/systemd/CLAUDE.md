# deploy/systemd

deploy/systemd governs:
  mesh-bus.service — production systemd unit template
  schema.json — schema metadata for systemd deployment artifacts

deploy/systemd depends_on:
  mesh-bus-bin — CLI must support run --config before this unit can boot
  mesh-bus-runtime — YAML config and logging are owned by runtime config

deploy/systemd invariants:
  - systemd unit runs the binary with run --config, not an implicit working-directory config
  - service logging is controlled by YAML logging config and journald capture
  - unit template does not encode WAN topology; WAN lives in runtime YAML

deploy/systemd decisions:
  - 0.1.0 (2026-05-10): add production unit template aligned with master service shape and bus-mesh CLI
  - 0.1.1 (2026-05-10): unit hardened for live deployment: SIGTERM with 15s drain, LimitNOFILE=65536, ProtectSystem=strict + StateDirectory, namespace and syscall sandboxing
  - 0.1.2 (2026-05-11): systemd-analyze verify reaches ExecStart validation; local workspace lacks /opt/mesh-bus/bin/mesh-bus install path, so full systemctl start remains an install-host verification step
