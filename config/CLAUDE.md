# config

config governs:
  example.yaml — minimal local example
  multi-wan.yaml — production-like 4-WAN SOCKS5 sample aligned to master live shape

config depends_on:
  crates/mesh-bus-runtime — YAML schema and validation
  crates/mesh-bus-bin — run/check/status CLI over config files

config invariants:
  - samples must pass mesh-bus check before use
  - production-like samples should include logging, metrics, health, and explicit scheduler config
  - WAN topology belongs in YAML, not systemd unit templates

config decisions:
  - 0.1.0 (2026-05-10): add multi-wan.yaml with four SOCKS5 exits and LoadBalance round-robin scheduler
  - 0.1.1 (2026-05-10): multi-wan sample exports Prometheus textfile metrics for node_exporter collection
  - 0.1.2 (2026-05-11): release smoke used multi-wan.yaml successfully for HTTP over SOCKS5; direct non-systemd runs may warn on /var/lib/mesh-bus metrics permissions unless the state directory exists
