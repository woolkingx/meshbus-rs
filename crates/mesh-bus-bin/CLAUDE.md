# mesh-bus-bin


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/main.rs — CLI entrypoint; supports run/check/status and admin M0 commands with optional --config path
  schema.json — binary CLI surface schema metadata
  tests/boot.rs — integration smoke: bus starts and shuts down from embedded YAML
  tests/e2e.rs — binary smoke for run --config, check, status, SOCKS5 CONNECT, SOCKS5 UDP ASSOCIATE, HTTP metrics, concurrent TCP/UDP smoke, mesh-peer two-node UDP datagram, native direct forward (`direct_tcp_forward_reaches_tcp_egress`, `direct_udp_forward_reaches_udp_egress`), route_group causal selection (`direct_tcp_route_group_*`), native direct reverse service sink (`direct_tcp_reverse_*`), and a `#[ignore]` direct-vs-SOCKS5 comparison record (`direct_vs_socks5_comparison_record`)
  tests/pipeline_source.rs — binary smoke for `pipeline.source.ingress_index` attachment selection
  tests/throughput_transport.rs — release transport-substrate matrix; seven `#[ignore]` rows (plain/batch/GSO-GRO/pacing-PMTU UDP, native Secure UDP steer/replicate/stripe) gated on `MESH_BUS_TRANSPORT_BENCH` + one non-ignored `matrix_skips_clean_without_env` build-skip-clean guard; every row drives real `UdpPacketLoop` or native policy evidence

local dependencies:
  mesh-bus-runtime — parse_config, status_text, run, build_pipeline_runtime, BusHandle, LoggingCfg
  tokio — async runtime, signal::ctrl_c and Unix SIGTERM
  tracing-subscriber — fmt logger init
  anyhow — error propagation to main
  mb-proto-socks5 — dev-only SOCKS5 wire client for binary e2e smoke
  mb-endpoint — dev-only endpoint construction for binary e2e smoke
  bytes — dev-only BytesMut for binary e2e smoke decoding

boundary rules:
  - `check` must resolve every operator-owned relative path the same way `run` does; config-local legacy `ingress.rule_chain_path` is resolved against the config file directory, not the process cwd
  - `check` must load legacy local `rule_sets` with the same chain-file-relative semantics as runtime fallback policy loading
  - `check` must reject legacy RulePolicy actions that the selected SOCKS5 adapter cannot project onto BusSessionRequest; preflight must not be weaker than run startup
  - `check` delegates pipeline source selection to mesh-bus-runtime; CLI preflight does not carry a second source-selection contract
  - `admin` commands are Operator API clients; they must call mesh-bus-operator-api response builders and must not duplicate status/config/redaction logic

mesh-bus-bin decisions:
  - 0.4.7 (2026-05-21): Operator Plane M0 CLI client added. `mesh-bus admin status`, `mesh-bus admin config-check`, and `mesh-bus admin config-effective` consume mesh-bus-operator-api response builders; config-check shares runtime preflight, and config-effective redacts MeshSec keys and passwords.
  - 0.4.6 (2026-05-18): DDTR M3 + M6 — `tests/e2e.rs` 4374→3718 LOC: subprocess+sleep e2e converted to in-process composition over the REAL `run`, shared helpers lifted to `tests/e2e_client.rs`, `tests/e2e_composition.rs` (Probe enum, template substitution) + 8 `tests/fixtures/e2e/*.yaml`; 6 protected secure-UDP e2e kept verbatim. M6: `tests/throughput_socks5.rs` + `tests/throughput_transport.rs` + `lib/mb-splice` relay_matrix reclassified as PERFORMANCE EVIDENCE (header + all rows `#[ignore]`/env-gated; `matrix_skips_clean_without_env` non-ignored), excluded from correctness accounting. Part of data-driven test-reduction close-out (root `mesh-bus` 0.4.40; ledger docs/plan/2026-05-18-ddtr-audit.md). cargo test --workspace 0 failed; binary e2e green.
  - 0.4.5 (2026-05-18): native plan M8 — throughput matrix grew native Secure UDP policy rows: `bench_native_secure_udp_steer`/`_replicate`/`_stripe` drive the real `UdpPacketLoop` loopback the native Secure UDP fast path rides; replicate notes ~2x fan-out wire volume; policy-specific live drive directive-deferred, functional proof = M7 e2e trio. A non-`#[ignore]` `matrix_skips_clean_without_env` guard makes a plain `cargo test --test throughput_transport` build the matrix and prove skip-clean.

handbook:
  ../../docs/handbook/index.html
