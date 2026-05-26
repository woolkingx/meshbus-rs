# mesh-bus tests

tests role:
  Root testing development guide. This file governs how tests are designed, grouped, and used to decide readiness across the whole `bus-mesh` workspace.

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

purpose:
  - A module test proves only the module contract.
  - Tests are designed from `data -> schema -> module -> integration -> e2e`.
  - The module that owns a data shape owns the schema and lowest contract tests for that data.
  - A feature is not complete until codec, adapter, core session/runtime, pipeline hooks, observers, scheduler behavior, binary e2e, and required live WAN smoke all pass for the affected path.
  - Passing `cargo test -p <one crate>` is never a system-complete claim.
  - Test evidence must name the exact command, scope, and live environment used.

owned files:
  owner module tests — colocated with the module code and schema that own the data
  crates/*/tests — crate-level public contract tests for that crate only
  lib/*/tests — pure algorithm, data-structure, and codec contract tests
  crates/mesh-bus-core/tests — kernel/session/registry/observer boundary tests
  crates/mesh-bus-bin/tests — product composition, binary boot, e2e, perf, and live smoke tests
  tests/ — root testing guide, shared composition policy, and product live runners, not a dumping ground for module-owned tests

local dependencies:
  docs/handbook/index.html — topologic/logic schema and layer ownership
  CLAUDE.md — execution rules and owner navigation
  crate-local CLAUDE.md — module contract and invariants
  schema.json files — config/type/data contract truth
  docs/handbook/spec/*.schema.json — handbook-owned cross-layer machine contracts
  docs/plan — active implementation-specific acceptance gates

boundary rules:
  - Start every non-trivial test change by reading root `CLAUDE.md`, the affected module `CLAUDE.md`, its `schema.json`, and existing tests for the same surface.
  - New behavior starts from the data it creates or consumes; add or update the schema before writing behavior tests.
  - New behavior requires tests at the lowest owner layer and at the integration layer that can observe the real feature.
  - Module tests live with the module code and schema: use inline/unit tests for private owner invariants, and the crate's `tests/` directory for public module contracts.
  - Root `tests/` must only define cross-module policy or shared support; it must not own module data, module schema, or module edge-case correctness.
  - Integration and e2e tests compose tested module contracts; they must not duplicate codec, crypto, reorder, algorithm, schema, or parser edge-case tests owned by modules.
  - Schema or handbook wording that carries contract meaning must have a test or boundary guard.
  - Core tests must not import L7 protocol crates. L7 protocol tests belong in ingress/egress adapter crates or codec libs.
  - Algorithm plugins own algorithm correctness tests; core tests only verify that core consumes declared capabilities, metadata, snapshots, or observer outputs without embedding the algorithm.
  - Hook tests must cover both metadata writes and fail-closed behavior.
  - Observer tests must cover delivery/backpressure/lifecycle semantics, not only counter increments.
  - Scheduler tests must cover local scoring logic and one runtime/e2e path proving the scheduler is wired into dispatch.
  - WAN/live tests must be explicit and env-gated; skipping because env is absent must be reported as "not live-verified", not success.

tests phases:
  0. Data and schema contract:
     Identify the owner module for the data shape, then run or add the schema test/boundary guard at that owner.
     Commands: owner-specific schema tests such as `cargo test -p mb-proto-mesh --test codec`, `cargo test -p mb-reorder`, or focused boundary guards when the contract is handbook-owned.
     Purpose: prove the legal data shape before testing behavior.

  1. Codec and pure libraries:
     Run L6 codec, pure data-structure, and pure algorithm tests first.
     Commands: `cargo test -p mb-proto-socks5`, `cargo test -p mb-proto-dns`, plus affected `lib/mb-*`.
     Purpose: prove wire format, parsing, ranking, cost, health, rule evaluation, and data structures without runtime noise.

  2. Core L4/L5/L6 substrate:
     Run `cargo test -p mesh-bus-core`.
     Required focused gates when touched: `cargo test -p mesh-bus-core --test kernel_invariant`, `--test session_surface`, `--test registry_verify`, `--test reliable_publish_deadline`, `--test core_event_surface`.
     Purpose: prove registry verification, metadata legality, session behavior, return semantics, observation bus behavior, and dispatch invariants.

  3. Adapter contracts:
     Run affected ingress/egress crates.
     Common commands: `cargo test -p mesh-bus-ingress-socks5`, `cargo test -p mesh-bus-egress-socks5`, `cargo test -p mesh-bus-ingress-udp`, `cargo test -p mesh-bus-egress-udp`, `cargo test -p mesh-bus-ingress-tcp`, `cargo test -p mesh-bus-egress-tcp`.
     Purpose: prove edge protocol stitching without leaking adapter protocol details into core.

  4. Pipeline hooks and resolver:
     Run `cargo test -p mesh-bus-pipeline-hooks` and `cargo test -p mesh-bus-resolver`.
     Required focus for routing/policy work: `resolve_hook`, `rule_hook`, `pick_sink_hook`, `runtime`, `wiring`, resolver `m1_tunneled`, `m2_mesh_direct`, `m3_system`, and cache tests.
     Purpose: prove metadata enrichment, DNS policy, route_group, schedule_hint, rule_chain, and fail-closed behavior.

  5. Scheduler and observer modules:
     Run `cargo test -p mesh-bus-scheduler-cake`, `cargo test -p mesh-bus-scheduler-loadbalance`, `cargo test -p mesh-bus-scheduler-replicate`, `cargo test -p mesh-bus-observer-metrics`, and `cargo test -p mesh-bus-observer-prometheus` when affected.
     Purpose: prove algorithm plugins, feedback observers, metrics, and presentation observers independently of e2e smoke.

  6. Runtime config assembly:
     Run `cargo test -p mesh-bus-runtime`.
     Required focus: `config` and `pipeline_assembly`.
     Purpose: prove YAML config, schema exposure, source/sink kind projection, candidate capability bits, and runtime wiring.

  7. Binary local e2e:
     Run `cargo test -p mesh-bus-bin --test e2e`.
     Required focus by feature: SOCKS5 CONNECT, SOCKS5 UDP ASSOCIATE, TCP/UDP concurrent smoke, route_group, auth, metrics, pipeline source, and binary boot.
     Purpose: prove a real process shape can boot from config and move traffic across configured modules.

  8. Performance and ignored benches:
     Run only after correctness passes.
     Commands: `cargo test --release --package mesh-bus-bin --test throughput_socks5 -- --ignored --nocapture --test-threads=1` and `cargo test -p mb-splice --test relay_matrix --release -- --ignored --nocapture --test-threads=1` when data-plane speed is under review.
     Purpose: produce numbers, not correctness claims.

  9. Live WAN smoke:
     Run when deployment, WAN routing, upstream SOCKS5, DNS policy, scheduler selection, route_group, or remote mesh-peer behavior is part of the claim.
     Upstream SOCKS5 env gate: `MESH_BUS_LIVE_SOCKS5_UPSTREAMS`, optional `MESH_BUS_LIVE_TARGET_HOST`, `MESH_BUS_LIVE_TARGET_PORT`.
     Command: `cargo test -p mesh-bus-bin --test e2e live_upstream -- --nocapture --test-threads=1`.
     Native MeshSec peer env gate: `MESH_BUS_MESHSEC_KEY_HEX` with optional `MESH_BUS_REMOTE_HOST`, `MESH_BUS_REMOTE_PORT`, `MESH_BUS_LIVE_TARGET_HOST`, `MESH_BUS_LIVE_TARGET_PORT`, `MESH_BUS_LIVE_DNS_SERVER`, and `MESH_BUS_LIVE_DNS_NAME`.
     Command: `node tests/live-mihomo-replacement-smoke.mjs`.
     Deployed MVP acceptance gate: `MESH_BUS_REMOTE_HOST=198.51.100.36 MESH_BUS_REMOTE_SOCKS5=198.51.100.36:1081 MESH_BUS_REMOTE_OPERATOR=http://127.0.0.1:19080 MESH_BUS_REMOTE_SSH=root@198.51.100.36 node tests/live-mvp-production-acceptance.mjs`.
     Purpose: prove the installed node is active, Operator API answers, real SOCKS5 HTTPS traffic increments dispatch/egress metrics, and any missing optional HTTP CONNECT or UDP client probe is reported as partial live acceptance rather than hidden as success.
     Operations fault gate: `MESH_BUS_REMOTE_SSH=root@198.51.100.36 MESH_BUS_REMOTE_CONFIG=/etc/mesh-bus/config.yaml MESH_BUS_REMOTE_BIN=/opt/mesh-bus/bin/mesh-bus node tests/live-production-faults.mjs`.
     Purpose: prove bad config, port collision, restart/rollback evidence, and temporary unavailable-upstream behavior without mutating or killing the active service.
     Service soak gate: `MESH_BUS_REMOTE_SSH=root@198.51.100.36 MESH_BUS_REMOTE_SOCKS5=198.51.100.36:1081 MESH_BUS_REMOTE_OPERATOR=http://127.0.0.1:19080 MESH_BUS_SOAK_SECONDS=120 node tests/live-service-soak.mjs`.
     Purpose: prove the deployed service can sustain repeated real SOCKS5 HTTPS probes while dispatch_success increases, dispatch_failure stays flat, RSS/fd counts stay bounded, and systemd remains active.
     Diagnose bundle gate: `MESH_BUS_REMOTE_SSH=root@198.51.100.36 MESH_BUS_REMOTE_OPERATOR=http://127.0.0.1:19080 node tests/live-diagnose-bundle.mjs`.
     Purpose: prove the deployed Operator diagnose path returns redacted status, metrics, effective config, systemd, process, socket, and journal evidence.
     Observe/hooks profile gate: `MESH_BUS_OBSERVE_REMOTE_SSH=root@192.0.2.36 MESH_BUS_OBSERVE_REMOTE_OPERATOR=http://127.0.0.1:19081 node tests/live-observe-hooks-profile.mjs`.
     Purpose: prove a deployed node can be optimized through existing Operator probes and observer projections: every probe enters the public Operator API, crosses the normal ingress -> hooks -> scheduler -> egress path, moves dispatch/exit counters, and keeps dispatch failures plus MeshSec/native drops flat.
     Observe/syscall profile gate: `MESH_BUS_PROFILE_REMOTE_SSH=root@192.0.2.36 MESH_BUS_PROFILE_REMOTE_OPERATOR=http://127.0.0.1:19081 node tests/live-observe-syscall-profile.mjs`.
     Purpose: prove CPU optimization claims with phase evidence: idle and active Operator-probe windows keep dispatch/drop deltas flat while `strace -c` syscall rates stay under the configured mmap/munmap churn threshold. Raw syscall data is supporting evidence; Operator/observer deltas remain the path truth.
     Run2 pool gate: `MESH_BUS_RUN2_GATEWAY_SSH=root@192.0.2.36 MESH_BUS_RUN2_GATEWAY_SOCKS5=192.0.2.36:2080 MESH_BUS_RUN2_GATEWAY_OPERATOR=http://127.0.0.1:19081 MESH_BUS_RUN2_GATEWAY_SERVICE=mesh-bus-run2.service MESH_BUS_RUN2_GATEWAY_BIN=/opt/mesh-bus/bin/mesh-bus-run2 MESH_BUS_RUN2_GATEWAY_CONFIG=/etc/mesh-bus/run2.yaml node tests/live-run2-pool-validation.mjs`.
     Purpose: prove the exact systemd-owned gateway service is active, its ExecStart binary/config match the expected Run2 role, SOCKS5 traffic increments at least one pool exit, dispatch failures and MeshSec/native drops stay flat in a quiet window, and the JSON artifact captures service identity, binary/config hashes, MainPID/thread CPU, sockets, journal tail, metrics, and per-exit deltas. Optional service-mutation failover requires `MESH_BUS_RUN2_ALLOW_SERVICE_MUTATION=1` plus `MESH_BUS_RUN2_FAILOVER_PEER_SSH` and `MESH_BUS_RUN2_FAILOVER_EXIT`.
     Run2 stream gate: `MESH_BUS_RUN2_GATEWAY_SSH=root@192.0.2.36 MESH_BUS_RUN2_GATEWAY_SOCKS5=192.0.2.36:2080 MESH_BUS_RUN2_GATEWAY_OPERATOR=http://127.0.0.1:19081 MESH_BUS_RUN2_GATEWAY_SERVICE=mesh-bus-run2.service MESH_BUS_RUN2_GATEWAY_BIN=/opt/mesh-bus/bin/mesh-bus-run2 MESH_BUS_RUN2_GATEWAY_CONFIG=/etc/mesh-bus/run2.yaml node tests/live-run2-stream-validation.mjs`.
     Purpose: prove a long-lived HTTP/video-like stream through the deployed Run2 gateway remains active until EOF, downloads the expected bytes, keeps dispatch failures and MeshSec/native drops flat in a quiet window, and keeps gateway CPU under the configured threshold. The default mode starts a temporary systemd-owned origin on the gateway; external progressive video URLs may be tested with `MESH_BUS_RUN2_STREAM_TARGET`.
     Purpose: prove traffic reaches the real remote MeshPeerUdp service and real upstream targets, with SOCKS5 CONNECT, SOCKS5 UDP DNS, encrypted wire capture, and clear-packet fail-closed evidence.

  10. Path contract graph:
     Run after affected module tests and after live smoke when runtime evidence is part of the claim.
     Command: `node tools/flowgraph.mjs --focus mesh-peer-udp --out-dir artifacts/flowgraph`.
     Purpose: explain how green is built by owner, boundary, edge, data flow, control flow, and backpressure paths. `artifacts/flowgraph/path-contracts.md` must show affected contracts as `ok`; `warning` is a named gap/fix, not a completion claim. `artifacts/flowgraph/flowgraph-report.md` must have no critical/high findings.

tests completion rules:
  - Module-complete requires data/schema proof plus owner module contract tests.
  - Integration-complete requires the two module contracts on both sides of the boundary to already be green.
  - Feature-complete requires the narrow test, the owning module test, runtime assembly if config/wiring changed, binary e2e if traffic path changed, and live WAN smoke if the claim includes deployment/WAN readiness.
  - Production-ready requires all relevant phases plus `cargo fmt --check`, `cargo test --workspace`, and `git diff --check`.
  - If live WAN env is absent, report "local verified; live WAN not verified".
  - If perf was not rerun, report "correctness verified; throughput not refreshed".
  - A skipped ignored test is not a pass unless the skip reason is explicitly named.

tests feature matrix:
  - SOCKS5 CONNECT: `mb-proto-socks5`, `mesh-bus-ingress-socks5`, stream egress crate, `mesh-bus-runtime`, `mesh-bus-bin --test e2e`, optional live upstream.
  - SOCKS5 UDP ASSOCIATE: `mb-proto-socks5`, `mesh-bus-ingress-socks5 udp_associate`, datagram egress crate, `mesh-bus-runtime`, `mesh-bus-bin --test e2e socks5_udp`, live upstream when real UDP exit is claimed.
  - SOCKS5 BIND: `mb-proto-socks5` (Bind request/reply codec), `mesh-bus-ingress-socks5 bind`, `mesh-bus-bin --test e2e bind`; client-facing local relay, no bus egress session, policy/pipeline gated only.
  - SOCKS5 command/auth contract: any command or auth readiness claim must be checked against the four-column `command_auth_matrix` in `lib/mb-proto-socks5/schema.json` (codec vs live-ingress vs live-egress-stream vs live-egress-datagram); a test asserting support outside its column is a contract violation.
  - Raw UDP ingress/egress: `mesh-bus-ingress-udp`, `mesh-bus-egress-udp`, `mesh-bus-core` datagram session tests, runtime config, binary UDP e2e.
  - Mesh peer raw UDP datagram: `mb-proto-mesh`, `mesh-bus-egress-mesh-peer-udp`, `mesh-bus-ingress-mesh-peer-udp`, runtime config once wired, binary two-node raw UDP e2e, live WAN when remote peer deployment is claimed.
  - Mesh peer QUIC stream/datagram: `mb-proto-mesh`, QUIC reference/fallback binding crate tests, runtime config, binary two-node QUIC e2e, live WAN only when QUIC reference deployment is claimed.
  - DNS resolver: `mb-proto-dns`, `mesh-bus-resolver`, `mesh-bus-pipeline-hooks resolve_hook`, runtime pipeline assembly, live smoke when WAN DNS policy is claimed.
  - Hook/rule routing: `mb-rule`, `mesh-bus-pipeline-hooks`, adapter event/rule_ctx tests, runtime pipeline assembly, binary e2e showing selected sink metrics.
  - Scheduler/load balancing: scheduler crate tests, observer feedback tests, runtime pipeline assembly, binary e2e metrics proving selected exit behavior.
  - Observer/metrics: core observation tests, observer crate tests, binary metrics e2e proving exported counters/labels.
  - Splice/data-plane speed: `mb-splice` relay matrix, SOCKS5 throughput bench, and comparison against current root `CLAUDE.md` perf-backlog guidance.

tests anti-patterns:
  - Do not claim system completion from one crate's unit tests.
  - Do not add an e2e test to cover a missing module owner test.
  - Do not duplicate schema/codec/crypto/reorder edge cases in e2e.
  - Do not place module-owned tests in root `tests/`.
  - Do not call loopback e2e a WAN live smoke.
  - Do not hide skipped env-gated live tests inside "all tests pass".
  - Do not add protocol parsing tests to core to make an adapter test easier.
  - Do not update CLAUDE/schema text without a corresponding test or a reason why the text is non-contract commentary.
