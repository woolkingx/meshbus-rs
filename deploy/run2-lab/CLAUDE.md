# deploy/run2-lab

deploy/run2-lab role:
  Run2 private-lab deployment composition wrapper
  composes deploy/service per-host binary-only deployment with the Run2 live validation gate
  owns lab deployment order and evidence aggregation, not runtime topology truth

handbook:
  ../../docs/handbook/index.html

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned action shape
  - deploy/service owns single-host artifact movement and systemd lifecycle
  - this directory may compose multiple deploy/service calls but must not rewrite remote runtime YAML or own mesh route policy
  - private lab hosts are command/env input data; public examples use documentation addresses

deploy/run2-lab governs:
  deploy.mjs — Run2 lab pool-first/gateway-last deployment wrapper and optional live validation
  schema.json — wrapper input contract
  test.html — proof contract

deploy/run2-lab depends_on:
  deploy/service — single-host binary deployment owner
  tests/live-run2-pool-validation.mjs — Run2 live acceptance owner
  cargo build --release -p mesh-bus-bin — local release binary producer

deploy/run2-lab invariants:
  - Pool nodes deploy before gateway because Mesh Protocol wire changes may require all peers to be on the same binary generation.
  - Gateway and pool binary paths are role-owned data and may differ. The default gateway binary is `/opt/mesh-bus/bin/mesh-bus-run2`; the default pool binary is `/opt/mesh-bus/bin/mesh-bus`. A deploy that updates only one role's ExecStart binary is invalid evidence.
  - The default build target is `x86_64-unknown-linux-musl` so lab nodes with older glibc can run the deployed binary.
  - Remote configs are preserved by default; this wrapper deploys binary updates, not topology mutations.
  - Validation is a normal product gate and must emit JSON evidence.
  - Failover validation is explicit because it stops one pool node service.

deploy/run2-lab decisions:
  - 0.1.1 (2026-05-24): role-specific binary paths are part of the wrapper contract. 10.36 runs `mesh-bus-run2.service` from `/opt/mesh-bus/bin/mesh-bus-run2`, while pool nodes run `/opt/mesh-bus/bin/mesh-bus`; a single `remote_bin` default can create mixed ABI live tests.
  - 0.1.0 (2026-05-24): introduced Run2 lab deployment wrapper after repeated manual gateway/pool binary updates became the bottleneck for live validation.
