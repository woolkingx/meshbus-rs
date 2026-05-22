# MeshBus-rs

MeshBus-rs is an OSI-aware Rust event/data mesh runtime for programmable direct proxy and protocol-over-mesh transport.

It is not a SOCKS5 clone, HTTP proxy, VPN product, QUIC wrapper, or Kubernetes service mesh. Those are edge adapters or deployment shapes. The core product is a rule-driven L4/L5/L6 substrate:

```text
source intent
  -> metadata enrichment
  -> rule / policy
  -> scheduler
  -> exit | service | upstream peer
  -> opaque stream/datagram movement
```

## Current Shape

MeshBus-rs currently focuses on a personal-deployable MVP:

| Lane | Status |
|---|---|
| SOCKS5 forward over MeshSec MeshPeerUdp | Functional and live two-node smoke proven |
| HTTP CONNECT forward over MeshSec MeshPeerUdp | Functional gate proven |
| L4 reverse TCP / UDP service sink | Functional gate proven |
| Operator local API and CLI reads | Functional MVP |
| MeshSec encrypted event envelope | Functional MVP |
| Advanced multi-hop, striping, migration, remote admin writes | Roadmap |

The architecture source of truth is the handbook, not this README:

- [Handbook index](docs/handbook/index.html)
- [Product roadmap](docs/handbook/product-roadmap.html)
- [System architecture](docs/handbook/system-architecture.html)
- [Mesh Protocol](docs/handbook/mesh-protocol.html)
- [Production readiness](docs/handbook/production-readiness.html)

## Build

```bash
cargo build --workspace
cargo build --release -p mesh-bus-bin
```

The CLI binary is currently named `mesh-bus`.

## Quick Run

Validate a config:

```bash
cargo run -p mesh-bus-bin -- check --config config/example.yaml
```

Run a local node from the example config:

```bash
cargo run -p mesh-bus-bin -- run --config config/example.yaml
```

Query config-only operator data:

```bash
cargo run -p mesh-bus-bin -- admin config-check --config config/example.yaml
cargo run -p mesh-bus-bin -- admin config-effective --config config/example.yaml
```

For live runtime API commands, start a config with `operator: LocalHttp` and use:

```bash
mesh-bus admin status --api http://127.0.0.1:19080
mesh-bus admin metrics-snapshot --api http://127.0.0.1:19080
mesh-bus admin diagnose --api http://127.0.0.1:19080
```

## Test

Fast correctness gates:

```bash
cargo test --workspace
cargo fmt --all --check
```

Handbook gate:

```bash
node docs/handbook/handbook-gate.mjs
```

Live deployment gates require an installed remote node and explicit environment variables. See [tests/CLAUDE.md](tests/CLAUDE.md) and [testing gates](docs/handbook/testing-gates.html).

## Design Rules

- Handbook owns topology, architecture, invariants, and acceptance gates.
- `schema.json` owns config, protocol, capability, and data shapes.
- Each module owns only its PCI/data; carried SDU bytes remain opaque.
- Core must not parse SOCKS5, HTTP, DNS, TLS, VMess, XRAY, or application payloads.
- New application protocols enter as edge adapters or plugin pairs.
- Tests follow `data -> schema -> owner module test -> integration -> product e2e`.

## Repository Map

| Path | Role |
|---|---|
| `docs/handbook/` | Architecture and spec truth |
| `docs/plan/` | Runnable task plans |
| `crates/mesh-bus-core` | Kernel and transport substrate |
| `crates/mesh-bus-runtime` | Config assembly and runtime wiring |
| `crates/mesh-bus-bin` | CLI, daemon, local Operator API |
| `crates/mesh-bus-ingress-*` | Source adapters |
| `crates/mesh-bus-egress-*` | Exit/service/peer adapters |
| `lib/mb-*` | Pure codecs and algorithms |
| `tests/` | System test guide and live/product runners |

## Naming

- Repository: `meshbus-rs`
- Product family: MeshBus
- Protocol: MeshBus Protocol
- Security layer: MeshSec
- Implemented CLI: `mesh-bus`

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))
