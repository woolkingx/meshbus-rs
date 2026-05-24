# MeshBus-rs

MeshBus-rs is a Rust encrypted mesh proxy runtime for forward proxy, reverse proxy, upstream proxy pools, load balancing, and protocol plugins.

The first working use case is replacing fragile proxy chains such as:

```text
client -> danted / mihomo -> upstream SOCKS proxies
```

with a cleaner mesh shape:

```text
client SOCKS5
  -> MeshBus gateway
  -> MeshSec encrypted MeshPeerUdp
  -> upstream MeshBus pool
  -> direct TCP/UDP egress
  -> server
```

The practical first use case is simple: run one gateway, run several upstream pool nodes, point your client at the gateway, and let MeshBus keep related sessions sticky while still giving you a visible, encrypted, multi-exit fabric.

Protocol support is adapter-shaped: SOCKS5 and HTTP CONNECT are the first compatibility adapters; XRAY, VMess, and custom app protocols are future plugin lanes if needed, not core rewrites.

## Product Layers

| Layer | Role |
|---|---|
| SOCKS5 / HTTP CONNECT / future XRAY / VMess | Edge adapters |
| Forward proxy / reverse proxy / load balancing / upstream pool | Product deployment shapes |
| MeshBus runtime | L4/L5 session, scheduling, movement, and observation substrate |
| Mesh Protocol | Native event/package language that makes the mesh possible |

## Why It Exists

Most proxy stacks grow around protocols: SOCKS, HTTP, DNS, QUIC, rules, outbounds, sniffing, fallback, and chains. That works, but the control path and data path tend to fight each other.

MeshBus-rs treats SOCKS5 and HTTP CONNECT as edge adapters. The core is lower-level:

```text
source intent -> rule/policy -> scheduler -> selected peer/exit -> opaque byte/datagram movement
```

That means the hot path does not parse application payloads. It moves already-decided streams and datagrams through explicit owners: L4 routing, L5 session, L6 MeshSec transform, and operator-visible evidence.

## Current Status

| Lane | Status |
|---|---|
| SOCKS5 gateway -> encrypted MeshBus upstream pool | Private-lab live green across five pool nodes |
| Forward proxy / upstream pool / load balancing | Functional through SOCKS5 + MeshPeerUdp pool |
| Reverse proxy / service sink | Functional for L4 TCP/UDP service paths |
| Session-sticky daily mode | Enabled for browser/site stability |
| Round-robin validation mode | Used to prove every pool peer carries traffic |
| Direct pool-node SOCKS5 entry | Functional |
| MeshSec encrypted event envelope | Functional MVP |
| Operator local API and metrics | Functional MVP |
| HTTP CONNECT over MeshSec | Functional gate proven |
| XRAY / VMess / custom protocol plugins | Future adapters if needed |
| Health-aware sticky failover, dashboard, geo/rules, long soak | Roadmap |

The handbook is the architecture source of truth. This README is only the public landing page:

- [Handbook index](docs/handbook/index.html)
- [Product roadmap](docs/handbook/product-roadmap.html)
- [Direct proxy](docs/handbook/direct-proxy.html)
- [System architecture](docs/handbook/system-architecture.html)
- [Mesh Protocol](docs/handbook/mesh-protocol.html)
- [Production readiness](docs/handbook/production-readiness.html)

## Topology

Gateway node:

```text
SOCKS5 client entry
  -> scheduler
  -> MeshPeerUdp egress: mesh20 | mesh21 | mesh22 | ...
```

Pool node:

```text
MeshPeerUdp + MeshSec ingress
  -> local bus re-entry
  -> direct TCP/UDP egress
```

Default Run 2 convention:

| Port | Owner |
|---|---|
| `2080/tcp` | Optional direct SOCKS5 entry on pool nodes |
| `2080/udp` | MeshPeerUdp + MeshSec peer traffic |

The shared number is only an operator convention. TCP and UDP are separate L4 listeners.

## Build

```bash
cargo build --workspace
cargo build --release -p mesh-bus-bin
```

The CLI binary is currently named `mesh-bus`.

## Quick Start

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

## Operating Modes

Use `sticky-sessions` for daily browser/proxy use:

```yaml
scheduler:
  kind: LoadBalance
  mode: sticky-sessions
```

Use `round-robin` only when validating that every pool node can carry traffic:

```yaml
scheduler:
  kind: LoadBalance
  mode: round-robin
```

Sticky mode keeps related source/target sessions on a stable exit, which avoids breaking sites that dislike exit changes during login, CDN fetches, or risk checks.

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

Short version:

```text
protocols are adapters
MeshBus is the encrypted session fabric
operator evidence is part of the product
```

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
