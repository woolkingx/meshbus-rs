# Security Policy

MeshBus-rs is a network runtime. Treat security reports as high priority even when the affected path is marked experimental.

## Supported Status

This repository is currently an MVP/developer-preview codebase. Security fixes target the `bus-mesh` development branch until a public release branch exists.

## Report a Vulnerability

Use a private channel when available. If no private channel has been published yet, open a minimal GitHub issue that says a vulnerability report is available and avoid public exploit details, live keys, packet captures with secrets, or production endpoints.

Include:

- affected commit or version
- affected path: config, MeshSec, SOCKS5, HTTP CONNECT, direct TCP/UDP, Operator API, deployment, or tests
- expected boundary and observed violation
- reproduction steps with test keys or synthetic configs
- whether the issue exposes secrets, accepts unauthenticated events, bypasses route policy, leaks payload, crashes the runtime, or causes resource exhaustion

## Security Boundaries

| Boundary | Rule |
|---|---|
| Core payload opacity | Core must not inspect application payload bytes or protocol-specific fields. |
| MeshSec | WAN MeshPeerUdp traffic must be encrypted and fail closed for clear, wrong-key, tampered, and replayed packets. |
| Operator API | Local API is loopback-first. Remote admin writes require MeshSec, auth, replay protection, audit, and explicit gates before production use. |
| Config and logs | PSK, SOCKS5 passwords, bearer tokens, and raw payload bytes must not appear in logs, diagnose bundles, metrics, or panic paths. |
| Protocol adapters | SOCKS5, HTTP CONNECT, DNS, and future protocol parsers stay at the edge and project only protocol-neutral intent into the bus. |

## Non-Security Bugs

Use a normal bug report for correctness, performance, documentation, or compatibility issues that do not cross a security boundary.

## Current Hardening Gaps

The handbook owns canonical status. Start with:

- [Production readiness](docs/handbook/production-readiness.html)
- [Mesh Protocol](docs/handbook/mesh-protocol.html)
- [Testing gates](docs/handbook/testing-gates.html)
