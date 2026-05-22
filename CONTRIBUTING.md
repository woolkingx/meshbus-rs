# Contributing

MeshBus-rs is handbook-first and schema-first. Contributions are welcome, but changes must respect the owner boundary model.

## Start Here

1. Read [docs/handbook/index.html](docs/handbook/index.html).
2. Locate the owner chapter for the change.
3. Read the nearest `CLAUDE.md`, `schema.json`, and `test.html` in the affected directory.
4. If the change has three or more subtasks, write a plan under `docs/plan/YYYY-MM-DD-<title>.md`.

## Required Shape

| Change | First owner |
|---|---|
| Architecture, topology, product meaning, acceptance gate | `docs/handbook/` |
| Config/protocol/capability data shape | nearest `schema.json` |
| Module execution rule or local invariant | nearest `CLAUDE.md` |
| Code behavior | owner crate or lib |
| Proof | owner module test, then integration/product e2e |

Do not place durable architecture truth only in issues, PR text, README, or a plan file.

## Design Rules

- Each directory is an owner boundary.
- A layer may mutate only its own PCI/data.
- Carried SDU bytes remain opaque to lower layers.
- Core crates must not depend on L7 protocol parser crates.
- New L7 protocol support enters as an ingress/egress adapter or plugin pair.
- Rules and hooks decide over metadata, not payload inspection.
- Tests follow `data -> schema -> module owner test -> integration -> product e2e`.

## Local Checks

Run the narrow owner tests first. Before opening a PR, run:

```bash
cargo fmt --all --check
cargo test --workspace
node docs/handbook/handbook-gate.mjs
git diff --check
```

If a live deployment claim is part of the change, also run the relevant runner under `tests/` with explicit environment variables. See [tests/CLAUDE.md](tests/CLAUDE.md).

## Pull Request Standard

A PR should state:

- owner boundary touched
- handbook section or schema updated
- tests run
- live gates run or explicitly not run
- known remaining gaps

## Commit Style

Use short engineering commit messages:

```text
docs: add github publication landing files
core: fix datagram close observation
test: add meshsec fail-closed fixture
```

Do not mix unrelated cleanup with behavior changes.
