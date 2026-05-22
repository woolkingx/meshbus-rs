# mb-rule

mb-rule role:
  rule engine library — flat RuleCtx + AST + Action union + ruleset registry;
  plane-uniform decision primitive consumed by application adapters, resolver policy, and pipeline hooks
  no dependency on mesh-bus-core; rule-side DTOs only

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mb-rule governs:
  schema/*.schema.json — JSON Schema definitions for RuleCtx, RuleChain, Action, Ruleset
  src/types.rs — Rust types mirroring the schemas one-to-one
  src/data_handle.rs — evaluate_with_trace(), validate(), YAML parser, RuleSetRegistry
  tests/evaluate.rs — short-circuit, missing-field-false, first-match-wins, default
  tests/yaml.rs — flat + explicit `match:` round-trip
  tests/validate.rs — Compose conflict, ruleset format/field compatibility
  tests/schema_sync.rs — every public type has a schema definition
  tests/boundary.rs — grep guard: src/ never references mesh_bus_core

mb-rule depends_on:
  serde, serde_yaml, serde_json, thiserror, ipnet, regex

mb-rule extends:
  ../../docs/handbook/system-architecture.html

mb-rule invariants:
  - mb-rule MUST NOT depend on mesh-bus-core or any adapter crate
  - every non-primitive field in RuleCtx and every payload in Action is a rule DTO owned here
  - RuleCtx.operation is the protocol-neutral source operation predicate; protocol-named fields such as socks5_command are compatibility fields, not the extension pattern for future adapters
  - generic operation names describe source action shape (`connect`, `datagram_associate`, `datagram_send`); protocol command names such as `udp_associate` stay in compatibility fields
  - rule schemas must describe socks5_command as legacy compatibility and point future adapters at operation rather than protocol-named predicates
  - Action payload DTO schemas are non-null; RuleCtx optional/null field schemas must not leak into action intent payloads
  - missing field in RuleCtx evaluates Term to false; engine never panics on None
  - RuleChain.rules and RuleChain.default are mandatory in YAML; use `rules: []` for explicit default-only chains
  - RuleChain top-level YAML is closed; only rules/default/rule_sets are accepted
  - Rule.id is optional; when present it is a non-empty decision-trace label
  - Rule must use exactly one match shape: explicit `match:` or at least one flat predicate key
  - Action object schema variants are closed one-key mappings, matching parser exact-one-key behavior
  - Allow/Deny object action payloads are empty objects; no ignored reason/debug fields
  - RuleScheduleHint::FanOut payloads are closed; `fanout.k` must be >= 1 in parser and validate()
  - SetTransform descriptor payloads are closed; `params` is absent/Null or an object preserved for the transform consumer
  - SetRouteGroup is a non-empty L4 route-group label; schema, YAML parsing, and validate() reject empty strings
  - SetResolverPool is a non-empty resolver pool label; empty does not mean the implicit system/default pool
  - SetCostBias is bounded to -9000..=9000 in schema, YAML parsing, and validate()
  - ruleset names and `ruleset:` references are non-empty symbols; names are unique registry identities
  - ruleset declarations are closed; inline owns values only, local owns path only, unknown ruleset keys reject
  - classical rulesets omit ruleset-level field; field routing is embedded per classical line
  - inline ruleset value lists, entries, local ruleset paths, and filtered local file entries are non-empty; blank/comment lines are ignored before entries are built
  - resolved ruleset entry parse errors carry `rule_sets.<name>.values[]` plus the offending value
  - RuleSetRegistry::load enforces ruleset invariants; direct programmatic callers cannot bypass validate()
  - string predicate payloads are non-empty; empty suffix/keyword/regex is not a wildcard
  - set predicate payloads are non-empty; `asn: []` is invalid
  - `dst_port_range` is inclusive and ordered; start must be <= end
  - `all` and `any` match groups are non-empty; empty `all` is not a wildcard
  - explicit MatchExpr operator forms are closed; control keys cannot mix sibling predicate keys
  - explicit MatchExpr Term schema is closed to parser-supported predicate keys
  - flat Rule property names are closed to id/match/action plus parser-supported predicate keys
  - flat Rule predicate value schemas reuse explicit Term predicate schemas
  - Compose is non-empty; an empty Compose is not an Allow/no-op
  - validate() rejects Compose containing both Allow and Deny, or two SetRouteGroup

mb-rule decisions:
  - 0.2.34 (2026-05-13): RuleCtx.operation schema examples now use generic source action names and keep SOCKS5 command names out of the extension pattern.
  - 0.2.33 (2026-05-13): rule schemas now document socks5_command as a legacy compatibility predicate and direct future adapters to protocol-neutral operation.
  - 0.2.32 (2026-05-13): Added protocol-neutral `operation` predicate and RuleCtx field. SOCKS5 legacy RulePolicy now fills operation alongside socks5_command so future adapters can match source operations without adding protocol-named fields to mb-rule.
