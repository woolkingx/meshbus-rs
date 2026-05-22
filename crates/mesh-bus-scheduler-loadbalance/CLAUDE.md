# mesh-bus-scheduler-loadbalance


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
mesh-bus-scheduler-loadbalance governs:
  src/lib.rs — LoadBalanceScheduler and LoadBalanceMode
  tests/loadbalance.rs — scheduling behavior for round-robin, sticky-sessions, and consistent-hashing modes
  tests/schema.rs — schema closure, mode vocabulary, and weights-key guard

mesh-bus-scheduler-loadbalance depends_on:
  mesh-bus-core — SchedulerPlugin, ScheduleDecision, RankContext
  mb-loadbalance — pure WRR, consistent-hash, and StickyTable algorithms

mesh-bus-scheduler-loadbalance invariants:
  - scheduler decisions are metadata-only and never inspect Frame.payload
  - config weights are keyed by exit identity and must match the shared ExitId/SinkId shape
  - load-balance output is an Ordered decision: chosen exit first, remaining exits as fallback order
  - round-robin ignores both source_key and target_key
  - consistent-hashing keys on RankContext.target_key (falls back to flow_id when absent); aligns with mihomo target-only consistent-hash
  - sticky-sessions keys on RankContext.source_key|RankContext.target_key (falls back to either side alone, then flow_id); aligns with mihomo (same source + same target → same exit)
  - sticky-sessions is first-pick plus TTL; after ttl expiry the flow can be rebalanced by WRR
  - priority/weight changes candidate preference only; core flow_pins still keep an active flow on its successful exit

mesh-bus-scheduler-loadbalance decisions:
  - 0.1.6 (2026-05-11): sticky-sessions key uses length-prefix encoding (`{src.len}:{src}|{tgt.len}:{tgt}`) so opaque ingress keys containing `|` cannot collide across (source,target) pairs
  - 0.1.7 (2026-05-13): schema root is closed and weights keys are constrained to the shared ExitId/SinkId shape
  - 0.1.8 (2026-05-17): sticky-sessions key replaced length-prefix concat with a type-tagged length-delimited DefaultHasher digest; the prior 0.1.6 length-prefix claim did not make the encoding injective for opaque keys containing the separator.

handbook:
  ../../docs/handbook/index.html
