# mesh-bus-scheduler-loadbalance


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  src/lib.rs — LoadBalanceScheduler and LoadBalanceMode
  tests/loadbalance.rs — scheduling behavior for round-robin, sticky-sessions, consistent-hashing, and source-lease-rotate modes
  tests/schema.rs — schema closure, mode vocabulary, and weights-key guard

local dependencies:
  mesh-bus-core — SchedulerPlugin, ScheduleDecision, RankContext
  mb-loadbalance — pure WRR, consistent-hash, StickyTable, and SourceLeaseRotate algorithms

boundary rules:
  - scheduler decisions are metadata-only and never inspect Frame.payload
  - config weights are keyed by exit identity and must match the shared ExitId/SinkId shape
  - load-balance output is an Ordered decision: chosen exit first, remaining exits as fallback order
  - round-robin ignores both source_key and target_key
  - consistent-hashing keys on RankContext.target_key (falls back to flow_id when absent); aligns with mihomo target-only consistent-hash
  - sticky-sessions keys on RankContext.source_key|RankContext.target_key (falls back to either side alone, then flow_id); aligns with mihomo (same source + same target → same exit)
  - sticky-sessions is first-pick plus TTL; after ttl expiry the flow can be rebalanced by WRR
  - source-lease-rotate keys on RankContext.source_key only (falls back to flow_id); target_key must not affect daily-use lease selection
  - source-lease-rotate daily default reselects only for new flow opens after core reports source-key active_flows=0 and idle_since_ms has exceeded idle timeout, or after missing/unhealthy leased exit; explicit non-default max-age policy is validation/deliberate distribution, not daily active-source rotation
  - priority/weight changes candidate preference only; core flow_pins still keep an active flow on its successful exit

mesh-bus-scheduler-loadbalance decisions:
  - 0.1.6 (2026-05-11): sticky-sessions key uses length-prefix encoding (`{src.len}:{src}|{tgt.len}:{tgt}`) so opaque ingress keys containing `|` cannot collide across (source,target) pairs
  - 0.1.7 (2026-05-13): schema root is closed and weights keys are constrained to the shared ExitId/SinkId shape
  - 0.1.8 (2026-05-17): sticky-sessions key replaced length-prefix concat with a type-tagged length-delimited DefaultHasher digest; the prior 0.1.6 length-prefix claim did not make the encoding injective for opaque keys containing the separator.
  - 0.1.9 (2026-05-25): source-lease-rotate is the Run 2 daily-use mode; it keeps same-source new flows on one exit during the active window and ignores target_key by design.
  - 0.1.10 (2026-05-26): source-lease-rotate daily default uses MaxAgePolicy::Off; active sources do not switch due to age, only source-key idle expiry or candidate loss.
  - 0.1.11 (2026-05-26): source idle is core lifecycle truth, not scheduler last-seen time. The scheduler consumes RankContext.source_activity and must not expire a source lease while active_flows > 0.

handbook:
  ../../docs/handbook/index.html
