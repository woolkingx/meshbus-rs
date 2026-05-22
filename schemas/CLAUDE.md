# schemas

schemas governs:
  endpoint.schema.json — host+port pair; referenced by session and frame
  exit-id.schema.json — opaque exit plugin identity sharing the kernel SinkId id shape
  session.schema.json — client session: id, target endpoint, open timestamp, optional pinned exit
  frame.schema.json — bus frame header + payload: packet id, flow id, session ref, seq, kind, target, ttl, traffic class, schedule hint, flow semantics, return semantics; Open is the stream connect-attempt frame and ShutdownWrite is stream write-half EOF
  return-event.schema.json — response events back to a session: Connected with path metadata | Data | Idle | Closed with typed close reasons
  measurement.schema.json — per-dispatch telemetry: exit, timestamp, rtt, payload bytes, jitter, throughput, success
  capability.schema.json — exit plugin capability: opaque adapter protocol label, stream/datagram support, max payload
  policy.schema.json — dispatch policy: mode, load-balance algorithm, probe budget, sticky ttl
  health-policy.schema.json — shared exit health policy: failure threshold, recovery window, probe delay
  bus-event.schema.json — observable bus events: SessionOpened | SessionClosed | Core(EventEnvelope over CoreEventId)
  exit-snapshot.schema.json — in-process per-exit runtime status: opaque adapter protocol label, capabilities, counters, RTT, bytes
  transform.schema.json — L6 transform descriptor: TransformKind tag plus opaque policy_ref
  fragment.schema.json — L6 fragment metadata: group/fragment ids, seq, total, offset, deadline, checksum
  reassembly.schema.json — L6 reassembly policy: ReassemblyMode plus opaque policy_ref
  test-runtime.schema.json — schema-driven test fixture row used by generic test runners

schemas extends:
  ../docs/superpowers/specs/2026-05-10-mesh-bus-redesign-design.md

schemas invariants:
  - cross-module schemas describe L4 routing metadata and return semantics, not L7 protocol fields
  - frame.payload is represented as bytes/base64 and remains opaque to bus schemas
  - protocol-specific request or response structures belong in protocol/plugin schemas such as lib/mb-proto-* or ingress/egress module schemas
  - observable BusEvent variants are closed contracts; observers must not receive untyped extension fields through cross-module schemas
  - TestRuntime fixture rows are data contracts for test runners; Rust test code may dispatch by kind/owner/expect type, never by individual fixture id
  - ExitId shares the kernel SinkId id shape (`^[A-Za-z0-9_.:-]+$`) so runtime-derived sink ids remain valid in status, measurement, session, and return-event schemas
  - HealthPolicy numeric minimums match runtime parse_config validation; failure_threshold, recovery_window_ms, and probe_after_ms all reject zero
  - Frame.flow_semantics is generic L4 flow-shape metadata for capability matching and dispatch placement, not protocol-level semantics or an L7 policy input
  - Capabilities.protocol and ExitSnapshot.protocol are opaque adapter labels for status/capability display only, not parser inputs or dispatch branch keys
  - 1.5.6 (2026-05-14): bus-event.schema.json retires DispatchResult/DispatchFailure; core dispatch observation is carried by Core(EventEnvelope) with closed CoreEventId variants

schemas decisions:
  - 1.5.3 (2026-05-13): health-policy.schema.json recovery/probe windows now reject zero to match runtime config validation
  - 1.5.4 (2026-05-13): Frame.flow_semantics wording now says generic L4 flow-shape metadata instead of protocol-level semantics
  - 1.5.5 (2026-05-13): capability and exit snapshot protocol fields are documented as opaque adapter labels, not parser or dispatch branch contracts
