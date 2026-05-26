# mesh-bus-core.kernel.metadata


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
owned files:
  schema.json    — TypedMap (fixed hot struct + SmallMap ext), all Meta sub-structs, MetaValue
  types.rs       — TypedMap, NetMeta, TransportMeta, PolicyMeta, AuthMeta, TraceMeta, MetaValue, SmallMap, ScheduleHintLabel
  data_handle.rs — set/get helpers and ExtKey tail validation
  tests.rs       — unit tests

metadata contract:
  - schema.json roots at TypedMap and mirrors the fixed hot struct shape: TypedMap requires net/transport/policy/auth/trace/ext, all metadata object shapes reject unknown fields, and MetaValue variants are closed tagged objects
  - NetMeta.src_ip is absent/null when unavailable and an IPv4/IPv6 literal when present; schema declares the literal formats and hooks that consume it fail closed if parsing rejects it
  - TypedMap.ext stores local extension key tails (`operation`, `dst_ip_primary`, `geo_country`), not full registry metadata keys; schema ExtKey uses `^[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)*$` and rejects leading metadata namespace prefixes (`ext.`, `net.`, etc.), while HookSpec/SourceSpec declarations use full `ext.<key>` metadata keys
  - NetMeta.dst_host is absent/null for IP-literal paths and non-empty for hostname paths; empty string is invalid adapter metadata
  - NetMeta.protocol is a closed L4 transport-family hint (`tcp` / `udp` / null) for capability matching; it is not an adapter protocol label, L7 parser input, or branch key for SOCKS/HTTP/HTTPS behavior
  - TransportMeta stores schedule intent as label plus payload: `schedule_hint=FanOut` carries its count in `schedule_fanout_k`; absent `schedule_hint` means downstream core `ScheduleHint::Auto`
  - ext_set debug-asserts the same local tail contract; invalid ext keys are programmer errors, while registry declarations remain load-time verify errors
  - is_valid_ext_key_tail is exported through the kernel public surface so protocol-neutral hook and adapter crates do not duplicate metadata-key validation

metadata decisions:
  - 0.2.10 (2026-05-13): NetMeta.src_ip schema now declares IPv4/IPv6 literal formats instead of relying on minLength plus prose.
  - 0.2.9 (2026-05-13): NetMeta.src_ip schema rejects empty strings and policy.rule_chain fails closed on unparseable src_ip or dst_ip_primary metadata.
  - 0.2.8 (2026-05-13): NetMeta.dst_host schema rejects empty strings; resolve_or_recover treats empty dst_host as invalid adapter metadata.
