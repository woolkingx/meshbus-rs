# mb-geoip

mb-geoip role:
  pure MMDB lookup library — opens MaxMind country + ASN databases at startup, exposes sync IpAddr → GeoIpResult lookups, falls back to GeoIpResult::unknown() when DB absent

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mb-geoip governs:
  schema/geoip_result.schema.json
  src/types.rs — GeoIpResult { country, asn, asn_org }
  src/data_handle.rs — GeoIpDb::open / GeoIpDb::empty / GeoIpDb::lookup
  tests/lookup.rs

mb-geoip depends_on:
  maxminddb — MaxMind .mmdb reader (pure Rust)
  thiserror, serde, serde_json

mb-geoip invariants:
  - lookup is sync, allocation-free except for the final String/u32 in GeoIpResult
  - missing DB file is NOT an error — call sites use GeoIpDb::empty()
  - unknown lookup returns ("XX", 0, "")

mb-geoip decisions:
  - 0.1.0 (2026-05-12): initial; empty-DB fallback; backed by maxminddb crate

handbook:
  ../../docs/handbook/index.html
