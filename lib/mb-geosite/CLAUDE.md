# mb-geosite

mb-geosite role:
  operator datafile lookup library — loads hostname suffix tags at startup, exposes sync host → tag lookup, and falls back to empty DB when file is missing

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mb-geosite governs:
  src/lib.rs — GeositeDb, GeositeError, GeositeDb::open / empty / parse / lookup / lookup_packed
  tests/lookup.rs — datafile parsing, suffix lookup, packed tag output, missing-file fallback

mb-geosite depends_on:
  thiserror

mb-geosite invariants:
  - lookup is sync and performs no I/O after open
  - internal storage is a reversed-label tree, so lookup walks host labels instead of scanning every datafile entry
  - hot-path hook use goes through lookup_packed(), which writes NUL-separated tag bytes without cloning tag strings
  - datafile format is one `tag:domain` entry per nonempty non-comment line
  - parser rejects invalid operator entries at startup; tags are ASCII alnum/underscore/hyphen/dot, domains are DNS labels with ASCII alnum/hyphen and no empty labels
  - host/domain comparisons are ASCII-case-insensitive and ignore one trailing dot
  - missing datafile is NOT an error; call sites get GeositeDb::empty()

mb-geosite decisions:
  - 0.1.2 (2026-05-13): operator schema hardened. GeositeDb::parse rejects malformed tags/domains instead of silently loading entries that would never match or match ambiguous operator intent.
  - 0.1.1 (2026-05-13): hot-path lookup tightened. GeositeDb now stores tags in a reversed-label tree and exposes `lookup_packed()` for `ext.geosite_tags`, avoiding Vec<String> tag clones in `net.enrich_geo_asn`; `lookup()` remains for tests and low-frequency inspection.
  - 0.1.0 (2026-05-13): initial contract for domain-side geosite tags consumed by net.enrich_geo_asn. Kept separate from mb-geoip because owner/data shape is hostname suffix tags, not IP MMDB.

handbook:
  ../../docs/handbook/index.html
