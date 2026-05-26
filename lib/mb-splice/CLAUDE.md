# mb-splice

mb-splice role:
  Linux TCP splice relay primitive plus byte accounting callback lifecycle.

design-rule:
  - handbook defines topology and logic; this directory owns only the splice
    relay primitive and SpliceStats
  - this directory has no local schema.json by design; test.html records the
    schema waiver and owner proof contract
  - do not add routing, policy, socket creation strategy, or product throughput
    gates here

owned files:
  src/lib.rs              — splice_tcp_streams, SpliceStats, platform split
  tests/relay_matrix.rs   — ignored relay performance evidence
  test.html               — owner proof contract and schema waiver

local dependencies:
  mesh-bus-core TcpSpliceSession / TcpSpliceAccounting
  tokio::net::TcpStream
  libc on Linux

boundary rules:
  - Linux uses blocking splice workers over a pipe pair
  - non-Linux returns io::ErrorKind::Unsupported
  - close accounting runs once after relay exit/error
  - performance matrix tests are evidence-only and not correctness gates

handbook:
  ../../docs/handbook/index.html
