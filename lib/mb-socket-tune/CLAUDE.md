# mb-socket-tune

mb-socket-tune role:
  shared socket buffer tuning helpers for ingress and egress plugins before
  async connect or socket handoff.

design-rule:
  - handbook defines topology and logic; this directory owns socket buffer DTOs
    and native socket tuning helpers only
  - this directory has no local schema.json by design; test.html records the
    schema waiver and owner proof contract
  - do not add routing, retry policy, session lifecycle, or throughput gates here

owned files:
  src/lib.rs   — SocketBufferConfig, TCP/UDP buffer setters, connect_tcp
  test.html    — owner proof contract and schema waiver

local dependencies:
  socket2
  tokio::net

boundary rules:
  - disabled config is a no-op
  - buffer sizes that exceed u32::MAX fail with InvalidInput before TcpSocket use
  - connect_tcp resolves addresses and returns the first successful connection
  - retry strategy, transport routing, and perf claims belong to consumer crates

handbook:
  ../../docs/handbook/index.html
