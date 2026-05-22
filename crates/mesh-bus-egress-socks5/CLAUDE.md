# mesh-bus-egress-socks5

mesh-bus-egress-socks5 role:
  L7 adapter — thin stitcher of L6 content + L5 control + L4 transport per layer-model §2.4
  L6 content: SOCKS5 wire format via mb-proto-socks5 (greeting/request/reply codec)
  L5 control: StreamEgress factory + BusStreamSession halves + BusPathInfo for upstream-reported BND endpoint
  L4 transport: opaque payload bytes flow through the bus kernel; this crate never constructs Frame/FrameKind/EgressPlugin

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts

mesh-bus-egress-socks5 implements:
  StreamEgress — SOCKS5 upstream CONNECT factory; each StreamSession owns one upstream SOCKS5 tunnel
  DatagramEgress — SOCKS5 upstream UDP ASSOCIATE factory; each DatagramSession owns one UDP relay plus its retained TCP control connection

mesh-bus-egress-socks5 invariants:
  - live-egress command/auth support is the `live_egress_stream_commands` (Connect), `live_egress_datagram_commands` (UdpAssociate), and `live_egress_auth` (NoAuth/UserPass) columns of `lib/mb-proto-socks5/schema.json` `command_auth_matrix`; that matrix is the single contract source and this crate must not diverge from it
  - L7 stitcher boundary: code in this crate may import mb-proto-socks5 (L6 codec) and canonical Bus* L5 session surface only; it must never reference mesh-bus-core::Frame, FrameKind, EgressPlugin, SchedulerPlugin, or any L4 internal type
  - upstream SOCKS5 wire bytes are produced/parsed by mb-proto-socks5; this crate owns only the I/O timing, auth-method selection, and the L5 session lifecycle
  - configured timeout bounds every upstream SOCKS5 open step: TCP connect, greeting write/read, optional RFC1929 user/pass subnegotiation, request write, and ATYP-aware reply read
  - upstream auth offers UserPass+NoAuth when credentials are configured and NoAuth only otherwise; an unconfigured user/pass demand is a hard failure
  - upstream reply reading is ATYP-aware: IPv4/IPv6/DOMAIN BND endpoints are all read to completion before decode, never truncated to the IPv4 minimum
  - UDP ASSOCIATE binds the local UDP socket first and sends its bound address as DST; mb-endpoint forbids port 0 so the literal 0.0.0.0:0 wildcard is replaced by the real local bind endpoint, which is also the RFC1928 client send-address hint
  - the TCP control connection is retained for the DatagramSession lifetime and dropped on close(); dropping it terminates the UDP association per RFC1928
  - if the BND.ADDR in the UDP ASSOCIATE reply is unspecified (0.0.0.0 / ::), the relay endpoint is the control connection peer IP with BND.PORT

mesh-bus-egress-socks5 governs:
  src/lib.rs — Socks5Egress StreamEgress factory; stitches the upstream CONNECT handshake then exposes split send/recv halves
  src/udp.rs — Socks5UdpEgress DatagramEgress factory; UDP ASSOCIATE handshake, relay-addr resolution, encode/decode UDP datagram wrap, split halves, control-TCP retention
  src/upstream.rs — shared upstream handshake helpers: Socks5UpstreamAuth, negotiate_auth, read_reply_frame_atyp, timed_io, disconnect mappers
  tests/upstream.rs — fake SOCKS5 server stream conformance: auth, ATYP reply, roundtrip, large response streaming
  tests/upstream_udp.rs — fake SOCKS5 UDP ASSOCIATE conformance: datagram send/recv roundtrip, send non-blocking, reply-source decode, control-drop terminates association

mesh-bus-egress-socks5 depends_on:
  mesh-bus-core — StreamEgress/StreamSession/StreamSendHalf/StreamRecvHalf, DatagramEgress/DatagramSession/DatagramSendHalf/DatagramRecvHalf, SessionInfo, SendError
  mb-endpoint — Endpoint type
  mb-proto-socks5 — greeting, connect-request, udp-associate-request, reply, udp-datagram codec (no inline byte twiddling)
  tokio — async TCP/UDP, timeouts

mesh-bus-egress-socks5 decisions:
  - 0.1.16 (2026-05-15): upstream reply length now delegates to the L6 codec. read_reply_frame_atyp calls mb-proto-socks5 `reply_frame_total_len` instead of inlining per-ATYP byte arithmetic, restoring the no-inline-byte-twiddling boundary. Socks5UdpRecvHalf/Socks5UdpSession own one reusable MAX_UDP_PAYLOAD_BYTES receive buffer (no per-datagram 65 KB allocation), and relay_recv drops a malformed or FRAG-rejected relay datagram and keeps receiving instead of terminating the association on the first bad packet (RFC1928 datagram drop semantics).
  - 0.1.15 (2026-05-15): Socks5UdpEgress DatagramEgress landed in src/udp.rs reusing the upstream.rs handshake helpers. open_datagram binds local UDP first, opens+retains the TCP control connection, sends UDP ASSOCIATE with the local bind addr as DST (mb-endpoint forbids port 0 so the literal 0.0.0.0:0 wildcard is the real bind endpoint), parses the ATYP-aware BND reply, and resolves an unspecified BND.ADDR to the control peer IP. send_to wraps with encode_udp_datagram; recv_from decodes with decode_udp_datagram into (target, payload); close() drops the control TCP to end the association. Wired into mesh-bus-runtime as the EgressCfg::Socks5Udp datagram sink.
  - 0.1.14 (2026-05-15): upstream handshake helpers extracted to src/upstream.rs and hardened for full RFC: negotiate_auth runs NoAuth or RFC1929 user/pass per configured Socks5UpstreamAuth, and read_reply_frame_atyp reads IPv4/IPv6/DOMAIN BND replies to completion before decode (was IPv4-only 10-byte read). Socks5Egress gained an optional auth builder. Helpers are generic over AsyncRead+AsyncWrite for reuse by the upcoming Socks5Udp datagram egress.

handbook:
  ../../docs/handbook/index.html
