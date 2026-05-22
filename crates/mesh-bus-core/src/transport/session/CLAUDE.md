# mesh-bus-core.session


design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only its owned PCI/data; carried SDU/payload from other layers stays opaque unless this CLAUDE.md names the owner boundary
  - new behavior starts by naming owner data, boundary, and proof gate; do not add cross-layer shortcuts
session governs:
  schema.json — data contract for L5 session domain types and trait capabilities
  types.rs — BusSessionRequest, BusSessionInfo, BusPathInfo, PathState, DisconnectReason, SendError; StreamSession/StreamSendHalf/StreamRecvHalf/DatagramSession/StreamEgress/DatagramEgress traits; Bus* canonical aliases
  data_handle.rs — InternalStreamSession, InternalStreamSendHalf, InternalStreamRecvHalf, InternalDatagramSession; session_info_for, validate_stream_request, validate_datagram_request, apply_request helpers
  tests.rs — domain-local session tests: stream connect path info, half-close, datagram source preservation, FanOut k=0 rejection

session owns:
  L5 session request/info, stream/datagram session traits, split halves, lifecycle, path proof, and close reasons

session decisions:
  - 0.1.0 (2026-05-11): skeleton created; types/handlers move here in subsequent tasks
  - 0.1.1 (2026-05-11): L5 session data and handlers moved into session/; Bus* canonical names added as the public surface for all downstream crates
  - 0.1.2 (2026-05-14): datagram split halves added. DatagramSendHalf / DatagramRecvHalf traits define independent write/read halves. InternalDatagramSendHalf and InternalDatagramRecvHalf in datagram_halves.rs implement the traits with shared Arc<DatagramShared> carrying HashMap[seq→Endpoint] for correct out-of-order return source mapping. DatagramSession::split() added to trait and implemented.
