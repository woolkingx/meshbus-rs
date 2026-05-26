# mb-mesh-control

mb-mesh-control role:
  pure Mesh Protocol control engine for send budget, in-flight package accounting,
  RTT, loss, PTO, and AckNack-derived repair decisions

design-rule:
  - handbook defines topology and logic; this directory's schema.json defines owned data shape
  - this directory may mutate only mesh control PCI/data; carried SDU payload stays opaque
  - QUIC RFCs and mb-quic are reference shapes only; do not import QUIC stream or connection ontology

owned files:
  src/lib.rs — pure controller and data types
  schema.json — controller state projection
  tests/control.rs — owner proof tests

boundary rules:
  - no sockets, no tokio, no runtime task ownership
  - AckNack confirms or requests Mesh DataPackages, not transport streams
  - send budget is bytes-based and cannot become a fixed per-chunk sleep
  - loss/PTO decisions return data-only actions for adapters to execute

handbook:
  ../../docs/handbook/index.html
