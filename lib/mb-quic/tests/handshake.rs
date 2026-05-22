//! Transport-parameter round trip and a local sans-I/O client/server handshake
//! driven purely by `recv()` / `poll_transmit()`.

use mb_quic::TransportParameters;
use mb_quic::packet::ConnectionId;
#[cfg(feature = "dangerous-insecure-tls")]
use mb_quic::{Conn, ConnConfig, Version};

#[test]
fn transport_parameters_round_trip() {
    let tp = TransportParameters {
        original_dcid: Some(ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]).unwrap()),
        initial_scid: Some(ConnectionId::new(&[0xaa, 0xbb]).unwrap()),
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: 1452,
        initial_max_data: 1 << 20,
        initial_max_stream_data_bidi_local: 256 * 1024,
        initial_max_stream_data_bidi_remote: 256 * 1024,
        initial_max_stream_data_uni: 128 * 1024,
        initial_max_streams_bidi: 64,
        initial_max_streams_uni: 8,
        max_datagram_frame_size: 1200,
    };
    let encoded = tp.encode();
    let decoded = TransportParameters::decode(&encoded).unwrap();
    assert_eq!(decoded, tp);
}

#[test]
fn transport_parameters_default_round_trips() {
    let tp = TransportParameters::default();
    let decoded = TransportParameters::decode(&tp.encode()).unwrap();
    assert_eq!(decoded, tp);
}

// Bare engine-default TLS path; fails closed without `dangerous-insecure-tls`.
#[cfg(feature = "dangerous-insecure-tls")]
#[test]
fn local_client_server_handshake_completes() {
    let client_tp = TransportParameters::default().encode();
    let server_tp = TransportParameters::default().encode();
    let mut client = Conn::client(ConnConfig {
        version: Version::V1,
        transport_params: client_tp,
        ..ConnConfig::default()
    })
    .unwrap();
    let mut server = Conn::server(ConnConfig {
        version: Version::V1,
        transport_params: server_tp,
        ..ConnConfig::default()
    })
    .unwrap();

    let mut established = false;
    for _ in 0..32 {
        while let Some(dg) = client.poll_transmit() {
            server.recv(&dg).unwrap();
        }
        while let Some(dg) = server.poll_transmit() {
            client.recv(&dg).unwrap();
        }
        if client.is_established() && server.is_established() {
            established = true;
            break;
        }
    }

    assert!(established, "handshake did not converge");
    assert!(client.is_established());
    assert!(server.is_established());
    assert!(
        client.peer_transport_parameters().is_some(),
        "client learned server transport params"
    );
    assert!(
        server.peer_transport_parameters().is_some(),
        "server learned client transport params"
    );
}
