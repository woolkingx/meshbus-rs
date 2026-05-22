//! RFC 9221 unreliable DATAGRAM behaviour over two sans-I/O `Conn`s:
//! best-effort delivery on an established connection and the no-backpressure
//! drop when the local send queue is full.
//!
//! Uses the bare engine-default TLS path (no injected pinned config), which
//! fails closed unless the test-only `dangerous-insecure-tls` feature is on.
#![cfg(feature = "dangerous-insecure-tls")]

use mb_quic::{Conn, ConnConfig, TransportParameters, Version};

fn conn(server: bool) -> Conn {
    let cfg = ConnConfig {
        version: Version::V1,
        transport_params: TransportParameters::default().encode(),
        ..ConnConfig::default()
    };
    if server {
        Conn::server(cfg).unwrap()
    } else {
        Conn::client(cfg).unwrap()
    }
}

fn drain(client: &mut Conn, server: &mut Conn) {
    for _ in 0..64 {
        let mut moved = false;
        while let Some(dg) = client.poll_transmit() {
            server.recv(&dg).unwrap();
            moved = true;
        }
        while let Some(dg) = server.poll_transmit() {
            client.recv(&dg).unwrap();
            moved = true;
        }
        if !moved {
            break;
        }
    }
}

fn established() -> (Conn, Conn) {
    let (mut c, mut s) = (conn(false), conn(true));
    drain(&mut c, &mut s);
    assert!(c.is_established() && s.is_established());
    (c, s)
}

#[test]
fn datagram_is_delivered_best_effort() {
    let (mut c, mut s) = established();
    assert!(c.send_datagram(b"telemetry".to_vec()));
    drain(&mut c, &mut s);
    assert_eq!(s.recv_datagram().as_deref(), Some(&b"telemetry"[..]));
    assert!(
        s.recv_datagram().is_none(),
        "exactly one datagram delivered"
    );
}

#[test]
fn datagrams_keep_arrival_order_on_a_quiet_path() {
    let (mut c, mut s) = established();
    for n in 0..4u8 {
        assert!(c.send_datagram(vec![n]));
    }
    drain(&mut c, &mut s);
    let got: Vec<u8> = std::iter::from_fn(|| s.recv_datagram())
        .map(|d| d[0])
        .collect();
    assert_eq!(got, vec![0, 1, 2, 3]);
}

#[test]
fn full_send_queue_drops_without_backpressure() {
    let mut c = conn(false);
    // Default queue depth is 64; the 65th enqueue is dropped, never blocks.
    let mut accepted = 0;
    for _ in 0..128 {
        if c.send_datagram(vec![0u8; 16]) {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 64, "queue is bounded and best-effort");
}
