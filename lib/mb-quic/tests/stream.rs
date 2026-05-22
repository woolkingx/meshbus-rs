//! Connection-level stream behaviour over two sans-I/O `Conn`s: bidirectional
//! data, in-order reads after out-of-order packet delivery, several streams on
//! one connection, connection close, and idle timeout (RFC 9000 §2/§3/§10).
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

/// Pump both directions to quiescence so subsequent `poll_transmit` packets
/// carry only application frames.
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
    assert!(
        c.is_established() && s.is_established(),
        "handshake converged"
    );
    (c, s)
}

#[test]
fn bidirectional_stream_carries_data_both_ways() {
    let (mut c, mut s) = established();
    let sid = c.open_bidi_stream().expect("peer bidi limit > 0").0;

    c.write_stream(sid, b"ping", false);
    drain(&mut c, &mut s);
    assert_eq!(s.read_stream(sid), b"ping");

    s.write_stream(sid, b"pong", true);
    drain(&mut c, &mut s);
    assert_eq!(c.read_stream(sid), b"pong");
    assert!(c.stream_finished(sid), "FIN observed after peer finalised");
}

#[test]
fn out_of_order_packets_reassemble_in_order() {
    let (mut c, mut s) = established();
    let sid = c.open_bidi_stream().unwrap().0;

    c.write_stream(sid, b"AAA", false);
    let dg1 = c.poll_transmit().expect("first stream packet");
    c.write_stream(sid, b"BBB", true);
    let dg2 = c.poll_transmit().expect("second stream packet");

    // Deliver newest first; RecvStream must order by offset, not arrival.
    s.recv(&dg2).unwrap();
    s.recv(&dg1).unwrap();
    assert_eq!(s.read_stream(sid), b"AAABBB");
    assert!(s.stream_finished(sid));
}

#[test]
fn multiple_streams_on_one_connection_are_independent() {
    let (mut c, mut s) = established();
    let a = c.open_bidi_stream().unwrap().0;
    let b = c.open_bidi_stream().unwrap().0;
    assert_ne!(a, b, "distinct stream ids");

    c.write_stream(a, b"stream-a", false);
    c.write_stream(b, b"stream-b", false);
    drain(&mut c, &mut s);

    assert_eq!(s.read_stream(a), b"stream-a");
    assert_eq!(s.read_stream(b), b"stream-b");
}

#[test]
fn connection_close_propagates_to_peer() {
    let (mut c, mut s) = established();
    c.close(true, 0, b"bye");
    drain(&mut c, &mut s);
    assert!(c.is_closed(), "initiator is closed");
    assert!(s.is_closed(), "peer observed CONNECTION_CLOSE");
}

#[test]
fn idle_timeout_closes_the_connection() {
    let (mut c, mut s) = established();
    assert!(
        c.poll_timeout().is_some(),
        "loss/idle timer armed while open"
    );
    // Drive the clock far past any idle window (default 30s) with no activity.
    c.on_timeout(1_000_000_000_000);
    assert!(c.is_closed(), "idle expiry closes the connection");
    assert!(c.poll_timeout().is_none(), "no timer after close");
    drain(&mut c, &mut s);
}
