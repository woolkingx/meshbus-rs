//! M5 Step 3 interop gate.
//!
//! Cross-stack interop against Cloudflare quiche reference *binaries* is
//! **NOT RUN**: per decision 0.4.32 quiche is a read-only source reference and
//! never a build dependency, so there is no quiche binary in this environment.
//! Instead we keep a deterministic own-engine vector — a fixed client/server
//! exchange driven purely by `recv`/`poll_transmit` with an injected clock —
//! that pins the wire behaviour M6 will build on. Run with `--nocapture` to see
//! the recorded interop status.
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

#[test]
fn deterministic_vector_handshake_stream_and_datagram_round_trip() {
    println!(
        "QUIC interop vs quiche reference binaries: NOT RUN \
         (quiche is read-only source reference, never a build dependency; \
         decision 0.4.32). Using deterministic own-engine vector instead."
    );

    let (mut c, mut s) = (conn(false), conn(true));

    // Deterministic, clock-injected pump: identical input -> identical output.
    let mut established = false;
    for tick in 0..64u64 {
        let now = tick * 1_000;
        c.set_now(now);
        s.set_now(now);
        let mut moved = false;
        while let Some(dg) = c.poll_transmit() {
            s.recv(&dg).unwrap();
            moved = true;
        }
        while let Some(dg) = s.poll_transmit() {
            c.recv(&dg).unwrap();
            moved = true;
        }
        if c.is_established() && s.is_established() {
            established = true;
        }
        if established && !moved {
            break;
        }
    }
    assert!(established, "deterministic handshake converged");

    let sid = c.open_bidi_stream().expect("bidi stream").0;
    c.write_stream(sid, b"interop-vector", true);
    assert!(c.send_datagram(b"dgram-vector".to_vec()));

    for _ in 0..32 {
        let mut moved = false;
        while let Some(dg) = c.poll_transmit() {
            s.recv(&dg).unwrap();
            moved = true;
        }
        while let Some(dg) = s.poll_transmit() {
            c.recv(&dg).unwrap();
            moved = true;
        }
        if !moved {
            break;
        }
    }

    assert_eq!(s.read_stream(sid), b"interop-vector");
    assert!(s.stream_finished(sid), "FIN delivered in the vector");
    assert_eq!(s.recv_datagram().as_deref(), Some(&b"dgram-vector"[..]));
}
