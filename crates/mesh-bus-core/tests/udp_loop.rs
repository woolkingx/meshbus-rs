//! M1 substrate gate: the L4 `UdpPacketLoop` moves opaque datagrams between
//! two locally bound sockets, and the raw UDP mesh-peer crates no longer own
//! direct `UdpSocket` send/recv loops.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use mesh_bus_core::transport::link_evidence::{LinkEvidence, LinkEvidenceSnapshot};
use mesh_bus_core::transport::path_stats::PathStats;
use mesh_bus_core::transport::udp_loop::{OutboundDatagram, UdpPacketLoop};

fn local_v4() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

#[tokio::test]
async fn udp_packet_loop_delivers_payload_and_source_endpoint() {
    let sender = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind sender loop");
    let receiver = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind receiver loop");

    let sender_addr = sender.local_addr().expect("sender local addr");
    let receiver_addr = receiver.local_addr().expect("receiver local addr");

    let payload = Bytes::from_static(b"hello-udp-packet-loop");
    sender.enqueue(OutboundDatagram {
        destination: receiver_addr,
        payload: payload.clone(),
    });
    assert_eq!(sender.pending_outbound(), 1);

    let outcome = sender.flush().await.expect("flush outbound");
    assert_eq!(outcome.sent, 1);
    assert_eq!(sender.pending_outbound(), 0);

    tokio::time::timeout(Duration::from_secs(2), receiver.poll_recv())
        .await
        .expect("recv did not time out")
        .expect("poll_recv ok");

    let inbound = receiver.drain_inbound();
    assert_eq!(inbound.len(), 1, "exactly one datagram delivered");
    assert_eq!(&inbound[0].payload[..], &payload[..]);
    assert_eq!(
        inbound[0].source, sender_addr,
        "source endpoint preserved through the packet loop"
    );

    // Path evidence must update without parsing payload.
    let stats = receiver.path_stats();
    assert!(
        stats.sampled_at_ms > 0,
        "packet loop samples a path-stats timestamp"
    );
}

#[tokio::test]
async fn udp_packet_loop_preserves_per_datagram_boundaries() {
    let sender = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind sender loop");
    let receiver = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind receiver loop");
    let receiver_addr = receiver.local_addr().expect("receiver local addr");

    for idx in 0u8..4 {
        sender.enqueue(OutboundDatagram {
            destination: receiver_addr,
            payload: Bytes::copy_from_slice(&[idx; 8]),
        });
    }
    let outcome = sender.flush().await.expect("flush burst");
    assert_eq!(outcome.sent, 4);

    let mut received: Vec<Bytes> = Vec::new();
    while received.len() < 4 {
        tokio::time::timeout(Duration::from_secs(2), receiver.poll_recv())
            .await
            .expect("burst recv did not time out")
            .expect("poll_recv ok");
        for dgram in receiver.drain_inbound() {
            received.push(dgram.payload);
        }
    }

    assert_eq!(received.len(), 4, "one logical datagram per enqueue");
    for (idx, payload) in received.iter().enumerate() {
        assert!(
            payload.iter().all(|byte| usize::from(*byte) < 4),
            "datagram {idx} body stays intact, no coalescing"
        );
        assert_eq!(payload.len(), 8, "datagram {idx} length preserved");
    }
}

/// The raw UDP mesh-peer crates must delegate socket I/O to `UdpPacketLoop`
/// instead of owning `UdpSocket::recv_from` / `UdpSocket::send_to` loops.
#[test]
fn raw_udp_mesh_peer_crates_delegate_to_udp_packet_loop() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_crates = crate_root.parent().expect("crates/ dir").to_path_buf();

    for peer in [
        "mesh-bus-ingress-mesh-peer-udp",
        "mesh-bus-egress-mesh-peer-udp",
    ] {
        let lib_path = workspace_crates.join(peer).join("src").join("lib.rs");
        let src = std::fs::read_to_string(&lib_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", lib_path.display()));

        assert!(
            src.contains("UdpPacketLoop"),
            "{peer} must route UDP I/O through UdpPacketLoop"
        );
        assert!(
            !src.contains("UdpSocket"),
            "{peer} must not own a direct tokio UdpSocket; delegate to UdpPacketLoop"
        );
    }
}

/// M6: native policy must consume the same path-evidence shape as the UDP and
/// QUIC reference bindings. `LinkEvidence` is a pure projection of the L4
/// `PathStats` that `UdpPacketLoop` already samples; the schema-mirrored field
/// set carries no route truth.
#[test]
fn link_evidence_projects_path_stats_into_schema_shape() {
    let stats = PathStats {
        rtt_us: Some(3_200),
        rttvar_us: Some(450),
        pmtu: Some(1_400),
        pacing_delay_us: Some(120),
        drops: 2,
        send_errors: 1,
        queue_full_drops: 0,
        sampled_at_ms: 9,
        ..Default::default()
    };

    let ev = LinkEvidence::from_path_stats(&stats);

    assert_eq!(ev.srtt, 3_200.0, "srtt projects rtt_us");
    assert_eq!(ev.rttvar, 450.0, "rttvar projects rttvar_us");
    assert_eq!(ev.pmtu, 1_400, "pmtu carries through");
    assert_eq!(
        ev.queue_delay, 120.0,
        "queue_delay projects pacing_delay_us"
    );
    assert_eq!(ev.loss_burst, 2, "loss_burst projects drops");
    assert_eq!(ev.reorder_score, 0.0, "no send-side reorder evidence yet");
    // failures = send_errors(1) + drops(2) + queue_full_drops(0) = 3
    assert!(
        (ev.delivery_ratio - 0.25).abs() < 1e-9,
        "delivery_ratio = 1/(1+failures) = 0.25, got {}",
        ev.delivery_ratio
    );
    assert!(
        ev.delivery_ratio > 0.0 && ev.delivery_ratio <= 1.0,
        "delivery_ratio stays in schema range (0,1]"
    );
    assert!(
        ev.cost_weight >= ev.srtt,
        "cost_weight is RTO-shaped and never below srtt"
    );

    // A clean path projects a perfect delivery ratio and the cheapest cost.
    let clean = LinkEvidence::from_path_stats(&PathStats {
        rtt_us: Some(1_000),
        ..Default::default()
    });
    assert_eq!(clean.delivery_ratio, 1.0);
    assert!(
        clean.cost_weight < ev.cost_weight,
        "a clean low-RTT mouth costs less than a lossy one"
    );
}

/// M6: evidence expiry removes a mouth from the candidate set but must not
/// delete the operator-configured peer identity, and the hot-path read takes
/// no global mutex (lock-free `ArcSwap` load).
#[test]
fn evidence_expiry_removes_mouth_but_keeps_configured_identity() {
    let ttl_ms = 1_000u64;
    let snap = LinkEvidenceSnapshot::new(["peer-a".to_string(), "peer-b".to_string()], ttl_ms);

    let ev = LinkEvidence::from_path_stats(&PathStats {
        rtt_us: Some(2_000),
        ..Default::default()
    });

    // Both observed at t=0.
    snap.observe("peer-a", ev.clone(), 0);
    snap.observe("peer-b", ev.clone(), 0);

    // Within TTL: both are candidates.
    let mut at_mid = snap.candidate_mouths(ttl_ms / 2);
    at_mid.sort();
    assert_eq!(at_mid, vec!["peer-a".to_string(), "peer-b".to_string()]);
    assert!(snap.evidence_for("peer-b", ttl_ms / 2).is_some());

    // Past TTL, only peer-a refreshed: peer-b expires OUT OF the candidate set.
    let now = ttl_ms + 1;
    snap.observe("peer-a", ev.clone(), now);
    assert_eq!(
        snap.candidate_mouths(now),
        vec!["peer-a".to_string()],
        "stale peer-b is excluded from the candidate set"
    );
    assert!(
        snap.evidence_for("peer-b", now).is_none(),
        "stale evidence is not served"
    );

    // But the configured-peer identity is durable: expiry never deletes it.
    let mut configured = snap.configured_peers().to_vec();
    configured.sort();
    assert_eq!(
        configured,
        vec!["peer-a".to_string(), "peer-b".to_string()],
        "configured peer identity survives evidence expiry"
    );
}
