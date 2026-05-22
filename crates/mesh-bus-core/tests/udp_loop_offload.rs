//! M3 substrate gate: the L4 `UdpPacketLoop` applies UDP offload probes at
//! bind, selects a data-shaped GSO/sendmmsg send plan, paces release in
//! software, guards a conservative PMTU, and projects batch size / segment size
//! / pacing delay / PMTU / send errors / drops into `PathStats`. Linux-only
//! offload must fall back cleanly, and the receive path must still split one
//! logical datagram per message (no GRO coalescing across boundaries).

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use mesh_bus_core::transport::udp_loop::pacing::Pacer;
use mesh_bus_core::transport::udp_loop::pmtu::{CONSERVATIVE_PMTU, clamp_to_pmtu};
use mesh_bus_core::transport::udp_loop::{
    OUTBOUND_QUEUE_CAPACITY, OutboundDatagram, QueueFull, UdpPacketLoop,
};

fn local_v4() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

const BURST: usize = 6;

async fn drain_until(loop_: &UdpPacketLoop, want: usize) -> Vec<Bytes> {
    let mut received = Vec::new();
    while received.len() < want {
        tokio::time::timeout(Duration::from_secs(2), loop_.poll_recv())
            .await
            .expect("recv did not time out")
            .expect("poll_recv ok");
        for dgram in loop_.drain_inbound() {
            received.push(dgram.payload);
        }
    }
    received
}

#[test]
fn pmtu_guard_is_conservative_and_clamps_oversize() {
    assert_eq!(
        CONSERVATIVE_PMTU, 1232,
        "IPv6 min MTU 1280 - 40 IPv6 hdr - 8 UDP hdr"
    );
    assert_eq!(
        clamp_to_pmtu(2000),
        CONSERVATIVE_PMTU as usize,
        "oversize payload is clamped to the conservative PMTU"
    );
    assert_eq!(
        clamp_to_pmtu(500),
        500,
        "a payload under the PMTU is left untouched"
    );
    assert_eq!(
        clamp_to_pmtu(CONSERVATIVE_PMTU as usize),
        CONSERVATIVE_PMTU as usize,
        "exactly-PMTU stays whole"
    );
}

#[test]
fn pacer_zero_rate_is_unpaced() {
    let pacer = Pacer::new(0);
    assert_eq!(
        pacer.delay_for(1500),
        Duration::ZERO,
        "rate 0 means unpaced: never delay"
    );
    assert_eq!(pacer.delay_for(0), Duration::ZERO);
}

#[test]
fn pacer_positive_rate_delays_proportional_to_bytes() {
    // 1000 bytes/sec: 1000 bytes => ~1s, 500 bytes => ~0.5s.
    let pacer = Pacer::new(1000);
    let one_sec = pacer.delay_for(1000);
    let half_sec = pacer.delay_for(500);
    assert!(
        one_sec >= Duration::from_millis(900) && one_sec <= Duration::from_millis(1100),
        "1000 B at 1000 B/s ~= 1s, got {one_sec:?}"
    );
    assert!(
        half_sec >= Duration::from_millis(450) && half_sec <= Duration::from_millis(550),
        "500 B at 1000 B/s ~= 0.5s, got {half_sec:?}"
    );
    assert!(one_sec > half_sec, "more bytes means a longer pacing delay");
}

#[tokio::test]
async fn udp_loop_projects_offload_pathstats_and_keeps_boundaries() {
    let sender = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind sender loop");
    let receiver = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind receiver loop");
    let receiver_addr = receiver.local_addr().expect("receiver local addr");

    for idx in 0u8..BURST as u8 {
        sender.enqueue(OutboundDatagram {
            destination: receiver_addr,
            payload: Bytes::copy_from_slice(&[idx; 32]),
        });
    }
    sender.flush().await.expect("flush burst");

    let send_stats = sender.path_stats();
    assert_eq!(
        send_stats.send_errors, 0,
        "loopback burst has no send errors"
    );
    assert_eq!(send_stats.drops, 0, "nothing exceeded the PMTU guard");
    assert_eq!(
        send_stats.pmtu,
        Some(CONSERVATIVE_PMTU),
        "the conservative PMTU is projected after a flush"
    );
    let batch_stats = sender.batch_io_stats();
    match send_stats.gso_segment_size {
        Some(32) if cfg!(target_os = "linux") => {
            assert!(
                batch_stats.gso_send_syscalls > 0,
                "same-destination same-size burst used the per-message GSO plan"
            );
            assert!(
                batch_stats.gso_send_datagrams >= BURST as u64,
                "GSO datagram accounting reports logical datagrams, not super-buffers"
            );
        }
        None => {
            assert_eq!(
                batch_stats.gso_send_datagrams, 0,
                "fallback kernels keep GSO datagram accounting at zero"
            );
        }
        other => panic!("unexpected GSO segment projection: {other:?}"),
    }

    let received = drain_until(&receiver, BURST).await;
    assert_eq!(
        received.len(),
        BURST,
        "the receive path splits one logical datagram per message (no GRO coalescing)"
    );
    for payload in &received {
        assert_eq!(payload.len(), 32, "datagram boundary preserved end to end");
    }

    let recv_stats = receiver.path_stats();
    assert_eq!(
        recv_stats.recv_batch_size,
        Some(BURST as u32),
        "the last recv batch counted every datagram drained from the socket"
    );
}

#[tokio::test]
async fn udp_gso_is_data_shaped_and_mixed_sizes_use_plain_batch() {
    let sender = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind sender loop");
    let receiver = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind receiver loop");
    let receiver_addr = receiver.local_addr().expect("receiver local addr");

    for len in [16usize, 17, 18, 19] {
        sender.enqueue(OutboundDatagram {
            destination: receiver_addr,
            payload: Bytes::from(vec![0xCC; len]),
        });
    }
    let outcome = sender.flush().await.expect("flush mixed-size burst");
    assert_eq!(outcome.sent, 4);

    let stats = sender.batch_io_stats();
    assert_eq!(
        stats.gso_send_datagrams, 0,
        "mixed-size datagrams do not form a legal UDP GSO super-buffer"
    );
    assert_eq!(
        sender.path_stats().gso_segment_size,
        None,
        "PathStats keeps GSO unset when plain sendmmsg is the send plan"
    );

    let received = drain_until(&receiver, 4).await;
    let mut lens: Vec<usize> = received.iter().map(Bytes::len).collect();
    lens.sort_unstable();
    assert_eq!(
        lens,
        vec![16, 17, 18, 19],
        "plain batch preserves each logical datagram boundary"
    );
}

#[tokio::test]
async fn udp_loop_with_pacing_records_a_positive_delay() {
    let unpaced = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind unpaced loop");
    let receiver = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind receiver loop");
    let receiver_addr = receiver.local_addr().expect("receiver local addr");

    unpaced.enqueue(OutboundDatagram {
        destination: receiver_addr,
        payload: Bytes::copy_from_slice(&[7u8; 64]),
    });
    unpaced.flush().await.expect("flush unpaced");
    assert_eq!(
        unpaced.path_stats().pacing_delay_us,
        Some(0),
        "default loop is unpaced: zero pacing delay"
    );

    // 4096 bytes/sec is slow enough that a 512-byte datagram pays a measurable
    // pacing delay (~125 ms) without making the test slow.
    let paced = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind paced loop")
        .with_pacing(4096);
    paced.enqueue(OutboundDatagram {
        destination: receiver_addr,
        payload: Bytes::copy_from_slice(&[9u8; 512]),
    });
    paced.flush().await.expect("flush paced");
    let delay = paced
        .path_stats()
        .pacing_delay_us
        .expect("paced loop records a pacing delay");
    assert!(
        delay > 0,
        "a positive pacing rate produces a positive recorded delay, got {delay} us"
    );

    let received = drain_until(&receiver, 2).await;
    assert_eq!(received.len(), 2, "both datagrams still arrive intact");
}

#[tokio::test]
async fn udp_packet_loop_oversize_returns_payload_too_large() {
    let sender = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind sender loop");
    let receiver = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind receiver loop");
    let receiver_addr = receiver.local_addr().expect("receiver local addr");

    // One byte over the conservative PMTU: under the 65507 app ceiling but
    // unable to leave the substrate without fragmentation.
    let oversize = CONSERVATIVE_PMTU as usize + 1;
    sender.enqueue(OutboundDatagram {
        destination: receiver_addr,
        payload: Bytes::from(vec![0u8; oversize]),
    });
    let outcome = sender.flush().await.expect("flush completes");
    assert_eq!(outcome.sent, 0, "the oversize datagram is not sent");
    assert_eq!(
        outcome.pmtu_dropped, 1,
        "flush reports the PMTU drop explicitly, not a silent Ok(0)"
    );
    assert_eq!(
        sender.path_stats().drops,
        1,
        "the PMTU drop is folded into PathStats"
    );
}

#[tokio::test]
async fn udp_packet_loop_outbound_queue_full_is_typed_and_counted() {
    let sender = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind sender loop");
    let dest: SocketAddr = "127.0.0.1:9".parse().expect("discard addr");

    for _ in 0..OUTBOUND_QUEUE_CAPACITY {
        sender
            .try_enqueue(OutboundDatagram {
                destination: dest,
                payload: Bytes::from_static(b"x"),
            })
            .expect("under capacity accepts");
    }

    let full = sender.try_enqueue(OutboundDatagram {
        destination: dest,
        payload: Bytes::from_static(b"x"),
    });
    assert!(
        matches!(full, Err(QueueFull { .. })),
        "past capacity is a typed QueueFull, not a silent drop"
    );

    // The infallible enqueue path drops and counts instead of growing unbounded.
    sender.enqueue(OutboundDatagram {
        destination: dest,
        payload: Bytes::from_static(b"x"),
    });
    assert_eq!(
        sender.path_stats().queue_full_drops,
        2,
        "the rejected try_enqueue and the dropped enqueue are both counted"
    );
    assert_eq!(
        sender.pending_outbound(),
        OUTBOUND_QUEUE_CAPACITY,
        "the queue never grows past its capacity"
    );
}
