//! M2 substrate gate: the L4 `UdpPacketLoop` coalesces an outbound burst into
//! one batched send syscall on Linux (`sendmmsg`) and falls back to a clean
//! per-datagram send elsewhere, while every batch boundary still maps to one
//! logical datagram.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use mesh_bus_core::transport::udp_loop::{OutboundDatagram, UdpPacketLoop};

fn local_v4() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

const BURST: usize = 8;

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

#[tokio::test]
async fn udp_batch_send_coalesces_burst_into_fewer_syscalls() {
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
            payload: Bytes::copy_from_slice(&[idx; 16]),
        });
    }
    let outcome = sender.flush().await.expect("flush burst");
    assert_eq!(outcome.sent, BURST);

    let stats = sender.batch_io_stats();
    assert_eq!(
        stats.send_datagrams, BURST as u64,
        "every queued datagram is accounted for"
    );
    if cfg!(target_os = "linux") {
        assert!(
            stats.batch_send_supported,
            "linux compiles the sendmmsg batch path"
        );
        assert!(
            stats.send_syscalls < BURST as u64,
            "linux coalesces the burst: {} send syscalls for {} datagrams",
            stats.send_syscalls,
            BURST
        );
        assert!(
            stats.send_syscalls >= 1,
            "at least one batched send happened"
        );
    } else {
        assert!(
            !stats.batch_send_supported,
            "non-linux reports per-datagram fallback"
        );
        assert_eq!(
            stats.send_syscalls, BURST as u64,
            "non-linux fallback is one send syscall per datagram"
        );
    }

    let received = drain_until(&receiver, BURST).await;
    assert_eq!(received.len(), BURST, "one logical datagram per enqueue");
    for payload in &received {
        assert_eq!(
            payload.len(),
            16,
            "datagram length preserved through the batch path, no coalescing"
        );
        assert!(payload.iter().all(|byte| usize::from(*byte) < BURST));
    }
}

#[tokio::test]
async fn udp_batch_recv_reports_platform_support_and_keeps_boundaries() {
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
            payload: Bytes::copy_from_slice(&[idx; 24]),
        });
    }
    sender.flush().await.expect("flush burst");

    let received = drain_until(&receiver, BURST).await;

    let stats = receiver.batch_io_stats();
    assert_eq!(
        stats.recv_datagrams, BURST as u64,
        "every received datagram is accounted for"
    );
    if cfg!(target_os = "linux") {
        assert!(
            stats.batch_recv_supported,
            "linux compiles the recvmmsg batch path"
        );
        assert!(
            stats.recv_syscalls >= 1,
            "at least one recv syscall serviced the burst"
        );
    } else {
        assert!(
            !stats.batch_recv_supported,
            "non-linux reports per-datagram fallback"
        );
    }

    assert_eq!(received.len(), BURST);
    for payload in &received {
        assert_eq!(
            payload.len(),
            24,
            "recv keeps one logical datagram per message, no splitting"
        );
    }
}
