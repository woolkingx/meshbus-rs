//! PERFORMANCE EVIDENCE — not a correctness gate. Env-gated / #[ignore].
//! Excluded from the test-code budget denominator (handbook testing-gates:
//! "Numbers and live reachability are not module correctness").
#![cfg(target_os = "linux")]
#![allow(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[path = "relay_matrix/linux_io.rs"]
mod linux_io;
use linux_io::*;
#[path = "relay_matrix/case_runner.rs"]
mod case_runner;
use case_runner::*;

const CHUNK_BYTES: usize = 64 * 1024;
const CHUNK_256K_BYTES: usize = 256 * 1024;
const PIPE_256K_BYTES: usize = 256 * 1024;
const PIPE_1M_BYTES: usize = 1024 * 1024;
const DEFAULT_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_CONCURRENT_BYTES_PER_FLOW: u64 = 16 * 1024 * 1024;
const DEFAULT_UDP_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_UDP_DATAGRAM_BYTES: usize = 1200;
const DEFAULT_UDP_BATCH: usize = 8;
const UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const UDP_IO_TIMEOUT: Duration = Duration::from_secs(10);

const SPLICE_F_MOVE: u32 = libc::SPLICE_F_MOVE;
const SPLICE_F_NONBLOCK: u32 = libc::SPLICE_F_NONBLOCK;
const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_TYPE_DEVMAP: u32 = 14;
const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
const IORING_ENTER_GETEVENTS: u32 = 1;
const IORING_FEAT_SINGLE_MMAP: u32 = 1;
const IORING_OFF_SQ_RING: libc::off_t = 0;
const IORING_OFF_CQ_RING: libc::off_t = 0x8000000;
const IORING_OFF_SQES: libc::off_t = 0x10000000;
const IORING_OP_SPLICE: u8 = 30;

#[derive(Clone, Copy)]
enum RelayMode {
    DirectEcho,
    StdCopy,
    ManualReadWrite256k,
    TokioCopyBidirectional,
    BlockingSplice,
    BlockingSplicePipe256k,
    BlockingSplicePipe1m,
    IoUringSplice,
    NonblockingPollSplice,
    NonblockingPollSplicePipe256k,
    NonblockingPollSplicePipe1m,
}

impl RelayMode {
    const ALL: [Self; 11] = [
        Self::DirectEcho,
        Self::StdCopy,
        Self::ManualReadWrite256k,
        Self::TokioCopyBidirectional,
        Self::BlockingSplice,
        Self::BlockingSplicePipe256k,
        Self::BlockingSplicePipe1m,
        Self::IoUringSplice,
        Self::NonblockingPollSplice,
        Self::NonblockingPollSplicePipe256k,
        Self::NonblockingPollSplicePipe1m,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::DirectEcho => "direct_echo",
            Self::StdCopy => "std_copy",
            Self::ManualReadWrite256k => "manual_rw_256k",
            Self::TokioCopyBidirectional => "tokio_copy_bidirectional",
            Self::BlockingSplice => "blocking_splice",
            Self::BlockingSplicePipe256k => "blocking_splice_pipe_256k",
            Self::BlockingSplicePipe1m => "blocking_splice_pipe_1m",
            Self::IoUringSplice => "io_uring_splice",
            Self::NonblockingPollSplice => "nonblocking_poll_splice",
            Self::NonblockingPollSplicePipe256k => "nonblocking_poll_splice_pipe_256k",
            Self::NonblockingPollSplicePipe1m => "nonblocking_poll_splice_pipe_1m",
        }
    }
}

#[derive(Clone, Copy)]
enum UdpRelayMode {
    DirectEcho,
    StdDatagram,
    RecvmmsgSendmmsg,
}

impl UdpRelayMode {
    const ALL: [Self; 3] = [Self::DirectEcho, Self::StdDatagram, Self::RecvmmsgSendmmsg];

    fn label(self) -> &'static str {
        match self {
            Self::DirectEcho => "direct_echo",
            Self::StdDatagram => "std_datagram",
            Self::RecvmmsgSendmmsg => "recvmmsg_sendmmsg",
        }
    }
}

#[derive(Clone, Copy)]
enum OffloadMode {
    IoUring,
    Sockmap,
    TcXdp,
    AfXdp,
}

impl OffloadMode {
    const ALL: [Self; 4] = [Self::IoUring, Self::Sockmap, Self::TcXdp, Self::AfXdp];

    fn label(self) -> &'static str {
        match self {
            Self::IoUring => "io_uring",
            Self::Sockmap => "sockmap",
            Self::TcXdp => "tc_xdp",
            Self::AfXdp => "af_xdp",
        }
    }
}

impl fmt::Debug for RelayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[test]
#[ignore]
fn tcp_relay_matrix_stream_1conn() {
    let bytes = env_u64("MB_SPLICE_MATRIX_STREAM_BYTES", DEFAULT_STREAM_BYTES);
    for mode in RelayMode::ALL {
        let mib = run_matrix_case(mode, 1, bytes);
        println!(
            "MB_SPLICE_RELAY_MATRIX_STREAM_1CONN_{}_MIB_PER_SEC={mib:.2}",
            mode.label().to_ascii_uppercase()
        );
    }
}

#[test]
#[ignore]
fn tcp_relay_matrix_stream_8conn() {
    let bytes = env_u64(
        "MB_SPLICE_MATRIX_CONCURRENT_BYTES_PER_FLOW",
        DEFAULT_CONCURRENT_BYTES_PER_FLOW,
    );
    for mode in RelayMode::ALL {
        let mib = run_matrix_case(mode, 8, bytes);
        println!(
            "MB_SPLICE_RELAY_MATRIX_STREAM_8CONN_{}_MIB_PER_SEC={mib:.2}",
            mode.label().to_ascii_uppercase()
        );
    }
}

#[test]
#[ignore]
fn udp_relay_matrix_datagram_1conn() {
    for mode in UdpRelayMode::ALL {
        let mib = run_udp_matrix_case(mode, 1);
        println!(
            "MB_SPLICE_RELAY_MATRIX_UDP_1CONN_{}_MIB_PER_SEC={mib:.2}",
            mode.label().to_ascii_uppercase()
        );
    }
}

#[test]
#[ignore]
fn kernel_offload_matrix_capabilities() {
    for mode in OffloadMode::ALL {
        let result = probe_offload(mode);
        println!(
            "MB_SPLICE_OFFLOAD_MATRIX_{}_STATUS={}",
            mode.label().to_ascii_uppercase(),
            result.status
        );
        println!(
            "MB_SPLICE_OFFLOAD_MATRIX_{}_DETAIL={}",
            mode.label().to_ascii_uppercase(),
            result.detail
        );
    }
}
