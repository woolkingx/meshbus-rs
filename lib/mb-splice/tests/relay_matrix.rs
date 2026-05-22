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

fn run_matrix_case(mode: RelayMode, concurrency: usize, bytes_per_flow: u64) -> f64 {
    let upstream = spawn_echo().expect("spawn echo");
    let target = match mode {
        RelayMode::DirectEcho => upstream,
        _ => spawn_relay(upstream, mode).expect("spawn relay"),
    };
    let started = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        workers.push(thread::spawn(move || drive_stream(target, bytes_per_flow)));
    }

    let mut total = 0u64;
    for worker in workers {
        total += worker.join().expect("driver thread").expect("driver");
    }

    let elapsed = started.elapsed().as_secs_f64();
    let mib = total as f64 / elapsed / (1024.0 * 1024.0);
    println!(
        "  mode={} elapsed_ms={} concurrency={} bytes_per_flow={} total_bytes={}",
        mode.label(),
        started.elapsed().as_millis(),
        concurrency,
        bytes_per_flow,
        total
    );
    mib
}

fn run_udp_matrix_case(mode: UdpRelayMode, concurrency: usize) -> f64 {
    assert_eq!(concurrency, 1, "udp relay matrix is single-client scoped");
    let total_bytes = env_u64("MB_SPLICE_MATRIX_UDP_BYTES", DEFAULT_UDP_BYTES);
    let datagram_bytes = env_usize(
        "MB_SPLICE_MATRIX_UDP_DATAGRAM_BYTES",
        DEFAULT_UDP_DATAGRAM_BYTES,
    );
    let batch = env_usize("MB_SPLICE_MATRIX_UDP_BATCH", DEFAULT_UDP_BATCH).max(1);
    let upstream = spawn_udp_echo(datagram_bytes).expect("spawn udp echo");
    let target = match mode {
        UdpRelayMode::DirectEcho => upstream,
        UdpRelayMode::StdDatagram | UdpRelayMode::RecvmmsgSendmmsg => {
            spawn_udp_relay(upstream, datagram_bytes, mode).expect("spawn udp relay")
        }
    };
    let packets = total_bytes / datagram_bytes as u64;
    let started = Instant::now();
    let total = drive_udp_datagrams(target, datagram_bytes, packets, batch).expect("udp driver");
    let elapsed = started.elapsed().as_secs_f64();
    let mib = total as f64 / elapsed / (1024.0 * 1024.0);
    println!(
        "  udp_mode={} elapsed_ms={} datagram_bytes={} batch={} packets={} total_bytes={}",
        mode.label(),
        started.elapsed().as_millis(),
        datagram_bytes,
        batch,
        packets,
        total
    );
    mib
}

fn probe_offload(mode: OffloadMode) -> ProbeResult {
    match mode {
        OffloadMode::IoUring => probe_io_uring(),
        OffloadMode::Sockmap => probe_bpf_map(BPF_MAP_TYPE_SOCKMAP, "BPF_MAP_TYPE_SOCKMAP"),
        OffloadMode::TcXdp => probe_tc_xdp(),
        OffloadMode::AfXdp => probe_af_xdp(),
    }
}

fn probe_io_uring() -> ProbeResult {
    let mut params = [0u8; 256];
    let fd = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            2u32,
            params.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    probe_fd("io_uring_setup", fd)
}

fn probe_tc_xdp() -> ProbeResult {
    let tc = Command::new("tc").arg("-V").output();
    let tc_detail = match tc {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            format!("tc present: {}", version.trim())
        }
        Ok(output) => format!("tc exited with status {}", output.status),
        Err(err) => format!("tc unavailable: {err}"),
    };
    let map = probe_bpf_map(BPF_MAP_TYPE_DEVMAP, "BPF_MAP_TYPE_DEVMAP");
    ProbeResult {
        status: map.status,
        detail: format!("{tc_detail}; {}", map.detail),
    }
}

fn probe_af_xdp() -> ProbeResult {
    let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
    probe_fd("AF_XDP socket", fd as libc::c_long)
}

fn probe_bpf_map(map_type: u32, label: &'static str) -> ProbeResult {
    let attr = BpfMapCreateAttr {
        map_type,
        key_size: 4,
        value_size: 4,
        max_entries: 4,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
        map_ifindex: 0,
        btf_fd: 0,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        map_extra: 0,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            (&attr as *const BpfMapCreateAttr).cast::<libc::c_void>(),
            std::mem::size_of::<BpfMapCreateAttr>(),
        )
    };
    probe_fd(label, fd)
}

fn probe_fd(label: &'static str, fd: libc::c_long) -> ProbeResult {
    if fd >= 0 {
        unsafe {
            libc::close(fd as libc::c_int);
        }
        return ProbeResult::available(format!("{label} opened fd={fd}"));
    }
    let err = io::Error::last_os_error();
    ProbeResult::unavailable(format!("{label} failed: {err}"))
}

fn spawn_echo() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            let _ = stream.set_nodelay(true);
            thread::spawn(move || {
                let mut buf = vec![0u8; CHUNK_BYTES];
                loop {
                    let n = match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(addr)
}

fn spawn_udp_echo(datagram_bytes: usize) -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    tune_udp_socket(&socket);
    let addr = socket.local_addr()?;
    thread::spawn(move || {
        let mut buf = vec![0u8; datagram_bytes];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                break;
            };
            if socket.send_to(&buf[..n], peer).is_err() {
                break;
            }
        }
    });
    Ok(addr)
}

fn spawn_relay(upstream: SocketAddr, mode: RelayMode) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else {
                break;
            };
            let Ok(upstream) = TcpStream::connect(upstream) else {
                continue;
            };
            tune_socket(&client);
            tune_socket(&upstream);
            thread::spawn(move || {
                let _ = run_relay_pair(client, upstream, mode);
            });
        }
    });
    Ok(addr)
}

fn spawn_udp_relay(
    upstream: SocketAddr,
    datagram_bytes: usize,
    mode: UdpRelayMode,
) -> io::Result<SocketAddr> {
    let client_socket = UdpSocket::bind("127.0.0.1:0")?;
    tune_udp_socket(&client_socket);
    let addr = client_socket.local_addr()?;
    thread::spawn(move || {
        let mut first = vec![0u8; datagram_bytes];
        let Ok((n, client_addr)) = client_socket.recv_from(&mut first) else {
            return;
        };
        if client_socket.connect(client_addr).is_err() {
            return;
        }
        let Ok(upstream_socket) = UdpSocket::bind("127.0.0.1:0") else {
            return;
        };
        tune_udp_socket(&upstream_socket);
        if upstream_socket.connect(upstream).is_err() {
            return;
        }
        if relay_one_udp_datagram(
            &client_socket,
            &upstream_socket,
            &first[..n],
            datagram_bytes,
        )
        .is_err()
        {
            return;
        }
        let _ = match mode {
            UdpRelayMode::DirectEcho => unreachable!("direct echo bypasses udp relay"),
            UdpRelayMode::StdDatagram => {
                std_udp_relay(client_socket, upstream_socket, datagram_bytes)
            }
            UdpRelayMode::RecvmmsgSendmmsg => {
                mmsg_udp_relay(client_socket, upstream_socket, datagram_bytes)
            }
        };
    });
    Ok(addr)
}

fn run_relay_pair(client: TcpStream, upstream: TcpStream, mode: RelayMode) -> io::Result<()> {
    match mode {
        RelayMode::DirectEcho => unreachable!("direct echo bypasses relay"),
        RelayMode::TokioCopyBidirectional => tokio_copy_bidirectional(client, upstream),
        RelayMode::StdCopy
        | RelayMode::ManualReadWrite256k
        | RelayMode::BlockingSplice
        | RelayMode::BlockingSplicePipe256k
        | RelayMode::BlockingSplicePipe1m
        | RelayMode::IoUringSplice
        | RelayMode::NonblockingPollSplice
        | RelayMode::NonblockingPollSplicePipe256k
        | RelayMode::NonblockingPollSplicePipe1m => {
            let up_src = client.try_clone()?;
            let up_dst = upstream.try_clone()?;
            let down_src = upstream;
            let down_dst = client;
            let up = thread::spawn(move || relay_direction(up_src, up_dst, mode));
            let down = thread::spawn(move || relay_direction(down_src, down_dst, mode));
            let _ = up
                .join()
                .map_err(|_| io::Error::other("up relay panicked"))??;
            let _ = down
                .join()
                .map_err(|_| io::Error::other("down relay panicked"))??;
            Ok(())
        }
    }
}

fn relay_direction(src: TcpStream, dst: TcpStream, mode: RelayMode) -> io::Result<u64> {
    match mode {
        RelayMode::StdCopy => std_copy(src, dst, CHUNK_BYTES),
        RelayMode::ManualReadWrite256k => std_copy(src, dst, CHUNK_256K_BYTES),
        RelayMode::BlockingSplice => blocking_splice(src, dst, None),
        RelayMode::BlockingSplicePipe256k => blocking_splice(src, dst, Some(PIPE_256K_BYTES)),
        RelayMode::BlockingSplicePipe1m => blocking_splice(src, dst, Some(PIPE_1M_BYTES)),
        RelayMode::IoUringSplice => io_uring_splice(src, dst),
        RelayMode::NonblockingPollSplice => nonblocking_poll_splice(src, dst, None),
        RelayMode::NonblockingPollSplicePipe256k => {
            nonblocking_poll_splice(src, dst, Some(PIPE_256K_BYTES))
        }
        RelayMode::NonblockingPollSplicePipe1m => {
            nonblocking_poll_splice(src, dst, Some(PIPE_1M_BYTES))
        }
        RelayMode::DirectEcho | RelayMode::TokioCopyBidirectional => {
            unreachable!("handled as a pair")
        }
    }
}

fn tokio_copy_bidirectional(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    client.set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(async move {
        let mut client = tokio::net::TcpStream::from_std(client)?;
        let mut upstream = tokio::net::TcpStream::from_std(upstream)?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .map(|_| ())
    })
}

fn std_copy(mut src: TcpStream, mut dst: TcpStream, chunk_bytes: usize) -> io::Result<u64> {
    let mut buf = vec![0u8; chunk_bytes];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => {
                let _ = dst.shutdown(Shutdown::Write);
                return Ok(total);
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        total += n as u64;
    }
}

fn blocking_splice(src: TcpStream, dst: TcpStream, pipe_bytes: Option<usize>) -> io::Result<u64> {
    let pipe = Pipe::new(libc::O_CLOEXEC)?;
    if let Some(pipe_bytes) = pipe_bytes {
        set_pipe_size(pipe.write.as_raw_fd(), pipe_bytes)?;
    }
    let mut total = 0u64;
    loop {
        let n = splice_fd(
            src.as_raw_fd(),
            pipe.write.as_raw_fd(),
            CHUNK_BYTES,
            SPLICE_F_MOVE,
        )?;
        if n == 0 {
            let _ = dst.shutdown(Shutdown::Write);
            return Ok(total);
        }
        drain_pipe(&pipe, dst.as_raw_fd(), n, SPLICE_F_MOVE)?;
        total += n as u64;
    }
}

fn io_uring_splice(src: TcpStream, dst: TcpStream) -> io::Result<u64> {
    let pipe = Pipe::new(libc::O_CLOEXEC)?;
    let ring = IoUring::new(8)?;
    let mut total = 0u64;
    loop {
        let n = ring.splice(
            src.as_raw_fd(),
            pipe.write.as_raw_fd(),
            CHUNK_BYTES,
            SPLICE_F_MOVE,
        )?;
        if n == 0 {
            let _ = dst.shutdown(Shutdown::Write);
            return Ok(total);
        }
        let mut remaining = n;
        while remaining > 0 {
            let written = ring.splice(
                pipe.read.as_raw_fd(),
                dst.as_raw_fd(),
                remaining,
                SPLICE_F_MOVE,
            )?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "io_uring splice wrote zero bytes",
                ));
            }
            remaining -= written;
        }
        total += n as u64;
    }
}

fn nonblocking_poll_splice(
    src: TcpStream,
    dst: TcpStream,
    pipe_bytes: Option<usize>,
) -> io::Result<u64> {
    set_nonblocking(src.as_raw_fd())?;
    set_nonblocking(dst.as_raw_fd())?;
    let pipe = Pipe::new(libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    if let Some(pipe_bytes) = pipe_bytes {
        set_pipe_size(pipe.write.as_raw_fd(), pipe_bytes)?;
    }
    let mut total = 0u64;
    let mut in_pipe = 0usize;
    let mut src_eof = false;

    loop {
        let mut progressed = false;
        if !src_eof && in_pipe < CHUNK_BYTES {
            match splice_fd(
                src.as_raw_fd(),
                pipe.write.as_raw_fd(),
                CHUNK_BYTES - in_pipe,
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
            ) {
                Ok(0) => src_eof = true,
                Ok(n) => {
                    in_pipe += n;
                    progressed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if is_closed(&e) => src_eof = true,
                Err(e) => return Err(e),
            }
        }

        while in_pipe > 0 {
            match splice_fd(
                pipe.read.as_raw_fd(),
                dst.as_raw_fd(),
                in_pipe,
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
            ) {
                Ok(0) => {
                    let _ = dst.shutdown(Shutdown::Write);
                    return Ok(total);
                }
                Ok(n) => {
                    in_pipe -= n;
                    total += n as u64;
                    progressed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if is_closed(&e) => return Ok(total),
                Err(e) => return Err(e),
            }
        }

        if src_eof && in_pipe == 0 {
            let _ = dst.shutdown(Shutdown::Write);
            return Ok(total);
        }
        if !progressed {
            wait_ready(src.as_raw_fd(), dst.as_raw_fd(), !src_eof, in_pipe > 0)?;
        }
    }
}

fn relay_one_udp_datagram(
    client: &UdpSocket,
    upstream: &UdpSocket,
    payload: &[u8],
    datagram_bytes: usize,
) -> io::Result<()> {
    let mut buf = vec![0u8; datagram_bytes];
    upstream.send(payload)?;
    let n = upstream.recv(&mut buf)?;
    client.send(&buf[..n])?;
    Ok(())
}

fn std_udp_relay(client: UdpSocket, upstream: UdpSocket, datagram_bytes: usize) -> io::Result<u64> {
    let mut client_buf = vec![0u8; datagram_bytes];
    let mut upstream_buf = vec![0u8; datagram_bytes];
    loop {
        let n = client.recv(&mut client_buf)?;
        upstream.send(&client_buf[..n])?;
        let echoed = upstream.recv(&mut upstream_buf)?;
        client.send(&upstream_buf[..echoed])?;
    }
}

fn mmsg_udp_relay(
    client: UdpSocket,
    upstream: UdpSocket,
    datagram_bytes: usize,
) -> io::Result<u64> {
    let batch = env_usize("MB_SPLICE_MATRIX_UDP_BATCH", DEFAULT_UDP_BATCH).max(1);
    let mut from_client = vec![vec![0u8; datagram_bytes]; batch];
    let mut from_upstream = vec![vec![0u8; datagram_bytes]; batch];
    let mut total = 0u64;
    loop {
        let received = recvmmsg_connected(client.as_raw_fd(), &mut from_client)?;
        if received == 0 {
            return Ok(total);
        }
        sendmmsg_connected(
            upstream.as_raw_fd(),
            &from_client[..received],
            datagram_bytes,
        )?;
        let mut echoed = 0usize;
        while echoed < received {
            let n = recvmmsg_connected(upstream.as_raw_fd(), &mut from_upstream[echoed..received])?;
            if n == 0 {
                return Ok(total);
            }
            echoed += n;
        }
        sendmmsg_connected(
            client.as_raw_fd(),
            &from_upstream[..received],
            datagram_bytes,
        )?;
        total += (received * datagram_bytes) as u64;
    }
}

fn drain_pipe(pipe: &Pipe, dst: RawFd, mut remaining: usize, flags: u32) -> io::Result<()> {
    while remaining > 0 {
        let written = splice_fd(pipe.read.as_raw_fd(), dst, remaining, flags)?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "splice wrote zero bytes",
            ));
        }
        remaining -= written;
    }
    Ok(())
}

fn drive_stream(addr: SocketAddr, total_bytes: u64) -> io::Result<u64> {
    let stream = TcpStream::connect(addr)?;
    tune_socket(&stream);
    let mut writer = stream.try_clone()?;
    let mut reader = stream;
    let write_handle = thread::spawn(move || -> io::Result<()> {
        let chunk = vec![0xab; CHUNK_BYTES];
        let mut remaining = total_bytes;
        while remaining > 0 {
            let n = remaining.min(CHUNK_BYTES as u64) as usize;
            writer.write_all(&chunk[..n])?;
            remaining -= n as u64;
        }
        writer.shutdown(Shutdown::Write)
    });

    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut received = 0u64;
    while received < total_bytes {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        received += n as u64;
    }

    write_handle
        .join()
        .map_err(|_| io::Error::other("writer panicked"))??;
    assert_eq!(received, total_bytes, "echoed byte count must match");
    Ok(received)
}

fn drive_udp_datagrams(
    addr: SocketAddr,
    datagram_bytes: usize,
    packets: u64,
    batch: usize,
) -> io::Result<u64> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    tune_udp_socket(&socket);
    socket.connect(addr)?;
    let payload = vec![0xcd; datagram_bytes];
    let mut buf = vec![0u8; datagram_bytes];
    let mut total = 0u64;
    if packets == 0 {
        return Ok(total);
    }
    socket.send(&payload)?;
    total += socket.recv(&mut buf)? as u64;
    let mut remaining = packets - 1;
    while remaining > 0 {
        let window = remaining.min(batch as u64) as usize;
        for _ in 0..window {
            socket.send(&payload)?;
        }
        for _ in 0..window {
            match socket.recv(&mut buf) {
                Ok(n) => total += n as u64,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(total),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(total),
                Err(e) => return Err(e),
            }
        }
        remaining -= window as u64;
    }
    Ok(total)
}

fn splice_fd(src: RawFd, dst: RawFd, len: usize, flags: u32) -> io::Result<usize> {
    loop {
        let n = unsafe {
            libc::splice(
                src,
                std::ptr::null_mut(),
                dst,
                std::ptr::null_mut(),
                len,
                flags,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

fn wait_ready(src: RawFd, dst: RawFd, wait_read: bool, wait_write: bool) -> io::Result<()> {
    let mut fds = [
        libc::pollfd {
            fd: src,
            events: if wait_read { libc::POLLIN } else { 0 },
            revents: 0,
        },
        libc::pollfd {
            fd: dst,
            events: if wait_write { libc::POLLOUT } else { 0 },
            revents: 0,
        },
    ];
    loop {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_pipe_size(fd: RawFd, bytes: usize) -> io::Result<()> {
    let rc = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, bytes as libc::c_int) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

fn tune_udp_socket(socket: &UdpSocket) {
    let _ = socket.set_read_timeout(Some(UDP_IO_TIMEOUT));
    let _ = socket.set_write_timeout(Some(UDP_IO_TIMEOUT));
    let bytes = UDP_SOCKET_BUFFER_BYTES as libc::c_int;
    unsafe {
        let _ = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&bytes as *const libc::c_int).cast(),
            std::mem::size_of_val(&bytes) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&bytes as *const libc::c_int).cast(),
            std::mem::size_of_val(&bytes) as libc::socklen_t,
        );
    }
}

fn is_closed(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::ConnectionReset || err.kind() == io::ErrorKind::BrokenPipe
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn recvmmsg_connected(fd: RawFd, bufs: &mut [Vec<u8>]) -> io::Result<usize> {
    let mut iovecs: Vec<libc::iovec> = bufs
        .iter_mut()
        .map(|buf| libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        })
        .collect();
    let mut messages: Vec<libc::mmsghdr> = iovecs
        .iter_mut()
        .map(|iov| libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iov as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        })
        .collect();
    loop {
        let n = unsafe {
            libc::recvmmsg(
                fd,
                messages.as_mut_ptr(),
                messages.len() as libc::c_uint,
                0,
                std::ptr::null_mut(),
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn sendmmsg_connected(fd: RawFd, bufs: &[Vec<u8>], datagram_bytes: usize) -> io::Result<()> {
    let mut sent = 0usize;
    // sendmmsg may send fewer than requested; rebuild iovecs for the unsent tail on retry.
    while sent < bufs.len() {
        let mut iovecs: Vec<libc::iovec> = bufs[sent..]
            .iter()
            .map(|buf| libc::iovec {
                iov_base: buf.as_ptr().cast_mut().cast(),
                iov_len: datagram_bytes.min(buf.len()),
            })
            .collect();
        let mut messages: Vec<libc::mmsghdr> = iovecs
            .iter_mut()
            .map(|iov| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: iov as *mut libc::iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect();
        let n =
            unsafe { libc::sendmmsg(fd, messages.as_mut_ptr(), messages.len() as libc::c_uint, 0) };
        if n >= 0 {
            sent += n as usize;
            continue;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Ok(())
}

struct ProbeResult {
    status: &'static str,
    detail: String,
}

impl ProbeResult {
    fn available(detail: String) -> Self {
        Self {
            status: "AVAILABLE",
            detail,
        }
    }

    fn unavailable(detail: String) -> Self {
        Self {
            status: "UNAVAILABLE",
            detail,
        }
    }
}

#[repr(C)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

struct IoUring {
    fd: RawFd,
    sq_ring: *mut libc::c_void,
    cq_ring: *mut libc::c_void,
    sq_ring_sz: usize,
    cq_ring_sz: usize,
    sqes: *mut IoUringSqe,
    sqes_sz: usize,
    sq_tail: *mut u32,
    sq_mask: *mut u32,
    sq_array: *mut u32,
    cq_head: *mut u32,
    cq_tail: *mut u32,
    cq_mask: *mut u32,
    cqes: *mut IoUringCqe,
}

impl IoUring {
    fn new(entries: u32) -> io::Result<Self> {
        let mut params = IoUringParams::default();
        let fd = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                entries,
                (&mut params as *mut IoUringParams).cast::<libc::c_void>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = fd as RawFd;
        match unsafe { Self::mmap(fd, &params) } {
            Ok(ring) => Ok(ring),
            Err(err) => {
                unsafe {
                    libc::close(fd);
                }
                Err(err)
            }
        }
    }

    unsafe fn mmap(fd: RawFd, params: &IoUringParams) -> io::Result<Self> {
        let sq_ring_sz = params.sq_off.array as usize + params.sq_entries as usize * 4;
        let cq_ring_sz = params.cq_off.cqes as usize
            + params.cq_entries as usize * std::mem::size_of::<IoUringCqe>();
        let single_mmap = params.features & IORING_FEAT_SINGLE_MMAP != 0;
        let sq_map_sz = if single_mmap {
            sq_ring_sz.max(cq_ring_sz)
        } else {
            sq_ring_sz
        };
        let sq_ring = mmap_ring(fd, sq_map_sz, IORING_OFF_SQ_RING)?;
        let cq_ring = if single_mmap {
            sq_ring
        } else {
            mmap_ring(fd, cq_ring_sz, IORING_OFF_CQ_RING)?
        };
        let sqes_sz = params.sq_entries as usize * std::mem::size_of::<IoUringSqe>();
        let sqes = mmap_ring(fd, sqes_sz, IORING_OFF_SQES)?.cast::<IoUringSqe>();

        Ok(Self {
            fd,
            sq_ring,
            cq_ring,
            sq_ring_sz: sq_map_sz,
            cq_ring_sz: if single_mmap { 0 } else { cq_ring_sz },
            sqes,
            sqes_sz,
            sq_tail: sq_ring.byte_add(params.sq_off.tail as usize).cast(),
            sq_mask: sq_ring.byte_add(params.sq_off.ring_mask as usize).cast(),
            sq_array: sq_ring.byte_add(params.sq_off.array as usize).cast(),
            cq_head: cq_ring.byte_add(params.cq_off.head as usize).cast(),
            cq_tail: cq_ring.byte_add(params.cq_off.tail as usize).cast(),
            cq_mask: cq_ring.byte_add(params.cq_off.ring_mask as usize).cast(),
            cqes: cq_ring.byte_add(params.cq_off.cqes as usize).cast(),
        })
    }

    fn splice(&self, src: RawFd, dst: RawFd, len: usize, flags: u32) -> io::Result<usize> {
        unsafe {
            let tail = self.sq_tail.read_volatile();
            let mask = self.sq_mask.read_volatile();
            let index = tail & mask;
            let sqe = self.sqes.add(index as usize);
            std::ptr::write_bytes(sqe.cast::<u8>(), 0, std::mem::size_of::<IoUringSqe>());
            (*sqe).opcode = IORING_OP_SPLICE;
            (*sqe).fd = dst;
            (*sqe).off = u64::MAX;
            (*sqe).addr = u64::MAX;
            (*sqe).len = len as u32;
            (*sqe).splice_flags = flags;
            (*sqe).splice_fd_in = src;
            (*sqe).user_data = 1;
            self.sq_array.add(index as usize).write_volatile(index);
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            self.sq_tail.write_volatile(tail.wrapping_add(1));

            let rc = libc::syscall(
                libc::SYS_io_uring_enter,
                self.fd,
                1u32,
                1u32,
                IORING_ENTER_GETEVENTS,
                std::ptr::null::<libc::sigset_t>(),
                0usize,
            );
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            self.pop_cqe()
        }
    }

    unsafe fn pop_cqe(&self) -> io::Result<usize> {
        loop {
            let head = self.cq_head.read_volatile();
            let tail = self.cq_tail.read_volatile();
            if head != tail {
                let mask = self.cq_mask.read_volatile();
                let cqe = self.cqes.add((head & mask) as usize).read_volatile();
                self.cq_head.write_volatile(head.wrapping_add(1));
                if cqe.res < 0 {
                    return Err(io::Error::from_raw_os_error(-cqe.res));
                }
                return Ok(cqe.res as usize);
            }
        }
    }
}

impl Drop for IoUring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.sqes.cast(), self.sqes_sz);
            if self.cq_ring_sz > 0 {
                libc::munmap(self.cq_ring, self.cq_ring_sz);
            }
            libc::munmap(self.sq_ring, self.sq_ring_sz);
            libc::close(self.fd);
        }
    }
}

fn mmap_ring(fd: RawFd, len: usize, offset: libc::off_t) -> io::Result<*mut libc::c_void> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            offset,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(ptr)
}

#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

#[repr(C)]
#[derive(Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    splice_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    pad2: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoUringCqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

impl Pipe {
    fn new(flags: i32) -> io::Result<Self> {
        let mut fds = [0; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), flags) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }
}
