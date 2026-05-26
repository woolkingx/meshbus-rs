use super::*;

pub(super) fn run_matrix_case(mode: RelayMode, concurrency: usize, bytes_per_flow: u64) -> f64 {
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

pub(super) fn run_udp_matrix_case(mode: UdpRelayMode, concurrency: usize) -> f64 {
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

pub(super) fn probe_offload(mode: OffloadMode) -> ProbeResult {
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
