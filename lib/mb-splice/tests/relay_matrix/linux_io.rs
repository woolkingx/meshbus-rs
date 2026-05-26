use super::*;

pub(super) fn relay_one_udp_datagram(
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

pub(super) fn std_udp_relay(
    client: UdpSocket,
    upstream: UdpSocket,
    datagram_bytes: usize,
) -> io::Result<u64> {
    let mut client_buf = vec![0u8; datagram_bytes];
    let mut upstream_buf = vec![0u8; datagram_bytes];
    loop {
        let n = client.recv(&mut client_buf)?;
        upstream.send(&client_buf[..n])?;
        let echoed = upstream.recv(&mut upstream_buf)?;
        client.send(&upstream_buf[..echoed])?;
    }
}

pub(super) fn mmsg_udp_relay(
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

pub(super) fn drain_pipe(
    pipe: &Pipe,
    dst: RawFd,
    mut remaining: usize,
    flags: u32,
) -> io::Result<()> {
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

pub(super) fn drive_stream(addr: SocketAddr, total_bytes: u64) -> io::Result<u64> {
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

pub(super) fn drive_udp_datagrams(
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

pub(super) fn splice_fd(src: RawFd, dst: RawFd, len: usize, flags: u32) -> io::Result<usize> {
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

pub(super) fn wait_ready(
    src: RawFd,
    dst: RawFd,
    wait_read: bool,
    wait_write: bool,
) -> io::Result<()> {
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

pub(super) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
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

pub(super) fn set_pipe_size(fd: RawFd, bytes: usize) -> io::Result<()> {
    let rc = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, bytes as libc::c_int) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

pub(super) fn tune_udp_socket(socket: &UdpSocket) {
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

pub(super) fn is_closed(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::ConnectionReset || err.kind() == io::ErrorKind::BrokenPipe
}

pub(super) fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub(super) fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub(super) fn recvmmsg_connected(fd: RawFd, bufs: &mut [Vec<u8>]) -> io::Result<usize> {
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

pub(super) fn sendmmsg_connected(
    fd: RawFd,
    bufs: &[Vec<u8>],
    datagram_bytes: usize,
) -> io::Result<()> {
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

pub(super) struct ProbeResult {
    pub(super) status: &'static str,
    pub(super) detail: String,
}

impl ProbeResult {
    pub(super) fn available(detail: String) -> Self {
        Self {
            status: "AVAILABLE",
            detail,
        }
    }

    pub(super) fn unavailable(detail: String) -> Self {
        Self {
            status: "UNAVAILABLE",
            detail,
        }
    }
}

#[repr(C)]
pub(super) struct BpfMapCreateAttr {
    pub(super) map_type: u32,
    pub(super) key_size: u32,
    pub(super) value_size: u32,
    pub(super) max_entries: u32,
    pub(super) map_flags: u32,
    pub(super) inner_map_fd: u32,
    pub(super) numa_node: u32,
    pub(super) map_name: [u8; 16],
    pub(super) map_ifindex: u32,
    pub(super) btf_fd: u32,
    pub(super) btf_key_type_id: u32,
    pub(super) btf_value_type_id: u32,
    pub(super) btf_vmlinux_value_type_id: u32,
    pub(super) map_extra: u64,
}

pub(super) struct IoUring {
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
    pub(super) fn new(entries: u32) -> io::Result<Self> {
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

    pub(super) unsafe fn mmap(fd: RawFd, params: &IoUringParams) -> io::Result<Self> {
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

    pub(super) fn splice(
        &self,
        src: RawFd,
        dst: RawFd,
        len: usize,
        flags: u32,
    ) -> io::Result<usize> {
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

    pub(super) unsafe fn pop_cqe(&self) -> io::Result<usize> {
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

pub(super) fn mmap_ring(
    fd: RawFd,
    len: usize,
    offset: libc::off_t,
) -> io::Result<*mut libc::c_void> {
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
pub(super) struct IoUringParams {
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
pub(super) struct IoSqringOffsets {
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
pub(super) struct IoCqringOffsets {
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
pub(super) struct IoUringSqe {
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
pub(super) struct IoUringCqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

pub(super) struct Pipe {
    pub(super) read: OwnedFd,
    pub(super) write: OwnedFd,
}

impl Pipe {
    pub(super) fn new(flags: i32) -> io::Result<Self> {
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
