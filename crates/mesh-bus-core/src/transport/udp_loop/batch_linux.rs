//! Linux-only `sendmmsg`/`sendmsg+UDP_SEGMENT`/`recvmmsg` helpers for the UDP
//! packet loop.
//!
//! Operates on a raw fd; payload bytes stay opaque. Exactly one `mmsghdr` per
//! logical datagram, so a batch boundary always maps 1:1 to one datagram (one
//! MeshFrame for the peer crates). GSO is the only exception, and only as a
//! data-shaped send plan: same destination, same segment size, one super-buffer,
//! and per-message `UDP_SEGMENT` control data. The receiver still observes the
//! original datagram boundaries.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;

use super::queue::OutboundDatagram;

/// Datagrams per `sendmmsg`/`recvmmsg` syscall. Larger bursts loop.
pub(super) const MAX_MMSG: usize = 32;

/// Linux UDP GSO caps one super-buffer at 64 UDP segments.
const MAX_GSO_SEGMENTS: usize = 64;

/// Largest UDP payload a single `sendmsg` super-buffer may carry.
const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

/// Largest UDP payload a single received datagram may carry.
const RECV_BUF_BYTES: usize = 65_535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GsoOutcome {
    pub segments: usize,
    pub segment_size: u16,
}

fn to_sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sin = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
            };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sin6 = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
            };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    (storage, len)
}

fn from_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin =
                unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe {
                &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

fn gso_prefix(batch: &[OutboundDatagram]) -> Option<GsoOutcome> {
    let first = batch.first()?;
    let segment_size = first.payload.len();
    if segment_size == 0 || segment_size > u16::MAX as usize {
        return None;
    }
    let mut segments = 0usize;
    let mut bytes = 0usize;
    for dgram in batch.iter().take(MAX_GSO_SEGMENTS) {
        if dgram.destination != first.destination || dgram.payload.len() != segment_size {
            break;
        }
        let next_bytes = bytes.checked_add(segment_size)?;
        if next_bytes > MAX_UDP_PAYLOAD_BYTES {
            break;
        }
        segments += 1;
        bytes = next_bytes;
    }
    if segments < 2 {
        return None;
    }
    Some(GsoOutcome {
        segments,
        segment_size: segment_size as u16,
    })
}

/// Send a same-destination, same-size prefix as one UDP GSO super-buffer.
/// Returns `Ok(None)` when the batch does not have a legal GSO shape.
pub(super) fn sendmsg_gso(fd: RawFd, batch: &[OutboundDatagram]) -> io::Result<Option<GsoOutcome>> {
    let Some(plan) = gso_prefix(batch) else {
        return Ok(None);
    };
    let prefix = &batch[..plan.segments];
    let (addr, addr_len) = to_sockaddr(&prefix[0].destination);
    let mut payload = Vec::with_capacity(plan.segments * plan.segment_size as usize);
    for dgram in prefix {
        payload.extend_from_slice(&dgram.payload);
    }

    let mut iovec = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let control_len = unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as libc::c_uint) as usize };
    let mut control = vec![0u8; control_len];
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    hdr.msg_name = &addr as *const libc::sockaddr_storage as *mut libc::c_void;
    hdr.msg_namelen = addr_len;
    hdr.msg_iov = &mut iovec as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = control.len().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP GSO control buffer length does not fit msghdr",
        )
    })?;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        if cmsg.is_null() {
            return Ok(None);
        }
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as libc::c_uint)
            .try_into()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP GSO cmsg length does not fit cmsghdr",
                )
            })?;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, plan.segment_size);
        hdr.msg_controllen = (*cmsg).cmsg_len;
    }

    let sent = unsafe { libc::sendmsg(fd, &hdr, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short UDP GSO super-buffer send",
        ));
    }
    Ok(Some(plan))
}

/// Send up to `MAX_MMSG` datagrams from the front of `batch` in one syscall.
/// Returns the number the kernel accepted; the caller loops for the rest.
pub(super) fn sendmmsg(fd: RawFd, batch: &[OutboundDatagram]) -> io::Result<usize> {
    let n = batch.len().min(MAX_MMSG);
    if n == 0 {
        return Ok(0);
    }
    let mut addrs: Vec<(libc::sockaddr_storage, libc::socklen_t)> = Vec::with_capacity(n);
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(n);
    for dgram in &batch[..n] {
        addrs.push(to_sockaddr(&dgram.destination));
        iovecs.push(libc::iovec {
            iov_base: dgram.payload.as_ptr() as *mut libc::c_void,
            iov_len: dgram.payload.len(),
        });
    }
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(n);
    for i in 0..n {
        let mut hdr: libc::mmsghdr = unsafe { mem::zeroed() };
        hdr.msg_hdr.msg_name = &addrs[i].0 as *const libc::sockaddr_storage as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = addrs[i].1;
        hdr.msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
        hdr.msg_hdr.msg_iovlen = 1;
        msgs.push(hdr);
    }
    let res = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(res as usize)
}

/// Receive up to `MAX_MMSG` datagrams in one syscall. One vector entry per
/// logical datagram, source endpoint preserved.
pub(super) fn recvmmsg(fd: RawFd) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
    let mut bufs: Vec<Vec<u8>> = (0..MAX_MMSG).map(|_| vec![0u8; RECV_BUF_BYTES]).collect();
    let mut addrs: Vec<libc::sockaddr_storage> =
        (0..MAX_MMSG).map(|_| unsafe { mem::zeroed() }).collect();
    let mut iovecs: Vec<libc::iovec> = (0..MAX_MMSG)
        .map(|i| libc::iovec {
            iov_base: bufs[i].as_mut_ptr() as *mut libc::c_void,
            iov_len: RECV_BUF_BYTES,
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(MAX_MMSG);
    for i in 0..MAX_MMSG {
        let mut hdr: libc::mmsghdr = unsafe { mem::zeroed() };
        hdr.msg_hdr.msg_name = &mut addrs[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
        hdr.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        hdr.msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
        hdr.msg_hdr.msg_iovlen = 1;
        msgs.push(hdr);
    }
    let res = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            MAX_MMSG as libc::c_uint,
            0,
            std::ptr::null_mut(),
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::with_capacity(res as usize);
    for i in 0..res as usize {
        let len = msgs[i].msg_len as usize;
        let Some(src) = from_sockaddr(&addrs[i]) else {
            continue;
        };
        out.push((src, bufs[i][..len.min(RECV_BUF_BYTES)].to_vec()));
    }
    Ok(out)
}
