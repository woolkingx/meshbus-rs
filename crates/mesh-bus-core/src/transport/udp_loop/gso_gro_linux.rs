//! Linux UDP offload sockopts and probes, applied once at bind.
//!
//! GSO: never enabled as socket-global state. The socket-level `UDP_SEGMENT`
//! option is incompatible with this crate's batched `sendmmsg` fallback path:
//! on kernels through at least 5.15 a `sendmmsg` on a socket carrying
//! `UDP_SEGMENT` is rejected with `EINVAL`. GSO is therefore expressed only as a
//! per-message `sendmsg` control message in `batch_linux`, where the batch data
//! proves a legal same-destination/same-size super-buffer.
//!
//! GRO: enabling `UDP_GRO` would let the kernel concatenate several datagrams
//! into one receive buffer, which our `cmsg`-unaware `recvmmsg` path cannot
//! split back apart without corrupting boundaries. So GRO is probed (enabled to
//! detect support, then immediately disabled); the data path stays plain 1:1
//! `recvmmsg`.
//!
//! All knobs are best effort: a kernel without the option simply leaves the
//! capability unset. Off Linux this whole module is absent.

use std::os::unix::io::RawFd;

/// Raw `setsockopt` for an `int`-valued option. Returns whether the kernel
/// accepted it. Shared with the PMTU guard.
pub(super) fn set_int(fd: RawFd, level: i32, optname: i32, value: i32) -> bool {
    // SAFETY: `fd` is a live socket for the lifetime of the endpoint; the value
    // pointer and length describe a single `c_int`.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Clear socket-level GSO so the `sendmmsg` fallback cannot inherit a global
/// UDP_SEGMENT mark. Per-message GSO remains available through `sendmsg` cmsg.
pub(super) fn clear_socket_gso(fd: RawFd) {
    let _ = set_int(fd, libc::SOL_UDP, libc::UDP_SEGMENT, 0);
}

/// Probe UDP_GRO support, then disable it so the receive path keeps splitting
/// one logical datagram per message. Returns whether the kernel supports GRO.
pub(super) fn probe_gro(fd: RawFd) -> bool {
    let supported = set_int(fd, libc::SOL_UDP, libc::UDP_GRO, 1);
    if supported {
        set_int(fd, libc::SOL_UDP, libc::UDP_GRO, 0);
    }
    supported
}
