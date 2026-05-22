//! Conservative path-MTU guard for the UDP substrate.
//!
//! We never trust a discovered MTU on the data path: a single oversize send
//! that the kernel fragments (or drops with EMSGSIZE) corrupts the 1:1
//! datagram-to-frame contract. Instead the substrate clamps every release to a
//! floor that survives any conformant IPv6 path, and on Linux switches the
//! socket into DF-probe mode so the kernel reports `EMSGSIZE` instead of
//! silently fragmenting.

/// IPv6 minimum link MTU (1280) minus the 40-byte IPv6 header and the 8-byte
/// UDP header. Any datagram at or below this size traverses every conformant
/// path without fragmentation.
pub const CONSERVATIVE_PMTU: u16 = 1232;

/// Clamp a payload length to the conservative PMTU. Lengths at or below the
/// guard pass through untouched.
pub fn clamp_to_pmtu(len: usize) -> usize {
    len.min(CONSERVATIVE_PMTU as usize)
}

/// Put the socket into DF-probe mode so the kernel returns `EMSGSIZE` for an
/// oversize datagram instead of fragmenting it. Best effort: succeeds if either
/// the IPv4 or the IPv6 knob is accepted. Off Linux this is a no-op.
#[cfg(target_os = "linux")]
pub(super) fn enable_pmtu_probe(fd: std::os::unix::io::RawFd) -> bool {
    let v4 = super::gso_gro_linux::set_int(
        fd,
        libc::IPPROTO_IP,
        libc::IP_MTU_DISCOVER,
        libc::IP_PMTUDISC_PROBE,
    );
    let v6 = super::gso_gro_linux::set_int(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_MTU_DISCOVER,
        libc::IPV6_PMTUDISC_PROBE,
    );
    v4 || v6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_leaves_small_payloads_untouched() {
        assert_eq!(clamp_to_pmtu(0), 0);
        assert_eq!(clamp_to_pmtu(500), 500);
        assert_eq!(
            clamp_to_pmtu(CONSERVATIVE_PMTU as usize),
            CONSERVATIVE_PMTU as usize
        );
    }

    #[test]
    fn clamp_caps_oversize_payloads() {
        assert_eq!(clamp_to_pmtu(65_535), CONSERVATIVE_PMTU as usize);
        assert_eq!(
            clamp_to_pmtu(CONSERVATIVE_PMTU as usize + 1),
            CONSERVATIVE_PMTU as usize
        );
    }
}
