//! Pure-software release pacer.
//!
//! Linux `SO_TXTIME`/fq pacing is not portable and not required for a
//! correctness substrate, so the loop spreads a release in userspace: given a
//! byte count it returns how long to sleep before the kernel hands the run to
//! the wire. Rate `0` means unpaced and the pacer always returns
//! `Duration::ZERO`, so the default path pays no cost.

use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub struct Pacer {
    rate_bytes_per_sec: u64,
}

impl Pacer {
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        Self { rate_bytes_per_sec }
    }

    pub fn rate_bytes_per_sec(&self) -> u64 {
        self.rate_bytes_per_sec
    }

    /// Delay this many bytes should wait before release. Unpaced (rate 0) is
    /// always zero; otherwise `bytes / rate` seconds, computed in microseconds
    /// to keep sub-second resolution.
    pub fn delay_for(&self, bytes: usize) -> Duration {
        if self.rate_bytes_per_sec == 0 || bytes == 0 {
            return Duration::ZERO;
        }
        let micros = (bytes as u128 * 1_000_000) / self.rate_bytes_per_sec as u128;
        Duration::from_micros(micros.min(u64::MAX as u128) as u64)
    }
}

#[cfg(test)]
#[path = "pacing_tests.rs"]
mod pacing_tests;
