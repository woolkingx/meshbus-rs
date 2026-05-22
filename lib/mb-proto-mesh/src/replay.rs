//! Per-peer sliding-window anti-replay for MeshSec envelope counters.
//!
//! Replay state is keyed by `(peer_id, epoch_number, boot_salt)` because the
//! envelope counter is per-`K_tx` nonce material. `boot_salt` is part of
//! `K_tx`, so a sender restart with a fresh salt may legally restart counters
//! inside the same epoch. The window follows the RFC 4303 received-packet
//! bitmap shape.

use crate::meshsec::MeshSecError;
use std::collections::HashMap;

struct Window {
    highest: u64,
    seen: bool,
    bits: Vec<u64>,
}

impl Window {
    fn new(words: usize) -> Self {
        Self {
            highest: 0,
            seen: false,
            bits: vec![0u64; words],
        }
    }

    fn test(&self, counter: u64) -> bool {
        let idx = (counter % (self.bits.len() as u64 * 64)) as usize;
        self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    fn set(&mut self, counter: u64) {
        let idx = (counter % (self.bits.len() as u64 * 64)) as usize;
        self.bits[idx / 64] |= 1u64 << (idx % 64);
    }

    fn clear(&mut self, counter: u64) {
        let idx = (counter % (self.bits.len() as u64 * 64)) as usize;
        self.bits[idx / 64] &= !(1u64 << (idx % 64));
    }
}

/// Sliding-window replay cache. `check_and_insert` is called only after AEAD
/// authentication succeeds, so unauthenticated traffic never allocates state.
pub struct MeshSecReplayCache {
    words: usize,
    window_bits: u64,
    windows: HashMap<(String, u64, [u8; 4]), Window>,
}

impl MeshSecReplayCache {
    pub fn new(window_bits: u64) -> Self {
        let words = (window_bits / 64).max(1) as usize;
        Self {
            words,
            window_bits,
            windows: HashMap::new(),
        }
    }

    pub fn check_and_insert(
        &mut self,
        peer_id: &str,
        epoch_number: u64,
        boot_salt: [u8; 4],
        counter: u64,
    ) -> Result<(), MeshSecError> {
        let words = self.words;
        let window_bits = self.window_bits;
        let window = self
            .windows
            .entry((peer_id.to_string(), epoch_number, boot_salt))
            .or_insert_with(|| Window::new(words));

        if !window.seen {
            window.seen = true;
            window.highest = counter;
            window.set(counter);
            return Ok(());
        }
        if counter > window.highest {
            let diff = counter - window.highest;
            if diff >= window_bits {
                for w in window.bits.iter_mut() {
                    *w = 0;
                }
            } else {
                for skipped in (window.highest + 1)..counter {
                    window.clear(skipped);
                }
            }
            window.highest = counter;
            window.set(counter);
            return Ok(());
        }
        let diff = window.highest - counter;
        if diff >= window_bits {
            return Err(MeshSecError::ReplayTooOld);
        }
        if window.test(counter) {
            return Err(MeshSecError::Replay);
        }
        window.set(counter);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meshsec::MESHSEC_REPLAY_WINDOW_BITS;

    #[test]
    fn meshsec_replay_reject_duplicate_and_stale() {
        let mut cache = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
        let salt = [1, 2, 3, 4];
        assert_eq!(cache.check_and_insert("peer-a", 7, salt, 5), Ok(()));
        assert_eq!(
            cache.check_and_insert("peer-a", 7, salt, 5),
            Err(MeshSecError::Replay)
        );
        assert_eq!(cache.check_and_insert("peer-a", 7, salt, 6), Ok(()));
        // Out-of-order within window is accepted once, rejected on repeat.
        assert_eq!(cache.check_and_insert("peer-a", 7, salt, 4), Ok(()));
        assert_eq!(
            cache.check_and_insert("peer-a", 7, salt, 4),
            Err(MeshSecError::Replay)
        );
        // Advance far beyond the window, then a very old counter is stale.
        assert_eq!(cache.check_and_insert("peer-a", 7, salt, 5000), Ok(()));
        assert_eq!(
            cache.check_and_insert("peer-a", 7, salt, 6),
            Err(MeshSecError::ReplayTooOld)
        );
    }

    #[test]
    fn meshsec_replay_reject_is_per_peer_and_per_epoch() {
        let mut cache = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
        let salt = [1, 2, 3, 4];
        assert_eq!(cache.check_and_insert("peer-a", 1, salt, 9), Ok(()));
        // Same counter, different peer and different epoch are independent.
        assert_eq!(cache.check_and_insert("peer-b", 1, salt, 9), Ok(()));
        assert_eq!(cache.check_and_insert("peer-a", 2, salt, 9), Ok(()));
        assert_eq!(
            cache.check_and_insert("peer-a", 1, salt, 9),
            Err(MeshSecError::Replay)
        );
    }

    #[test]
    fn meshsec_replay_reject_is_per_boot_salt() {
        let mut cache = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
        assert_eq!(cache.check_and_insert("peer-a", 1, [1, 2, 3, 4], 9), Ok(()));
        assert_eq!(cache.check_and_insert("peer-a", 1, [4, 3, 2, 1], 9), Ok(()));
        assert_eq!(
            cache.check_and_insert("peer-a", 1, [1, 2, 3, 4], 9),
            Err(MeshSecError::Replay)
        );
    }
}
