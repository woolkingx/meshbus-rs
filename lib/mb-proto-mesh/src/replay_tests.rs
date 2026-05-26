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
