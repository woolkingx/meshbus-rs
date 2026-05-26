use super::*;

#[test]
fn probe_snapshot_delta_is_subtraction() {
    let p = ForwarderProbe::default();
    let s0 = p.snapshot();
    p.atomic_hits.fetch_add(7, Ordering::Relaxed);
    p.publish_calls.fetch_add(1, Ordering::Relaxed);
    let s1 = p.snapshot();
    let d = s1.delta(&s0);
    assert_eq!(d.atomic_hits, 7);
    assert_eq!(d.publish_calls, 1);
    assert_eq!(d.lock_hits, 0);
}
