use super::*;

#[test]
fn unpaced_never_delays() {
    let p = Pacer::new(0);
    assert_eq!(p.delay_for(1_000_000), Duration::ZERO);
    assert_eq!(p.rate_bytes_per_sec(), 0);
}

#[test]
fn paced_delay_is_proportional() {
    let p = Pacer::new(1_000);
    assert_eq!(p.delay_for(0), Duration::ZERO);
    assert_eq!(p.delay_for(1_000), Duration::from_secs(1));
    assert_eq!(p.delay_for(500), Duration::from_millis(500));
    assert!(p.delay_for(2_000) > p.delay_for(1_000));
}
