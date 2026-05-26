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
