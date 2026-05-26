use super::*;

#[test]
fn empty_jitter_is_zero() {
    assert_eq!(HealthWindow::new(64).jitter_ms(), 0);
}

#[test]
fn stable_samples_have_low_jitter() {
    let mut w = HealthWindow::new(64);
    for _ in 0..10 {
        w.record_rtt(100);
    }
    assert_eq!(w.jitter_ms(), 0);
}

#[test]
fn outlier_raises_jitter_but_decays() {
    let mut w = HealthWindow::new(64);
    for _ in 0..5 {
        w.record_rtt(100);
    }
    w.record_rtt(500);
    let j_after_spike = w.jitter_ms();
    assert!(
        j_after_spike > 10,
        "jitter should respond to outlier, got {}",
        j_after_spike
    );
    for _ in 0..20 {
        w.record_rtt(100);
    }
    let j_decayed = w.jitter_ms();
    assert!(
        j_decayed < j_after_spike,
        "jitter should decay, was {} now {}",
        j_after_spike,
        j_decayed
    );
}
