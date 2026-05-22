use mb_health::{ExitHealthTable, HealthPolicy, HealthWindow};

#[test]
fn empty_window_reports_no_samples() {
    let w = HealthWindow::new(10);
    assert_eq!(w.sample_count(), 0);
}

#[test]
fn records_rtt_samples() {
    let mut w = HealthWindow::new(10);
    w.record_rtt(50);
    w.record_rtt(150);
    assert_eq!(w.sample_count(), 2);
    assert_eq!(w.mean_rtt_ms(), 62); // EWMA α=1/8: 50 + (150-50)/8 = 62
}

#[test]
fn evicts_oldest_when_full() {
    let mut w = HealthWindow::new(2);
    w.record_rtt(100);
    w.record_rtt(200);
    w.record_rtt(300);
    assert_eq!(w.sample_count(), 2);
    assert_eq!(w.mean_rtt_ms(), 135); // EWMA α=1/8: 100→200→112, evict 100, →300: 112+(300-112)/8=135
}

#[test]
fn computes_success_rate() {
    let mut w = HealthWindow::new(4);
    w.record_outcome(true);
    w.record_outcome(true);
    w.record_outcome(false);
    w.record_outcome(true);
    assert!((w.success_rate() - 0.75).abs() < 1e-9);
}

#[test]
fn exit_health_marks_unhealthy_after_threshold() {
    let policy = HealthPolicy {
        failure_threshold: 2,
        recovery_window_ms: 1_000,
        probe_after_ms: 500,
    };
    let mut table = ExitHealthTable::new(policy);
    table.record("wan20", false, 0);
    assert!(table.can_dispatch("wan20", 100));
    table.record("wan20", false, 100);
    assert!(!table.can_dispatch("wan20", 200));
}

#[test]
fn exit_health_allows_probe_after_delay() {
    let policy = HealthPolicy {
        failure_threshold: 2,
        recovery_window_ms: 1_000,
        probe_after_ms: 500,
    };
    let mut table = ExitHealthTable::new(policy);
    table.record("wan20", false, 0);
    table.record("wan20", false, 100);
    assert!(!table.can_dispatch("wan20", 599));
    assert!(table.can_dispatch("wan20", 600));
}

#[test]
fn exit_health_success_recovers_exit() {
    let policy = HealthPolicy {
        failure_threshold: 2,
        recovery_window_ms: 1_000,
        probe_after_ms: 500,
    };
    let mut table = ExitHealthTable::new(policy);
    table.record("wan20", false, 0);
    table.record("wan20", false, 100);
    table.record("wan20", true, 600);
    assert!(table.can_dispatch("wan20", 601));
}
