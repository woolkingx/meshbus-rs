use super::*;
#[test]
fn publish_then_load() {
    let p = HealthPublisher::new();
    assert!(p.load().unhealthy.is_empty());
    let mut s = HealthSnapshot::default();
    s.unhealthy.insert("exit-a".into());
    p.publish(s);
    assert!(p.load().unhealthy.contains("exit-a"));
}
