use mesh_bus_resolver::cache::{CacheKey, DnsCache, Lookup};
use mesh_bus_resolver::types::{AnswerRecord, QType};
use std::net::Ipv4Addr;
use std::time::Duration;

#[test]
fn lookup_stale_returns_expired_entry_within_window() {
    let cache = DnsCache::with_stale_window(Duration::from_secs(60));
    let key = CacheKey {
        qname: "stale.".into(),
        qtype: QType::A,
    };
    let recs = vec![AnswerRecord::A(Ipv4Addr::new(1, 1, 1, 1))];
    cache.put_positive(key.clone(), recs.clone(), Duration::from_millis(5));
    std::thread::sleep(Duration::from_millis(50));
    let hit = cache.lookup_stale(&key).expect("stale entry within window");
    assert!(matches!(hit, Lookup::Positive { .. }));
    assert!(!hit.is_fresh()); // expired, but serve-stale-eligible
    assert_eq!(hit.records(), recs.as_slice());
}

#[test]
fn lookup_stale_returns_none_beyond_window() {
    let cache = DnsCache::with_stale_window(Duration::from_millis(20));
    let key = CacheKey {
        qname: "expired.".into(),
        qtype: QType::A,
    };
    cache.put_positive(key.clone(), vec![], Duration::from_millis(5));
    std::thread::sleep(Duration::from_millis(60));
    assert!(cache.lookup_stale(&key).is_none());
}
