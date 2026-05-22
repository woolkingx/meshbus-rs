use mesh_bus_resolver::cache::{CacheKey, DnsCache};
use mesh_bus_resolver::types::{AnswerRecord, QType};
use std::net::Ipv4Addr;
use std::time::Duration;

#[test]
fn positive_hit_within_ttl() {
    let cache = DnsCache::new();
    let key = CacheKey {
        qname: "example.com.".into(),
        qtype: QType::A,
    };
    let records = vec![AnswerRecord::A(Ipv4Addr::new(93, 184, 216, 34))];
    cache.put_positive(key.clone(), records.clone(), Duration::from_secs(60));
    let hit = cache.lookup(&key).expect("hit");
    assert!(hit.is_fresh());
    assert_eq!(hit.records(), records.as_slice());
}

#[test]
fn positive_expires_after_ttl() {
    let cache = DnsCache::new();
    let key = CacheKey {
        qname: "ex.test.".into(),
        qtype: QType::A,
    };
    let records = vec![AnswerRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
    cache.put_positive(key.clone(), records, Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(20));
    let hit = cache.lookup(&key);
    assert!(hit.is_some());
    assert!(!hit.expect("expired hit still present").is_fresh());
}

#[test]
fn ttl_clamped_to_max_300s() {
    let cache = DnsCache::new();
    let key = CacheKey {
        qname: "bigttl.".into(),
        qtype: QType::A,
    };
    cache.put_positive(key.clone(), vec![], Duration::from_secs(86400));
    let remaining = cache.lookup(&key).expect("hit").remaining();
    assert!(remaining <= Duration::from_secs(300));
}
