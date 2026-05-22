use mesh_bus_resolver::cache::{CacheKey, DnsCache, Lookup};
use mesh_bus_resolver::types::QType;
use std::time::Duration;

#[test]
fn negative_returns_lookup_negative() {
    let cache = DnsCache::new();
    let key = CacheKey {
        qname: "nx.example.".into(),
        qtype: QType::A,
    };
    cache.put_negative(key.clone(), Some(Duration::from_secs(60)));
    let hit = cache.lookup(&key).expect("negative cache hit");
    assert!(matches!(hit, Lookup::Negative { .. }));
    assert!(hit.is_fresh());
}

#[test]
fn negative_default_60s_when_none_passed() {
    let cache = DnsCache::new();
    let key = CacheKey {
        qname: "nx2.".into(),
        qtype: QType::A,
    };
    cache.put_negative(key.clone(), None);
    let r = cache.lookup(&key).expect("negative cache hit").remaining();
    assert!(r <= Duration::from_secs(60) && r >= Duration::from_secs(59));
}
