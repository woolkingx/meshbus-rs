use mesh_bus_resolver::cache::{DnsCache, ReverseEntry};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

#[test]
fn reverse_map_round_trip() {
    let cache = DnsCache::new();
    let ip: IpAddr = "1.2.3.4".parse().expect("ipv4 literal");
    cache.put_reverse(
        ip,
        ReverseEntry {
            qname: "example.com.".into(),
            geo: Some("US".into()),
            asn: Some(15169),
            expires_at: Instant::now() + Duration::from_secs(60),
        },
    );
    let got = cache.lookup_reverse(ip).expect("reverse hit");
    assert_eq!(got.qname, "example.com.");
    assert_eq!(got.geo.as_deref(), Some("US"));
    assert_eq!(got.asn, Some(15169));
}

#[test]
fn reverse_map_expired_returns_none_and_evicts() {
    let cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    cache.put_reverse(
        ip,
        ReverseEntry {
            qname: "g.".into(),
            geo: None,
            asn: None,
            expires_at: Instant::now() - Duration::from_secs(1),
        },
    );
    assert!(cache.lookup_reverse(ip).is_none());
    cache.put_reverse(
        ip,
        ReverseEntry {
            qname: "g2.".into(),
            geo: None,
            asn: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        },
    );
    assert_eq!(
        cache.lookup_reverse(ip).expect("reverse re-put hit").qname,
        "g2."
    );
}
