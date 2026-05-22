use mb_geoip::{GeoIpDb, GeoIpResult};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn empty_db_returns_unknown_for_any_ip() {
    let db = GeoIpDb::empty();
    let r = db.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        r,
        GeoIpResult {
            country: "XX".into(),
            asn: 0,
            asn_org: String::new()
        }
    );
}

#[test]
fn empty_db_handles_ipv6() {
    let db = GeoIpDb::empty();
    let r = db.lookup("2001:4860:4860::8888".parse().expect("ipv6 literal parses"));
    assert_eq!(r.country, "XX");
    assert_eq!(r.asn, 0);
}

#[test]
fn open_missing_file_returns_err_not_panic() {
    let err = GeoIpDb::open(
        std::path::Path::new("/no/such/country.mmdb"),
        std::path::Path::new("/no/such/asn.mmdb"),
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("mmdb open"));
}
