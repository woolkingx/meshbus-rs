use mb_geosite::GeositeDb;

#[test]
fn datafile_tags_exact_and_subdomain_suffixes() {
    let dir = std::env::temp_dir().join(format!("mb-geosite-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir temp");
    let path = dir.join("geosite.dat");
    std::fs::write(
        &path,
        r#"
# tag:domain suffix
cn:example.cn
ad:ads.example.com
tracker:track.example.com.
"#,
    )
    .expect("write geosite");

    let db = GeositeDb::open(&path).expect("open geosite");
    assert_eq!(db.lookup("EXAMPLE.cn."), vec!["cn"]);
    assert_eq!(db.lookup("www.example.cn"), vec!["cn"]);
    assert_eq!(db.lookup("cdn.ads.example.com"), vec!["ad"]);
    assert_eq!(db.lookup("track.example.com"), vec!["tracker"]);
    assert!(db.lookup("example.com").is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_file_returns_empty_db() {
    let path = std::env::temp_dir().join(format!("mb-geosite-missing-{}", std::process::id()));
    let db = GeositeDb::open(&path).expect("missing file is empty db");
    assert!(db.lookup("www.example.cn").is_empty());
}

#[test]
fn lookup_packed_writes_nul_separated_tags_without_string_clones() {
    let db = GeositeDb::parse(
        r#"
ad:ads.example.com
tracker:ads.example.com
"#,
    )
    .expect("parse geosite");

    assert_eq!(db.lookup_packed("cdn.ads.example.com"), b"ad\0tracker");
    assert!(db.lookup_packed("example.com").is_empty());
}

#[test]
fn parse_rejects_invalid_tag_or_domain() {
    let cases = [
        ("bad tag:example.com\n", "invalid tag"),
        ("ad:bad domain\n", "invalid domain"),
        ("ad:example..com\n", "invalid domain"),
        ("ad:example.com:extra\n", "invalid domain"),
    ];

    for (body, reason) in cases {
        let err = GeositeDb::parse(body).expect_err("invalid geosite line must fail");
        assert!(
            err.to_string().contains(reason),
            "error {err:?} should mention {reason}"
        );
    }
}
