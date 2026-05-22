use super::data_handle::{ext_get, ext_set, is_valid_ext_key_tail};
#[allow(unused_imports)]
use super::types::{
    AuthMeta, MetaValue, NetMeta, PolicyMeta, ScheduleHintLabel, TraceMeta, TransportMeta, TypedMap,
};
use bytes::Bytes;

#[test]
fn typed_map_hot_fields_read_write() {
    let mut m = TypedMap::default();
    m.policy.route_group = Some("cn".into());
    m.transport.deadline_ms = Some(5_000);
    m.transport.schedule_hint = Some(ScheduleHintLabel::Ordered);
    m.transport.schedule_fanout_k = Some(2);
    m.auth.user = Some("alice".into());
    m.trace.flow_id = Some("f-001".into());
    m.net.dst_host = Some("example.com".into());

    assert_eq!(m.policy.route_group.as_deref(), Some("cn"));
    assert_eq!(m.transport.deadline_ms, Some(5_000));
    assert_eq!(m.transport.schedule_fanout_k, Some(2));
    assert_eq!(m.auth.user.as_deref(), Some("alice"));
    assert_eq!(m.trace.flow_id.as_deref(), Some("f-001"));
    assert_eq!(m.net.dst_host.as_deref(), Some("example.com"));
}

#[test]
fn ext_insert_and_get() {
    let mut m = TypedMap::default();
    ext_set(&mut m.ext, "custom.key", MetaValue::U64(42));
    assert_eq!(ext_get(&m.ext, "custom.key"), Some(&MetaValue::U64(42)));
    assert_eq!(ext_get(&m.ext, "custom.missing"), None);
}

#[test]
fn ext_overwrites_existing_key() {
    let mut m = TypedMap::default();
    ext_set(&mut m.ext, "custom.x", MetaValue::Bool(true));
    ext_set(&mut m.ext, "custom.x", MetaValue::Bool(false));
    assert_eq!(ext_get(&m.ext, "custom.x"), Some(&MetaValue::Bool(false)));
    assert_eq!(m.ext.len(), 1, "insert-or-update must not duplicate");
}

#[test]
fn ext_key_tail_shape_matches_schema() {
    for key in ["operation", "dst_ip_primary", "geo.country"] {
        assert!(is_valid_ext_key_tail(key), "{key} should be valid");
    }
    for key in [
        "",
        "ext.operation",
        "net.dst_host",
        "bad-key",
        "bad key",
        "bad/key",
    ] {
        assert!(!is_valid_ext_key_tail(key), "{key} should be invalid");
    }
}

#[test]
fn meta_value_variants_are_distinct() {
    let s = MetaValue::String("hello".into());
    let u = MetaValue::U64(7);
    let b = MetaValue::Bool(true);
    let raw = MetaValue::Bytes(Bytes::from_static(b"raw"));
    assert_ne!(s, u);
    assert_ne!(b, raw);
}
