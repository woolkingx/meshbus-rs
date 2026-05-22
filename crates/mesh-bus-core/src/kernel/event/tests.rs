use super::data_handle::{event_empty, event_new, hook_trace_record};
#[allow(unused_imports)]
use super::types::{Event, HookTrace};
#[allow(unused_imports)]
use crate::kernel::metadata::types::MetaValue;
use crate::kernel::verdict::types::{HookId, SinkId, Verdict};
#[allow(unused_imports)]
use bytes::Bytes;

#[test]
fn event_new_has_payload_and_empty_meta() {
    let ev = event_new(Bytes::from_static(b"hello"));
    assert_eq!(&ev.payload[..], b"hello");
    assert!(ev.meta.policy.route_group.is_none());
    assert!(ev.meta.ext.is_empty());
}

#[test]
fn event_empty_has_zero_payload() {
    let ev = event_empty();
    assert!(ev.payload.is_empty());
}

#[test]
fn event_meta_is_mutable() {
    let mut ev = event_new(Bytes::from_static(b"data"));
    ev.meta.policy.route_group = Some("cn".into());
    assert_eq!(ev.meta.policy.route_group.as_deref(), Some("cn"));
}

#[test]
fn hook_trace_record_captures_id_and_label() {
    let hook_id = HookId::new("health_filter");
    let verdict = Verdict::Accept(SinkId::new("direct"));
    let entry = hook_trace_record(&hook_id, &verdict);
    assert_eq!(entry.hook_id.as_str(), "health_filter");
    assert_eq!(entry.verdict, "Accept");
}

#[test]
fn hook_trace_vec_accumulates_entries() {
    let trace: Vec<HookTrace> = vec![
        hook_trace_record(&HookId::new("h1"), &Verdict::Continue),
        hook_trace_record(&HookId::new("h2"), &Verdict::Drop),
    ];
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[0].verdict, "Continue");
    assert_eq!(trace[1].verdict, "Drop");
}
