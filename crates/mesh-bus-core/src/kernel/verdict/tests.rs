use super::data_handle::verdict_label;
use super::types::{HookId, PipelineId, Reason, SinkId, SourceId, Verdict};

#[test]
fn verdict_five_variants_exhaustive() {
    let variants = [
        Verdict::Continue,
        Verdict::Jump(PipelineId::new("cn")),
        Verdict::Accept(SinkId::new("direct")),
        Verdict::Reject(Reason::code("policy_deny")),
        Verdict::Drop,
    ];
    for v in variants {
        // Exhaustive match — adding a variant must break this test.
        let _ = match v {
            Verdict::Continue => "Continue",
            Verdict::Jump(_) => "Jump",
            Verdict::Accept(_) => "Accept",
            Verdict::Reject(_) => "Reject",
            Verdict::Drop => "Drop",
        };
    }
}

#[test]
fn id_newtypes_round_trip() {
    assert_eq!(PipelineId::new("main").as_str(), "main");
    assert_eq!(SinkId::new("vip").as_str(), "vip");
    assert_eq!(SourceId::new("ingress:0").as_str(), "ingress:0");
    assert_eq!(HookId::new("health_filter").as_str(), "health_filter");
}

#[test]
fn reason_code_and_detail() {
    let r = Reason::code("denied");
    assert_eq!(r.code, "denied");
    assert!(r.detail.is_none());
    let r2 = Reason::with_detail("denied", "upstream refused");
    assert_eq!(r2.detail.as_deref(), Some("upstream refused"));
}

#[test]
fn verdict_label_matches_variant() {
    assert_eq!(verdict_label(&Verdict::Continue), "Continue");
    assert_eq!(verdict_label(&Verdict::Jump(PipelineId::new("x"))), "Jump");
    assert_eq!(verdict_label(&Verdict::Accept(SinkId::new("y"))), "Accept");
    assert_eq!(verdict_label(&Verdict::Reject(Reason::code("z"))), "Reject");
    assert_eq!(verdict_label(&Verdict::Drop), "Drop");
}
