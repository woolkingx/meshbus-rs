use mb_rule::types::*;
use mesh_bus_resolver::signals::*;
use mesh_bus_resolver::types::*;

#[test]
fn fresh_signals_populates_qname_key_and_pool() {
    let sig = fresh_signals("example.com.:A", "direct-cn");
    assert_eq!(sig.qname_key, "example.com.:A");
    assert_eq!(sig.pool, "direct-cn");
    assert_eq!(sig.attempted, 0);
    assert!(!sig.default_used);
    assert_eq!(sig.action, "allow");
    assert!(sig.matched_rule_id.is_none());
    assert!(sig.matched_rule_index.is_none());
    assert!(sig.resolver_rtt_ms == 0);
}

#[test]
fn record_rule_decision_copies_all_fields_with_match() {
    let dec = RuleDecision {
        action: Action::SetResolverPool("china".into()),
        trace: MatchTrace {
            matched: true,
            rule_index: Some(2),
            rule_id: Some("cn-direct".into()),
            default_used: false,
        },
    };
    let mut sig = fresh_signals("api.baidu.com.:A", "china");
    record_rule_decision(&mut sig, &dec);
    assert_eq!(sig.matched_rule_id.as_deref(), Some("cn-direct"));
    assert_eq!(sig.matched_rule_index, Some(2));
    assert!(!sig.default_used);
    assert_eq!(sig.action, "set_resolver_pool:china");
}

#[test]
fn record_rule_decision_copies_default_used_flag() {
    let dec = RuleDecision {
        action: Action::Allow,
        trace: MatchTrace {
            matched: false,
            rule_index: None,
            rule_id: None,
            default_used: true,
        },
    };
    let mut sig = fresh_signals("unknown.example.com.:A", "sys");
    record_rule_decision(&mut sig, &dec);
    assert!(sig.default_used);
    assert!(sig.matched_rule_id.is_none());
    assert!(sig.matched_rule_index.is_none());
}

#[test]
fn record_rule_decision_deny_sets_action_label() {
    let dec = RuleDecision {
        action: Action::Deny,
        trace: MatchTrace {
            matched: true,
            rule_index: Some(0),
            rule_id: Some("block-ad".into()),
            default_used: false,
        },
    };
    let mut sig = fresh_signals("tracker.ads.example.:A", "sys");
    record_rule_decision(&mut sig, &dec);
    assert_eq!(sig.action, "deny");
    assert_eq!(sig.matched_rule_id.as_deref(), Some("block-ad"));
}

#[test]
fn emit_access_log_does_not_panic_on_minimal_signals() {
    let sig = fresh_signals("minimal.test.:A", "sys");
    // Should not panic; just logs
    emit_access_log(&sig, "mesh_bus.resolver.open");
}

#[test]
fn emit_access_log_does_not_panic_on_denied_signals() {
    let mut sig = fresh_signals("blocked.ads.example.:A", "sys");
    sig.action = "deny".into();
    sig.matched_rule_id = Some("block-ad".into());
    emit_access_log(&sig, "mesh_bus.resolver.denied");
}

#[test]
fn action_label_fn_returns_correct_labels() {
    assert_eq!(action_label(&Action::Allow), "allow");
    assert_eq!(action_label(&Action::Deny), "deny");
    assert_eq!(
        action_label(&Action::SetResolverPool("p".into())),
        "set_resolver_pool:p"
    );
}

#[test]
fn winner_exit_default_is_system() {
    let sig = fresh_signals("x.:A", "sys");
    assert_eq!(sig.winner_exit, WinnerExit::System);
}
