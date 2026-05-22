use mb_rule::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleCtx, RuleSetRegistry};

fn chain(rules: Vec<Rule>, default: Action) -> RuleChain {
    RuleChain { rules, default }
}

fn term(p: Predicate) -> MatchExpr {
    MatchExpr::Term(p)
}

fn rule(id: Option<&str>, m: MatchExpr, a: Action) -> Rule {
    Rule {
        id: id.map(|s| s.to_string()),
        r#match: m,
        action: a,
    }
}

#[test]
fn missing_field_is_false() {
    let c = chain(
        vec![rule(
            None,
            term(Predicate::HostnameSuffix(".cn".into())),
            Action::Deny,
        )],
        Action::Allow,
    );
    let ctx = RuleCtx::empty(); // hostname is None
    let reg = RuleSetRegistry::empty();
    let a = mb_rule::evaluate_with_trace(&c, &ctx, &reg).action;
    assert!(
        matches!(a, Action::Allow),
        "missing hostname should not match suffix rule"
    );
}

#[test]
fn first_match_wins() {
    let c = chain(
        vec![
            rule(
                None,
                term(Predicate::HostnameSuffix(".cn".into())),
                Action::SetRouteGroup("cn".into()),
            ),
            rule(
                None,
                term(Predicate::HostnameSuffix(".cn".into())),
                Action::Deny,
            ),
        ],
        Action::Allow,
    );
    let ctx = RuleCtx {
        hostname: Some("a.example.cn".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();
    match mb_rule::evaluate_with_trace(&c, &ctx, &reg).action {
        Action::SetRouteGroup(g) => assert_eq!(g, "cn"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn default_applies_when_no_rule_matches() {
    let c = chain(vec![], Action::Deny);
    let reg = RuleSetRegistry::empty();
    assert!(matches!(
        mb_rule::evaluate_with_trace(&c, &RuleCtx::empty(), &reg).action,
        Action::Deny
    ));
}

#[test]
fn operation_matches_generic_source_operation() {
    let c = chain(
        vec![rule(
            None,
            term(Predicate::OperationEq("connect".into())),
            Action::Deny,
        )],
        Action::Allow,
    );
    let ctx = RuleCtx {
        operation: Some("connect".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();

    assert!(matches!(
        mb_rule::evaluate_with_trace(&c, &ctx, &reg).action,
        Action::Deny
    ));
}

#[test]
fn all_short_circuits_on_false() {
    let c = chain(
        vec![rule(
            None,
            MatchExpr::All(vec![
                term(Predicate::DstPortEq(443)),
                term(Predicate::HostnameSuffix(".cn".into())),
            ]),
            Action::Deny,
        )],
        Action::Allow,
    );
    let ctx = RuleCtx {
        dst_port: Some(80),
        hostname: Some("a.cn".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();
    assert!(matches!(
        mb_rule::evaluate_with_trace(&c, &ctx, &reg).action,
        Action::Allow
    ));
}

#[test]
fn any_short_circuits_on_true() {
    let c = chain(
        vec![rule(
            None,
            MatchExpr::Any(vec![
                term(Predicate::HostnameSuffix(".cn".into())),
                term(Predicate::DstPortEq(443)),
            ]),
            Action::SetRouteGroup("cn".into()),
        )],
        Action::Allow,
    );
    let ctx = RuleCtx {
        hostname: Some("a.cn".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();
    assert!(matches!(
        mb_rule::evaluate_with_trace(&c, &ctx, &reg).action,
        Action::SetRouteGroup(_)
    ));
}

#[test]
fn not_inverts() {
    let c = chain(
        vec![rule(
            None,
            MatchExpr::Not(Box::new(term(Predicate::HostnameSuffix(".cn".into())))),
            Action::Deny,
        )],
        Action::Allow,
    );
    let ctx = RuleCtx {
        hostname: Some("a.com".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();
    assert!(matches!(
        mb_rule::evaluate_with_trace(&c, &ctx, &reg).action,
        Action::Deny
    ));
}

#[test]
fn trace_matched_returns_rule_index_and_id() {
    let c = chain(
        vec![
            rule(None, term(Predicate::DstPortEq(22)), Action::Deny),
            rule(
                Some("cn-traffic"),
                term(Predicate::HostnameSuffix(".cn".into())),
                Action::SetRouteGroup("cn".into()),
            ),
        ],
        Action::Allow,
    );
    let ctx = RuleCtx {
        hostname: Some("a.example.cn".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();
    let d = mb_rule::evaluate_with_trace(&c, &ctx, &reg);
    assert!(matches!(d.action, Action::SetRouteGroup(ref g) if g == "cn"));
    assert!(d.trace.matched);
    assert_eq!(d.trace.rule_index, Some(1));
    assert_eq!(d.trace.rule_id.as_deref(), Some("cn-traffic"));
    assert!(!d.trace.default_used);
}

#[test]
fn trace_default_used_when_no_match() {
    let c = chain(
        vec![rule(
            Some("only-cn"),
            term(Predicate::HostnameSuffix(".cn".into())),
            Action::Deny,
        )],
        Action::Allow,
    );
    let ctx = RuleCtx {
        hostname: Some("a.com".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();
    let d = mb_rule::evaluate_with_trace(&c, &ctx, &reg);
    assert!(matches!(d.action, Action::Allow));
    assert!(!d.trace.matched);
    assert!(d.trace.default_used);
    assert_eq!(d.trace.rule_index, None);
    assert_eq!(d.trace.rule_id, None);
}

#[test]
fn trace_rule_with_no_id_returns_none_id() {
    let c = chain(
        vec![rule(
            None,
            term(Predicate::HostnameSuffix(".cn".into())),
            Action::Deny,
        )],
        Action::Allow,
    );
    let ctx = RuleCtx {
        hostname: Some("a.cn".into()),
        ..RuleCtx::empty()
    };
    let reg = RuleSetRegistry::empty();
    let d = mb_rule::evaluate_with_trace(&c, &ctx, &reg);
    assert!(d.trace.matched);
    assert_eq!(d.trace.rule_index, Some(0));
    assert_eq!(d.trace.rule_id, None);
}

#[test]
fn evaluate_returns_set_resolver_pool_action() {
    use mb_rule::types::*;
    let chain = RuleChain {
        rules: vec![Rule {
            id: Some("dns-china".into()),
            r#match: Match::Predicate(Predicate::DnsQtype("A".into())),
            action: Action::SetResolverPool("china".into()),
        }],
        default: Action::Allow,
    };
    let ctx = RuleCtx {
        dns_qtype: Some("A".into()),
        ..RuleCtx::default()
    };
    let reg = RuleSetRegistry::default();
    let decision = mb_rule::evaluate_with_trace(&chain, &ctx, &reg);
    assert_eq!(decision.action, Action::SetResolverPool("china".into()));
    assert!(decision.trace.matched);
    assert_eq!(decision.trace.rule_id.as_deref(), Some("dns-china"));
}

#[test]
fn evaluate_matches_authenticated_user_eq() {
    use mb_rule::types::*;
    let chain = RuleChain {
        rules: vec![Rule {
            id: Some("alice-only".into()),
            r#match: Match::Predicate(Predicate::AuthenticatedUserEq("alice".into())),
            action: Action::SetRouteGroup("vip".into()),
        }],
        default: Action::Allow,
    };
    let reg = RuleSetRegistry::default();
    let ctx_alice = RuleCtx {
        authenticated_user: Some("alice".into()),
        ..RuleCtx::default()
    };
    let d = mb_rule::evaluate_with_trace(&chain, &ctx_alice, &reg);
    assert_eq!(d.action, Action::SetRouteGroup("vip".into()));
    assert!(d.trace.matched);

    let ctx_bob = RuleCtx {
        authenticated_user: Some("bob".into()),
        ..RuleCtx::default()
    };
    let d = mb_rule::evaluate_with_trace(&chain, &ctx_bob, &reg);
    assert_eq!(d.action, Action::Allow);
    assert!(!d.trace.matched);

    let ctx_none = RuleCtx::default();
    let d = mb_rule::evaluate_with_trace(&chain, &ctx_none, &reg);
    assert_eq!(d.action, Action::Allow);
    assert!(!d.trace.matched);
}

#[test]
fn evaluate_matches_authenticated_user_any() {
    use mb_rule::types::*;
    let chain = RuleChain {
        rules: vec![Rule {
            id: Some("require-auth".into()),
            r#match: Match::Predicate(Predicate::AuthenticatedUserAny),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let reg = RuleSetRegistry::default();

    let ctx_authed = RuleCtx {
        authenticated_user: Some("alice".into()),
        ..RuleCtx::default()
    };
    let d = mb_rule::evaluate_with_trace(&chain, &ctx_authed, &reg);
    assert_eq!(d.action, Action::Allow);
    assert!(d.trace.matched);

    let ctx_unauth = RuleCtx::default();
    let d = mb_rule::evaluate_with_trace(&chain, &ctx_unauth, &reg);
    assert_eq!(d.action, Action::Deny);
    assert!(!d.trace.matched);
}

#[test]
fn evaluate_matches_consumer_predicate() {
    use mb_rule::types::*;
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: Match::Predicate(Predicate::Consumer("egress-socks5".into())),
            action: Action::SetResolverPool("internal".into()),
        }],
        default: Action::Allow,
    };
    let ctx = RuleCtx {
        consumer: Some("egress-socks5".into()),
        ..RuleCtx::default()
    };
    let reg = RuleSetRegistry::default();
    let decision = mb_rule::evaluate_with_trace(&chain, &ctx, &reg);
    assert_eq!(decision.action, Action::SetResolverPool("internal".into()));
}
