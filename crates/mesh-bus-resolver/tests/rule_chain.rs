use mb_rule::types::*;
use mesh_bus_resolver::rule::*;
use mesh_bus_resolver::*;

#[test]
fn ctx_from_request_lowercases_qname_and_fills_qtype_consumer() {
    let req = ResolveRequest {
        qname: "WWW.Example.COM.".into(),
        qtype: QType::A,
        consumer: ConsumerId("egress-socks5".into()),
    };
    let ctx = build_rule_ctx(&req);
    assert_eq!(ctx.hostname.as_deref(), Some("www.example.com"));
    assert_eq!(ctx.dns_qtype.as_deref(), Some("A"));
    assert_eq!(ctx.consumer.as_deref(), Some("egress-socks5"));
}

#[test]
fn apply_decision_extracts_pool_from_set_resolver_pool() {
    let dec = RuleDecision {
        action: Action::SetResolverPool("china".into()),
        trace: MatchTrace {
            matched: true,
            rule_index: Some(0),
            rule_id: Some("r1".into()),
            default_used: false,
        },
    };
    let proj = project_decision(&dec);
    assert_eq!(proj.pool.as_deref(), Some("china"));
    assert_eq!(proj.action_label, "set_resolver_pool:china");
    assert!(!proj.denied);
}

#[test]
fn apply_decision_treats_deny_as_short_circuit() {
    let dec = RuleDecision {
        action: Action::Deny,
        trace: MatchTrace {
            matched: true,
            rule_index: Some(0),
            rule_id: None,
            default_used: false,
        },
    };
    let proj = project_decision(&dec);
    assert!(proj.denied);
}

#[test]
fn apply_decision_compose_extracts_pool_and_route_group_and_hint() {
    let dec = RuleDecision {
        action: Action::Compose(vec![
            Action::SetResolverPool("china".into()),
            Action::SetRouteGroup("cn".into()),
            Action::SetScheduleHint(RuleScheduleHint::FanOut {
                fanout: FanOutParams { k: 3 },
            }),
        ]),
        trace: MatchTrace {
            matched: true,
            rule_index: Some(2),
            rule_id: Some("compose".into()),
            default_used: false,
        },
    };
    let proj = project_decision(&dec);
    assert_eq!(proj.pool.as_deref(), Some("china"));
    assert_eq!(proj.route_group.as_deref(), Some("cn"));
    assert_eq!(proj.schedule_hint_label, "fanout:k=3");
    assert!(!proj.denied);
}
