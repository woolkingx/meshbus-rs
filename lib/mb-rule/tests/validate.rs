use mb_rule::{
    Action, RuleChain,
    types::{Ruleset, RulesetField, RulesetFormat, RulesetSource},
    validate,
};

#[test]
fn compose_allow_and_deny_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::Compose(vec![Action::Allow, Action::Deny]),
    };
    assert!(validate(&c, &[]).is_err());
}

#[test]
fn compose_two_set_route_group_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::Compose(vec![
            Action::SetRouteGroup("a".into()),
            Action::SetRouteGroup("b".into()),
        ]),
    };
    assert!(validate(&c, &[]).is_err());
}

#[test]
fn empty_compose_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::Compose(vec![]),
    };
    let err = validate(&c, &[]).expect_err("empty Compose must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("Compose") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn set_route_group_empty_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::SetRouteGroup(String::new()),
    };
    let err = validate(&c, &[]).expect_err("empty route group must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("SetRouteGroup") || msg.contains("route group"),
        "unexpected error: {msg}"
    );
}

#[test]
fn set_resolver_pool_empty_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::SetResolverPool(String::new()),
    };
    let err = validate(&c, &[]).expect_err("empty resolver pool must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("set_resolver_pool") || msg.contains("resolver pool"),
        "unexpected error: {msg}"
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "serde_json::json! macro expands to unwrap"
)]
fn set_transform_params_must_be_absent_or_object() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![],
        default: Action::SetTransform(RuleTransformDescriptor {
            kind: RuleTransformKind::Fragment,
            params: serde_json::json!("mtu=1200"),
        }),
    };
    let err = validate(&c, &[]).expect_err("non-object transform params must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("SetTransform") || msg.contains("params"),
        "unexpected error: {msg}"
    );
}

#[test]
fn set_schedule_hint_fanout_k_zero_rejected() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![],
        default: Action::SetScheduleHint(RuleScheduleHint::FanOut {
            fanout: FanOutParams { k: 0 },
        }),
    };
    let err = validate(&c, &[]).expect_err("fanout.k=0 must reject");
    let msg = format!("{err}");
    assert!(msg.contains("fanout.k"), "unexpected error: {msg}");
}

#[test]
fn set_cost_bias_out_of_range_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::SetCostBias(9001),
    };
    let err = validate(&c, &[]).expect_err("out-of-range SetCostBias must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("SetCostBias") || msg.contains("cost_bias"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_name_empty_rejected() {
    let rs = Ruleset {
        name: String::new(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline {
            values: vec![".example".into()],
        },
    };
    let c = RuleChain {
        rules: vec![],
        default: Action::Allow,
    };
    let err = validate(&c, &[rs]).expect_err("empty ruleset name must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_ref_empty_rejected() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: Match::Predicate(Predicate::RulesetMember(String::new())),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let err = validate(&c, &[]).expect_err("empty ruleset ref must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_inline_empty_value_rejected() {
    let rs = Ruleset {
        name: "domains".into(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline {
            values: vec!["".into()],
        },
    };
    let c = RuleChain {
        rules: vec![],
        default: Action::Allow,
    };
    let err = validate(&c, &[rs]).expect_err("empty ruleset value must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_inline_empty_values_list_rejected() {
    let rs = Ruleset {
        name: "domains".into(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline { values: vec![] },
    };
    let c = RuleChain {
        rules: vec![],
        default: Action::Allow,
    };
    let err = validate(&c, &[rs]).expect_err("empty ruleset values list must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_local_empty_path_rejected() {
    let rs = Ruleset {
        name: "domains".into(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Local { path: "".into() },
    };
    let c = RuleChain {
        rules: vec![],
        default: Action::Allow,
    };
    let err = validate(&c, &[rs]).expect_err("empty ruleset path must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn duplicate_ruleset_name_rejected() {
    let rs1 = Ruleset {
        name: "domains".into(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline {
            values: vec![".example".into()],
        },
    };
    let rs2 = Ruleset {
        name: "domains".into(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline {
            values: vec![".internal".into()],
        },
    };
    let c = RuleChain {
        rules: vec![],
        default: Action::Allow,
    };
    let err = validate(&c, &[rs1, rs2]).expect_err("duplicate ruleset name must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") && msg.contains("duplicate"),
        "unexpected error: {msg}"
    );
}

#[test]
fn rule_id_empty_rejected() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![Rule {
            id: Some(String::new()),
            r#match: Match::Predicate(Predicate::HostnameExact("example.com".into())),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let err = validate(&c, &[]).expect_err("empty rule id must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule id") || msg.contains("Rule id"),
        "unexpected error: {msg}"
    );
}

#[test]
fn string_predicate_empty_value_rejected() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: Match::Predicate(Predicate::HostnameSuffix(String::new())),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let err = validate(&c, &[]).expect_err("empty string predicate must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("predicate") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn empty_match_group_rejected() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: Match::All(vec![]),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let err = validate(&c, &[]).expect_err("empty all group must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("match") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn invalid_dst_port_range_rejected() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: Match::Predicate(Predicate::DstPortRange(9000, 80)),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let err = validate(&c, &[]).expect_err("reversed dst_port_range must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("dst_port_range") || msg.contains("port range"),
        "unexpected error: {msg}"
    );
}

#[test]
fn empty_asn_set_rejected() {
    use mb_rule::types::*;
    let c = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: Match::Predicate(Predicate::AsnAny(vec![])),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let err = validate(&c, &[]).expect_err("empty ASN set must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("asn") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ip_cidr_ruleset_requires_ip_field() {
    let rs = Ruleset {
        name: "bad".into(),
        format: RulesetFormat::IpCidr,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline {
            values: vec!["10.0.0.0/8".into()],
        },
    };
    let c = RuleChain {
        rules: vec![],
        default: Action::Allow,
    };
    assert!(validate(&c, &[rs]).is_err());
}

#[test]
fn classical_ruleset_rejects_field() {
    let rs = Ruleset {
        name: "classic".into(),
        format: RulesetFormat::Classical,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline {
            values: vec!["hostname_suffix,.example".into()],
        },
    };
    let c = RuleChain {
        rules: vec![],
        default: Action::Allow,
    };
    let err = validate(&c, &[rs]).expect_err("classical ruleset field must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("classical") && msg.contains("field"),
        "unexpected error: {msg}"
    );
}

#[test]
fn nested_compose_two_set_route_groups_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::Compose(vec![
            Action::SetRouteGroup("a".into()),
            Action::Compose(vec![Action::SetRouteGroup("b".into())]),
        ]),
    };
    let err =
        validate(&c, &[]).expect_err("two SetRouteGroup across nested Compose must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("SetRouteGroup") || msg.contains("RouteGroup"),
        "unexpected error: {msg}"
    );
}

#[test]
fn nested_compose_allow_and_deny_rejected() {
    let c = RuleChain {
        rules: vec![],
        default: Action::Compose(vec![Action::Allow, Action::Compose(vec![Action::Deny])]),
    };
    let err = validate(&c, &[]).expect_err("Allow + nested Deny must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("Allow") || msg.contains("Deny") || msg.contains("Compose"),
        "unexpected error: {msg}"
    );
}

#[test]
fn valid_chain_passes() {
    let c = RuleChain {
        rules: vec![],
        default: Action::Compose(vec![Action::Allow, Action::SetRouteGroup("cn".into())]),
    };
    assert!(validate(&c, &[]).is_ok());
}

#[test]
fn validate_rejects_duplicate_set_resolver_pool_in_compose() {
    use mb_rule::types::*;
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: Match::Predicate(Predicate::DnsQtype("A".into())),
            action: Action::Compose(vec![
                Action::SetResolverPool("china".into()),
                Action::SetResolverPool("global".into()),
            ]),
        }],
        default: Action::Allow,
    };
    let err =
        mb_rule::validate(&chain, &[]).expect_err("duplicate SetResolverPool must be rejected");
    assert!(
        format!("{err}")
            .to_lowercase()
            .contains("set_resolver_pool")
    );
}
