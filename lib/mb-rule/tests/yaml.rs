use mb_rule::types::{Ruleset, RulesetField, RulesetFormat, RulesetSource};
use mb_rule::{Action, parse_chain_and_rulesets_yaml, parse_chain_yaml};

#[test]
fn flat_form_with_implicit_and() {
    let yaml = r#"
rules:
  - hostname_suffix: ".cn"
    dst_port: 443
    action: { set_route_group: cn }
default: { allow: {} }
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert_eq!(chain.rules.len(), 1);
}

#[test]
fn explicit_any_form() {
    let yaml = r#"
rules:
  - match:
      any:
        - { hostname_suffix: ".video.com" }
        - { dst_cidr: "1.1.1.0/24" }
    action: { set_route_group: cn }
default: { allow: {} }
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert_eq!(chain.rules.len(), 1);
    match &chain.rules[0].action {
        Action::SetRouteGroup(g) => assert_eq!(g, "cn"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn deny_string_action() {
    let yaml = r#"
rules:
  - { socks5_command: udp_associate, action: deny }
default: { allow: {} }
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert!(matches!(chain.rules[0].action, Action::Deny));
}

#[test]
fn yaml_parses_generic_operation_predicate() {
    let yaml = r#"
rules:
  - { operation: connect, action: deny }
default: allow
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert!(matches!(chain.rules[0].action, Action::Deny));
}

#[test]
fn missing_default_rejected() {
    let yaml = r#"
rules: []
"#;
    assert!(parse_chain_yaml(yaml).is_err());
}

#[test]
fn missing_rules_rejected() {
    let yaml = r#"
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("missing rules must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rules") && msg.contains("missing"),
        "unexpected error: {msg}"
    );
}

#[test]
fn unknown_top_level_key_rejected() {
    let yaml = r#"
rules: []
default: allow
rule_set: {}
"#;
    let err = parse_chain_yaml(yaml).expect_err("unknown top-level key must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_set") && msg.contains("unknown"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_ref() {
    let yaml = r#"
rules:
  - { ruleset: lan_blocks, action: { allow: {} } }
default: deny
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert_eq!(chain.rules.len(), 1);
}

#[test]
fn empty_ruleset_ref_rejected() {
    let yaml = r#"
rules:
  - { ruleset: "", action: { allow: {} } }
default: deny
"#;
    let err = parse_chain_yaml(yaml).expect_err("empty ruleset ref must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn empty_ruleset_name_rejected() {
    let yaml = r#"
rule_sets:
  "":
    type: inline
    format: domain-suffix
    field: hostname
    values: [".example"]
rules:
  - { ruleset: empty, action: deny }
default: allow
"#;
    let err = parse_chain_and_rulesets_yaml(yaml).expect_err("empty ruleset name must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_inline_empty_value_rejected() {
    let yaml = r#"
rule_sets:
  domains:
    type: inline
    format: domain-suffix
    field: hostname
    values: [""]
rules:
  - { ruleset: domains, action: deny }
default: allow
"#;
    let err =
        parse_chain_and_rulesets_yaml(yaml).expect_err("empty inline ruleset value must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.domains.values") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_inline_empty_values_list_rejected() {
    let yaml = r#"
rule_sets:
  domains:
    type: inline
    format: domain-suffix
    field: hostname
    values: []
rules:
  - { ruleset: domains, action: deny }
default: allow
"#;
    let err =
        parse_chain_and_rulesets_yaml(yaml).expect_err("empty inline values list must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.domains.values") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_local_empty_path_rejected() {
    let yaml = r#"
rule_sets:
  domains:
    type: local
    format: domain-suffix
    field: hostname
    path: ""
rules:
  - { ruleset: domains, action: deny }
default: allow
"#;
    let err = parse_chain_and_rulesets_yaml(yaml).expect_err("empty local path must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.domains.path") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_inline_rejects_path_key() {
    let yaml = r#"
rule_sets:
  domains:
    type: inline
    format: domain-suffix
    field: hostname
    values: [".example"]
    path: ./ignored.txt
rules: []
default: allow
"#;
    let err = parse_chain_and_rulesets_yaml(yaml).expect_err("inline ruleset path must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.domains.path") || msg.contains("path"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_local_rejects_values_key() {
    let yaml = r#"
rule_sets:
  domains:
    type: local
    format: domain-suffix
    field: hostname
    path: ./domains.txt
    values: [".ignored"]
rules: []
default: allow
"#;
    let err = parse_chain_and_rulesets_yaml(yaml).expect_err("local ruleset values must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.domains.values") || msg.contains("values"),
        "unexpected error: {msg}"
    );
}

#[test]
fn ruleset_rejects_unknown_key() {
    let yaml = r#"
rule_sets:
  domains:
    type: inline
    format: domain-suffix
    field: hostname
    values: [".example"]
    refresh: 60
rules: []
default: allow
"#;
    let err = parse_chain_and_rulesets_yaml(yaml).expect_err("unknown ruleset key must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.domains.refresh") || msg.contains("refresh"),
        "unexpected error: {msg}"
    );
}

#[test]
fn classical_ruleset_rejects_field() {
    let yaml = r#"
rule_sets:
  classic:
    type: inline
    format: classical
    field: hostname
    values: ["HOST-SUFFIX,example.com,DIRECT"]
rules: []
default: allow
"#;
    let err = parse_chain_and_rulesets_yaml(yaml).expect_err("classical field must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("classical") && msg.contains("field"),
        "unexpected error: {msg}"
    );
}

#[test]
fn top_level_rule_sets_parses_inline_and_local() {
    let dir = std::env::temp_dir().join(format!("mbrule-test-yaml-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cn_path = dir.join("cn.txt");
    std::fs::write(&cn_path, ".cn\n.gov.cn\n").expect("write cn.txt");
    let yaml = format!(
        r#"
rule_sets:
  lan_blocks:
    type: inline
    format: ip-cidr
    field: src_ip
    values: ["10.0.0.0/8", "192.168.0.0/16"]
  cn_domains:
    type: local
    format: domain-suffix
    field: hostname
    path: {path}
rules:
  - {{ ruleset: lan_blocks, action: deny }}
  - {{ ruleset: cn_domains, action: {{ set_route_group: cn }} }}
default: allow
"#,
        path = cn_path.display()
    );
    let (chain, rulesets) =
        parse_chain_and_rulesets_yaml(&yaml).expect("parse chain with rule_sets");
    assert_eq!(chain.rules.len(), 2);
    assert_eq!(rulesets.len(), 2);
    let reg = mb_rule::RuleSetRegistry::load(&rulesets).expect("load registry");
    assert_eq!(
        reg.sets.get("lan_blocks").expect("lan_blocks").cidrs.len(),
        2
    );
    let cn_entries = &reg.sets.get("cn_domains").expect("cn_domains").entries;
    assert!(cn_entries.contains(&".cn".to_string()));
}

#[test]
fn ruleset_member_predicate_evaluates_through_runtime_registry() {
    let yaml = r#"
rule_sets:
  lan_blocks:
    type: inline
    format: ip-cidr
    field: src_ip
    values: ["10.0.0.0/8"]
rules:
  - { ruleset: lan_blocks, action: deny }
default: allow
"#;
    let (chain, rulesets) =
        parse_chain_and_rulesets_yaml(yaml).expect("parse chain with rule_sets");
    let reg = mb_rule::RuleSetRegistry::load(&rulesets).expect("load registry");
    let mut ctx = mb_rule::types::RuleCtx::empty();
    ctx.src_ip = Some("10.0.1.5".parse().expect("ip"));
    let action = mb_rule::evaluate_with_trace(&chain, &ctx, &reg).action;
    assert!(
        matches!(action, Action::Deny),
        "lan_blocks must deny 10.0.0.0/8 src"
    );
    ctx.src_ip = Some("8.8.8.8".parse().expect("ip"));
    let action = mb_rule::evaluate_with_trace(&chain, &ctx, &reg).action;
    assert!(
        matches!(action, Action::Allow),
        "outside lan_blocks falls through to default allow"
    );
}

#[test]
fn registry_resolves_ip_cidr_inline() {
    let rs = Ruleset {
        name: "lan".into(),
        format: RulesetFormat::IpCidr,
        field: Some(RulesetField::SrcIp),
        source: RulesetSource::Inline {
            values: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
        },
    };
    let reg = mb_rule::RuleSetRegistry::load(&[rs]).expect("load inline ip-cidr");
    assert_eq!(
        reg.sets.get("lan").expect("set 'lan' exists").cidrs.len(),
        2
    );
}

#[test]
fn registry_rejects_ip_cidr_entry_with_ruleset_context() {
    let rs = Ruleset {
        name: "lan".into(),
        format: RulesetFormat::IpCidr,
        field: Some(RulesetField::SrcIp),
        source: RulesetSource::Inline {
            values: vec!["not-a-cidr".into()],
        },
    };
    let err = mb_rule::RuleSetRegistry::load(&[rs]).expect_err("invalid cidr must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.lan.values[]") && msg.contains("not-a-cidr"),
        "unexpected error: {msg}"
    );
}

#[test]
fn registry_rejects_ip_cidr_ruleset_with_non_ip_field() {
    let rs = Ruleset {
        name: "lan".into(),
        format: RulesetFormat::IpCidr,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Inline {
            values: vec!["10.0.0.0/8".into()],
        },
    };
    let err = mb_rule::RuleSetRegistry::load(&[rs])
        .expect_err("registry load must reject field/format drift");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets.lan") && msg.contains("ip-cidr") && msg.contains("field"),
        "unexpected error: {msg}"
    );
}

#[test]
fn registry_duplicate_ruleset_name_rejected() {
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
    let err = mb_rule::RuleSetRegistry::load(&[rs1, rs2])
        .expect_err("duplicate ruleset name must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets") && msg.contains("duplicate"),
        "unexpected error: {msg}"
    );
}

#[test]
fn registry_rejects_local_ruleset_with_no_entries_after_filtering() {
    let dir = std::env::temp_dir().join(format!("mbrule-empty-local-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("empty.txt");
    std::fs::write(&path, "\n# comment only\n   \n").expect("write empty local ruleset");
    let rs = Ruleset {
        name: "domains".into(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Local { path },
    };
    let err = mb_rule::RuleSetRegistry::load(&[rs])
        .expect_err("local ruleset with no entries must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("rule_sets") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn multi_key_action_mapping_rejected() {
    let yaml = r#"
rules:
  - { hostname: a.example.com, action: { allow: {}, deny: {} } }
default: deny
"#;
    let err = parse_chain_yaml(yaml).expect_err("multi-key action mapping must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("exactly one key") || msg.contains("multiple keys"),
        "unexpected error: {msg}"
    );
}

#[test]
fn allow_payload_must_be_empty_object() {
    let yaml = r#"
rules:
  - { hostname: a.example.com, action: { allow: { reason: debug } } }
default: deny
"#;
    let err = parse_chain_yaml(yaml).expect_err("allow payload must be empty");
    let msg = format!("{err}");
    assert!(
        msg.contains("allow") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn deny_payload_must_be_empty_object() {
    let yaml = r#"
rules:
  - { hostname: a.example.com, action: { deny: { reason: debug } } }
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("deny payload must be empty");
    let msg = format!("{err}");
    assert!(
        msg.contains("deny") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "serde_json::json! macro expands to unwrap"
)]
fn set_transform_params_round_trip() {
    let yaml = r#"
rules:
  - hostname: a.example.com
    action:
      set_transform:
        kind: fragment
        params:
          mtu: 1200
          strategy: stream
default: allow
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    match &chain.rules[0].action {
        Action::SetTransform(desc) => {
            assert_eq!(desc.kind, mb_rule::RuleTransformKind::Fragment);
            assert_eq!(
                desc.params,
                serde_json::json!({ "mtu": 1200, "strategy": "stream" })
            );
        }
        other => panic!("unexpected action: {other:?}"),
    }
}

#[test]
fn set_transform_rejects_unknown_field() {
    let yaml = r#"
rules:
  - hostname: a.example.com
    action:
      set_transform:
        kind: fragment
        ignored: true
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("unknown transform field must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("set_transform.ignored") || msg.contains("ignored"),
        "unexpected error: {msg}"
    );
}

#[test]
fn non_string_set_route_group_rejected() {
    let yaml = r#"
rules:
  - { hostname: a.example.com, action: { set_route_group: 42 } }
default: deny
"#;
    let err = parse_chain_yaml(yaml).expect_err("non-string set_route_group must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("set_route_group"), "unexpected error: {msg}");
}

#[test]
fn empty_set_route_group_rejected() {
    let yaml = r#"
rules:
  - { hostname: a.example.com, action: { set_route_group: "" } }
default: deny
"#;
    let err = parse_chain_yaml(yaml).expect_err("empty set_route_group must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("set_route_group"), "unexpected error: {msg}");
}

#[test]
fn empty_compose_rejected() {
    let yaml = r#"
rules: []
default:
  compose: []
"#;
    let err = parse_chain_yaml(yaml).expect_err("empty compose must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("compose") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn empty_hostname_suffix_rejected() {
    let yaml = r#"
rules:
  - { hostname_suffix: "", action: deny }
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("empty hostname_suffix must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("hostname_suffix") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn empty_match_all_rejected() {
    let yaml = r#"
rules:
  - match: { all: [] }
    action: deny
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("empty all group must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("all") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn fanout_k_overflow_rejected() {
    let yaml = r#"
rules:
  - hostname: a.example.com
    action: { set_schedule_hint: { fanout: { k: 5000000000 } } }
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("fanout.k > u32::MAX must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("fanout.k"), "unexpected error: {msg}");
}

#[test]
fn fanout_k_zero_rejected() {
    let yaml = r#"
rules:
  - hostname: a.example.com
    action: { set_schedule_hint: { fanout: { k: 0 } } }
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("fanout.k=0 must reject");
    let msg = format!("{err}");
    assert!(msg.contains("fanout.k"), "unexpected error: {msg}");
}

#[test]
fn set_schedule_hint_rejects_unknown_fields() {
    let yaml = r#"
rules:
  - hostname: a.example.com
    action:
      set_schedule_hint:
        fanout:
          k: 2
          ignored: true
        extra: true
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("unknown schedule_hint fields must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("schedule_hint") || msg.contains("fanout"),
        "unexpected error: {msg}"
    );
}

#[test]
fn reversed_dst_port_range_rejected() {
    let yaml = r#"
rules:
  - { dst_port_range: "9000-80", action: deny }
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("reversed dst_port_range must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("dst_port_range") && msg.contains("9000-80"),
        "unexpected error: {msg}"
    );
}

#[test]
fn match_all_with_extra_key_rejected() {
    let yaml = r#"
rules:
  - match:
      all: [ { hostname: a.com } ]
      dst_port: 443
    action: deny
default: allow
"#;
    let err = parse_chain_yaml(yaml)
        .expect_err("control key `all` mixed with extra keys must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("all") || msg.contains("control key") || msg.contains("only key"),
        "unexpected error: {msg}",
    );
}

#[test]
fn match_any_with_extra_key_rejected() {
    let yaml = r#"
rules:
  - match:
      any: [ { hostname: a.com }, { hostname: b.com } ]
      dst_port: 443
    action: deny
default: allow
"#;
    let err = parse_chain_yaml(yaml)
        .expect_err("control key `any` mixed with extra keys must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("any") || msg.contains("control key") || msg.contains("only key"),
        "unexpected error: {msg}"
    );
}

#[test]
fn match_not_with_extra_key_rejected() {
    let yaml = r#"
rules:
  - match:
      not: { hostname: a.com }
      dst_port: 443
    action: deny
default: allow
"#;
    let err = parse_chain_yaml(yaml)
        .expect_err("control key `not` mixed with extra keys must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("not") || msg.contains("control key") || msg.contains("only key"),
        "unexpected error: {msg}"
    );
}

#[test]
fn match_ruleset_with_extra_key_rejected() {
    let yaml = r#"
rules:
  - match:
      ruleset: cn
      dst_port: 443
    action: deny
default: allow
"#;
    let err = parse_chain_yaml(yaml)
        .expect_err("control key `ruleset` mixed with extra keys must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("ruleset") || msg.contains("control key") || msg.contains("only key"),
        "unexpected error: {msg}"
    );
}

#[test]
fn dst_port_overflow_rejected() {
    let yaml = r#"
rules:
  - { dst_port: 70000, action: deny }
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("dst_port > u16::MAX must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("dst_port"), "unexpected error: {msg}");
}

#[test]
fn registry_resolves_domain_suffix_local() {
    let dir = std::env::temp_dir().join(format!("mbrule-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("cn.txt");
    std::fs::write(&path, ".cn\n.gov.cn\n").expect("write temp file");
    let rs = Ruleset {
        name: "cn".into(),
        format: RulesetFormat::DomainSuffix,
        field: Some(RulesetField::Hostname),
        source: RulesetSource::Local { path },
    };
    let reg = mb_rule::RuleSetRegistry::load(&[rs]).expect("load local domain-suffix");
    let entries = &reg.sets.get("cn").expect("set 'cn' exists").entries;
    assert!(entries.contains(&".cn".to_string()));
    assert!(entries.contains(&".gov.cn".to_string()));
}

#[test]
fn parse_rule_with_id() {
    let yaml = r#"
rules:
  - id: cn-traffic
    hostname_suffix: ".cn"
    action: { set_route_group: cn }
default: allow
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert_eq!(chain.rules.len(), 1);
    assert_eq!(chain.rules[0].id.as_deref(), Some("cn-traffic"));
}

#[test]
fn parse_rule_without_id_is_none() {
    let yaml = r#"
rules:
  - hostname_suffix: ".cn"
    action: deny
default: allow
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert_eq!(chain.rules[0].id, None);
}

#[test]
fn parse_rule_with_non_string_id_rejected() {
    let yaml = r#"
rules:
  - id: 42
    hostname_suffix: ".cn"
    action: deny
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("non-string id must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("id"), "error message should mention id: {msg}");
}

#[test]
fn parse_rule_with_empty_id_rejected() {
    let yaml = r#"
rules:
  - id: ""
    hostname_suffix: .cn
    action: { set_route_group: cn }
default: allow
"#;
    let err = parse_chain_yaml(yaml).expect_err("empty rule id must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("id") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn yaml_parses_set_resolver_pool_and_consumer_predicate() {
    let yaml = r#"
rules:
  - id: pin-dns
    match:
      all:
        - consumer: egress-socks5
        - dns_qtype: A
    action:
      set_resolver_pool: china
default: allow
"#;
    let (chain, _rs) = mb_rule::parse_chain_and_rulesets_yaml(yaml).expect("valid yaml");
    assert_eq!(chain.rules.len(), 1);
    assert_eq!(chain.rules[0].id.as_deref(), Some("pin-dns"));
    assert!(
        matches!(chain.rules[0].action, mb_rule::types::Action::SetResolverPool(ref s) if s == "china")
    );
}

#[test]
fn yaml_parses_authenticated_user_eq() {
    let yaml = r#"
rules:
  - id: alice-vip
    authenticated_user: alice
    action: { set_route_group: vip }
default: allow
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    assert_eq!(chain.rules.len(), 1);
    use mb_rule::types::{MatchExpr, Predicate};
    let extract = |m: &MatchExpr| -> Option<Predicate> {
        match m {
            MatchExpr::All(v) | MatchExpr::Any(v) if v.len() == 1 => match &v[0] {
                MatchExpr::Term(p) | MatchExpr::Predicate(p) => Some(p.clone()),
                _ => None,
            },
            MatchExpr::Term(p) | MatchExpr::Predicate(p) => Some(p.clone()),
            _ => None,
        }
    };
    match extract(&chain.rules[0].r#match) {
        Some(Predicate::AuthenticatedUserEq(s)) => assert_eq!(s, "alice"),
        other => panic!("expected AuthenticatedUserEq, got {other:?}"),
    }
}

#[test]
fn yaml_parses_authenticated_user_any_via_star() {
    let yaml = r#"
rules:
  - id: require-auth
    authenticated_user: "*"
    action: allow
default: deny
"#;
    let chain = parse_chain_yaml(yaml).expect("valid yaml");
    use mb_rule::types::{MatchExpr, Predicate};
    let extract = |m: &MatchExpr| -> Option<Predicate> {
        match m {
            MatchExpr::All(v) | MatchExpr::Any(v) if v.len() == 1 => match &v[0] {
                MatchExpr::Term(p) | MatchExpr::Predicate(p) => Some(p.clone()),
                _ => None,
            },
            MatchExpr::Term(p) | MatchExpr::Predicate(p) => Some(p.clone()),
            _ => None,
        }
    };
    assert!(matches!(
        extract(&chain.rules[0].r#match),
        Some(Predicate::AuthenticatedUserAny)
    ));
}

#[test]
fn yaml_rejects_non_string_set_resolver_pool() {
    let yaml = r#"
rules:
  - match: {dns_qtype: A}
    action: {set_resolver_pool: 42}
default: allow
"#;
    let err = mb_rule::parse_chain_and_rulesets_yaml(yaml)
        .expect_err("non-string set_resolver_pool must be rejected");
    assert!(
        format!("{err}")
            .to_lowercase()
            .contains("set_resolver_pool")
    );
}

#[test]
fn yaml_rejects_empty_set_resolver_pool() {
    let yaml = r#"
rules:
  - match: {dns_qtype: A}
    action: {set_resolver_pool: ""}
default: allow
"#;
    let err = mb_rule::parse_chain_and_rulesets_yaml(yaml)
        .expect_err("empty set_resolver_pool must be rejected");
    assert!(
        format!("{err}").contains("set_resolver_pool"),
        "unexpected error: {err}"
    );
}
