use super::*;

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
