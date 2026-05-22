use mb_rule::{
    data_handle::parse_chain_yaml,
    types::{Action, MatchExpr, Predicate},
};

#[test]
fn yaml_parses_dst_geo() {
    let s = r#"
rules:
  - dst_geo: CN
    action:
      set_route_group: cn-pool
default: allow
"#;
    let chain = parse_chain_yaml(s).expect("yaml parses");
    assert_eq!(chain.rules.len(), 1);
    match &chain.rules[0].r#match {
        MatchExpr::Term(Predicate::DstGeoEq(s)) => assert_eq!(s, "CN"),
        m => panic!("unexpected match: {m:?}"),
    }
}

#[test]
fn yaml_parses_asn_scalar_and_list() {
    let s1 = r#"
rules:
  - asn: 13335
    action: allow
default: deny
"#;
    let c = parse_chain_yaml(s1).expect("yaml s1 parses");
    assert!(matches!(
        c.rules[0].r#match,
        MatchExpr::Term(Predicate::AsnEq(13335))
    ));

    let s2 = r#"
rules:
  - asn: [13335, 15169]
    action: allow
default: deny
"#;
    let c = parse_chain_yaml(s2).expect("yaml s2 parses");
    match &c.rules[0].r#match {
        MatchExpr::Term(Predicate::AsnAny(v)) => assert_eq!(v, &vec![13335, 15169]),
        m => panic!("unexpected: {m:?}"),
    }
}

#[test]
fn yaml_rejects_empty_asn_list() {
    let s = r#"
rules:
  - asn: []
    action: deny
default: allow
"#;
    let err = parse_chain_yaml(s).expect_err("empty ASN list must reject");
    let msg = format!("{err}");
    assert!(
        msg.contains("asn") && msg.contains("empty"),
        "unexpected error: {msg}"
    );
}

#[test]
fn yaml_parses_geosite_tag() {
    let s = r#"
rules:
  - geosite_tag: ad
    action: deny
default: allow
"#;
    let c = parse_chain_yaml(s).expect("yaml parses");
    assert!(matches!(&c.rules[0].r#match, MatchExpr::Term(Predicate::GeositeTag(t)) if t == "ad"));
}

#[test]
fn yaml_parses_set_cost_bias() {
    let s = r#"
rules:
  - asn: 13335
    action:
      set_cost_bias: 500
default: allow
"#;
    let c = parse_chain_yaml(s).expect("yaml parses");
    assert_eq!(c.rules[0].action, Action::SetCostBias(500));
}

#[test]
fn yaml_set_cost_bias_clamps_out_of_range() {
    let s = r#"
rules:
  - asn: 13335
    action:
      set_cost_bias: 99999
default: allow
"#;
    let err = parse_chain_yaml(s).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("set_cost_bias") || msg.contains("invalid"));
}
