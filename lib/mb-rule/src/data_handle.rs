use crate::types::*;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Default, Clone)]
pub struct RuleSetRegistry {
    pub sets: HashMap<String, ResolvedRuleset>,
}

#[derive(Debug, Clone)]
pub struct ResolvedRuleset {
    pub field: Option<RulesetField>,
    pub format: RulesetFormat,
    pub entries: Vec<String>,
    pub cidrs: Vec<ipnet::IpNet>,
}

impl RuleSetRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn load(sets: &[Ruleset]) -> Result<Self, ParseError> {
        let mut out = HashMap::new();
        for rs in sets {
            if out.contains_key(&rs.name) {
                return Err(ParseError::InvalidValue {
                    field: "rule_sets".into(),
                    value: format!("duplicate name `{}`", rs.name),
                });
            }
            validate_ruleset(rs).map_err(|e| ParseError::InvalidValue {
                field: format!("rule_sets.{}", rs.name),
                value: e.to_string(),
            })?;
            let raw_lines: Vec<String> = match &rs.source {
                RulesetSource::Inline { values } => values.clone(),
                RulesetSource::Local { path } => std::fs::read_to_string(path)
                    .map_err(|e| {
                        ParseError::UnknownAction(format!("read {}: {}", path.display(), e))
                    })?
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                    .map(|l| l.trim().to_string())
                    .collect(),
            };
            if raw_lines.is_empty() {
                return Err(ParseError::InvalidValue {
                    field: "rule_sets".into(),
                    value: format!("`{}` empty", rs.name),
                });
            }
            let mut entries = Vec::new();
            let mut cidrs = Vec::new();
            match rs.format {
                RulesetFormat::DomainSuffix => entries = raw_lines,
                RulesetFormat::IpCidr => {
                    for l in &raw_lines {
                        let cidr = l.parse().map_err(|e| ParseError::InvalidValue {
                            field: format!("rule_sets.{}.values[]", rs.name),
                            value: format!("{l}: {e}"),
                        })?;
                        cidrs.push(cidr);
                    }
                }
                RulesetFormat::Classical => entries = raw_lines,
            }
            out.insert(
                rs.name.clone(),
                ResolvedRuleset {
                    field: rs.field,
                    format: rs.format.clone(),
                    entries,
                    cidrs,
                },
            );
        }
        Ok(Self { sets: out })
    }
}

pub fn evaluate_with_trace(
    chain: &RuleChain,
    ctx: &RuleCtx,
    reg: &RuleSetRegistry,
) -> RuleDecision {
    for (idx, rule) in chain.rules.iter().enumerate() {
        if eval_match(&rule.r#match, ctx, reg) {
            return RuleDecision {
                action: rule.action.clone(),
                trace: MatchTrace {
                    matched: true,
                    rule_index: Some(idx),
                    rule_id: rule.id.clone(),
                    default_used: false,
                },
            };
        }
    }
    RuleDecision {
        action: chain.default.clone(),
        trace: MatchTrace {
            matched: false,
            rule_index: None,
            rule_id: None,
            default_used: true,
        },
    }
}

fn eval_match(m: &MatchExpr, ctx: &RuleCtx, reg: &RuleSetRegistry) -> bool {
    match m {
        MatchExpr::Term(p) | MatchExpr::Predicate(p) => eval_predicate(p, ctx, reg),
        MatchExpr::All(xs) => xs.iter().all(|x| eval_match(x, ctx, reg)),
        MatchExpr::Any(xs) => xs.iter().any(|x| eval_match(x, ctx, reg)),
        MatchExpr::Not(x) => !eval_match(x, ctx, reg),
    }
}

fn eval_predicate(p: &Predicate, ctx: &RuleCtx, reg: &RuleSetRegistry) -> bool {
    match p {
        Predicate::SrcCidr(n) => ctx.src_ip.is_some_and(|ip| n.contains(&ip)),
        Predicate::DstCidr(n) => ctx.dst_ip.is_some_and(|ip| n.contains(&ip)),
        Predicate::SrcIpEq(ip) => ctx.src_ip == Some(*ip),
        Predicate::DstIpEq(ip) => ctx.dst_ip == Some(*ip),
        Predicate::DstPortEq(p2) => ctx.dst_port == Some(*p2),
        Predicate::DstPortRange(a, b) => ctx.dst_port.is_some_and(|p| p >= *a && p <= *b),
        Predicate::NetworkEq(n) => ctx.network.as_ref() == Some(n),
        Predicate::SessionShapeEq(s) => ctx.session_shape.as_ref() == Some(s),
        Predicate::OperationEq(s) => ctx.operation.as_deref() == Some(s.as_str()),
        Predicate::Socks5CommandEq(c) => ctx.socks5_command.as_ref() == Some(c),
        Predicate::HostnameExact(s) => ctx.hostname.as_deref() == Some(s.as_str()),
        Predicate::HostnameSuffix(s) => ctx
            .hostname
            .as_deref()
            .is_some_and(|h| h.ends_with(s.as_str())),
        Predicate::HostnameKeyword(s) => ctx
            .hostname
            .as_deref()
            .is_some_and(|h| h.contains(s.as_str())),
        Predicate::HostnameRegex(r) => ctx.hostname.as_deref().is_some_and(|h| r.is_match(h)),
        Predicate::FragmentGroupExact(s) => ctx.fragment_group.as_deref() == Some(s.as_str()),
        Predicate::TransformKindEq(k) => ctx.transform_kind.as_ref() == Some(k),
        Predicate::TrafficClassEq(c) => ctx.traffic_class.as_ref() == Some(c),
        Predicate::RulesetMember(name) => eval_ruleset(name, ctx, reg),
        Predicate::Consumer(s) => ctx.consumer.as_deref() == Some(s.as_str()),
        Predicate::DnsQtype(s) => ctx
            .dns_qtype
            .as_deref()
            .is_some_and(|q| q.eq_ignore_ascii_case(s.as_str())),
        Predicate::AuthenticatedUserEq(s) => ctx.authenticated_user.as_deref() == Some(s.as_str()),
        Predicate::AuthenticatedUserAny => ctx.authenticated_user.is_some(),
        Predicate::DstGeoEq(s) => ctx.dst_geo.as_deref() == Some(s.as_str()),
        Predicate::AsnEq(n) => ctx.asn == Some(*n),
        Predicate::AsnAny(s) => ctx.asn.is_some_and(|a| s.contains(&a)),
        Predicate::GeositeTag(t) => ctx.geosite_tags.iter().any(|x| x == t),
    }
}

fn eval_ruleset(name: &str, ctx: &RuleCtx, reg: &RuleSetRegistry) -> bool {
    let Some(rs) = reg.sets.get(name) else {
        return false;
    };
    let pick_ip = |f: Option<RulesetField>| -> Option<IpAddr> {
        match f {
            Some(RulesetField::SrcIp) => ctx.src_ip,
            Some(RulesetField::DstIp) => ctx.dst_ip,
            _ => None,
        }
    };
    match rs.format {
        RulesetFormat::DomainSuffix => {
            let Some(h) = ctx.hostname.as_deref() else {
                return false;
            };
            rs.entries.iter().any(|s| h.ends_with(s.as_str()))
        }
        RulesetFormat::IpCidr => {
            let Some(ip) = pick_ip(rs.field) else {
                return false;
            };
            rs.cidrs.iter().any(|n| n.contains(&ip))
        }
        RulesetFormat::Classical => false, // resolved at parse time into individual rules in v1
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    #[error("Compose contains both Allow and Deny")]
    ComposeAllowDenyConflict,
    #[error("Compose contains more than one SetRouteGroup")]
    ComposeMultipleRouteGroup,
    #[error("Compose contains more than one set_resolver_pool")]
    ComposeMultipleResolverPool,
    #[error("Compose contains more than one SetCostBias")]
    ComposeMultipleCostBias,
    #[error("Compose must not be empty")]
    EmptyCompose,
    #[error("SetRouteGroup must not be empty")]
    EmptyRouteGroup,
    #[error("set_resolver_pool must not be empty")]
    EmptyResolverPool,
    #[error("SetTransform params must be absent or object")]
    InvalidTransformParams,
    #[error("fanout.k must be >= 1")]
    InvalidFanoutK,
    #[error("SetCostBias must be between -9000 and 9000")]
    InvalidCostBias,
    #[error("ruleset name must not be empty")]
    EmptyRulesetName,
    #[error("ruleset reference must not be empty")]
    EmptyRulesetRef,
    #[error("ruleset `{name}` is duplicate")]
    DuplicateRulesetName { name: String },
    #[error("ruleset `{name}` value must not be empty")]
    EmptyRulesetValue { name: String },
    #[error("ruleset `{name}` local path must not be empty")]
    EmptyRulesetPath { name: String },
    #[error("rule id must not be empty")]
    EmptyRuleId,
    #[error("predicate `{field}` must not be empty")]
    EmptyPredicateValue { field: &'static str },
    #[error("predicate set `{field}` must not be empty")]
    EmptyPredicateSet { field: &'static str },
    #[error("match `{op}` group must not be empty")]
    EmptyMatchGroup { op: &'static str },
    #[error("dst_port_range start `{start}` must be <= end `{end}`")]
    InvalidDstPortRange { start: u16, end: u16 },
    #[error("Ruleset `{name}` format `ip-cidr` requires field=src_ip or dst_ip")]
    RulesetIpCidrField { name: String },
    #[error("Ruleset `{name}` format `domain-suffix` requires field=hostname")]
    RulesetDomainSuffixField { name: String },
    #[error("Ruleset `{name}` format `classical` must omit field")]
    RulesetClassicalField { name: String },
}

pub fn validate(chain: &RuleChain, rulesets: &[Ruleset]) -> Result<(), ValidateError> {
    for r in &chain.rules {
        if r.id.as_deref() == Some("") {
            return Err(ValidateError::EmptyRuleId);
        }
        validate_match(&r.r#match)?;
        validate_action(&r.action)?;
    }
    validate_action(&chain.default)?;
    let mut ruleset_names = HashSet::new();
    for rs in rulesets {
        validate_ruleset(rs)?;
        if !ruleset_names.insert(rs.name.as_str()) {
            return Err(ValidateError::DuplicateRulesetName {
                name: rs.name.clone(),
            });
        }
    }
    Ok(())
}

fn validate_match(m: &MatchExpr) -> Result<(), ValidateError> {
    match m {
        MatchExpr::Term(p) | MatchExpr::Predicate(p) => validate_predicate(p),
        MatchExpr::All(items) => {
            if items.is_empty() {
                return Err(ValidateError::EmptyMatchGroup { op: "all" });
            }
            for item in items {
                validate_match(item)?;
            }
            Ok(())
        }
        MatchExpr::Any(items) => {
            if items.is_empty() {
                return Err(ValidateError::EmptyMatchGroup { op: "any" });
            }
            for item in items {
                validate_match(item)?;
            }
            Ok(())
        }
        MatchExpr::Not(inner) => validate_match(inner),
    }
}

fn validate_predicate(p: &Predicate) -> Result<(), ValidateError> {
    let check = |field, value: &str| {
        if value.is_empty() {
            Err(ValidateError::EmptyPredicateValue { field })
        } else {
            Ok(())
        }
    };
    match p {
        Predicate::DstPortRange(a, b) if a > b => {
            Err(ValidateError::InvalidDstPortRange { start: *a, end: *b })
        }
        Predicate::HostnameExact(s) => check("hostname", s),
        Predicate::OperationEq(s) => check("operation", s),
        Predicate::HostnameSuffix(s) => check("hostname_suffix", s),
        Predicate::HostnameKeyword(s) => check("hostname_keyword", s),
        Predicate::HostnameRegex(r) => check("hostname_regex", r.as_str()),
        Predicate::FragmentGroupExact(s) => check("fragment_group", s),
        Predicate::RulesetMember(name) if name.is_empty() => Err(ValidateError::EmptyRulesetRef),
        Predicate::RulesetMember(_) => Ok(()),
        Predicate::Consumer(s) => check("consumer", s),
        Predicate::DnsQtype(s) => check("dns_qtype", s),
        Predicate::AuthenticatedUserEq(s) => check("authenticated_user", s),
        Predicate::DstGeoEq(s) => check("dst_geo", s),
        Predicate::AsnAny(items) if items.is_empty() => {
            Err(ValidateError::EmptyPredicateSet { field: "asn" })
        }
        Predicate::GeositeTag(s) => check("geosite_tag", s),
        _ => Ok(()),
    }
}

fn validate_action(a: &Action) -> Result<(), ValidateError> {
    match a {
        Action::SetRouteGroup(g) if g.is_empty() => return Err(ValidateError::EmptyRouteGroup),
        Action::SetResolverPool(p) if p.is_empty() => return Err(ValidateError::EmptyResolverPool),
        Action::SetScheduleHint(RuleScheduleHint::FanOut { fanout }) if fanout.k == 0 => {
            return Err(ValidateError::InvalidFanoutK);
        }
        Action::SetTransform(desc) if !desc.params.is_null() && !desc.params.is_object() => {
            return Err(ValidateError::InvalidTransformParams);
        }
        Action::SetCostBias(n) if !(-9000..=9000).contains(n) => {
            return Err(ValidateError::InvalidCostBias);
        }
        Action::Compose(actions) if actions.is_empty() => return Err(ValidateError::EmptyCompose),
        Action::Compose(actions) => {
            for child in actions {
                validate_action(child)?;
            }
        }
        _ => return Ok(()),
    }
    let mut eff = ComposeEffects::default();
    collect_effects(a, &mut eff);
    if eff.has_allow && eff.has_deny {
        return Err(ValidateError::ComposeAllowDenyConflict);
    }
    if eff.route_groups > 1 {
        return Err(ValidateError::ComposeMultipleRouteGroup);
    }
    if eff.resolver_pools > 1 {
        return Err(ValidateError::ComposeMultipleResolverPool);
    }
    if eff.cost_biases > 1 {
        return Err(ValidateError::ComposeMultipleCostBias);
    }
    Ok(())
}

#[derive(Default)]
struct ComposeEffects {
    has_allow: bool,
    has_deny: bool,
    route_groups: u32,
    resolver_pools: u32,
    cost_biases: u32,
}

fn collect_effects(a: &Action, out: &mut ComposeEffects) {
    match a {
        Action::Allow => out.has_allow = true,
        Action::Deny => out.has_deny = true,
        Action::SetRouteGroup(_) => out.route_groups += 1,
        Action::SetResolverPool(_) => out.resolver_pools += 1,
        Action::SetCostBias(_) => out.cost_biases += 1,
        Action::Compose(items) => {
            for sub in items {
                collect_effects(sub, out);
            }
        }
        _ => {}
    }
}

fn validate_ruleset(rs: &Ruleset) -> Result<(), ValidateError> {
    if rs.name.is_empty() {
        return Err(ValidateError::EmptyRulesetName);
    }
    match &rs.source {
        RulesetSource::Inline { values } if values.is_empty() => {
            return Err(ValidateError::EmptyRulesetValue {
                name: rs.name.clone(),
            });
        }
        RulesetSource::Inline { values } if values.iter().any(|value| value.is_empty()) => {
            return Err(ValidateError::EmptyRulesetValue {
                name: rs.name.clone(),
            });
        }
        RulesetSource::Local { path } if path.as_os_str().is_empty() => {
            return Err(ValidateError::EmptyRulesetPath {
                name: rs.name.clone(),
            });
        }
        _ => {}
    }
    match (&rs.format, rs.field) {
        (RulesetFormat::IpCidr, Some(RulesetField::SrcIp) | Some(RulesetField::DstIp)) => Ok(()),
        (RulesetFormat::IpCidr, _) => Err(ValidateError::RulesetIpCidrField {
            name: rs.name.clone(),
        }),
        (RulesetFormat::DomainSuffix, Some(RulesetField::Hostname)) => Ok(()),
        (RulesetFormat::DomainSuffix, _) => Err(ValidateError::RulesetDomainSuffixField {
            name: rs.name.clone(),
        }),
        (RulesetFormat::Classical, None) => Ok(()),
        (RulesetFormat::Classical, Some(_)) => Err(ValidateError::RulesetClassicalField {
            name: rs.name.clone(),
        }),
    }
}

// ----- YAML parser -----

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("missing required field `default`")]
    MissingDefault,
    #[error("missing required field `rules`")]
    MissingRules,
    #[error("unknown action shape: {0}")]
    UnknownAction(String),
    #[error("unknown predicate key: {0}")]
    UnknownPredicateKey(String),
    #[error("rule must have exactly one of `match:` or flat predicate keys, not both")]
    RuleBothMatchAndFlat,
    #[error("cidr: {0}")]
    Cidr(#[from] ipnet::AddrParseError),
    #[error("regex: {0}")]
    Regex(#[from] regex::Error),
    #[error("ip: {0}")]
    Ip(#[from] std::net::AddrParseError),
    #[error("integer parse: {0}")]
    Int(#[from] std::num::ParseIntError),
    #[error("invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },
}

pub fn parse_chain_yaml(s: &str) -> Result<RuleChain, ParseError> {
    let (chain, _) = parse_chain_and_rulesets_yaml(s)?;
    Ok(chain)
}

/// Parse a chain document that may carry a top-level `rule_sets:` block alongside
/// `rules:` and `default:`. Returns the chain plus declared rulesets ready for
/// [`RuleSetRegistry::load`].
pub fn parse_chain_and_rulesets_yaml(s: &str) -> Result<(RuleChain, Vec<Ruleset>), ParseError> {
    let raw: serde_yaml::Value = serde_yaml::from_str(s)?;
    let map = raw
        .as_mapping()
        .ok_or_else(|| ParseError::UnknownAction("chain must be mapping".into()))?;
    for key in map.keys() {
        let Some(key) = key.as_str() else {
            return Err(ParseError::UnknownAction(
                "top-level keys must be strings".into(),
            ));
        };
        if !matches!(key, "rules" | "default" | "rule_sets") {
            return Err(ParseError::InvalidValue {
                field: key.into(),
                value: "unknown top-level key".into(),
            });
        }
    }
    let default_val = map.get("default").ok_or(ParseError::MissingDefault)?;
    let default = parse_action(default_val)?;
    let rules = match map.get("rules") {
        None => return Err(ParseError::MissingRules),
        Some(serde_yaml::Value::Sequence(seq)) => {
            seq.iter().map(parse_rule).collect::<Result<_, _>>()?
        }
        Some(_) => return Err(ParseError::UnknownAction("rules must be sequence".into())),
    };
    let rulesets = match map.get("rule_sets") {
        None => Vec::new(),
        Some(serde_yaml::Value::Mapping(rs_map)) => {
            let mut out = Vec::new();
            for (name_v, decl_v) in rs_map {
                let name = name_v
                    .as_str()
                    .ok_or_else(|| {
                        ParseError::UnknownAction("rule_sets keys must be strings".into())
                    })?
                    .to_string();
                if name.is_empty() {
                    return Err(ParseError::InvalidValue {
                        field: "rule_sets".into(),
                        value: "empty name".into(),
                    });
                }
                out.push(parse_ruleset(name, decl_v)?);
            }
            out
        }
        Some(_) => {
            return Err(ParseError::UnknownAction(
                "rule_sets must be mapping".into(),
            ));
        }
    };
    Ok((RuleChain { rules, default }, rulesets))
}

fn parse_ruleset(name: String, v: &serde_yaml::Value) -> Result<Ruleset, ParseError> {
    let map = v
        .as_mapping()
        .ok_or_else(|| ParseError::UnknownAction(format!("rule_sets.{name} must be mapping")))?;
    for key in map.keys() {
        let Some(key) = key.as_str() else {
            return Err(ParseError::UnknownAction(format!(
                "rule_sets.{name} keys must be strings"
            )));
        };
        if !matches!(key, "type" | "format" | "field" | "values" | "path") {
            return Err(ParseError::InvalidValue {
                field: format!("rule_sets.{name}.{key}"),
                value: "unknown key".into(),
            });
        }
    }
    let format_str = map
        .get("format")
        .and_then(|x| x.as_str())
        .ok_or_else(|| ParseError::UnknownAction(format!("rule_sets.{name}.format missing")))?;
    let format = match format_str {
        "domain-suffix" => RulesetFormat::DomainSuffix,
        "ip-cidr" => RulesetFormat::IpCidr,
        "classical" => RulesetFormat::Classical,
        other => {
            return Err(ParseError::InvalidValue {
                field: format!("rule_sets.{name}.format"),
                value: other.into(),
            });
        }
    };
    let field = match map.get("field").and_then(|x| x.as_str()) {
        None => None,
        Some("hostname") => Some(RulesetField::Hostname),
        Some("src_ip") => Some(RulesetField::SrcIp),
        Some("dst_ip") => Some(RulesetField::DstIp),
        Some(other) => {
            return Err(ParseError::InvalidValue {
                field: format!("rule_sets.{name}.field"),
                value: other.into(),
            });
        }
    };
    if matches!(format, RulesetFormat::Classical) && field.is_some() {
        return Err(ParseError::InvalidValue {
            field: format!("rule_sets.{name}.field"),
            value: "not allowed for classical".into(),
        });
    }
    let source_kind = map.get("type").and_then(|x| x.as_str()).ok_or_else(|| {
        ParseError::UnknownAction(format!("rule_sets.{name}.type missing (inline|local)"))
    })?;
    let source = match source_kind {
        "inline" => {
            if map.contains_key("path") {
                return Err(ParseError::InvalidValue {
                    field: format!("rule_sets.{name}.path"),
                    value: "not allowed for inline source".into(),
                });
            }
            let seq = map
                .get("values")
                .and_then(|x| x.as_sequence())
                .ok_or_else(|| {
                    ParseError::UnknownAction(format!("rule_sets.{name}.values missing"))
                })?;
            if seq.is_empty() {
                return Err(ParseError::InvalidValue {
                    field: format!("rule_sets.{name}.values"),
                    value: "empty".into(),
                });
            }
            let values: Vec<String> = seq
                .iter()
                .map(|v| {
                    let value = v.as_str().ok_or_else(|| ParseError::InvalidValue {
                        field: format!("rule_sets.{name}.values[]"),
                        value: format!("{v:?}"),
                    })?;
                    if value.is_empty() {
                        return Err(ParseError::InvalidValue {
                            field: format!("rule_sets.{name}.values[]"),
                            value: "empty".into(),
                        });
                    }
                    Ok(value.to_string())
                })
                .collect::<Result<_, _>>()?;
            RulesetSource::Inline { values }
        }
        "local" => {
            if map.contains_key("values") {
                return Err(ParseError::InvalidValue {
                    field: format!("rule_sets.{name}.values"),
                    value: "not allowed for local source".into(),
                });
            }
            let p = map.get("path").and_then(|x| x.as_str()).ok_or_else(|| {
                ParseError::UnknownAction(format!("rule_sets.{name}.path missing"))
            })?;
            if p.is_empty() {
                return Err(ParseError::InvalidValue {
                    field: format!("rule_sets.{name}.path"),
                    value: "empty".into(),
                });
            }
            RulesetSource::Local {
                path: std::path::PathBuf::from(p),
            }
        }
        other => {
            return Err(ParseError::InvalidValue {
                field: format!("rule_sets.{name}.type"),
                value: other.into(),
            });
        }
    };
    Ok(Ruleset {
        name,
        format,
        field,
        source,
    })
}

fn parse_rule(v: &serde_yaml::Value) -> Result<Rule, ParseError> {
    let map = v
        .as_mapping()
        .ok_or_else(|| ParseError::UnknownAction("rule must be mapping".into()))?;
    let action_val = map
        .get("action")
        .ok_or_else(|| ParseError::UnknownAction("rule missing `action`".into()))?;
    let action = parse_action(action_val)?;
    let id = match map.get("id") {
        None => None,
        Some(serde_yaml::Value::String(s)) if s.is_empty() => {
            return Err(ParseError::InvalidValue {
                field: "id".into(),
                value: "empty".into(),
            });
        }
        Some(serde_yaml::Value::String(s)) => Some(s.clone()),
        Some(other) => {
            return Err(ParseError::InvalidValue {
                field: "id".into(),
                value: format!("{other:?}"),
            });
        }
    };
    let has_match = map.contains_key("match");
    let flat_keys: Vec<&serde_yaml::Value> = map
        .keys()
        .filter(|k| {
            let s = k.as_str().unwrap_or("");
            s != "action" && s != "match" && s != "id"
        })
        .collect();
    if has_match && !flat_keys.is_empty() {
        return Err(ParseError::RuleBothMatchAndFlat);
    }
    let m = if has_match {
        let mv = map.get("match").expect("has_match guarantees key exists");
        parse_match(mv)?
    } else {
        let mut terms = Vec::new();
        for k in flat_keys {
            let key = k.as_str().expect("yaml mapping keys are strings");
            let val = map.get(k).expect("key came from map iterator");
            terms.push(MatchExpr::Term(parse_predicate(key, val)?));
        }
        if terms.is_empty() {
            return Err(ParseError::UnknownAction("rule has no predicates".into()));
        }
        if terms.len() == 1 {
            terms.pop().expect("len==1")
        } else {
            MatchExpr::All(terms)
        }
    };
    Ok(Rule {
        id,
        r#match: m,
        action,
    })
}

fn parse_match(v: &serde_yaml::Value) -> Result<MatchExpr, ParseError> {
    let map = v
        .as_mapping()
        .ok_or_else(|| ParseError::UnknownAction("match must be mapping".into()))?;
    for ctrl in ["all", "any", "not", "ruleset"] {
        if map.contains_key(ctrl) && map.len() > 1 {
            return Err(ParseError::UnknownAction(format!(
                "match control key `{ctrl}` must be the only key in mapping"
            )));
        }
    }
    if let Some(seq) = map.get("all").and_then(|x| x.as_sequence()) {
        reject_empty_match_group("all", seq)?;
        return Ok(MatchExpr::All(
            seq.iter().map(parse_match).collect::<Result<_, _>>()?,
        ));
    }
    if let Some(seq) = map.get("any").and_then(|x| x.as_sequence()) {
        reject_empty_match_group("any", seq)?;
        return Ok(MatchExpr::Any(
            seq.iter().map(parse_match).collect::<Result<_, _>>()?,
        ));
    }
    if let Some(inner) = map.get("not") {
        return Ok(MatchExpr::Not(Box::new(parse_match(inner)?)));
    }
    if let Some(name) = map.get("ruleset").and_then(|x| x.as_str()) {
        reject_empty_symbol("ruleset", name)?;
        return Ok(MatchExpr::Term(Predicate::RulesetMember(name.into())));
    }
    // single predicate term
    let mut iter = map.iter();
    let (k, vv) = iter
        .next()
        .ok_or_else(|| ParseError::UnknownAction("empty match".into()))?;
    if iter.next().is_some() {
        // multiple keys → implicit AND
        let terms: Result<Vec<_>, _> = map
            .iter()
            .map(|(k, v)| {
                Ok::<_, ParseError>(MatchExpr::Term(parse_predicate(
                    k.as_str().unwrap_or(""),
                    v,
                )?))
            })
            .collect();
        return Ok(MatchExpr::All(terms?));
    }
    Ok(MatchExpr::Term(parse_predicate(
        k.as_str().unwrap_or(""),
        vv,
    )?))
}

fn parse_predicate(key: &str, val: &serde_yaml::Value) -> Result<Predicate, ParseError> {
    use Predicate as P;
    let s = || val.as_str().unwrap_or("").to_string();
    match key {
        "src_cidr" => Ok(P::SrcCidr(s().parse()?)),
        "dst_cidr" => Ok(P::DstCidr(s().parse()?)),
        "src_ip" => Ok(P::SrcIpEq(s().parse()?)),
        "dst_ip" => Ok(P::DstIpEq(s().parse()?)),
        "dst_port" => {
            let n = val.as_u64().ok_or_else(|| ParseError::InvalidValue {
                field: "dst_port".into(),
                value: s(),
            })?;
            if n > u16::MAX as u64 {
                return Err(ParseError::InvalidValue {
                    field: "dst_port".into(),
                    value: n.to_string(),
                });
            }
            Ok(P::DstPortEq(n as u16))
        }
        "dst_port_range" => {
            let sv = s();
            let (a, b) = sv.split_once('-').ok_or_else(|| ParseError::InvalidValue {
                field: "dst_port_range".into(),
                value: sv.clone(),
            })?;
            let start = a.parse()?;
            let end = b.parse()?;
            if start > end {
                return Err(ParseError::InvalidValue {
                    field: "dst_port_range".into(),
                    value: sv,
                });
            }
            Ok(P::DstPortRange(start, end))
        }
        "network" => Ok(P::NetworkEq(match s().as_str() {
            "tcp" => RuleNetwork::Tcp,
            "udp" => RuleNetwork::Udp,
            v => {
                return Err(ParseError::InvalidValue {
                    field: "network".into(),
                    value: v.into(),
                });
            }
        })),
        "session_shape" => Ok(P::SessionShapeEq(match s().as_str() {
            "stream" => RuleSessionShape::Stream,
            "datagram" => RuleSessionShape::Datagram,
            v => {
                return Err(ParseError::InvalidValue {
                    field: "session_shape".into(),
                    value: v.into(),
                });
            }
        })),
        "operation" => Ok(P::OperationEq(parse_non_empty_string("operation", val)?)),
        "socks5_command" => Ok(P::Socks5CommandEq(match s().as_str() {
            "connect" => RuleSocks5Command::Connect,
            "bind" => RuleSocks5Command::Bind,
            "udp_associate" => RuleSocks5Command::UdpAssociate,
            v => {
                return Err(ParseError::InvalidValue {
                    field: "socks5_command".into(),
                    value: v.into(),
                });
            }
        })),
        "hostname" => Ok(P::HostnameExact(parse_non_empty_string("hostname", val)?)),
        "hostname_suffix" => Ok(P::HostnameSuffix(parse_non_empty_string(
            "hostname_suffix",
            val,
        )?)),
        "hostname_keyword" => Ok(P::HostnameKeyword(parse_non_empty_string(
            "hostname_keyword",
            val,
        )?)),
        "hostname_regex" => Ok(P::HostnameRegex(regex::Regex::new(
            &parse_non_empty_string("hostname_regex", val)?,
        )?)),
        "fragment_group" => Ok(P::FragmentGroupExact(parse_non_empty_string(
            "fragment_group",
            val,
        )?)),
        "traffic_class" => Ok(P::TrafficClassEq(match s().as_str() {
            "interactive" => RuleTrafficClass::Interactive,
            "bulk" => RuleTrafficClass::Bulk,
            "control" => RuleTrafficClass::Control,
            v => {
                return Err(ParseError::InvalidValue {
                    field: "traffic_class".into(),
                    value: v.into(),
                });
            }
        })),
        "transform_kind" => Ok(P::TransformKindEq(match s().as_str() {
            "fragment" => RuleTransformKind::Fragment,
            "compress" => RuleTransformKind::Compress,
            "encrypt" => RuleTransformKind::Encrypt,
            "checksum" => RuleTransformKind::Checksum,
            "parity" => RuleTransformKind::Parity,
            v => {
                return Err(ParseError::InvalidValue {
                    field: "transform_kind".into(),
                    value: v.into(),
                });
            }
        })),
        "ruleset" => {
            let name = s();
            reject_empty_symbol("ruleset", &name)?;
            Ok(P::RulesetMember(name))
        }
        "consumer" => Ok(P::Consumer(parse_non_empty_string("consumer", val)?)),
        "dns_qtype" => Ok(P::DnsQtype(parse_non_empty_string("dns_qtype", val)?)),
        "authenticated_user" => {
            let value = parse_non_empty_string("authenticated_user", val)?;
            if value == "*" {
                Ok(P::AuthenticatedUserAny)
            } else {
                Ok(P::AuthenticatedUserEq(value))
            }
        }
        "dst_geo" => Ok(P::DstGeoEq(parse_non_empty_string("dst_geo", val)?)),
        "asn" => {
            if let Some(n) = val.as_u64() {
                if n > u32::MAX as u64 {
                    return Err(ParseError::InvalidValue {
                        field: "asn".into(),
                        value: n.to_string(),
                    });
                }
                return Ok(P::AsnEq(n as u32));
            }
            if let Some(seq) = val.as_sequence() {
                if seq.is_empty() {
                    return Err(ParseError::InvalidValue {
                        field: "asn".into(),
                        value: "empty".into(),
                    });
                }
                let mut out = Vec::with_capacity(seq.len());
                for v in seq {
                    let n = v.as_u64().ok_or_else(|| ParseError::InvalidValue {
                        field: "asn[]".into(),
                        value: format!("{v:?}"),
                    })?;
                    if n > u32::MAX as u64 {
                        return Err(ParseError::InvalidValue {
                            field: "asn[]".into(),
                            value: n.to_string(),
                        });
                    }
                    out.push(n as u32);
                }
                return Ok(P::AsnAny(out));
            }
            Err(ParseError::InvalidValue {
                field: "asn".into(),
                value: format!("{val:?}"),
            })
        }
        "geosite_tag" => Ok(P::GeositeTag(parse_non_empty_string("geosite_tag", val)?)),
        other => Err(ParseError::UnknownPredicateKey(other.into())),
    }
}

fn parse_non_empty_string(field: &str, value: &serde_yaml::Value) -> Result<String, ParseError> {
    let value = value.as_str().ok_or_else(|| ParseError::InvalidValue {
        field: field.into(),
        value: format!("{value:?}"),
    })?;
    reject_empty_symbol(field, value)?;
    Ok(value.to_string())
}

fn reject_empty_match_group(field: &str, values: &[serde_yaml::Value]) -> Result<(), ParseError> {
    if values.is_empty() {
        return Err(ParseError::InvalidValue {
            field: field.into(),
            value: "empty".into(),
        });
    }
    Ok(())
}

fn reject_empty_symbol(field: &str, value: &str) -> Result<(), ParseError> {
    if value.is_empty() {
        return Err(ParseError::InvalidValue {
            field: field.into(),
            value: "empty".into(),
        });
    }
    Ok(())
}

fn parse_action(v: &serde_yaml::Value) -> Result<Action, ParseError> {
    if let Some(s) = v.as_str() {
        return match s {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            other => Err(ParseError::UnknownAction(other.into())),
        };
    }
    let map = v
        .as_mapping()
        .ok_or_else(|| ParseError::UnknownAction("action must be string or mapping".into()))?;
    if map.len() != 1 {
        return Err(ParseError::UnknownAction(format!(
            "action mapping must have exactly one key, got {}",
            map.len()
        )));
    }
    let (k, vv) = map.iter().next().expect("len==1 guarantees a key");
    let key = k
        .as_str()
        .ok_or_else(|| ParseError::UnknownAction("action key must be a string".into()))?;
    match key {
        "allow" => {
            parse_empty_action_payload("allow", vv)?;
            Ok(Action::Allow)
        }
        "deny" => {
            parse_empty_action_payload("deny", vv)?;
            Ok(Action::Deny)
        }
        "set_route_group" => {
            let g = vv.as_str().ok_or_else(|| ParseError::InvalidValue {
                field: "set_route_group".into(),
                value: format!("{vv:?}"),
            })?;
            if g.is_empty() {
                return Err(ParseError::InvalidValue {
                    field: "set_route_group".into(),
                    value: "empty".into(),
                });
            }
            Ok(Action::SetRouteGroup(g.into()))
        }
        "set_resolver_pool" => {
            let p = vv.as_str().ok_or_else(|| ParseError::InvalidValue {
                field: "set_resolver_pool".into(),
                value: format!("{vv:?}"),
            })?;
            if p.is_empty() {
                return Err(ParseError::InvalidValue {
                    field: "set_resolver_pool".into(),
                    value: "empty".into(),
                });
            }
            Ok(Action::SetResolverPool(p.into()))
        }
        "set_schedule_hint" => Ok(Action::SetScheduleHint(parse_schedule_hint(vv)?)),
        "set_transform" => {
            let m = vv
                .as_mapping()
                .ok_or_else(|| ParseError::UnknownAction("set_transform must be mapping".into()))?;
            for key in m.keys() {
                let key = key.as_str().ok_or_else(|| {
                    ParseError::UnknownAction("set_transform keys must be strings".into())
                })?;
                if !matches!(key, "kind" | "params") {
                    return Err(ParseError::InvalidValue {
                        field: format!("set_transform.{key}"),
                        value: "unknown key".into(),
                    });
                }
            }
            let kind = m
                .get("kind")
                .and_then(|x| x.as_str())
                .ok_or_else(|| ParseError::UnknownAction("set_transform.kind missing".into()))?;
            let kind = match kind {
                "fragment" => RuleTransformKind::Fragment,
                "compress" => RuleTransformKind::Compress,
                "encrypt" => RuleTransformKind::Encrypt,
                "checksum" => RuleTransformKind::Checksum,
                "parity" => RuleTransformKind::Parity,
                v => {
                    return Err(ParseError::InvalidValue {
                        field: "transform.kind".into(),
                        value: v.into(),
                    });
                }
            };
            let params = match m.get("params") {
                None => serde_json::Value::Null,
                Some(params) => {
                    if !params.is_mapping() {
                        return Err(ParseError::InvalidValue {
                            field: "set_transform.params".into(),
                            value: format!("{params:?}"),
                        });
                    }
                    serde_json::to_value(params).map_err(|e| ParseError::InvalidValue {
                        field: "set_transform.params".into(),
                        value: e.to_string(),
                    })?
                }
            };
            Ok(Action::SetTransform(RuleTransformDescriptor {
                kind,
                params,
            }))
        }
        "compose" => {
            let seq = vv
                .as_sequence()
                .ok_or_else(|| ParseError::UnknownAction("compose must be sequence".into()))?;
            if seq.is_empty() {
                return Err(ParseError::InvalidValue {
                    field: "compose".into(),
                    value: "empty".into(),
                });
            }
            Ok(Action::Compose(
                seq.iter().map(parse_action).collect::<Result<_, _>>()?,
            ))
        }
        "set_cost_bias" => {
            let n = vv.as_i64().ok_or_else(|| ParseError::InvalidValue {
                field: "set_cost_bias".into(),
                value: format!("{vv:?}"),
            })?;
            if !(-9000..=9000).contains(&n) {
                return Err(ParseError::InvalidValue {
                    field: "set_cost_bias".into(),
                    value: n.to_string(),
                });
            }
            Ok(Action::SetCostBias(n as i32))
        }
        other => Err(ParseError::UnknownAction(other.into())),
    }
}

fn parse_empty_action_payload(field: &str, value: &serde_yaml::Value) -> Result<(), ParseError> {
    let map = value.as_mapping().ok_or_else(|| ParseError::InvalidValue {
        field: field.into(),
        value: format!("{value:?}"),
    })?;
    if !map.is_empty() {
        return Err(ParseError::InvalidValue {
            field: field.into(),
            value: "non-empty payload".into(),
        });
    }
    Ok(())
}

fn parse_schedule_hint(v: &serde_yaml::Value) -> Result<RuleScheduleHint, ParseError> {
    if v.as_str() == Some("auto") {
        return Ok(RuleScheduleHint::Auto);
    }
    let map = v
        .as_mapping()
        .ok_or_else(|| ParseError::UnknownAction("schedule_hint shape".into()))?;
    for key in map.keys() {
        let key = key.as_str().ok_or_else(|| {
            ParseError::UnknownAction("schedule_hint keys must be strings".into())
        })?;
        if key != "fanout" {
            return Err(ParseError::InvalidValue {
                field: format!("schedule_hint.{key}"),
                value: "unknown key".into(),
            });
        }
    }
    if let Some(fanout) = map.get("fanout") {
        let fanout_map = fanout
            .as_mapping()
            .ok_or_else(|| ParseError::InvalidValue {
                field: "fanout".into(),
                value: format!("{fanout:?}"),
            })?;
        for key in fanout_map.keys() {
            let key = key
                .as_str()
                .ok_or_else(|| ParseError::UnknownAction("fanout keys must be strings".into()))?;
            if key != "k" {
                return Err(ParseError::InvalidValue {
                    field: format!("fanout.{key}"),
                    value: "unknown key".into(),
                });
            }
        }
        let k_u64 = fanout_map
            .get("k")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| ParseError::InvalidValue {
                field: "fanout.k".into(),
                value: "missing".into(),
            })?;
        if k_u64 == 0 || k_u64 > u32::MAX as u64 {
            return Err(ParseError::InvalidValue {
                field: "fanout.k".into(),
                value: k_u64.to_string(),
            });
        }
        return Ok(RuleScheduleHint::FanOut {
            fanout: FanOutParams { k: k_u64 as u32 },
        });
    }
    Err(ParseError::UnknownAction("unknown schedule_hint".into()))
}
