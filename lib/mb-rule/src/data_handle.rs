use crate::types::*;

mod yaml_parser;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
pub use yaml_parser::{ParseError, parse_chain_and_rulesets_yaml, parse_chain_yaml};

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
