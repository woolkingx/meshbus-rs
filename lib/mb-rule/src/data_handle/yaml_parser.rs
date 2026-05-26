//! YAML parser for rule chains and rulesets.

use crate::types::*;

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
