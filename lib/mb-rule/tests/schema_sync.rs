//! Schema-sync guard: every public Rust type that the spec lists has a JSON Schema entry.
//! Walks schema/*.schema.json and asserts every `definitions` key plus root `title`
//! resolves to a token present in src/types.rs.

use std::fs;
use std::path::PathBuf;

fn schema_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("schema")
}
fn types_text() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("types.rs"),
    )
    .expect("read types.rs failed")
}

#[test]
fn every_schema_type_exists_in_types_rs() {
    let types = types_text();
    let mut required = Vec::new();
    for e in fs::read_dir(schema_dir())
        .expect("read_dir schema failed")
        .flatten()
    {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read schema file failed"))
                .expect("parse schema json failed");
        if let Some(t) = v.get("title").and_then(|x| x.as_str()) {
            required.push(t.to_string());
        }
        if let Some(defs) = v.get("definitions").and_then(|x| x.as_object()) {
            for k in defs.keys() {
                required.push(k.clone());
            }
        }
    }
    let mut missing = Vec::new();
    for name in required {
        // crude word-boundary check — token must appear after a non-ident char or BOF
        let pattern_a = format!(" {name}");
        let pattern_b = format!("\t{name}");
        let pattern_c = format!("\n{name}");
        if !types.contains(&pattern_a) && !types.contains(&pattern_b) && !types.contains(&pattern_c)
        {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "schema definitions missing in types.rs: {missing:?}"
    );
}

#[test]
fn action_object_variants_are_closed() {
    let path = schema_dir().join("action.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read action schema failed"))
            .expect("parse action schema failed");
    let variants = v
        .get("oneOf")
        .and_then(|x| x.as_array())
        .expect("Action schema oneOf must be an array");
    let mut open = Vec::new();
    for variant in variants {
        if variant.get("type").and_then(|x| x.as_str()) != Some("object") {
            continue;
        }
        let name = variant
            .get("required")
            .and_then(|x| x.as_array())
            .and_then(|items| items.first())
            .and_then(|x| x.as_str())
            .unwrap_or("<unknown>");
        if variant
            .get("additionalProperties")
            .and_then(|x| x.as_bool())
            != Some(false)
        {
            open.push(name.to_string());
        }
    }
    assert!(
        open.is_empty(),
        "Action object variants must be closed to match parser exact-one-key contract: {open:?}"
    );
}

#[test]
fn set_transform_descriptor_is_closed() {
    let path = schema_dir().join("action.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read action schema failed"))
            .expect("parse action schema failed");
    let descriptor = v
        .get("definitions")
        .and_then(|x| x.get("RuleTransformDescriptor"))
        .expect("RuleTransformDescriptor schema must exist");
    assert_eq!(
        descriptor
            .get("additionalProperties")
            .and_then(|x| x.as_bool()),
        Some(false),
        "RuleTransformDescriptor must be closed so parser and schema reject ignored transform fields"
    );
}

#[test]
fn match_expr_operator_variants_are_closed() {
    let path = schema_dir().join("rule_chain.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read rule_chain schema failed"))
            .expect("parse rule_chain schema failed");
    let variants = v
        .get("definitions")
        .and_then(|x| x.get("MatchExpr"))
        .and_then(|x| x.get("oneOf"))
        .and_then(|x| x.as_array())
        .expect("MatchExpr.oneOf must be an array");
    let mut open = Vec::new();
    for variant in variants {
        if variant.get("$ref").is_some() {
            continue;
        }
        let name = variant
            .get("required")
            .and_then(|x| x.as_array())
            .and_then(|items| items.first())
            .and_then(|x| x.as_str())
            .unwrap_or("<unknown>");
        if variant
            .get("additionalProperties")
            .and_then(|x| x.as_bool())
            != Some(false)
        {
            open.push(name.to_string());
        }
    }
    assert!(
        open.is_empty(),
        "MatchExpr operator variants must be closed to match parser control-key behavior: {open:?}"
    );
}

#[test]
fn fanout_params_schema_is_closed() {
    let path = schema_dir().join("rule_ctx.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read rule_ctx schema failed"))
            .expect("parse rule_ctx schema failed");
    let variants = v
        .get("definitions")
        .and_then(|x| x.get("RuleScheduleHint"))
        .and_then(|x| x.get("oneOf"))
        .and_then(|x| x.as_array())
        .expect("RuleScheduleHint.oneOf must be an array");
    let fanout = variants
        .iter()
        .find_map(|variant| {
            variant
                .get("properties")
                .and_then(|x| x.get("fanout"))
                .filter(|_| {
                    variant
                        .get("required")
                        .and_then(|x| x.as_array())
                        .is_some_and(|items| {
                            items.iter().any(|item| item.as_str() == Some("fanout"))
                        })
                })
        })
        .expect("RuleScheduleHint fanout variant must exist");
    assert_eq!(
        fanout.get("additionalProperties").and_then(|x| x.as_bool()),
        Some(false),
        "FanOutParams schema must be closed so parser and schema reject ignored fanout fields"
    );
}

#[test]
fn action_schema_dto_payloads_are_non_nullable() {
    let path = schema_dir().join("action.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read action schema failed"))
            .expect("parse action schema failed");
    let defs = v
        .get("definitions")
        .and_then(|x| x.as_object())
        .expect("action schema definitions must be an object");
    let transform_kind = defs
        .get("RuleTransformKind")
        .expect("action schema must define non-null RuleTransformKind");
    assert!(
        !schema_node_allows_null(transform_kind),
        "Action RuleTransformDescriptor.kind must not accept null"
    );
    let schedule_hint = defs
        .get("RuleScheduleHint")
        .expect("action schema must define non-null RuleScheduleHint");
    assert!(
        !schema_node_allows_null(schedule_hint),
        "Action SetScheduleHint payload must not accept null"
    );
}

#[test]
fn explicit_term_schema_is_closed_to_known_predicates() {
    let path = schema_dir().join("rule_chain.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read rule_chain schema failed"))
            .expect("parse rule_chain schema failed");
    let term = v
        .get("definitions")
        .and_then(|x| x.get("Term"))
        .expect("Term schema must exist");
    assert_eq!(
        term.get("additionalProperties").and_then(|x| x.as_bool()),
        Some(false),
        "explicit MatchExpr Term schema must reject unknown predicate keys"
    );
    let properties = term
        .get("properties")
        .and_then(|x| x.as_object())
        .expect("Term schema must list parser-supported predicate keys");
    let expected = [
        "src_cidr",
        "dst_cidr",
        "src_ip",
        "dst_ip",
        "dst_port",
        "dst_port_range",
        "network",
        "session_shape",
        "operation",
        "socks5_command",
        "hostname",
        "hostname_suffix",
        "hostname_keyword",
        "hostname_regex",
        "fragment_group",
        "traffic_class",
        "transform_kind",
        "consumer",
        "dns_qtype",
        "authenticated_user",
        "dst_geo",
        "asn",
        "geosite_tag",
    ];
    let missing: Vec<_> = expected
        .iter()
        .filter(|key| !properties.contains_key(**key))
        .collect();
    assert!(
        missing.is_empty(),
        "Term schema missing parser-supported predicate keys: {missing:?}"
    );
}

#[test]
fn socks5_command_schema_is_legacy_compatibility_not_extension_pattern() {
    let rule_ctx_path = schema_dir().join("rule_ctx.schema.json");
    let rule_ctx: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&rule_ctx_path).expect("read rule_ctx schema failed"),
    )
    .expect("parse rule_ctx schema failed");
    let ctx_command = rule_ctx
        .pointer("/properties/socks5_command")
        .and_then(|x| x.get("description"))
        .and_then(|x| x.as_str())
        .expect("RuleCtx.socks5_command must have a boundary description");
    assert!(
        ctx_command.contains("legacy compatibility")
            && ctx_command.contains("operation")
            && ctx_command.contains("future adapters"),
        "RuleCtx.socks5_command must point future adapters at operation"
    );

    let rule_chain_path = schema_dir().join("rule_chain.schema.json");
    let rule_chain: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&rule_chain_path).expect("read rule_chain schema failed"),
    )
    .expect("parse rule_chain schema failed");
    let term_command = rule_chain
        .pointer("/definitions/Term/properties/socks5_command")
        .and_then(|x| x.get("description"))
        .and_then(|x| x.as_str())
        .expect("Term.socks5_command must have a boundary description");
    assert!(
        term_command.contains("legacy compatibility")
            && term_command.contains("operation")
            && term_command.contains("future adapters"),
        "Term.socks5_command must point future adapters at operation"
    );
}

#[test]
fn operation_schema_examples_use_generic_source_actions() {
    let rule_ctx_path = schema_dir().join("rule_ctx.schema.json");
    let rule_ctx: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&rule_ctx_path).expect("read rule_ctx schema failed"),
    )
    .expect("parse rule_ctx schema failed");
    let operation = rule_ctx
        .pointer("/properties/operation/description")
        .and_then(|x| x.as_str())
        .expect("RuleCtx.operation must have a boundary description");

    assert!(
        operation.contains("datagram_associate") && operation.contains("datagram_send"),
        "RuleCtx.operation examples must include generic datagram action names"
    );
    assert!(
        !operation.contains("udp_associate"),
        "RuleCtx.operation examples must not teach SOCKS5 command names as generic operations"
    );
}

#[test]
fn rule_schema_property_names_are_closed_to_known_keys() {
    let path = schema_dir().join("rule_chain.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read rule_chain schema failed"))
            .expect("parse rule_chain schema failed");
    let rule = v
        .get("definitions")
        .and_then(|x| x.get("Rule"))
        .expect("Rule schema must exist");
    let names = rule
        .get("propertyNames")
        .and_then(|x| x.get("enum"))
        .and_then(|x| x.as_array())
        .expect("Rule schema must close property names with enum");
    let mut names: Vec<_> = names.iter().filter_map(|x| x.as_str()).collect();
    names.sort_unstable();
    let mut expected = vec![
        "action",
        "id",
        "match",
        "src_cidr",
        "dst_cidr",
        "src_ip",
        "dst_ip",
        "dst_port",
        "dst_port_range",
        "network",
        "session_shape",
        "operation",
        "socks5_command",
        "hostname",
        "hostname_suffix",
        "hostname_keyword",
        "hostname_regex",
        "fragment_group",
        "traffic_class",
        "transform_kind",
        "ruleset",
        "consumer",
        "dns_qtype",
        "authenticated_user",
        "dst_geo",
        "asn",
        "geosite_tag",
    ];
    expected.sort_unstable();
    assert_eq!(
        names, expected,
        "Rule schema property names must match parser-supported flat rule keys"
    );
}

#[test]
fn rule_schema_requires_match_xor_flat_predicate() {
    let path = schema_dir().join("rule_chain.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read rule_chain schema failed"))
            .expect("parse rule_chain schema failed");
    let rule = v
        .get("definitions")
        .and_then(|x| x.get("Rule"))
        .expect("Rule schema must exist");
    let variants = rule
        .get("oneOf")
        .and_then(|x| x.as_array())
        .expect("Rule schema must enforce match xor flat predicates with oneOf");
    assert_eq!(
        variants.len(),
        2,
        "Rule schema oneOf must contain explicit-match and flat-predicate variants"
    );
    assert!(
        variants
            .iter()
            .any(|variant| required_contains(variant, "match")),
        "Rule schema must have an explicit-match variant"
    );
    let flat = variants
        .iter()
        .find(|variant| !required_contains(variant, "match"))
        .expect("Rule schema must have a flat-predicate variant");
    let required_keys: Vec<_> = flat
        .get("anyOf")
        .and_then(|x| x.as_array())
        .expect("flat Rule variant must require at least one predicate key")
        .iter()
        .filter_map(|item| {
            item.get("required")
                .and_then(|x| x.as_array())
                .and_then(|items| items.first())
                .and_then(|x| x.as_str())
        })
        .collect();
    for key in parser_predicate_keys() {
        assert!(
            required_keys.contains(key),
            "flat Rule variant must accept `{key}` as a predicate key"
        );
    }
}

#[test]
fn rule_flat_predicate_values_reuse_term_schemas() {
    let path = schema_dir().join("rule_chain.schema.json");
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read rule_chain schema failed"))
            .expect("parse rule_chain schema failed");
    let rule = v
        .get("definitions")
        .and_then(|x| x.get("Rule"))
        .expect("Rule schema must exist");
    assert_eq!(
        rule.get("additionalProperties").and_then(|x| x.as_bool()),
        Some(false),
        "Rule schema must close additional properties once flat predicate properties are listed"
    );
    let properties = rule
        .get("properties")
        .and_then(|x| x.as_object())
        .expect("Rule schema must list properties");
    for key in parser_predicate_keys() {
        let expected_ref = format!("#/definitions/Term/properties/{key}");
        assert_eq!(
            properties
                .get(*key)
                .and_then(|x| x.get("$ref"))
                .and_then(|x| x.as_str()),
            Some(expected_ref.as_str()),
            "Rule flat predicate `{key}` must reuse the explicit Term schema"
        );
    }
}

fn required_contains(node: &serde_json::Value, key: &str) -> bool {
    node.get("required")
        .and_then(|x| x.as_array())
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(key)))
}

fn parser_predicate_keys() -> &'static [&'static str] {
    &[
        "src_cidr",
        "dst_cidr",
        "src_ip",
        "dst_ip",
        "dst_port",
        "dst_port_range",
        "network",
        "session_shape",
        "operation",
        "socks5_command",
        "hostname",
        "hostname_suffix",
        "hostname_keyword",
        "hostname_regex",
        "fragment_group",
        "traffic_class",
        "transform_kind",
        "ruleset",
        "consumer",
        "dns_qtype",
        "authenticated_user",
        "dst_geo",
        "asn",
        "geosite_tag",
    ]
}

fn schema_node_allows_null(node: &serde_json::Value) -> bool {
    if node.get("type").and_then(|x| x.as_str()) == Some("null") {
        return true;
    }
    if node
        .get("type")
        .and_then(|x| x.as_array())
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("null")))
    {
        return true;
    }
    if node
        .get("enum")
        .and_then(|x| x.as_array())
        .is_some_and(|items| items.iter().any(|item| item.is_null()))
    {
        return true;
    }
    for key in ["oneOf", "anyOf"] {
        if node
            .get(key)
            .and_then(|x| x.as_array())
            .is_some_and(|items| items.iter().any(schema_node_allows_null))
        {
            return true;
        }
    }
    false
}
