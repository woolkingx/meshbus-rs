use serde_json::Value;

fn schema() -> Value {
    serde_json::from_str(include_str!("../schema.json")).expect("schema parses as JSON")
}

#[test]
fn source_lease_activity_schema_names_only_two_legal_shapes() {
    let schema = schema();
    let variants = schema["$defs"]["SourceLeaseActivity"]["oneOf"]
        .as_array()
        .expect("SourceLeaseActivity oneOf variants");

    assert_eq!(variants.len(), 2);
    assert_eq!(variants[0]["title"], "active-source");
    assert_eq!(variants[0]["required"], serde_json::json!(["active_flows"]));
    assert_eq!(
        variants[0]["properties"]["active_flows"]["minimum"],
        serde_json::json!(1)
    );
    assert_eq!(variants[0]["additionalProperties"], false);

    assert_eq!(variants[1]["title"], "idle-source");
    assert_eq!(
        variants[1]["required"],
        serde_json::json!(["active_flows", "idle_since_ms"])
    );
    assert_eq!(
        variants[1]["properties"]["active_flows"]["const"],
        serde_json::json!(0)
    );
    assert_eq!(
        variants[1]["properties"]["idle_since_ms"]["minimum"],
        serde_json::json!(0)
    );
    assert_eq!(variants[1]["additionalProperties"], false);
}

#[test]
fn candidate_and_source_lease_decision_schema_are_closed() {
    let schema = schema();

    assert_eq!(
        schema["$defs"]["Candidate"]["required"],
        serde_json::json!(["id", "weight"])
    );
    assert_eq!(
        schema["$defs"]["Candidate"]["properties"]["weight"]["minimum"],
        serde_json::json!(1)
    );
    assert_eq!(schema["$defs"]["Candidate"]["additionalProperties"], false);

    assert_eq!(
        schema["$defs"]["SourceLeaseDecision"]["required"],
        serde_json::json!(["candidate_id", "reason", "generation"])
    );
    assert_eq!(
        schema["$defs"]["SourceLeaseReason"]["enum"],
        serde_json::json!([
            "new",
            "hit",
            "idle-expired",
            "max-age-soft",
            "max-age-hard",
            "unhealthy"
        ])
    );
    assert_eq!(
        schema["$defs"]["SourceLeaseDecision"]["additionalProperties"],
        false
    );
}
