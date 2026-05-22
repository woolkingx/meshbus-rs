#[test]
fn scheduler_schema_is_closed_and_constrains_weight_keys() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "load-balance scheduler schema root must reject unknown fields"
    );
    assert!(
        schema.contains(r#""enum": ["round-robin", "sticky-sessions", "consistent-hashing"]"#),
        "load-balance schema must keep the public mode vocabulary explicit"
    );
    assert!(
        schema.contains(r#""propertyNames": { "pattern": "^[A-Za-z0-9_.:-]+$" }"#),
        "load-balance weights keys must stay aligned with ExitId/SinkId shape"
    );
}
