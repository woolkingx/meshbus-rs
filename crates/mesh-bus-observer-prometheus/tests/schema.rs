#[test]
fn observer_schema_closes_modes_and_constrains_static_label_names() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "Prometheus observer variants must reject unknown fields"
    );
    assert!(
        schema.contains(r#""propertyNames": { "pattern": "^[A-Za-z_][A-Za-z0-9_]*$" }"#),
        "Prometheus static label keys must be valid Prometheus label names"
    );
}
