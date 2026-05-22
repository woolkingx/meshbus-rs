#[test]
fn observer_schema_is_closed_because_it_has_no_runtime_config() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains("No runtime config"),
        "counter observer schema must document the no-runtime-config contract"
    );
    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "counter observer schema root must reject unknown runtime config fields"
    );
}
