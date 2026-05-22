#[test]
fn scheduler_schema_is_closed_and_metadata_only() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "CAKE scheduler schema root must reject runtime config fields"
    );
    assert!(
        schema.contains("metadata-only"),
        "CAKE scheduler schema must document metadata-only scheduling"
    );
    assert!(
        !schema.contains("protocol-aware policy"),
        "CAKE scheduler schema must not describe protocol-aware routing policy"
    );
}
