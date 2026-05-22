#[test]
fn scheduler_schema_is_closed_and_generic_candidate_fanout() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "replicate scheduler schema root must reject unknown fields"
    );
    assert!(
        schema.contains("all candidate egresses"),
        "replicate scheduler schema must document candidate fan-out"
    );
    assert!(
        schema.contains("metadata-only"),
        "replicate scheduler schema must document metadata-only scheduling"
    );
    assert!(
        !schema.contains("one packet"),
        "replicate scheduler schema must not narrow the primitive to packet/datagram wording"
    );
}
