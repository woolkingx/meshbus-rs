#[test]
fn schema_crate_index_is_closed_and_points_to_workspace_authority() {
    let schema = include_str!("../schema.json");

    assert!(
        schema.contains("../../schemas/*.schema.json"),
        "mesh-bus-schema index must point at workspace schemas as the source of truth"
    );
    assert!(
        schema.contains(r#""additionalProperties": false"#),
        "mesh-bus-schema index must not accept runtime config or local shape extensions"
    );
}

#[test]
fn bus_event_variants_are_closed_observability_contracts() {
    let schema = include_str!("../../../schemas/bus-event.schema.json");

    for variant in ["SessionOpened", "SessionClosed", "Core"] {
        let marker = format!(r#""kind": {{ "const": "{variant}" }}"#);
        let start = schema
            .find(&marker)
            .unwrap_or_else(|| panic!("missing BusEvent variant {variant}"));
        let tail = &schema[start..];
        let next_variant = tail[marker.len()..]
            .find(r#""kind": { "const": "#)
            .map(|idx| marker.len() + idx)
            .unwrap_or(tail.len());
        let block = &tail[..next_variant];
        assert!(
            block.contains(r#""additionalProperties": false"#),
            "BusEvent variant {variant} must reject unknown observer payload fields"
        );
    }
}

#[test]
fn exit_id_schema_matches_kernel_sink_id_shape() {
    let exit_id_schema = include_str!("../../../schemas/exit-id.schema.json");
    let kernel_verdict_schema = include_str!("../../mesh-bus-core/src/kernel/verdict/schema.json");
    let expected = r#""pattern": "^[A-Za-z0-9_.:-]+$""#;

    assert!(
        kernel_verdict_schema.contains(expected),
        "kernel SinkId/SourceId schema must expose the shared id-shape contract"
    );
    assert!(
        exit_id_schema.contains(expected),
        "workspace ExitId schema must match the kernel SinkId id-shape contract"
    );
}

#[test]
fn health_policy_schema_matches_runtime_minimums() {
    let health_schema = include_str!("../../../schemas/health-policy.schema.json");
    let runtime_schema = include_str!("../../mesh-bus-runtime/schema.json");

    for field in ["failure_threshold", "recovery_window_ms", "probe_after_ms"] {
        let health_field = schema_field_block(health_schema, field);
        let runtime_field = schema_field_block(runtime_schema, field);
        assert!(
            health_field.contains(r#""minimum": 1"#),
            "workspace HealthPolicy field {field} must reject zero"
        );
        assert!(
            runtime_field.contains(r#""minimum": 1"#),
            "runtime health field {field} must reject zero"
        );
    }
}

#[test]
fn flow_semantics_schema_wording_is_l4_metadata_not_protocol_level() {
    for (label, schema) in [
        (
            "workspace frame",
            include_str!("../../../schemas/frame.schema.json"),
        ),
        (
            "mesh-bus-core",
            include_str!("../../mesh-bus-core/schema.json"),
        ),
        (
            "mesh-bus-core forwarding",
            include_str!("../../mesh-bus-core/src/transport/forwarding/schema.json"),
        ),
    ] {
        assert!(
            !schema.contains("Protocol-level flow semantics")
                && !schema.contains("protocol-level flow semantics"),
            "{label} schema must not describe flow_semantics as protocol-level"
        );
        assert!(
            schema.contains("L4") && schema.contains("generic"),
            "{label} schema must describe flow_semantics as generic L4 metadata"
        );
    }
}

#[test]
fn protocol_fields_are_opaque_adapter_labels_not_parser_inputs() {
    for (label, schema) in [
        (
            "workspace capability",
            include_str!("../../../schemas/capability.schema.json"),
        ),
        (
            "workspace exit snapshot",
            include_str!("../../../schemas/exit-snapshot.schema.json"),
        ),
    ] {
        let block = schema_field_block(schema, "protocol");
        assert!(
            block.contains("opaque adapter protocol label"),
            "{label} protocol field must be documented as an opaque adapter label"
        );
        assert!(
            block.contains("not a protocol parser") && block.contains("dispatch branch"),
            "{label} protocol field must not be a parser or dispatch branch contract"
        );
    }
}

fn schema_field_block<'a>(schema: &'a str, field: &str) -> &'a str {
    let marker = format!(r#""{field}":"#);
    let marker_with_space = format!(r#""{field}": "#);
    let start = schema
        .find(&marker)
        .or_else(|| schema.find(&marker_with_space))
        .unwrap_or_else(|| panic!("missing schema field {field}"));
    let tail = &schema[start..];
    let next = tail[marker_with_space.len()..]
        .find("\n    }")
        .map(|idx| marker_with_space.len() + idx)
        .unwrap_or(tail.len());
    &tail[..next]
}
