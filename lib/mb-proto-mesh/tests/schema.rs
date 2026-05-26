use serde_json::Value;

fn schema() -> Value {
    serde_json::from_str(include_str!("../schema.json")).expect("schema parses as JSON")
}

#[test]
fn path_controller_projection_names_mesh_control_state() {
    let schema = schema();
    let controller = &schema["properties"]["path_controller_v1"];

    assert_eq!(
        controller["properties"]["owner_layer"]["const"],
        "L5/L4-control"
    );
    assert_eq!(
        controller["required"],
        serde_json::json!([
            "owner_layer",
            "path_id",
            "cwnd_bytes",
            "bytes_in_flight",
            "send_budget_bytes",
            "srtt",
            "rttvar",
            "pto_count",
            "inflight_packages"
        ])
    );
    assert_eq!(controller["additionalProperties"], false);
}

#[test]
fn mesh_packetizer_projection_splits_control_and_data() {
    let schema = schema();
    let packetizer = &schema["properties"]["mesh_packetizer_v1"];

    assert_eq!(
        packetizer["properties"]["owner_layer"]["const"],
        "L5/L4-sender"
    );
    assert_eq!(
        packetizer["properties"]["control_flush_max_delay_us"]["const"],
        0
    );
    assert_eq!(
        packetizer["properties"]["data_budget_source"]["const"],
        "path_controller_v1"
    );
    assert_eq!(
        packetizer["properties"]["socket_owner"]["const"],
        "UdpPacketLoop"
    );
    assert_eq!(packetizer["additionalProperties"], false);
}
