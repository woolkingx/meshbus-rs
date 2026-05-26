use super::*;

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "serde_json::json! macro expands to unwrap"
)]
fn runtime_schema_exposes_current_operator_surface() {
    let schema: Value = serde_json::from_str(include_str!("../../schema.json"))
        .expect("runtime schema is valid json");

    assert_eq!(schema["x-schema-version"], "draft-08");
    assert_eq!(
        schema["properties"]["ingresses"]["minItems"], 1,
        "schema must reject the same empty ingress list as validate_config"
    );
    assert_eq!(
        schema["properties"]["egresses"]["minItems"], 1,
        "schema must reject the same empty egress list as validate_config"
    );

    assert!(
        schema["properties"]["pipeline"]["properties"]["rule_chain_path"].is_object(),
        "schema must expose top-level pipeline.rule_chain_path"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["geoip"]["properties"]["country_path"]
            .is_object(),
        "schema must expose pipeline.geoip.country_path"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["geoip"]["required"],
        serde_json::json!(["country_path", "asn_path"]),
        "schema must require complete GeoIP DB paths when geoip is configured"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["geosite"]["required"],
        serde_json::json!(["path"]),
        "schema must require geosite.path when geosite is configured"
    );
    for key in [
        "rule_chain_forward",
        "rule_chain_resolver",
        "geosite",
        "dns_cache",
        "source",
    ] {
        assert!(
            schema["properties"]["pipeline"]["properties"][key].is_object(),
            "schema must expose pipeline.{key}"
        );
    }
    for (field, value) in [
        (
            "rule_chain_path",
            &schema["properties"]["pipeline"]["properties"]["rule_chain_path"],
        ),
        (
            "rule_chain_forward",
            &schema["properties"]["pipeline"]["properties"]["rule_chain_forward"],
        ),
        (
            "rule_chain_resolver",
            &schema["properties"]["pipeline"]["properties"]["rule_chain_resolver"],
        ),
        (
            "geoip.country_path",
            &schema["properties"]["pipeline"]["properties"]["geoip"]["properties"]["country_path"],
        ),
        (
            "geoip.asn_path",
            &schema["properties"]["pipeline"]["properties"]["geoip"]["properties"]["asn_path"],
        ),
        (
            "geosite.path",
            &schema["properties"]["pipeline"]["properties"]["geosite"]["properties"]["path"],
        ),
    ] {
        assert!(
            value["description"]
                .as_str()
                .is_some_and(|description| description.contains("config file directory")),
            "schema must document that pipeline.{field} resolves relative to config file directory"
        );
    }
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["initial_writes"]
            .is_object(),
        "schema must expose pipeline.source.initial_writes"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["kind"]["const"],
        "application/source"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["kind"]
            ["description"]
            .as_str()
            .is_some_and(|description| description.contains("protocol-neutral")
                && description.contains("HTTP")
                && description.contains("HTTPS")),
        "schema must document that pipeline.source.kind stays generic across future adapters"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["id"]["pattern"],
        "^[A-Za-z0-9_.:-]+$",
        "schema must keep pipeline.source.id aligned with core SourceId"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["id"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("opaque SourceId")
                && description.contains("validates only SourceId shape")
                && description.contains("never interprets adapter protocol names")),
        "schema must document that pipeline.source.id is opaque instance identity"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["id"]["not"]
            .is_null(),
        "schema must not inspect protocol tokens inside opaque pipeline.source.id values"
    );
    assert_eq!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]["initial_writes"]["items"]
            ["pattern"],
        "^(net|transport|policy|auth|trace|ext)\\.[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)*$"
    );
    assert!(
        schema["properties"]["pipeline"]["properties"]["source"]["properties"]
            ["initial_writes"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("HookSpec.reads")
                && description.contains("kernel_registry_verify")),
        "schema must document that pipeline.source.initial_writes is verified against hook reads"
    );
    assert_eq!(
        schema["properties"]["logging"]["properties"]["level"]["enum"],
        serde_json::json!(["trace", "debug", "info", "warn", "error"])
    );
    for idx in 0..2 {
        assert_eq!(
            schema["properties"]["metrics"]["oneOf"][idx]["properties"]["labels"]["propertyNames"]
                ["pattern"],
            "^[A-Za-z_][A-Za-z0-9_]*$",
            "schema metrics labels must stay valid Prometheus label names for oneOf[{idx}]"
        );
    }
    assert_eq!(
        schema["properties"]["operator"]["oneOf"][0]["properties"]["kind"]["const"],
        "LocalHttp"
    );
    assert_eq!(
        schema["properties"]["operator"]["oneOf"][0]["properties"]["listen"]["minLength"],
        1
    );
    assert!(
        schema["properties"]["operator"]["oneOf"][0]["properties"]["listen"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("Loopback")),
        "schema must document operator LocalHttp loopback boundary"
    );

    let socks5 = &schema["properties"]["ingresses"]["items"]["oneOf"][0]["properties"];
    for key in [
        "rule_chain_path",
        "auth",
        "handshake_timeout_ms",
        "accept_backoff_ms",
        "max_connections",
        "udp_forward_concurrency",
        "socket_recv_buffer_bytes",
        "socket_send_buffer_bytes",
    ] {
        assert!(
            socks5[key].is_object(),
            "schema must expose Socks5 ingress field {key}"
        );
    }
    assert_eq!(socks5["listen"]["minLength"], 1);
    assert!(
        socks5["rule_chain_path"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("config file directory")
                && description.contains("BusSessionRequest")),
        "schema must document that legacy ingress.rule_chain_path resolves relative to config file directory and is adapter projection gated"
    );

    let tcp_ingress = &schema["properties"]["ingresses"]["items"]["oneOf"][1]["properties"];
    assert_eq!(tcp_ingress["listen"]["minLength"], 1);
    assert_eq!(tcp_ingress["target"]["minLength"], 1);
    assert_eq!(tcp_ingress["socket_recv_buffer_bytes"]["minimum"], 1);
    assert_eq!(tcp_ingress["socket_send_buffer_bytes"]["minimum"], 1);

    let udp_ingress = &schema["properties"]["ingresses"]["items"]["oneOf"][2]["properties"];
    assert_eq!(udp_ingress["listen"]["minLength"], 1);
    assert_eq!(udp_ingress["target"]["minLength"], 1);
    assert_eq!(udp_ingress["socket_recv_buffer_bytes"]["minimum"], 1);
    assert_eq!(udp_ingress["socket_send_buffer_bytes"]["minimum"], 1);

    let http_connect_ingress = schema["properties"]["ingresses"]["items"]["oneOf"]
        .as_array()
        .expect("ingress oneOf array")
        .iter()
        .find(|variant| variant["properties"]["kind"]["const"] == "HttpConnect")
        .expect("HttpConnect ingress schema variant");
    let http_connect = &http_connect_ingress["properties"];
    assert_eq!(http_connect["listen"]["minLength"], 1);
    assert_eq!(http_connect["max_header_bytes"]["minimum"], 1);
    assert_eq!(http_connect["max_connections"]["minimum"], 1);
    assert_eq!(
        http_connect["auth"]["properties"]["users"]["items"]["properties"]["name"]["minLength"],
        1
    );
    assert_eq!(
        http_connect["auth"]["properties"]["users"]["items"]["properties"]["password"]["minLength"],
        1
    );

    let socks5_egress = &schema["properties"]["egresses"]["items"]["oneOf"][1]["properties"];
    assert_eq!(socks5_egress["upstream"]["minLength"], 1);

    let socks5_udp_egress = &schema["properties"]["egresses"]["items"]["oneOf"][2]["properties"];
    assert_eq!(socks5_udp_egress["kind"]["const"], "Socks5Udp");
    assert_eq!(socks5_udp_egress["upstream"]["minLength"], 1);
    assert_eq!(
        socks5_udp_egress["auth"]["properties"]["username"]["minLength"],
        1
    );
    assert_eq!(
        socks5_udp_egress["auth"]["properties"]["password"]["minLength"],
        1
    );

    assert_eq!(
        schema["properties"]["node"]["properties"]["id"]["pattern"],
        "^[A-Za-z0-9_.:-]+$"
    );
    assert_eq!(
        schema["properties"]["peers"]["items"]["properties"]["id"]["pattern"],
        "^[A-Za-z0-9_.:-]+$"
    );
    assert_eq!(
        schema["properties"]["ingresses"]["items"]["oneOf"][3]["properties"]["kind"]["const"],
        "MeshPeerUdp"
    );
    assert!(
        schema["properties"]["ingresses"]["items"]["oneOf"][3]["properties"]["listen"]
            ["description"]
            .as_str()
            .is_some_and(|description| description.contains("MeshSec")
                && description.contains("Non-loopback")
                && description.contains("loopback")),
        "schema must document MeshPeerUdp WAN MeshSec and loopback debug-clear boundaries"
    );

    for idx in 0..6 {
        let egress = &schema["properties"]["egresses"]["items"]["oneOf"][idx]["properties"];
        assert!(
            egress["groups"].is_object(),
            "schema must expose egress groups for oneOf[{idx}]"
        );
        assert_eq!(
            egress["id"]["pattern"], "^[A-Za-z0-9_.:-]+$",
            "schema egress id must stay aligned with SinkId for oneOf[{idx}]"
        );
        assert!(
            egress["id"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("SinkId")
                    && description.contains("may_accept_to")
                    && description.contains("pick_sink")),
            "schema egress id must document SinkId / pick_sink projection for oneOf[{idx}]"
        );
        assert_eq!(egress["wan_id"]["minLength"], 1);
        assert!(
            egress["wan_id"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("observability")
                    && description.contains("label")),
            "schema egress wan_id must document observability-label semantics for oneOf[{idx}]"
        );
        assert_eq!(egress["groups"]["items"]["minLength"], 1);
        assert!(
            egress["groups"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("route-group")
                    && description.contains("candidate")),
            "schema egress groups must document route-group candidate-label semantics for oneOf[{idx}]"
        );
        assert!(
            egress["priority"]["description"]
                .as_str()
                .is_some_and(|description| description.contains("LoadBalance")
                    && description.contains("weight")),
            "schema egress priority must document load-balance weight semantics for oneOf[{idx}]"
        );
        if matches!(idx, 0 | 3 | 6) {
            assert_eq!(egress["socket_recv_buffer_bytes"]["minimum"], 1);
            assert_eq!(egress["socket_send_buffer_bytes"]["minimum"], 1);
        }
    }
    assert_eq!(
        schema["properties"]["egresses"]["items"]["oneOf"][4]["properties"]["kind"]["const"],
        "MeshPeerUdp"
    );
    assert_eq!(
        schema["properties"]["egresses"]["items"]["oneOf"][5]["properties"]["kind"]["const"],
        "ServiceTcp"
    );
    assert_eq!(
        schema["properties"]["egresses"]["items"]["oneOf"][6]["properties"]["kind"]["const"],
        "ServiceUdp"
    );
}
