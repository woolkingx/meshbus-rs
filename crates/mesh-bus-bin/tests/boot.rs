//! Integration smoke test: parse example config and verify bus starts + stops.

use mesh_bus_runtime::{parse_config, run};

#[tokio::test]
async fn boot_from_yaml_and_shutdown() {
    let yaml = r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19090
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 2000
"#;
    let cfg = parse_config(yaml).expect("valid config");
    let handle = run(cfg, std::path::Path::new("."))
        .await
        .expect("bus starts");
    handle.shutdown().await;
}
