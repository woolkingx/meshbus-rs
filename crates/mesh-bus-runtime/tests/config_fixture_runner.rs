//! Generic runtime-layer fixture runner. The legal operator over
//! schemas/test-runtime.schema.json for runtime config rows. Drives the REAL
//! product entrypoints mesh_bus_runtime::parse_config / run; no mock runtime.
//!
//! Behavior mapping:
//! - config.parse_ok: parse the fixture input YAML and assert parse success.
//! - config.parse_err: parse the fixture input YAML and assert parse failure.
//! - config.boot_shutdown: parse and boot/shutdown the runtime bus.

use mesh_bus_runtime::{parse_config, run};
use serde::Deserialize;
use serde_yaml::Value;
use std::path::Path;

#[derive(Deserialize)]
struct FixtureRow {
    id: String,
    owner: String,
    kind: String,
    case: String,
    schema_ref: String,
    input: Input,
    expect: Expect,
    #[serde(default)]
    observations: Vec<Value>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct Input {
    yaml: String,
}

#[derive(Deserialize)]
struct Expect {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error_contains: Option<String>,
    #[serde(default)]
    debug_contains: Vec<String>,
}

fn load_cases() -> Vec<FixtureRow> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("fixtures/config dir")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                return None;
            }
            Some(path)
        })
        .collect();

    paths.sort();

    let mut out = Vec::new();
    for p in paths {
        let txt = std::fs::read_to_string(&p).unwrap();
        let row: FixtureRow =
            serde_yaml::from_str(&txt).unwrap_or_else(|e| panic!("fixture {p:?}: {e}"));
        out.push(row);
    }
    out
}

fn execute_parse_ok(id: &str, row: &FixtureRow) {
    assert!(row.expect.ok, "[{id}] schema case requires ok=true");
    let cfg = parse_config(&row.input.yaml).unwrap_or_else(|e| panic!("[{id}] parse: {e:#}"));

    let dbg = format!("{cfg:?}");
    for sub in &row.expect.debug_contains {
        assert!(
            dbg.contains(sub.as_str()),
            "[{id}] Debug output missing {sub:?}\nfull debug: {dbg}",
        );
    }
}

fn execute_parse_err(id: &str, row: &FixtureRow) {
    let err = parse_config(&row.input.yaml)
        .err()
        .unwrap_or_else(|| panic!("[{id}] expected parse error, got Ok"));

    if let Some(sub) = &row.expect.error_contains {
        assert!(
            format!("{err:#}").contains(sub.as_str()),
            "[{id}] error {err:#} missing {sub:?}",
        );
    }
}

async fn execute_boot_shutdown(id: &str, row: &FixtureRow) {
    let cfg = parse_config(&row.input.yaml).unwrap_or_else(|e| panic!("[{id}] parse: {e:#}"));
    let handle = run(cfg, Path::new("."))
        .await
        .unwrap_or_else(|e| panic!("[{id}] boot: {e:#}"));
    handle.shutdown().await;
}

#[tokio::test]
async fn runtime_config_contract_fixtures() {
    let cases = load_cases();
    assert!(
        !cases.is_empty(),
        "no fixtures found in tests/fixtures/config/"
    );

    for row in cases {
        assert_eq!(
            row.owner.as_str(),
            "mesh-bus-runtime.config",
            "[{id}] unsupported fixture owner {owner:?}",
            id = row.id,
            owner = row.owner
        );
        assert_eq!(
            row.schema_ref,
            "schemas/test-runtime.schema.json",
            "[{id}] unsupported schema_ref {ref_name:?}",
            id = row.id,
            ref_name = row.schema_ref
        );
        assert!(
            row.observations.is_empty(),
            "[{id}] observations must be empty in M2 config runner",
            id = row.id
        );
        assert!(
            row.tags.is_empty(),
            "[{id}] tags must be empty in M2 config runner",
            id = row.id
        );

        match row.case.as_str() {
            "config.parse_ok" => {
                assert_eq!(row.kind, "data-owner");
                assert!(
                    row.expect.ok,
                    "[{id}] config.parse_ok requires expect.ok=true",
                    id = row.id
                );
                execute_parse_ok(&row.id, &row);
            }
            "config.parse_err" => {
                assert_eq!(row.kind, "data-owner");
                assert!(
                    !row.expect.ok,
                    "[{id}] config.parse_err requires expect.ok=false",
                    id = row.id
                );
                execute_parse_err(&row.id, &row);
            }
            "config.boot_shutdown" => {
                assert_eq!(row.kind, "service-composition");
                execute_boot_shutdown(&row.id, &row).await;
            }
            _ => panic!("[{}] unknown fixture case", row.id),
        }
    }
}
