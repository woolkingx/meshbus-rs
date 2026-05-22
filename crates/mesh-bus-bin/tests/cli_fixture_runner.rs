//! Binary CLI contract fixtures.
//!
//! CLI tests are argv/config data -> exit/stdout/stderr data. They stay out of
//! the traffic composition runner, but they are still data-shaped contracts and
//! must not be one hand-written Rust test per scenario.
#[allow(dead_code)]
mod e2e_client;

use e2e_client::{free_tcp_addr, wait_for_tcp_listener};
use serde::Deserialize;
use std::process::{Command as ProcCommand, Stdio};
use std::time::{Duration, SystemTime};

#[derive(Deserialize)]
struct Fixture {
    id: String,
    owner: String,
    kind: String,
    case: String,
    schema_ref: String,
    input: Input,
    #[serde(default)]
    observations: Vec<serde_yaml::Value>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct Input {
    commands: Vec<CommandCase>,
}

#[derive(Deserialize)]
struct CommandCase {
    id: String,
    command: CliCommand,
    config_yaml: String,
    #[serde(default)]
    files: Vec<TempFile>,
    expect: CommandExpect,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CliCommand {
    Check,
    Status,
    RunSigterm,
    AdminStatus,
    AdminStatusApi,
    AdminConfigCheck,
    AdminConfigEffective,
    AdminMetricsSnapshot,
}

#[derive(Deserialize)]
struct TempFile {
    path: String,
    contents: String,
}

#[derive(Deserialize)]
struct CommandExpect {
    success: bool,
    #[serde(default)]
    stdout_contains: Vec<String>,
    #[serde(default)]
    stdout_not_contains: Vec<String>,
    #[serde(default)]
    stderr_contains: Vec<String>,
    #[serde(default)]
    stderr_not_contains: Vec<String>,
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_command_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("fixtures/cli")
        .filter_map(|e| {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) == Some("yaml") {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    entries.sort();

    for p in entries {
        let fixture: Fixture = serde_yaml::from_str(&std::fs::read_to_string(&p).unwrap())
            .unwrap_or_else(|e| panic!("fixture {p:?}: {e}"));
        assert_eq!(fixture.owner, "mesh-bus-bin.cli", "[{}] owner", fixture.id);
        assert_eq!(fixture.kind, "service-composition", "[{}] kind", fixture.id);
        assert_eq!(fixture.case, "cli.command_table", "[{}] case", fixture.id);
        assert_eq!(
            fixture.schema_ref, "schemas/test-runtime.schema.json",
            "[{}] schema_ref",
            fixture.id
        );
        assert!(
            fixture.observations.is_empty(),
            "[{}] observations must be empty in this runner",
            fixture.id
        );
        assert!(
            fixture.tags.is_empty(),
            "[{}] tags must be empty in this runner",
            fixture.id
        );

        for command in fixture.input.commands {
            run_command_case(&fixture.id, command).await;
        }
    }
}

async fn run_command_case(fixture_id: &str, command: CommandCase) {
    let root = temp_named_dir(&command.id);
    for f in &command.files {
        let path = root.join(&f.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture file parent");
        }
        std::fs::write(&path, &f.contents).expect("write fixture file");
    }

    let listen = free_tcp_addr();
    let config_yaml = command
        .config_yaml
        .replace("{{ROOT}}", &root.display().to_string())
        .replace("{{TCP_LISTEN}}", &listen.to_string());
    let cfg = root.join("config.yaml");
    std::fs::write(&cfg, config_yaml).expect("write fixture config");

    match command.command {
        CliCommand::Check => {
            let output = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("check")
                .arg(&cfg)
                .output()
                .expect("run check");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
        CliCommand::Status => {
            let output = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("status")
                .arg(&cfg)
                .output()
                .expect("run status");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
        CliCommand::AdminStatus => {
            let output = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("admin")
                .arg("status")
                .arg("--config")
                .arg(&cfg)
                .output()
                .expect("run admin status");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
        CliCommand::AdminStatusApi => {
            let output = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("admin")
                .arg("status")
                .arg("--api")
                .arg(format!("http://{listen}"))
                .output()
                .expect("run admin status --api");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
        CliCommand::AdminConfigCheck => {
            let output = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("admin")
                .arg("config-check")
                .arg("--config")
                .arg(&cfg)
                .output()
                .expect("run admin config-check");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
        CliCommand::AdminConfigEffective => {
            let output = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("admin")
                .arg("config-effective")
                .arg("--config")
                .arg(&cfg)
                .output()
                .expect("run admin config-effective");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
        CliCommand::AdminMetricsSnapshot => {
            let output = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("admin")
                .arg("metrics-snapshot")
                .arg("--config")
                .arg(&cfg)
                .output()
                .expect("run admin metrics-snapshot");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
        CliCommand::RunSigterm => {
            let child = ProcCommand::new(env!("CARGO_BIN_EXE_mesh-bus"))
                .arg("run")
                .arg("--config")
                .arg(&cfg)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn mesh-bus binary");
            wait_for_tcp_listener(listen).await;
            let status = ProcCommand::new("kill")
                .arg("-TERM")
                .arg(child.id().to_string())
                .status()
                .expect("send sigterm");
            assert!(status.success(), "[{fixture_id}/{}] kill -TERM", command.id);
            let output = child.wait_with_output().expect("wait child");
            assert_command_output(fixture_id, &command.id, output, &command.expect);
        }
    }
}

fn assert_command_output(
    fixture_id: &str,
    command_id: &str,
    output: std::process::Output,
    expect: &CommandExpect,
) {
    assert_eq!(
        output.status.success(),
        expect.success,
        "[{fixture_id}/{command_id}] exit status; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in &expect.stdout_contains {
        assert!(
            stdout.contains(needle),
            "[{fixture_id}/{command_id}] stdout should contain {needle:?}; got: {stdout}"
        );
    }
    for needle in &expect.stdout_not_contains {
        assert!(
            !stdout.contains(needle),
            "[{fixture_id}/{command_id}] stdout must not contain {needle:?}; got: {stdout}"
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in &expect.stderr_contains {
        assert!(
            stderr.contains(needle),
            "[{fixture_id}/{command_id}] stderr should contain {needle:?}; got: {stderr}"
        );
    }
    for needle in &expect.stderr_not_contains {
        assert!(
            !stderr.contains(needle),
            "[{fixture_id}/{command_id}] stderr must not contain {needle:?}; got: {stderr}"
        );
    }
}

fn temp_named_dir(name: &str) -> std::path::PathBuf {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis();
    let path = std::env::temp_dir().join(format!(
        "mesh-bus-cli-fixture-{name}-{}-{millis}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create temp dir");
    path
}
