#[allow(dead_code)]
mod e2e_client;

use e2e_client::{free_tcp_addr, socks5_tcp_roundtrip, spawn_tcp_echo, wait_for_tcp_listener};
use mb_endpoint::Endpoint;
use serde_json::Value;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

#[tokio::test(flavor = "multi_thread")]
async fn operator_live_api_reports_daemon_status_and_metrics() {
    let socks = free_tcp_addr();
    let operator = free_tcp_addr();
    let echo = spawn_tcp_echo().await;
    let dir = temp_named_dir("operator-live");
    let config = dir.join("config.yaml");
    let token = dir.join("operator.token");
    std::fs::write(&token, "live-token\n").expect("write operator token");
    std::fs::write(
        &config,
        format!(
            r#"
operator:
  kind: LocalHttp
  listen: {operator}
  auth:
    kind: BearerTokenFile
    path: {token}
ingresses:
  - kind: Socks5
    listen: {socks}
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
"#,
            token = token.display()
        ),
    )
    .expect("write operator live config");

    let child = Command::new(env!("CARGO_BIN_EXE_mesh-bus"))
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mesh-bus");
    let mut child = ChildGuard::new(child);
    wait_for_tcp_listener(socks).await;
    wait_for_tcp_listener(operator).await;

    let api = format!("http://{operator}");
    assert_admin_api_rejects_missing_token("status", &api);
    assert_admin_api_rejects_wrong_token("status", &api, &dir);
    let status = run_admin_json("status", &api, Some(&token));
    assert_eq!(status["kind"], "operator.live_status");
    assert_eq!(status["status"]["counts"]["ingresses"], 1);
    assert_eq!(status["status"]["counts"]["egresses"], 1);
    assert_eq!(status["metrics"]["dispatch_success"], 0);

    let target = Endpoint::new(echo.ip().to_string(), echo.port()).expect("echo endpoint");
    let target_text = format!("{}:{}", echo.ip(), echo.port());
    let probe = run_admin_json_args(
        &["probe", "socks5-connect", "--target", &target_text],
        &api,
        Some(&token),
    );
    assert_eq!(probe["kind"], "operator.probe_result");
    assert_eq!(probe["probe"], "socks5-connect");
    assert_eq!(probe["ok"], true, "probe failed: {probe}");
    assert!(
        probe["dispatch_success_after"].as_u64().unwrap_or(0)
            > probe["dispatch_success_before"].as_u64().unwrap_or(0),
        "probe should move traffic through normal dispatch path: {probe}"
    );
    let probe_metrics = run_admin_json("metrics-snapshot", &api, Some(&token));
    assert!(
        probe_metrics["exits"][0]["send_count"]
            .as_u64()
            .unwrap_or(0)
            >= 1
            && probe_metrics["exits"][0]["success_count"]
                .as_u64()
                .unwrap_or(0)
                >= 1,
        "probe should increment selected exit counters, got {probe_metrics}"
    );

    socks5_tcp_roundtrip(socks, target, b"operator-live").await;

    let metrics = wait_for_dispatch_success(&api, &token).await;
    assert_eq!(metrics["kind"], "operator.metrics_snapshot");
    assert!(
        metrics["dispatch_success"].as_u64().unwrap_or(0) >= 1,
        "expected dispatch_success >= 1, got {metrics}"
    );
    assert!(
        metrics["meshsec_drop_total"].as_u64().is_some()
            && metrics["native_drop_total"].as_u64().is_some(),
        "expected observation drop projection fields, got {metrics}"
    );
    assert_eq!(metrics["exits"][0]["exit_id"], "direct");
    assert!(
        metrics["exits"][0]["send_count"].as_u64().unwrap_or(0) >= 1
            && metrics["exits"][0]["success_count"].as_u64().unwrap_or(0) >= 1,
        "expected exit send/success counters, got {metrics}"
    );
    let diagnose = run_admin_json("diagnose", &api, Some(&token));
    assert_eq!(diagnose["kind"], "operator.diagnose_bundle");
    assert_eq!(diagnose["status"]["kind"], "operator.live_status");
    assert_eq!(diagnose["metrics"]["kind"], "operator.metrics_snapshot");
    let redacted_yaml = diagnose["effective_config"]["redacted_yaml"]
        .as_str()
        .unwrap_or("");
    assert!(!redacted_yaml.contains("live-token"));

    let done = child.take();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(done.id().to_string())
        .status()
        .expect("send sigterm");
    assert!(status.success(), "kill -TERM");
    let output = done.wait_with_output().expect("wait mesh-bus child");
    assert!(
        output.status.success(),
        "mesh-bus child status; stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wait_for_dispatch_success(api: &str, token: &std::path::Path) -> Value {
    for _ in 0..100 {
        let metrics = run_admin_json("metrics-snapshot", api, Some(token));
        if metrics["dispatch_success"].as_u64().unwrap_or(0) >= 1 {
            return metrics;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    run_admin_json("metrics-snapshot", api, Some(token))
}

fn run_admin_json(command: &str, api: &str, token: Option<&std::path::Path>) -> Value {
    run_admin_json_args(&[command], api, token)
}

fn run_admin_json_args(args: &[&str], api: &str, token: Option<&std::path::Path>) -> Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mesh-bus"));
    cmd.arg("admin");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.arg("--api").arg(api);
    if let Some(token) = token {
        cmd.arg("--token-file").arg(token);
    }
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("run admin {}: {e}", args.join(" ")));
    assert!(
        output.status.success(),
        "admin {} failed; stdout={}; stderr={}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("admin json")
}

fn assert_admin_api_rejects_missing_token(command: &str, api: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_mesh-bus"))
        .arg("admin")
        .arg(command)
        .arg("--api")
        .arg(api)
        .output()
        .unwrap_or_else(|e| panic!("run admin {command}: {e}"));
    assert!(
        !output.status.success(),
        "admin without token unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("401 Unauthorized"),
        "unexpected stderr: {stderr}"
    );
}

fn assert_admin_api_rejects_wrong_token(command: &str, api: &str, dir: &std::path::Path) {
    let wrong = dir.join("wrong.token");
    std::fs::write(&wrong, "wrong-token\n").expect("write wrong token");
    let output = Command::new(env!("CARGO_BIN_EXE_mesh-bus"))
        .arg("admin")
        .arg(command)
        .arg("--api")
        .arg(api)
        .arg("--token-file")
        .arg(&wrong)
        .output()
        .unwrap_or_else(|e| panic!("run admin {command}: {e}"));
    assert!(
        !output.status.success(),
        "admin with wrong token unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("403 Forbidden"),
        "unexpected stderr: {stderr}"
    );
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn take(&mut self) -> Child {
        self.child.take().expect("child already taken")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
        }
    }
}

fn temp_named_dir(name: &str) -> std::path::PathBuf {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis();
    let path =
        std::env::temp_dir().join(format!("mesh-bus-{name}-{}-{millis}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create temp dir");
    path
}
