//! Shared process/config helpers for binary-backed e2e tests.
use std::process::{Command, Stdio};
use std::time::SystemTime;

pub fn write_temp_rule_chain(name: &str, yaml: &str) -> std::path::PathBuf {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time")
        .as_millis();
    let path =
        std::env::temp_dir().join(format!("{name}-rules-{}-{millis}.yaml", std::process::id()));
    std::fs::write(&path, yaml).expect("write temp rule chain");
    path
}

pub fn write_temp_config(name: &str, yaml: &str) -> std::path::PathBuf {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time")
        .as_millis();
    let path = std::env::temp_dir().join(format!("{name}-{}-{millis}.yaml", std::process::id()));
    std::fs::write(&path, yaml).expect("write temp config");
    path
}

pub fn spawn_mesh_bus(config: &std::path::Path) -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_mesh-bus");
    let (stdout, stderr) = if std::env::var_os("MESH_BUS_TEST_LOG").is_some() {
        (Stdio::inherit(), Stdio::inherit())
    } else {
        (Stdio::null(), Stdio::null())
    };
    Command::new(bin)
        .arg("run")
        .arg("--config")
        .arg(config)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn mesh-bus binary")
}

pub fn stop_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
