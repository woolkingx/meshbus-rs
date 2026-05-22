//! M6 no-Quinn gate.
//!
//! The mesh peer QUIC binding must run on the workspace-owned QUIC engine
//! (`mb-quic`) over the core `UdpPacketLoop`. Quinn is a reference/regression
//! baseline only and must not remain in the normal dependency tree once the
//! own-QUIC peer replaces it. This test fails while `quinn` is reachable
//! through `cargo tree -e normal` and passes once it is fully removed.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/crates/mesh-bus-core
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .expect("workspace root is two levels above the crate manifest")
}

#[test]
fn quinn_is_absent_from_normal_dependency_tree() {
    let root = workspace_root();
    assert!(
        root.join("Cargo.toml").is_file(),
        "expected workspace manifest at {}",
        root.join("Cargo.toml").display()
    );

    let output = Command::new(env!("CARGO"))
        .args(["tree", "-e", "normal", "--workspace", "--prefix", "none"])
        .current_dir(&root)
        .output()
        .expect("run `cargo tree -e normal`");

    assert!(
        output.status.success(),
        "`cargo tree -e normal` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let tree = String::from_utf8_lossy(&output.stdout).to_lowercase();
    let offending: Vec<&str> = tree.lines().filter(|line| line.contains("quinn")).collect();

    assert!(
        offending.is_empty(),
        "quinn must not appear in the normal dependency tree; found:\n{}",
        offending.join("\n")
    );
}
