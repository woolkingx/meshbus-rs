//! Boundary guard: mb-rule MUST NOT reference mesh_bus_core or any adapter crate.

use std::fs;
use std::path::PathBuf;

fn read_src() -> Vec<(PathBuf, String)> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    collect(&src, &mut out);
    out
}

fn collect(dir: &std::path::Path, out: &mut Vec<(PathBuf, String)>) {
    for e in fs::read_dir(dir).expect("read_dir failed").flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
            continue;
        }
        if p.extension().is_none_or(|x| x != "rs") {
            continue;
        }
        out.push((
            p.clone(),
            fs::read_to_string(&p).expect("read_to_string failed"),
        ));
    }
}

#[test]
fn no_mesh_bus_core_in_src() {
    for (p, text) in read_src() {
        assert!(
            !text.contains("mesh_bus_core"),
            "{}: forbidden mesh_bus_core token",
            p.display()
        );
        assert!(
            !text.contains("mesh-bus-core"),
            "{}: forbidden mesh-bus-core token",
            p.display()
        );
    }
}

#[test]
fn no_adapter_imports() {
    for (p, text) in read_src() {
        for forbidden in [
            "mesh_bus_ingress_",
            "mesh_bus_egress_",
            "mesh_bus_scheduler_",
            "mesh_bus_runtime",
        ] {
            assert!(
                !text.contains(forbidden),
                "{}: forbidden token `{forbidden}`",
                p.display()
            );
        }
    }
}
