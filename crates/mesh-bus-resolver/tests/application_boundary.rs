//! Application boundary guard for mesh-bus-resolver.
//!
//! This crate is a DNS client/cache component consumed by pipeline hooks. It
//! must never name kernel data-plane internals or expose a listener/ingress
//! surface.

use std::path::Path;
use std::process::Command;

const FORBIDDEN: &[&str] = &[
    "mesh_bus_core::Frame",
    "mesh_bus_core::FrameKind",
    "mesh_bus_core::EgressPlugin",
    "mesh_bus_core::SchedulerPlugin",
    "mesh_bus_core::ScheduleDecision",
    "mesh_bus_core::RankContext",
    "::Frame{",
    "FrameKind::",
];

const FORBIDDEN_LISTENER_SURFACE: &[&str] = &[
    "TcpListener",
    "UdpSocket::bind",
    "IngressPlugin",
    "struct DnsIngress",
    "impl DnsIngress",
];

#[test]
fn resolver_src_has_no_kernel_internals() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for needle in FORBIDDEN {
        let out = Command::new("grep")
            .args(["-rn", needle, src.to_str().expect("utf8 path")])
            .output()
            .expect("grep available");
        assert!(
            !out.status.success() || out.stdout.is_empty(),
            "forbidden token `{needle}` appears in mesh-bus-resolver/src:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn resolver_src_has_no_listener_or_ingress_surface() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for needle in FORBIDDEN_LISTENER_SURFACE {
        let out = Command::new("grep")
            .args(["-rn", needle, src.to_str().expect("utf8 path")])
            .output()
            .expect("grep available");
        assert!(
            !out.status.success() || out.stdout.is_empty(),
            "forbidden listener/ingress token `{needle}` appears in mesh-bus-resolver/src:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
