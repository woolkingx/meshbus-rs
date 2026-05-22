use std::fs;
use std::path::Path;

#[test]
fn mesh_peer_udp_drop_sites_publish_observation_events() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let source = fs::read_to_string(source_path).expect("read mesh peer udp ingress source");

    assert!(
        source.contains("OBS_MESHSEC_DROP"),
        "MeshSec drop event id must stay wired"
    );
    assert!(
        source.contains("OBS_NATIVE_DROP"),
        "native drop event id must stay wired"
    );
    assert!(
        source.contains("port.publish_observation("),
        "drop facts must publish through BusPort observation surface"
    );
    assert!(
        source.contains("drop_meshsec(&port, peer, &err);"),
        "MeshSec fail-closed path must publish before trace-only logging"
    );
    assert!(
        source.contains("drop_native(&port, peer, NativeDropReason::EventDecode);"),
        "native event decode drop must publish an owner fact"
    );
    assert!(
        source.contains("drop_native(&port, peer, NativeDropReason::QueueOverflow);"),
        "native queue overflow drop must publish an owner fact"
    );
}
