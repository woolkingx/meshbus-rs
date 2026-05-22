use bytes::Bytes;
use mb_proto_mesh::{
    DataPackage, EventPci, EventSemantic, MESHSEC_REPLAY_WINDOW_BITS, MeshEvent, MeshSecError,
    MeshSecOpenKey, MeshSecReplayCache, MeshSecSealContext, OrderingClass, ReliabilityClass,
    encode_event, open_bytes, seal_bytes,
};

const FAMILY_MARKER: &str = "fam-stream-secret-42";
const EVENT_MARKER: &str = "evt-secret-7f3a91c2";
const POLICY_MARKER: &str = "dp-secret-steer-default";
const PAYLOAD_MARKER: &[u8] = b"SECRET-SDU-PAYLOAD-MUST-NOT-LEAK-ON-WIRE";

fn secret_event() -> MeshEvent {
    MeshEvent {
        event_id: EVENT_MARKER.into(),
        family_id: FAMILY_MARKER.into(),
        semantic: EventSemantic::Stream,
        reliability: ReliabilityClass::Reliable,
        ordering: OrderingClass::OrderedWithinFamily,
        delivery_policy_id: POLICY_MARKER.into(),
        path_epoch: 3,
        ttl: 16,
        pci: EventPci {
            checksum: Some("crc32:9af1".into()),
            compression: Some("none".into()),
        },
        package: Some(DataPackage {
            package_id: "pkg-secret-000017".into(),
            seq: 17,
            offset: 17 * 1452,
            len: PAYLOAD_MARKER.len() as u32,
            fragment_id: 0,
            fragment_count: 1,
            payload: Bytes::from_static(PAYLOAD_MARKER),
        }),
    }
}

fn seal_ctx() -> MeshSecSealContext {
    MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key: [0x5a; 32],
        boot_salt: [0xAA, 0xBB, 0xCC, 0xDD],
    }
}

fn open_keys() -> Vec<MeshSecOpenKey> {
    vec![MeshSecOpenKey {
        peer_id: "peer-a".into(),
        remote_node_id: "node-a".into(),
        static_key: [0x5a; 32],
    }]
}

fn seal_ctx_with_salt(boot_salt: [u8; 4]) -> MeshSecSealContext {
    MeshSecSealContext {
        boot_salt,
        ..seal_ctx()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn sealed_native_event_leaks_no_cleartext_identifiers_or_payload() {
    let event = secret_event();
    let encoded = encode_event(&event).unwrap();
    let packet = seal_bytes(&encoded, &seal_ctx(), 42, 1).unwrap();

    assert!(!contains(&packet, FAMILY_MARKER.as_bytes()));
    assert!(!contains(&packet, EVENT_MARKER.as_bytes()));
    assert!(!contains(&packet, POLICY_MARKER.as_bytes()));
    assert!(!contains(&packet, PAYLOAD_MARKER));
    // The whole encoded event must not appear verbatim on the wire.
    assert!(!contains(&packet, &encoded));
    // No MB envelope magic on the secure-UDP wire.
    assert!(!contains(&packet, &mb_proto_mesh::MAGIC.to_be_bytes()));

    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    let (peer_id, clear) =
        open_bytes(&packet, &open_keys(), "node-b", 42..=42, &mut replay).unwrap();
    assert_eq!(peer_id, "peer-a");
    assert_eq!(clear, encoded);
    let decoded = mb_proto_mesh::decode_event(&mut bytes::BytesMut::from(&clear[..])).unwrap();
    assert_eq!(decoded, event);
}

#[test]
fn double_open_of_same_native_event_packet_is_replay_rejected() {
    let encoded = encode_event(&secret_event()).unwrap();
    let packet = seal_bytes(&encoded, &seal_ctx(), 42, 7).unwrap();

    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    let keys = open_keys();
    assert!(open_bytes(&packet, &keys, "node-b", 42..=42, &mut replay).is_ok());
    assert_eq!(
        open_bytes(&packet, &keys, "node-b", 42..=42, &mut replay),
        Err(MeshSecError::Replay)
    );
}

#[test]
fn same_epoch_counter_restart_with_new_boot_salt_is_not_replay() {
    let encoded = encode_event(&secret_event()).unwrap();
    let first_boot = seal_bytes(&encoded, &seal_ctx_with_salt([1, 2, 3, 4]), 42, 1).unwrap();
    let restarted = seal_bytes(&encoded, &seal_ctx_with_salt([4, 3, 2, 1]), 42, 1).unwrap();

    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    let keys = open_keys();
    assert!(open_bytes(&first_boot, &keys, "node-b", 42..=42, &mut replay).is_ok());
    assert!(open_bytes(&restarted, &keys, "node-b", 42..=42, &mut replay).is_ok());
    assert_eq!(
        open_bytes(&first_boot, &keys, "node-b", 42..=42, &mut replay),
        Err(MeshSecError::Replay)
    );
}

#[test]
fn tampered_ciphertext_fails_auth_before_any_higher_layer_state() {
    let encoded = encode_event(&secret_event()).unwrap();
    let packet = seal_bytes(&encoded, &seal_ctx(), 9, 5).unwrap();

    let mut tampered = packet.clone();
    let ct_start = mb_proto_mesh::MESHSEC_HEADER_LEN;
    tampered[ct_start] ^= 0x01;

    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    assert_eq!(
        open_bytes(&tampered, &open_keys(), "node-b", 9..=9, &mut replay),
        Err(MeshSecError::Auth)
    );
    // Auth failed before the replay window recorded anything, so the original
    // packet still opens cleanly on the same replay cache.
    assert!(open_bytes(&packet, &open_keys(), "node-b", 9..=9, &mut replay).is_ok());
}
