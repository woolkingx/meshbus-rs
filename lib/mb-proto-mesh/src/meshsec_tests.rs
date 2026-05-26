use super::*;
use crate::{BindingKind, Hello};

#[test]
fn meshsec_header_roundtrip_is_byte_stable() {
    let header = MeshSecEnvelopeHeader {
        version_flags: MESHSEC_VERSION_V1,
        receiver_hint: [1, 2, 3, 4, 5, 6, 7, 8],
        epoch_low: 0xAB,
        boot_salt: [9, 10, 11, 12],
        counter: 0x0102_0304_0506_0708,
    };
    let mut out = Vec::new();
    encode_meshsec_header(&header, &mut out);
    assert_eq!(out.len(), MESHSEC_HEADER_LEN);
    // Pad to fixed overhead so decode length guard passes.
    out.extend_from_slice(&[0u8; MESHSEC_TAG_LEN]);
    let decoded = decode_meshsec_header(&out).expect("decode");
    assert_eq!(decoded, header);
}

#[test]
fn meshsec_header_rejects_short_and_bad_version() {
    assert_eq!(
        decode_meshsec_header(&[0u8; 10]),
        Err(MeshSecError::Truncated)
    );
    let mut packet = vec![0xFFu8];
    packet.extend_from_slice(&[0u8; MESHSEC_FIXED_OVERHEAD - 1]);
    assert_eq!(
        decode_meshsec_header(&packet),
        Err(MeshSecError::UnsupportedVersion(0xFF))
    );
}

#[test]
fn meshsec_padding_selects_smallest_bucket() {
    assert_eq!(meshsec_bucket_len(0).unwrap(), 128);
    assert_eq!(meshsec_bucket_len(126).unwrap(), 128);
    assert_eq!(meshsec_bucket_len(127).unwrap(), 384);
    assert_eq!(meshsec_bucket_len(382).unwrap(), 384);
    assert_eq!(meshsec_bucket_len(383).unwrap(), 1024);
    assert_eq!(meshsec_bucket_len(MESHSEC_MAX_CLEAR_LEN).unwrap(), 1024);
    assert_eq!(
        meshsec_bucket_len(MESHSEC_MAX_CLEAR_LEN + 1),
        Err(MeshSecError::PayloadTooLarge)
    );
}

#[test]
fn meshsec_padding_pack_unpack_roundtrip_hides_real_len() {
    let clear = b"mesh-frame-bincode-bytes";
    let plain = pack_meshsec_plaintext(clear).unwrap();
    assert_eq!(plain.len(), 128);
    assert_eq!(&unpack_meshsec_plaintext(&plain).unwrap(), clear);

    let big = vec![7u8; 400];
    let plain = pack_meshsec_plaintext(&big).unwrap();
    assert_eq!(plain.len(), 1024);
    assert_eq!(unpack_meshsec_plaintext(&plain).unwrap(), big);

    assert_eq!(
        pack_meshsec_plaintext(&vec![0u8; MESHSEC_MAX_CLEAR_LEN + 1]),
        Err(MeshSecError::PayloadTooLarge)
    );
}

fn sample_frame() -> MeshFrame {
    MeshFrame::Hello(Hello {
        node_id: "node-a".to_string(),
        binding: BindingKind::RawUdp,
        nonce: 0xDEAD_BEEF,
        spki_pin_sha256: None,
    })
}

#[test]
fn meshsec_kdf_chain_is_deterministic_and_scoped() {
    let key = [5u8; 32];
    assert_eq!(meshsec_epoch_number(0), 0);
    assert_eq!(meshsec_epoch_number(599), 0);
    assert_eq!(meshsec_epoch_number(600), 1);

    let hint = derive_receiver_hint(&key, 7);
    assert_eq!(hint, derive_receiver_hint(&key, 7));
    assert_ne!(hint, derive_receiver_hint(&key, 8));
    assert_ne!(hint, derive_receiver_hint(&[6u8; 32], 7));
    assert_eq!(hint.len(), MESHSEC_RECEIVER_HINT_LEN);

    let ek = derive_epoch_key(&key, 7);
    assert_eq!(ek, derive_epoch_key(&key, 7));
    assert_ne!(ek, derive_epoch_key(&key, 8));
    assert_ne!(ek, derive_epoch_key(&[6u8; 32], 7));

    let salt = [1u8, 2, 3, 4];
    let ka = derive_sender_key(&ek, "node-a", "ab", &salt);
    assert_eq!(ka, derive_sender_key(&ek, "node-a", "ab", &salt));
    assert_ne!(ka, derive_sender_key(&ek, "node-b", "ab", &salt));
    assert_ne!(ka, derive_sender_key(&ek, "node-a", "ba", &salt));
    assert_ne!(ka, derive_sender_key(&ek, "node-a", "ab", &[9, 9, 9, 9]));
}

#[test]
fn meshsec_roundtrip_seal_open_returns_frame() {
    let static_key = [7u8; 32];
    let ctx = MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key,
        boot_salt: [0xAA, 0xBB, 0xCC, 0xDD],
    };
    let frame = sample_frame();
    let epoch = 42u64;
    let packet = seal_mesh_frame(&frame, &ctx, epoch, 1).unwrap();

    assert!(packet.len() >= MESHSEC_FIXED_OVERHEAD);
    // No debug-clear magic on wire.
    assert!(!packet.windows(2).any(|w| w == crate::MAGIC.to_be_bytes()));

    let keys = vec![MeshSecOpenKey {
        peer_id: "peer-a".into(),
        remote_node_id: "node-a".into(),
        static_key,
    }];
    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    let (peer_id, opened) =
        open_mesh_frame(&packet, &keys, "node-b", epoch..=epoch, &mut replay).unwrap();
    assert_eq!(peer_id, "peer-a");
    assert_eq!(opened, frame);

    // Same counter replayed within the window fails closed.
    assert_eq!(
        open_mesh_frame(&packet, &keys, "node-b", epoch..=epoch, &mut replay),
        Err(MeshSecError::Replay)
    );
}

#[test]
fn meshsec_tamper_reject_wrong_key_header_ciphertext_tag() {
    let static_key = [3u8; 32];
    let ctx = MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key,
        boot_salt: [1, 2, 3, 4],
    };
    let packet = seal_mesh_frame(&sample_frame(), &ctx, 9, 5).unwrap();
    let good = vec![MeshSecOpenKey {
        peer_id: "peer-a".into(),
        remote_node_id: "node-a".into(),
        static_key,
    }];

    let open = |pkt: &[u8], keys: &[MeshSecOpenKey]| {
        let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
        open_mesh_frame(pkt, keys, "node-b", 9..=9, &mut replay)
    };

    let wrong = vec![MeshSecOpenKey {
        peer_id: "peer-a".into(),
        remote_node_id: "node-a".into(),
        static_key: [9u8; 32],
    }];
    assert_eq!(open(&packet, &wrong), Err(MeshSecError::Auth));

    // Tampered header byte (boot_salt is AEAD AAD and binds K_tx).
    let mut bad_header = packet.clone();
    bad_header[10] ^= 0x01;
    assert_eq!(open(&bad_header, &good), Err(MeshSecError::Auth));

    // Tampered ciphertext.
    let mut bad_ct = packet.clone();
    bad_ct[MESHSEC_HEADER_LEN] ^= 0x01;
    assert_eq!(open(&bad_ct, &good), Err(MeshSecError::Auth));

    // Tampered tag.
    let mut bad_tag = packet.clone();
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0x01;
    assert_eq!(open(&bad_tag, &good), Err(MeshSecError::Auth));

    // Untampered packet still opens.
    assert!(open(&packet, &good).is_ok());
}
