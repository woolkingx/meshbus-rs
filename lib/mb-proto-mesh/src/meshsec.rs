//! MeshSec-0RTT-PSK-XChaCha secure UDP envelope. Pure codec/crypto, no I/O.
//!
//! Wire contract source: `schema.json` `meshsec_envelope_v1` and
//! `docs/handbook/mesh-protocol.html#meshsec-wire`.

use crate::MeshFrame;
use crate::replay::MeshSecReplayCache;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

pub const MESHSEC_VERSION_V1: u8 = 0x01;
pub const MESHSEC_HEADER_LEN: usize = 22;
pub const MESHSEC_TAG_LEN: usize = 16;
pub const MESHSEC_FIXED_OVERHEAD: usize = 38;
pub const MESHSEC_RECEIVER_HINT_LEN: usize = 8;
pub const MESHSEC_BOOT_SALT_LEN: usize = 4;
pub const MESHSEC_EPOCH_SECONDS: u64 = 600;
pub const MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS: u64 = 1;
pub const MESHSEC_REPLAY_WINDOW_BITS: u64 = 1024;
pub const MESHSEC_PADDING_BUCKETS: [usize; 3] = [128, 384, 1024];

/// Largest clear MeshFrame bincode length that still fits the biggest bucket
/// once the 2-byte real-length prefix is added.
pub const MESHSEC_MAX_CLEAR_LEN: usize = 1024 - 2;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum MeshSecError {
    #[error("packet shorter than meshsec fixed overhead")]
    Truncated,
    #[error("unsupported meshsec version_flags: {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("clear payload too large for meshsec padding buckets")]
    PayloadTooLarge,
    #[error("meshsec authentication failed")]
    Auth,
    #[error("meshsec replay: duplicate counter")]
    Replay,
    #[error("meshsec replay: counter older than window")]
    ReplayTooOld,
    #[error("meshsec frame serialize failed: {0}")]
    Serialize(String),
}

/// Fixed 22-byte outer header. Every field is AEAD additional data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshSecEnvelopeHeader {
    pub version_flags: u8,
    pub receiver_hint: [u8; MESHSEC_RECEIVER_HINT_LEN],
    pub epoch_low: u8,
    pub boot_salt: [u8; MESHSEC_BOOT_SALT_LEN],
    pub counter: u64,
}

/// Sender-side sealing material for one adjacent peer.
#[derive(Debug, Clone)]
pub struct MeshSecSealContext {
    pub local_node_id: String,
    pub remote_node_id: String,
    pub static_key: [u8; 32],
    pub boot_salt: [u8; MESHSEC_BOOT_SALT_LEN],
}

/// Receiver-side opening material for one configured peer key.
#[derive(Debug, Clone)]
pub struct MeshSecOpenKey {
    pub peer_id: String,
    pub remote_node_id: String,
    pub static_key: [u8; 32],
}

pub fn encode_meshsec_header(header: &MeshSecEnvelopeHeader, out: &mut Vec<u8>) {
    out.push(header.version_flags);
    out.extend_from_slice(&header.receiver_hint);
    out.push(header.epoch_low);
    out.extend_from_slice(&header.boot_salt);
    out.extend_from_slice(&header.counter.to_le_bytes());
}

pub fn decode_meshsec_header(packet: &[u8]) -> Result<MeshSecEnvelopeHeader, MeshSecError> {
    if packet.len() < MESHSEC_FIXED_OVERHEAD {
        return Err(MeshSecError::Truncated);
    }
    let version_flags = packet[0];
    if version_flags != MESHSEC_VERSION_V1 {
        return Err(MeshSecError::UnsupportedVersion(version_flags));
    }
    let mut receiver_hint = [0u8; MESHSEC_RECEIVER_HINT_LEN];
    receiver_hint.copy_from_slice(&packet[1..9]);
    let epoch_low = packet[9];
    let mut boot_salt = [0u8; MESHSEC_BOOT_SALT_LEN];
    boot_salt.copy_from_slice(&packet[10..14]);
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&packet[14..22]);
    Ok(MeshSecEnvelopeHeader {
        version_flags,
        receiver_hint,
        epoch_low,
        boot_salt,
        counter: u64::from_le_bytes(counter_bytes),
    })
}

/// Smallest padding bucket that holds `2 + clear_len` bytes.
pub fn meshsec_bucket_len(clear_len: usize) -> Result<usize, MeshSecError> {
    let needed = clear_len
        .checked_add(2)
        .ok_or(MeshSecError::PayloadTooLarge)?;
    MESHSEC_PADDING_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .ok_or(MeshSecError::PayloadTooLarge)
}

/// Inner plaintext = `u16 real_len BE || clear bytes || zero padding`.
pub fn pack_meshsec_plaintext(clear: &[u8]) -> Result<Vec<u8>, MeshSecError> {
    if clear.len() > MESHSEC_MAX_CLEAR_LEN {
        return Err(MeshSecError::PayloadTooLarge);
    }
    let bucket = meshsec_bucket_len(clear.len())?;
    let mut plain = vec![0u8; bucket];
    plain[0..2].copy_from_slice(&(clear.len() as u16).to_be_bytes());
    plain[2..2 + clear.len()].copy_from_slice(clear);
    Ok(plain)
}

pub fn unpack_meshsec_plaintext(plain: &[u8]) -> Result<Vec<u8>, MeshSecError> {
    if plain.len() < 2 {
        return Err(MeshSecError::Truncated);
    }
    let real = u16::from_be_bytes([plain[0], plain[1]]) as usize;
    if 2 + real > plain.len() {
        return Err(MeshSecError::Truncated);
    }
    Ok(plain[2..2 + real].to_vec())
}

fn hkdf_sha256_32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf-sha256 32-byte okm");
    okm
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("hmac-sha256 accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Direction tag both peers compute identically from the ordered pair so a
/// sealed envelope and its opener derive the same `K_tx`.
fn meshsec_direction(sender_id: &str, receiver_id: &str) -> &'static str {
    if sender_id <= receiver_id { "ab" } else { "ba" }
}

/// XChaCha20-Poly1305 24-byte nonce. `K_tx` already binds epoch/sender/
/// direction/boot_salt, so the per-`K_tx`-unique counter is sufficient nonce
/// material.
fn meshsec_nonce(counter: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

pub fn meshsec_epoch_number(now_unix_secs: u64) -> u64 {
    now_unix_secs / MESHSEC_EPOCH_SECONDS
}

pub fn derive_receiver_hint(
    static_key: &[u8; 32],
    epoch_number: u64,
) -> [u8; MESHSEC_RECEIVER_HINT_LEN] {
    let k_hint = hkdf_sha256_32(None, static_key, b"meshsec/v1/hint");
    let mac = hmac_sha256(&k_hint, &epoch_number.to_le_bytes());
    let mut hint = [0u8; MESHSEC_RECEIVER_HINT_LEN];
    hint.copy_from_slice(&mac[0..MESHSEC_RECEIVER_HINT_LEN]);
    hint
}

pub fn derive_epoch_key(static_key: &[u8; 32], epoch_number: u64) -> [u8; 32] {
    hkdf_sha256_32(
        Some(&epoch_number.to_le_bytes()),
        static_key,
        b"meshsec/v1/epoch",
    )
}

pub fn derive_sender_key(
    epoch_key: &[u8; 32],
    sender_id: &str,
    direction: &str,
    boot_salt: &[u8; MESHSEC_BOOT_SALT_LEN],
) -> [u8; 32] {
    let mut info = Vec::with_capacity(16 + direction.len() + MESHSEC_BOOT_SALT_LEN);
    info.extend_from_slice(b"meshsec/v1/dir/");
    info.extend_from_slice(direction.as_bytes());
    info.extend_from_slice(boot_salt);
    hkdf_sha256_32(Some(sender_id.as_bytes()), epoch_key, &info)
}

/// Seal already-encoded clear bytes into a MeshSec envelope. MeshSec is an L6
/// transform: it never interprets the SDU it carries, so the same envelope
/// equally carries a legacy `MeshFrame` or a native encoded `MeshEvent`.
pub fn seal_bytes(
    clear: &[u8],
    ctx: &MeshSecSealContext,
    epoch_number: u64,
    counter: u64,
) -> Result<Vec<u8>, MeshSecError> {
    let plain = pack_meshsec_plaintext(clear)?;
    let header = MeshSecEnvelopeHeader {
        version_flags: MESHSEC_VERSION_V1,
        receiver_hint: derive_receiver_hint(&ctx.static_key, epoch_number),
        epoch_low: (epoch_number & 0xff) as u8,
        boot_salt: ctx.boot_salt,
        counter,
    };
    let mut out = Vec::with_capacity(MESHSEC_HEADER_LEN + plain.len() + MESHSEC_TAG_LEN);
    encode_meshsec_header(&header, &mut out);
    let k_epoch = derive_epoch_key(&ctx.static_key, epoch_number);
    let direction = meshsec_direction(&ctx.local_node_id, &ctx.remote_node_id);
    let k_tx = derive_sender_key(&k_epoch, &ctx.local_node_id, direction, &ctx.boot_salt);
    let cipher = <XChaCha20Poly1305 as KeyInit>::new(Key::from_slice(&k_tx));
    let nonce = meshsec_nonce(counter);
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &out[..MESHSEC_HEADER_LEN],
            },
        )
        .map_err(|_| MeshSecError::Auth)?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Legacy convenience: bincode-encode a `MeshFrame` then seal it. The wire
/// bytes are byte-identical to `seal_bytes` over the same encoded frame.
pub fn seal_mesh_frame(
    frame: &MeshFrame,
    ctx: &MeshSecSealContext,
    epoch_number: u64,
    counter: u64,
) -> Result<Vec<u8>, MeshSecError> {
    let clear = bincode::serialize(frame).map_err(|e| MeshSecError::Serialize(e.to_string()))?;
    seal_bytes(&clear, ctx, epoch_number, counter)
}

fn meshsec_try_decrypt(
    key: &MeshSecOpenKey,
    local_node_id: &str,
    epoch_number: u64,
    header: &MeshSecEnvelopeHeader,
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if derive_receiver_hint(&key.static_key, epoch_number) != header.receiver_hint {
        return None;
    }
    let k_epoch = derive_epoch_key(&key.static_key, epoch_number);
    let direction = meshsec_direction(&key.remote_node_id, local_node_id);
    let k_tx = derive_sender_key(&k_epoch, &key.remote_node_id, direction, &header.boot_salt);
    let cipher = <XChaCha20Poly1305 as KeyInit>::new(Key::from_slice(&k_tx));
    let nonce = meshsec_nonce(header.counter);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

/// Open a MeshSec envelope to its opaque clear bytes. AEAD authentication and
/// the MeshSec replay window run here; the SDU is returned uninterpreted, so
/// the caller decodes it (legacy `MeshFrame` or native `MeshEvent`). A failed
/// decrypt returns before any replay or higher-layer state is touched.
pub fn open_bytes(
    packet: &[u8],
    keys: &[MeshSecOpenKey],
    local_node_id: &str,
    accepted_epoch: core::ops::RangeInclusive<u64>,
    replay: &mut MeshSecReplayCache,
) -> Result<(String, Vec<u8>), MeshSecError> {
    let header = decode_meshsec_header(packet)?;
    let aad = &packet[..MESHSEC_HEADER_LEN];
    let ciphertext = &packet[MESHSEC_HEADER_LEN..];
    for epoch in accepted_epoch {
        if (epoch & 0xff) as u8 != header.epoch_low {
            continue;
        }
        for key in keys {
            let Some(plain) =
                meshsec_try_decrypt(key, local_node_id, epoch, &header, aad, ciphertext)
            else {
                continue;
            };
            replay.check_and_insert(&key.peer_id, epoch, header.boot_salt, header.counter)?;
            let clear = unpack_meshsec_plaintext(&plain)?;
            return Ok((key.peer_id.clone(), clear));
        }
    }
    Err(MeshSecError::Auth)
}

/// Legacy convenience: open then bincode-decode a `MeshFrame`.
pub fn open_mesh_frame(
    packet: &[u8],
    keys: &[MeshSecOpenKey],
    local_node_id: &str,
    accepted_epoch: core::ops::RangeInclusive<u64>,
    replay: &mut MeshSecReplayCache,
) -> Result<(String, MeshFrame), MeshSecError> {
    let (peer_id, clear) = open_bytes(packet, keys, local_node_id, accepted_epoch, replay)?;
    let frame = bincode::deserialize::<MeshFrame>(&clear)
        .map_err(|e| MeshSecError::Serialize(e.to_string()))?;
    Ok((peer_id, frame))
}

#[cfg(test)]
mod tests {
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
}
