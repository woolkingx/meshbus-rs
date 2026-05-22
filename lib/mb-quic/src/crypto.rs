//! RFC 9001 packet protection.
//!
//! Initial keys are derived natively over `ring` so they can be asserted
//! against the RFC 9001 Appendix A.1 published vectors. Handshake / 1-RTT
//! keys come from the proven `rustls::quic` key schedule. Both paths produce
//! the same [`PacketKeys`] shape consumed by [`crate::conn`].

use ring::aead::{self, quic as ring_quic};
use ring::hkdf;

use crate::{Error, Result, Version};

/// RFC 9001 §5.2 Initial salt for QUIC v1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// AEAD tag length for AES-128-GCM (RFC 9001).
pub const AEAD_TAG_LEN: usize = 16;

/// HKDF output length helper (`ring::hkdf::KeyType`).
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with empty context.
fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], out_len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // zero-length context
    let info_parts: [&[u8]; 1] = [&info];
    let okm = prk
        .expand(&info_parts, HkdfLen(out_len))
        .expect("hkdf expand label");
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).expect("hkdf okm fill");
    out
}

/// Per-direction Initial secret (`client in` / `server in`, RFC 9001 §5.2).
pub fn initial_secret(dcid: &[u8], is_client: bool, version: Version) -> Vec<u8> {
    let salt = match version {
        Version::V1 => &INITIAL_SALT_V1,
    };
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let label: &[u8] = if is_client {
        b"client in"
    } else {
        b"server in"
    };
    hkdf_expand_label(&prk, label, 32)
}

/// AEAD + header-protection material for one direction and key phase.
pub struct PacketKeys {
    aead: aead::LessSafeKey,
    iv: [u8; 12],
    hp: ring_quic::HeaderProtectionKey,
}

impl PacketKeys {
    /// Derive native AES-128-GCM Initial keys from a per-direction secret.
    pub fn from_initial_secret(secret: &[u8]) -> PacketKeys {
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
        let key = hkdf_expand_label(&prk, b"quic key", 16);
        let iv = hkdf_expand_label(&prk, b"quic iv", 12);
        let hp = hkdf_expand_label(&prk, b"quic hp", 16);
        let aead = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &key).expect("aes128 key"),
        );
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(&iv);
        let hp = ring_quic::HeaderProtectionKey::new(&ring_quic::AES_128, &hp).expect("hp key");
        PacketKeys {
            aead,
            iv: iv_arr,
            hp,
        }
    }

    /// Raw Initial key/iv/hp bytes, for the RFC 9001 Appendix A.1 vector test.
    pub fn initial_material(secret: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
        (
            hkdf_expand_label(&prk, b"quic key", 16),
            hkdf_expand_label(&prk, b"quic iv", 12),
            hkdf_expand_label(&prk, b"quic hp", 16),
        )
    }

    /// AEAD nonce = IV XOR left-padded packet number (RFC 9001 §5.3).
    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut n = self.iv;
        let pn_be = pn.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= pn_be[i];
        }
        n
    }

    /// Seal `payload` in place, appending the auth tag. `header` is the AAD.
    pub fn seal(&self, pn: u64, header: &[u8], payload: &mut Vec<u8>) -> Result<()> {
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(pn));
        self.aead
            .seal_in_place_append_tag(nonce, aead::Aad::from(header), payload)
            .map_err(|_| Error::Crypto("aead seal"))
    }

    /// Open `payload` (ciphertext+tag) in place, returning the plaintext slice.
    pub fn open<'a>(&self, pn: u64, header: &[u8], payload: &'a mut [u8]) -> Result<&'a [u8]> {
        let nonce = aead::Nonce::assume_unique_for_key(self.nonce(pn));
        self.aead
            .open_in_place(nonce, aead::Aad::from(header), payload)
            .map(|p| &*p)
            .map_err(|_| Error::Crypto("aead open"))
    }

    /// Five-byte header-protection mask for a ciphertext sample (RFC 9001 §5.4).
    pub fn header_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        let mut s = [0u8; 16];
        if sample.len() < 16 {
            return Err(Error::Crypto("hp sample too short"));
        }
        s.copy_from_slice(&sample[..16]);
        self.hp.new_mask(&s).map_err(|_| Error::Crypto("hp mask"))
    }
}

/// Wrap `rustls::quic` directional keys (Handshake / 1-RTT) into [`PacketKeys`]
/// shape via the rustls trait objects.
pub struct RustlsKeys {
    /// Header-protection trait object.
    pub header: Box<dyn rustls::quic::HeaderProtectionKey>,
    /// Packet AEAD trait object.
    pub packet: Box<dyn rustls::quic::PacketKey>,
}

impl RustlsKeys {
    /// Adopt one direction of a `rustls::quic::Keys` set.
    pub fn from_directional(d: rustls::quic::DirectionalKeys) -> RustlsKeys {
        RustlsKeys {
            header: d.header,
            packet: d.packet,
        }
    }

    /// Seal in place, returning the appended tag bytes.
    pub fn seal(&self, pn: u64, header: &[u8], payload: &mut Vec<u8>) -> Result<()> {
        let tag = self
            .packet
            .encrypt_in_place(pn, header, payload)
            .map_err(|_| Error::Crypto("rustls aead seal"))?;
        payload.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Open in place, returning the plaintext length.
    pub fn open(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<usize> {
        let pt = self
            .packet
            .decrypt_in_place(pn, header, payload)
            .map_err(|_| Error::Crypto("rustls aead open"))?;
        Ok(pt.len())
    }

    /// Header-protection mask for a sample.
    pub fn header_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        let mut first = 0u8;
        let mut pn = [0u8; 4];
        // rustls applies the mask in place; reproduce the raw mask by masking
        // a zeroed first byte + packet-number field.
        self.header
            .encrypt_in_place(sample, &mut first, &mut pn)
            .map_err(|_| Error::Crypto("rustls hp mask"))?;
        Ok([first, pn[0], pn[1], pn[2], pn[3]])
    }
}

/// AEAD tag length used by every cipher suite this engine negotiates.
pub const fn tag_len() -> usize {
    AEAD_TAG_LEN
}
