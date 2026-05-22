//! RFC 9000 §16-§17 packet framing: varints, connection IDs, packet numbers,
//! long-header and short-header parse/serialize.

use crate::{Error, Result};

/// Maximum value representable by a QUIC variable-length integer.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Encode an RFC 9000 §16 variable-length integer.
pub fn encode_varint(out: &mut Vec<u8>, value: u64) {
    debug_assert!(value <= VARINT_MAX);
    if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Byte length a value would occupy as a varint.
pub fn varint_len(value: u64) -> usize {
    if value < 1 << 6 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        8
    }
}

/// Decode an RFC 9000 §16 varint, returning the value and bytes consumed.
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf.first().ok_or(Error::ShortBuffer)?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(Error::ShortBuffer);
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Ok((value, len))
}

/// A QUIC connection ID (0-20 bytes, RFC 9000 §5.1).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    /// Build from a slice (truncated/rejected above 20 bytes per RFC 9000).
    pub fn new(src: &[u8]) -> Result<ConnectionId> {
        if src.len() > 20 {
            return Err(Error::Malformed("connection id > 20 bytes"));
        }
        let mut bytes = [0u8; 20];
        bytes[..src.len()].copy_from_slice(src);
        Ok(ConnectionId {
            bytes,
            len: src.len() as u8,
        })
    }

    /// Generate a random connection ID of the given length.
    pub fn random(len: usize) -> ConnectionId {
        use rand::RngCore;
        let len = len.min(20);
        let mut bytes = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut bytes[..len]);
        ConnectionId {
            bytes,
            len: len as u8,
        }
    }

    /// Borrow the active ID bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Number of ID bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether this is the zero-length connection ID.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cid(")?;
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Long-header packet types (RFC 9000 §17.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LongType {
    /// Initial packet (carries the Initial CRYPTO stream and a token).
    Initial,
    /// Handshake packet.
    Handshake,
    /// 0-RTT packet (not produced by this engine; parsed for completeness).
    ZeroRtt,
    /// Retry packet.
    Retry,
}

impl LongType {
    fn type_bits(self) -> u8 {
        match self {
            LongType::Initial => 0b00,
            LongType::ZeroRtt => 0b01,
            LongType::Handshake => 0b10,
            LongType::Retry => 0b11,
        }
    }

    fn from_bits(bits: u8) -> LongType {
        match bits & 0b11 {
            0b00 => LongType::Initial,
            0b01 => LongType::ZeroRtt,
            0b10 => LongType::Handshake,
            _ => LongType::Retry,
        }
    }
}

/// Parsed long header up to (but excluding) the protected length/packet-number.
#[derive(Clone, Debug)]
pub struct LongHeader {
    /// Long-header packet type.
    pub ty: LongType,
    /// Wire version field.
    pub version: u32,
    /// Destination connection ID.
    pub dcid: ConnectionId,
    /// Source connection ID.
    pub scid: ConnectionId,
    /// Initial token (empty for non-Initial).
    pub token: Vec<u8>,
}

/// Encode the truncated packet number into `out` using `nbytes` (1-4) bytes.
pub fn encode_packet_number(out: &mut Vec<u8>, pn: u64, nbytes: usize) {
    let be = pn.to_be_bytes();
    out.extend_from_slice(&be[8 - nbytes..]);
}

/// Number of bytes needed to encode `pn` against `largest_acked` (RFC 9000 §17.1).
pub fn packet_number_len(pn: u64, largest_acked: Option<u64>) -> usize {
    let range = match largest_acked {
        Some(acked) => pn.saturating_sub(acked) * 2 + 1,
        None => pn + 1,
    };
    if range < 1 << 8 {
        1
    } else if range < 1 << 16 {
        2
    } else if range < 1 << 24 {
        3
    } else {
        4
    }
}

/// Decode a truncated packet number (RFC 9000 Appendix A.3).
pub fn decode_packet_number(largest_pn: u64, truncated: u64, pn_nbits: u32) -> u64 {
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let expected = largest_pn + 1;
    let candidate = (expected & !pn_mask) | truncated;
    if candidate + pn_hwin <= expected && candidate + pn_win < (1u64 << 62) {
        candidate + pn_win
    } else if candidate > expected + pn_hwin && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    }
}

/// Serialize a long header (everything before Length for Initial/Handshake).
pub fn write_long_header(out: &mut Vec<u8>, h: &LongHeader, first_byte_low: u8) {
    let first = 0b1100_0000 | (h.ty.type_bits() << 4) | (first_byte_low & 0x0f);
    out.push(first);
    out.extend_from_slice(&h.version.to_be_bytes());
    out.push(h.dcid.len() as u8);
    out.extend_from_slice(h.dcid.as_slice());
    out.push(h.scid.len() as u8);
    out.extend_from_slice(h.scid.as_slice());
    if h.ty == LongType::Initial {
        encode_varint(out, h.token.len() as u64);
        out.extend_from_slice(&h.token);
    }
}

/// Parse a long header. Returns the header and the offset of the byte after it
/// (the Length field for Initial/Handshake).
pub fn parse_long_header(buf: &[u8]) -> Result<(LongHeader, u8, usize)> {
    let first = *buf.first().ok_or(Error::ShortBuffer)?;
    if first & 0x80 == 0 {
        return Err(Error::Malformed("not a long header"));
    }
    if buf.len() < 7 {
        return Err(Error::ShortBuffer);
    }
    let ty = LongType::from_bits(first >> 4);
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let mut off = 5usize;
    let dcid_len = buf[off] as usize;
    off += 1;
    if buf.len() < off + dcid_len + 1 {
        return Err(Error::ShortBuffer);
    }
    let dcid = ConnectionId::new(&buf[off..off + dcid_len])?;
    off += dcid_len;
    let scid_len = buf[off] as usize;
    off += 1;
    if buf.len() < off + scid_len {
        return Err(Error::ShortBuffer);
    }
    let scid = ConnectionId::new(&buf[off..off + scid_len])?;
    off += scid_len;
    let mut token = Vec::new();
    if ty == LongType::Initial {
        let (tlen, n) = decode_varint(&buf[off..])?;
        off += n;
        if buf.len() < off + tlen as usize {
            return Err(Error::ShortBuffer);
        }
        token = buf[off..off + tlen as usize].to_vec();
        off += tlen as usize;
    }
    Ok((
        LongHeader {
            ty,
            version,
            dcid,
            scid,
            token,
        },
        first & 0x0f,
        off,
    ))
}

/// Parse a short-header (1-RTT) packet's destination connection ID.
/// `dcid_len` is known from the connection (RFC 9000 §17.3).
pub fn parse_short_header_dcid(buf: &[u8], dcid_len: usize) -> Result<(ConnectionId, usize)> {
    let first = *buf.first().ok_or(Error::ShortBuffer)?;
    if first & 0x80 != 0 {
        return Err(Error::Malformed("not a short header"));
    }
    if buf.len() < 1 + dcid_len {
        return Err(Error::ShortBuffer);
    }
    let dcid = ConnectionId::new(&buf[1..1 + dcid_len])?;
    Ok((dcid, 1 + dcid_len))
}
