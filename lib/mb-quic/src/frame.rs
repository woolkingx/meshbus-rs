//! RFC 9000 §19 QUIC frames.
//!
//! M4 needs the handshake-critical subset; M5 extends this with STREAM /
//! MAX_DATA / DATAGRAM and friends. Unknown frame types are surfaced so the
//! connection can emit a protocol error.

use crate::packet::{decode_varint, encode_varint};
use crate::{Error, Result};

/// Largest single CRYPTO/STREAM/Datagram/ConnectionClose-reason payload mb-quic
/// will materialize from one frame (defense against peer-driven huge alloc).
pub const MAX_FRAME_PAYLOAD: usize = 1 << 20; // 1 MiB

/// One contiguous ACK range (RFC 9000 §19.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// Gap to the previous range (encoded value).
    pub gap: u64,
    /// Length of this acknowledged range minus one (encoded value).
    pub range: u64,
}

/// A decoded QUIC frame (subset used through M4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// PADDING (0x00) — coalesced run length.
    Padding(usize),
    /// PING (0x01).
    Ping,
    /// ACK (0x02) without ECN counts.
    Ack {
        /// Largest acknowledged packet number.
        largest: u64,
        /// ACK delay (encoded units).
        delay: u64,
        /// First ACK range.
        first_range: u64,
        /// Additional ranges.
        ranges: Vec<AckRange>,
    },
    /// RESET_STREAM (0x04).
    ResetStream {
        /// Stream being reset.
        stream_id: u64,
        /// Application error code.
        error_code: u64,
        /// Final size of the stream.
        final_size: u64,
    },
    /// STOP_SENDING (0x05).
    StopSending {
        /// Stream the peer should stop sending on.
        stream_id: u64,
        /// Application error code.
        error_code: u64,
    },
    /// CRYPTO (0x06) — offset + handshake bytes.
    Crypto {
        /// Stream offset within the crypto stream.
        offset: u64,
        /// Handshake payload bytes.
        data: Vec<u8>,
    },
    /// STREAM (0x08-0x0f) — application stream data.
    Stream {
        /// Stream identifier.
        id: u64,
        /// Byte offset of `data` within the stream.
        offset: u64,
        /// FIN bit: this is the last data on the stream.
        fin: bool,
        /// Stream payload bytes.
        data: Vec<u8>,
    },
    /// MAX_DATA (0x10) — connection-level flow-control limit.
    MaxData {
        /// New connection data limit.
        max: u64,
    },
    /// MAX_STREAM_DATA (0x11) — per-stream flow-control limit.
    MaxStreamData {
        /// Stream the limit applies to.
        stream_id: u64,
        /// New stream data limit.
        max: u64,
    },
    /// MAX_STREAMS (0x12 bidi / 0x13 uni).
    MaxStreams {
        /// True for the bidirectional stream limit.
        bidi: bool,
        /// New maximum stream count.
        max: u64,
    },
    /// DATA_BLOCKED (0x14).
    DataBlocked {
        /// Limit at which the sender is blocked.
        limit: u64,
    },
    /// STREAM_DATA_BLOCKED (0x15).
    StreamDataBlocked {
        /// Stream that is blocked.
        stream_id: u64,
        /// Limit at which the sender is blocked.
        limit: u64,
    },
    /// STREAMS_BLOCKED (0x16 bidi / 0x17 uni).
    StreamsBlocked {
        /// True for the bidirectional stream limit.
        bidi: bool,
        /// Stream count limit at which the sender is blocked.
        limit: u64,
    },
    /// CONNECTION_CLOSE (0x1c transport / 0x1d application).
    ConnectionClose {
        /// Whether this is an application close (0x1d).
        application: bool,
        /// Error code.
        error_code: u64,
        /// Reason phrase.
        reason: Vec<u8>,
    },
    /// HANDSHAKE_DONE (0x1e).
    HandshakeDone,
    /// DATAGRAM (0x30 / 0x31) — RFC 9221 unreliable datagram.
    Datagram {
        /// Datagram payload bytes.
        data: Vec<u8>,
    },
}

impl Frame {
    /// Encode a single frame.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Padding(n) => out.resize(out.len() + n, 0x00),
            Frame::Ping => out.push(0x01),
            Frame::Ack {
                largest,
                delay,
                first_range,
                ranges,
            } => {
                out.push(0x02);
                encode_varint(out, *largest);
                encode_varint(out, *delay);
                encode_varint(out, ranges.len() as u64);
                encode_varint(out, *first_range);
                for r in ranges {
                    encode_varint(out, r.gap);
                    encode_varint(out, r.range);
                }
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                out.push(0x04);
                encode_varint(out, *stream_id);
                encode_varint(out, *error_code);
                encode_varint(out, *final_size);
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                out.push(0x05);
                encode_varint(out, *stream_id);
                encode_varint(out, *error_code);
            }
            Frame::Crypto { offset, data } => {
                out.push(0x06);
                encode_varint(out, *offset);
                encode_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                // Canonical encoding: LEN bit always set so a STREAM frame is
                // self-delimiting when coalesced; OFF bit only when non-zero.
                let mut ty = 0x08 | 0x02;
                if *offset != 0 {
                    ty |= 0x04;
                }
                if *fin {
                    ty |= 0x01;
                }
                out.push(ty);
                encode_varint(out, *id);
                if *offset != 0 {
                    encode_varint(out, *offset);
                }
                encode_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::MaxData { max } => {
                out.push(0x10);
                encode_varint(out, *max);
            }
            Frame::MaxStreamData { stream_id, max } => {
                out.push(0x11);
                encode_varint(out, *stream_id);
                encode_varint(out, *max);
            }
            Frame::MaxStreams { bidi, max } => {
                out.push(if *bidi { 0x12 } else { 0x13 });
                encode_varint(out, *max);
            }
            Frame::DataBlocked { limit } => {
                out.push(0x14);
                encode_varint(out, *limit);
            }
            Frame::StreamDataBlocked { stream_id, limit } => {
                out.push(0x15);
                encode_varint(out, *stream_id);
                encode_varint(out, *limit);
            }
            Frame::StreamsBlocked { bidi, limit } => {
                out.push(if *bidi { 0x16 } else { 0x17 });
                encode_varint(out, *limit);
            }
            Frame::Datagram { data } => {
                // 0x31: length-prefixed so it can be coalesced before other
                // frames (RFC 9221 §4).
                out.push(0x31);
                encode_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::ConnectionClose {
                application,
                error_code,
                reason,
            } => {
                out.push(if *application { 0x1d } else { 0x1c });
                encode_varint(out, *error_code);
                if !*application {
                    encode_varint(out, 0); // frame type that triggered the error
                }
                encode_varint(out, reason.len() as u64);
                out.extend_from_slice(reason);
            }
            Frame::HandshakeDone => out.push(0x1e),
        }
    }

    /// Decode the next frame, returning it and the bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Frame, usize)> {
        let ty = *buf.first().ok_or(Error::ShortBuffer)?;
        match ty {
            0x00 => {
                let mut n = 0;
                while n < buf.len() && buf[n] == 0x00 {
                    n += 1;
                }
                Ok((Frame::Padding(n), n))
            }
            0x01 => Ok((Frame::Ping, 1)),
            0x02 | 0x03 => {
                let mut off = 1;
                let (largest, n) = decode_varint(&buf[off..])?;
                off += n;
                let (delay, n) = decode_varint(&buf[off..])?;
                off += n;
                let (count, n) = decode_varint(&buf[off..])?;
                off += n;
                let (first_range, n) = decode_varint(&buf[off..])?;
                off += n;
                let mut ranges = Vec::new();
                for _ in 0..count {
                    let (gap, n) = decode_varint(&buf[off..])?;
                    off += n;
                    let (range, n) = decode_varint(&buf[off..])?;
                    off += n;
                    ranges.push(AckRange { gap, range });
                }
                if ty == 0x03 {
                    // ECN counts: ect0, ect1, ce
                    for _ in 0..3 {
                        let (_, n) = decode_varint(&buf[off..])?;
                        off += n;
                    }
                }
                Ok((
                    Frame::Ack {
                        largest,
                        delay,
                        first_range,
                        ranges,
                    },
                    off,
                ))
            }
            0x04 => {
                let mut off = 1;
                let (stream_id, n) = decode_varint(&buf[off..])?;
                off += n;
                let (error_code, n) = decode_varint(&buf[off..])?;
                off += n;
                let (final_size, n) = decode_varint(&buf[off..])?;
                off += n;
                Ok((
                    Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    },
                    off,
                ))
            }
            0x05 => {
                let mut off = 1;
                let (stream_id, n) = decode_varint(&buf[off..])?;
                off += n;
                let (error_code, n) = decode_varint(&buf[off..])?;
                off += n;
                Ok((
                    Frame::StopSending {
                        stream_id,
                        error_code,
                    },
                    off,
                ))
            }
            0x06 => {
                let mut off = 1;
                let (offset, n) = decode_varint(&buf[off..])?;
                off += n;
                let (len, n) = decode_varint(&buf[off..])?;
                off += n;
                let len = len as usize;
                if len > MAX_FRAME_PAYLOAD {
                    return Err(Error::Malformed("frame payload exceeds MAX_FRAME_PAYLOAD"));
                }
                if off + len > buf.len() {
                    return Err(Error::ShortBuffer);
                }
                let data = buf[off..off + len].to_vec();
                off += len;
                Ok((Frame::Crypto { offset, data }, off))
            }
            0x08..=0x0f => {
                let off_bit = ty & 0x04 != 0;
                let len_bit = ty & 0x02 != 0;
                let fin = ty & 0x01 != 0;
                let mut off = 1;
                let (id, n) = decode_varint(&buf[off..])?;
                off += n;
                let offset = if off_bit {
                    let (v, n) = decode_varint(&buf[off..])?;
                    off += n;
                    v
                } else {
                    0
                };
                let dlen = if len_bit {
                    let (v, n) = decode_varint(&buf[off..])?;
                    off += n;
                    v as usize
                } else {
                    buf.len() - off
                };
                if dlen > MAX_FRAME_PAYLOAD {
                    return Err(Error::Malformed("frame payload exceeds MAX_FRAME_PAYLOAD"));
                }
                if off + dlen > buf.len() {
                    return Err(Error::ShortBuffer);
                }
                let data = buf[off..off + dlen].to_vec();
                off += dlen;
                Ok((
                    Frame::Stream {
                        id,
                        offset,
                        fin,
                        data,
                    },
                    off,
                ))
            }
            0x10 => {
                let (max, n) = decode_varint(&buf[1..])?;
                Ok((Frame::MaxData { max }, 1 + n))
            }
            0x11 => {
                let mut off = 1;
                let (stream_id, n) = decode_varint(&buf[off..])?;
                off += n;
                let (max, n) = decode_varint(&buf[off..])?;
                off += n;
                Ok((Frame::MaxStreamData { stream_id, max }, off))
            }
            0x12 | 0x13 => {
                let bidi = ty == 0x12;
                let (max, n) = decode_varint(&buf[1..])?;
                Ok((Frame::MaxStreams { bidi, max }, 1 + n))
            }
            0x14 => {
                let (limit, n) = decode_varint(&buf[1..])?;
                Ok((Frame::DataBlocked { limit }, 1 + n))
            }
            0x15 => {
                let mut off = 1;
                let (stream_id, n) = decode_varint(&buf[off..])?;
                off += n;
                let (limit, n) = decode_varint(&buf[off..])?;
                off += n;
                Ok((Frame::StreamDataBlocked { stream_id, limit }, off))
            }
            0x16 | 0x17 => {
                let bidi = ty == 0x16;
                let (limit, n) = decode_varint(&buf[1..])?;
                Ok((Frame::StreamsBlocked { bidi, limit }, 1 + n))
            }
            0x1c | 0x1d => {
                let application = ty == 0x1d;
                let mut off = 1;
                let (error_code, n) = decode_varint(&buf[off..])?;
                off += n;
                if !application {
                    let (_, n) = decode_varint(&buf[off..])?;
                    off += n;
                }
                let (rlen, n) = decode_varint(&buf[off..])?;
                off += n;
                let rlen = rlen as usize;
                if rlen > MAX_FRAME_PAYLOAD {
                    return Err(Error::Malformed("frame payload exceeds MAX_FRAME_PAYLOAD"));
                }
                if off + rlen > buf.len() {
                    return Err(Error::ShortBuffer);
                }
                let reason = buf[off..off + rlen].to_vec();
                off += rlen;
                Ok((
                    Frame::ConnectionClose {
                        application,
                        error_code,
                        reason,
                    },
                    off,
                ))
            }
            0x1e => Ok((Frame::HandshakeDone, 1)),
            0x30 => {
                let data = buf[1..].to_vec();
                Ok((Frame::Datagram { data }, buf.len()))
            }
            0x31 => {
                let (len, n) = decode_varint(&buf[1..])?;
                let off = 1 + n;
                let len = len as usize;
                if len > MAX_FRAME_PAYLOAD {
                    return Err(Error::Malformed("frame payload exceeds MAX_FRAME_PAYLOAD"));
                }
                if off + len > buf.len() {
                    return Err(Error::ShortBuffer);
                }
                let data = buf[off..off + len].to_vec();
                Ok((Frame::Datagram { data }, off + len))
            }
            other => {
                let _ = other;
                Err(Error::Malformed("unsupported frame type"))
            }
        }
    }
}

/// Decode every frame in a packet payload.
pub fn decode_all(mut buf: &[u8]) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    while !buf.is_empty() {
        let (f, n) = Frame::decode(buf)?;
        if n == 0 {
            break;
        }
        frames.push(f);
        buf = &buf[n..];
    }
    Ok(frames)
}
