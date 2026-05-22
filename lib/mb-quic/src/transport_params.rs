//! RFC 9000 §18 QUIC transport parameters (the subset this engine negotiates).
//!
//! Parameters are carried inside the TLS 1.3 `quic_transport_parameters`
//! extension as a sequence of `{id, length, value}` varint-prefixed entries.

use crate::packet::{decode_varint, encode_varint};
use crate::{ConnectionId, Error, Result};

// RFC 9000 §18.2 parameter ids used here.
const TP_ORIGINAL_DCID: u64 = 0x00;
const TP_MAX_IDLE_TIMEOUT: u64 = 0x01;
const TP_MAX_UDP_PAYLOAD: u64 = 0x03;
const TP_INITIAL_MAX_DATA: u64 = 0x04;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const TP_INITIAL_SCID: u64 = 0x0f;
const TP_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

/// Negotiated QUIC transport parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParameters {
    /// `original_destination_connection_id` (server only).
    pub original_dcid: Option<ConnectionId>,
    /// `initial_source_connection_id`.
    pub initial_scid: Option<ConnectionId>,
    /// `max_idle_timeout` in milliseconds (0 = disabled).
    pub max_idle_timeout_ms: u64,
    /// `max_udp_payload_size`.
    pub max_udp_payload_size: u64,
    /// `initial_max_data` connection-level flow control.
    pub initial_max_data: u64,
    /// `initial_max_stream_data_bidi_local`.
    pub initial_max_stream_data_bidi_local: u64,
    /// `initial_max_stream_data_bidi_remote`.
    pub initial_max_stream_data_bidi_remote: u64,
    /// `initial_max_stream_data_uni`.
    pub initial_max_stream_data_uni: u64,
    /// `initial_max_streams_bidi`.
    pub initial_max_streams_bidi: u64,
    /// `initial_max_streams_uni`.
    pub initial_max_streams_uni: u64,
    /// `max_datagram_frame_size` (0 = QUIC DATAGRAM disabled).
    pub max_datagram_frame_size: u64,
}

impl Default for TransportParameters {
    fn default() -> Self {
        TransportParameters {
            original_dcid: None,
            initial_scid: None,
            max_idle_timeout_ms: 30_000,
            max_udp_payload_size: 1452,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 256 * 1024,
            initial_max_stream_data_bidi_remote: 256 * 1024,
            initial_max_stream_data_uni: 256 * 1024,
            initial_max_streams_bidi: 64,
            initial_max_streams_uni: 8,
            max_datagram_frame_size: 1200,
        }
    }
}

fn put_int(out: &mut Vec<u8>, id: u64, value: u64) {
    encode_varint(out, id);
    let mut v = Vec::new();
    encode_varint(&mut v, value);
    encode_varint(out, v.len() as u64);
    out.extend_from_slice(&v);
}

fn put_cid(out: &mut Vec<u8>, id: u64, cid: &ConnectionId) {
    encode_varint(out, id);
    encode_varint(out, cid.len() as u64);
    out.extend_from_slice(cid.as_slice());
}

impl TransportParameters {
    /// Encode to the `quic_transport_parameters` extension body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(c) = &self.original_dcid {
            put_cid(&mut out, TP_ORIGINAL_DCID, c);
        }
        if let Some(c) = &self.initial_scid {
            put_cid(&mut out, TP_INITIAL_SCID, c);
        }
        put_int(&mut out, TP_MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms);
        put_int(&mut out, TP_MAX_UDP_PAYLOAD, self.max_udp_payload_size);
        put_int(&mut out, TP_INITIAL_MAX_DATA, self.initial_max_data);
        put_int(
            &mut out,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        );
        put_int(
            &mut out,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        );
        put_int(
            &mut out,
            TP_INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        );
        put_int(
            &mut out,
            TP_INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
        );
        put_int(
            &mut out,
            TP_INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        );
        put_int(
            &mut out,
            TP_MAX_DATAGRAM_FRAME_SIZE,
            self.max_datagram_frame_size,
        );
        out
    }

    /// Decode from the `quic_transport_parameters` extension body.
    pub fn decode(buf: &[u8]) -> Result<TransportParameters> {
        let mut tp = TransportParameters {
            max_idle_timeout_ms: 0,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_datagram_frame_size: 0,
            original_dcid: None,
            initial_scid: None,
        };
        let mut off = 0usize;
        while off < buf.len() {
            let (id, n) = decode_varint(&buf[off..])?;
            off += n;
            let (len, n) = decode_varint(&buf[off..])?;
            off += n;
            let len = len as usize;
            if off + len > buf.len() {
                return Err(Error::ShortBuffer);
            }
            let val = &buf[off..off + len];
            off += len;
            match id {
                TP_ORIGINAL_DCID => tp.original_dcid = Some(ConnectionId::new(val)?),
                TP_INITIAL_SCID => tp.initial_scid = Some(ConnectionId::new(val)?),
                TP_MAX_IDLE_TIMEOUT => tp.max_idle_timeout_ms = decode_varint(val)?.0,
                TP_MAX_UDP_PAYLOAD => tp.max_udp_payload_size = decode_varint(val)?.0,
                TP_INITIAL_MAX_DATA => tp.initial_max_data = decode_varint(val)?.0,
                TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    tp.initial_max_stream_data_bidi_local = decode_varint(val)?.0
                }
                TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    tp.initial_max_stream_data_bidi_remote = decode_varint(val)?.0
                }
                TP_INITIAL_MAX_STREAM_DATA_UNI => {
                    tp.initial_max_stream_data_uni = decode_varint(val)?.0
                }
                TP_INITIAL_MAX_STREAMS_BIDI => tp.initial_max_streams_bidi = decode_varint(val)?.0,
                TP_INITIAL_MAX_STREAMS_UNI => tp.initial_max_streams_uni = decode_varint(val)?.0,
                TP_MAX_DATAGRAM_FRAME_SIZE => tp.max_datagram_frame_size = decode_varint(val)?.0,
                _ => {} // unknown parameters are ignored per RFC 9000 §18.1
            }
        }
        Ok(tp)
    }
}
