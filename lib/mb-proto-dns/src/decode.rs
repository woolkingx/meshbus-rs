use crate::types::*;
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_POINTER_HOPS: usize = 16;

pub struct Cursor {
    pub pos: usize,
}

impl Cursor {
    pub fn new() -> Self {
        Self { pos: 0 }
    }

    pub fn u16(&mut self, buf: &[u8]) -> Result<u16, DecodeError> {
        if self.pos + 2 > buf.len() {
            return Err(DecodeError::Truncated(self.pos));
        }
        let v = u16::from_be_bytes([buf[self.pos], buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn u32(&mut self, buf: &[u8]) -> Result<u32, DecodeError> {
        if self.pos + 4 > buf.len() {
            return Err(DecodeError::Truncated(self.pos));
        }
        let v = u32::from_be_bytes([
            buf[self.pos],
            buf[self.pos + 1],
            buf[self.pos + 2],
            buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
}

impl Default for Cursor {
    fn default() -> Self {
        Self::new()
    }
}

pub fn decode_message(buf: &[u8]) -> Result<Message, DecodeError> {
    let mut cur = Cursor::new();
    let id = cur.u16(buf)?;
    let flags = cur.u16(buf)?;
    let qd = cur.u16(buf)?;
    let an = cur.u16(buf)?;
    let ns = cur.u16(buf)?;
    let ar = cur.u16(buf)?;
    let mut msg = Message::default();
    msg.header.id = id;
    msg.header.flags = flags;
    msg.header.set_counts(qd, an, ns, ar);
    for _ in 0..qd {
        let name = decode_name(buf, &mut cur)?;
        let qtype_raw = cur.u16(buf)?;
        let _qclass_raw = cur.u16(buf)?;
        // QType::A is a placeholder when the wire qtype is unknown to us;
        // callers that care must check the rdata variant (Opaque carries the real number).
        let qtype = QType::from_u16(qtype_raw).unwrap_or(QType::A);
        msg.questions.push(Question {
            name,
            qtype,
            qclass: RClass::In,
        });
    }
    for _ in 0..an {
        msg.answers.push(decode_rr(buf, &mut cur)?);
    }
    for _ in 0..ns {
        msg.authorities.push(decode_rr(buf, &mut cur)?);
    }
    for _ in 0..ar {
        msg.additionals.push(decode_rr(buf, &mut cur)?);
    }
    Ok(msg)
}

pub fn decode_name(buf: &[u8], cur: &mut Cursor) -> Result<Name, DecodeError> {
    let mut out = String::new();
    let mut jumps = 0usize;
    let mut pos = cur.pos;
    let mut followed_pointer = false;
    loop {
        if pos >= buf.len() {
            return Err(DecodeError::Truncated(pos));
        }
        let len = buf[pos];
        if len == 0 {
            if !followed_pointer {
                cur.pos = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(DecodeError::Truncated(pos));
            }
            let ptr = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
            if !followed_pointer {
                cur.pos = pos + 2;
                followed_pointer = true;
            }
            jumps += 1;
            if jumps > MAX_POINTER_HOPS {
                return Err(DecodeError::CompressionLoop);
            }
            // RFC 1035 §4.1.4: pointers must point to a prior name; self/forward pointers form cycles.
            if ptr >= pos {
                return Err(DecodeError::CompressionLoop);
            }
            pos = ptr;
            continue;
        }
        if len & 0xC0 != 0 {
            return Err(DecodeError::InvalidLabel(len));
        }
        let llen = len as usize;
        if pos + 1 + llen > buf.len() {
            return Err(DecodeError::Truncated(pos));
        }
        for &b in &buf[pos + 1..pos + 1 + llen] {
            if !b.is_ascii() {
                return Err(DecodeError::NotUtf8);
            }
            out.push((b as char).to_ascii_lowercase());
        }
        out.push('.');
        pos += 1 + llen;
    }
    if out.is_empty() {
        out.push('.');
    }
    Name::from_ascii(&out)
}

fn decode_rr(buf: &[u8], cur: &mut Cursor) -> Result<ResourceRecord, DecodeError> {
    let name = decode_name(buf, cur)?;
    let qtype_raw = cur.u16(buf)?;
    let qclass_raw = cur.u16(buf)?;
    let ttl = cur.u32(buf)?;
    let rdlen = cur.u16(buf)? as usize;
    if cur.pos + rdlen > buf.len() {
        return Err(DecodeError::Truncated(cur.pos));
    }
    let rdata_start = cur.pos;
    let rdata_slice = &buf[rdata_start..rdata_start + rdlen];
    let qtype_opt = QType::from_u16(qtype_raw);
    let data = match qtype_opt {
        Some(QType::A) => {
            if rdlen != 4 {
                return Err(DecodeError::InvalidRData(qtype_raw));
            }
            RData::A(Ipv4Addr::new(
                rdata_slice[0],
                rdata_slice[1],
                rdata_slice[2],
                rdata_slice[3],
            ))
        }
        Some(QType::Aaaa) => {
            if rdlen != 16 {
                return Err(DecodeError::InvalidRData(qtype_raw));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(rdata_slice);
            RData::Aaaa(Ipv6Addr::from(o))
        }
        Some(QType::Ptr) | Some(QType::Cname) => {
            // Name may use compression pointing outside the rdata window — decode against the full message.
            let mut sub = Cursor { pos: rdata_start };
            let n = decode_name(buf, &mut sub)?;
            if qtype_opt == Some(QType::Ptr) {
                RData::Ptr(n)
            } else {
                RData::Cname(n)
            }
        }
        Some(QType::Txt) => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < rdlen {
                let l = rdata_slice[i] as usize;
                if i + 1 + l > rdlen {
                    return Err(DecodeError::InvalidRData(qtype_raw));
                }
                let s = std::str::from_utf8(&rdata_slice[i + 1..i + 1 + l])
                    .map_err(|_| DecodeError::NotUtf8)?;
                parts.push(s.to_string());
                i += 1 + l;
            }
            RData::Txt(parts)
        }
        Some(QType::Opt) => RData::Opt {
            udp_payload_size: qclass_raw,
            ext_rcode: (ttl >> 24) as u8,
            edns_version: (ttl >> 16) as u8,
            flags: (ttl & 0xFFFF) as u16,
            options: rdata_slice.to_vec(),
        },
        _ => RData::Opaque {
            qtype: qtype_raw,
            raw: rdata_slice.to_vec(),
        },
    };
    cur.pos += rdlen;
    // qtype fallback to A: see decode_message; real qtype is preserved in RData::Opaque.qtype
    Ok(ResourceRecord {
        name,
        qtype: qtype_opt.unwrap_or(QType::A),
        qclass: RClass::In,
        ttl,
        data,
    })
}
