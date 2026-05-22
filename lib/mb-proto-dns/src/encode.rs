use crate::types::*;
use bytes::{BufMut, BytesMut};

pub fn encode_message(msg: &Message) -> Result<Vec<u8>, DecodeError> {
    if msg.questions.len() > u16::MAX as usize
        || msg.answers.len() > u16::MAX as usize
        || msg.authorities.len() > u16::MAX as usize
        || msg.additionals.len() > u16::MAX as usize
    {
        return Err(DecodeError::Oversize("section count > u16"));
    }
    let mut buf = BytesMut::with_capacity(512);
    buf.put_u16(msg.header.id);
    buf.put_u16(msg.header.flags);
    buf.put_u16(msg.questions.len() as u16);
    buf.put_u16(msg.answers.len() as u16);
    buf.put_u16(msg.authorities.len() as u16);
    buf.put_u16(msg.additionals.len() as u16);
    for q in &msg.questions {
        encode_name(&q.name, &mut buf)?;
        buf.put_u16(q.qtype as u16);
        buf.put_u16(q.qclass as u16);
    }
    for rr in msg
        .answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
    {
        encode_rr(rr, &mut buf)?;
    }
    Ok(buf.to_vec())
}

pub fn encode_name(name: &Name, buf: &mut BytesMut) -> Result<(), DecodeError> {
    for label in name.labels() {
        if label.len() > 63 {
            return Err(DecodeError::Oversize("label > 63 octets"));
        }
        buf.put_u8(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.put_u8(0);
    Ok(())
}

fn encode_rr(rr: &ResourceRecord, buf: &mut BytesMut) -> Result<(), DecodeError> {
    // OPT pseudo-RR has its own field layout (RFC 6891 §6.1.2/3)
    if rr.qtype == QType::Opt {
        let RData::Opt {
            udp_payload_size,
            ext_rcode,
            edns_version,
            flags,
            options,
        } = &rr.data
        else {
            return Err(DecodeError::InvalidRData(QType::Opt as u16));
        };
        // NAME = root (single 0 octet)
        buf.put_u8(0);
        buf.put_u16(QType::Opt as u16);
        buf.put_u16(*udp_payload_size);
        let ttl: u32 =
            ((*ext_rcode as u32) << 24) | ((*edns_version as u32) << 16) | (*flags as u32);
        buf.put_u32(ttl);
        if options.len() > u16::MAX as usize {
            return Err(DecodeError::Oversize("OPT options > u16"));
        }
        buf.put_u16(options.len() as u16);
        buf.extend_from_slice(options);
        return Ok(());
    }

    encode_name(&rr.name, buf)?;
    buf.put_u16(rr.qtype as u16);
    buf.put_u16(rr.qclass as u16);
    buf.put_u32(rr.ttl);
    let rdata_start = buf.len();
    buf.put_u16(0); // rdlen placeholder
    let rdata_body_start = buf.len();
    match &rr.data {
        RData::A(ip) => buf.extend_from_slice(&ip.octets()),
        RData::Aaaa(ip) => buf.extend_from_slice(&ip.octets()),
        RData::Ptr(n) | RData::Cname(n) => encode_name(n, buf)?,
        RData::Txt(parts) => {
            for p in parts {
                if p.len() > 255 {
                    return Err(DecodeError::Oversize("TXT segment > 255"));
                }
                buf.put_u8(p.len() as u8);
                buf.extend_from_slice(p.as_bytes());
            }
        }
        RData::Opt { .. } => unreachable!("OPT handled above"),
        RData::Opaque { raw, .. } => buf.extend_from_slice(raw),
    }
    let rdlen = buf.len() - rdata_body_start;
    if rdlen > u16::MAX as usize {
        return Err(DecodeError::Oversize("rdata > u16"));
    }
    let rdlen_bytes = (rdlen as u16).to_be_bytes();
    buf[rdata_start] = rdlen_bytes[0];
    buf[rdata_start + 1] = rdlen_bytes[1];
    Ok(())
}

pub fn edns_opt_rr(cfg: &EdnsConfig) -> ResourceRecord {
    let flags = if cfg.dnssec_ok { 0x8000_u16 } else { 0 };
    ResourceRecord {
        name: Name::default_root(),
        qtype: QType::Opt,
        qclass: RClass::In, // ignored by encode_rr's OPT path; field unused for OPT wire
        ttl: 0,             // ignored by encode_rr's OPT path
        data: RData::Opt {
            udp_payload_size: cfg.udp_payload_size,
            ext_rcode: 0,
            edns_version: 0,
            flags,
            options: Vec::new(),
        },
    }
}
