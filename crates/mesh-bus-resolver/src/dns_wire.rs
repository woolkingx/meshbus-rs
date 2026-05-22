use crate::types::*;

/// Build an RFC 1035 query wire payload for the given qname / qtype.
/// Sets RD=1 and appends an EDNS OPT pseudo-RR (default UDP payload size).
pub(crate) fn build_query(txid: u16, qname: &str, qtype: QType) -> Result<Vec<u8>, ResolveError> {
    use mb_proto_dns::{EdnsConfig, Message, Name, Question, RClass};

    let name = Name::from_ascii(qname).map_err(ResolveError::Decode)?;
    let dns_qtype = qtype_to_dns(qtype);
    let mut msg = Message::default();
    msg.header.id = txid;
    msg.header.flags = 0x0100; // RD=1
    msg.questions.push(Question {
        name,
        qtype: dns_qtype,
        qclass: RClass::In,
    });
    let edns = mb_proto_dns::encode::edns_opt_rr(&EdnsConfig::default());
    msg.additionals.push(edns);
    mb_proto_dns::encode::encode_message(&msg).map_err(ResolveError::Decode)
}

pub(crate) fn qtype_to_dns(q: QType) -> mb_proto_dns::QType {
    match q {
        QType::A => mb_proto_dns::QType::A,
        QType::Aaaa => mb_proto_dns::QType::Aaaa,
        QType::Ptr => mb_proto_dns::QType::Ptr,
        QType::Cname => mb_proto_dns::QType::Cname,
        QType::Txt => mb_proto_dns::QType::Txt,
    }
}

/// Validate TXID + question QNAME match (RFC 5452 + RFC 4343 case-insensitive).
pub(crate) fn validate_reply(reply: &mb_proto_dns::Message, txid: u16, qname_lower: &str) -> bool {
    if reply.header.id != txid {
        return false;
    }
    if let Some(q) = reply.questions.first() {
        q.name.as_ascii_lower() == qname_lower
    } else {
        true
    }
}

pub(crate) fn rdata_to_answer(rr: &mb_proto_dns::ResourceRecord) -> Option<AnswerRecord> {
    match &rr.data {
        mb_proto_dns::RData::A(ip) => Some(AnswerRecord::A(*ip)),
        mb_proto_dns::RData::Aaaa(ip) => Some(AnswerRecord::Aaaa(*ip)),
        mb_proto_dns::RData::Ptr(n) => Some(AnswerRecord::Ptr(n.as_ascii_lower().to_string())),
        mb_proto_dns::RData::Cname(n) => Some(AnswerRecord::Cname(n.as_ascii_lower().to_string())),
        mb_proto_dns::RData::Txt(parts) => Some(AnswerRecord::Txt(parts.clone())),
        _ => None,
    }
}

/// Normalize a qname for case-insensitive comparison: lowercase + trailing dot.
pub(crate) fn normalize_qname(qname: &str) -> String {
    let mut s = qname.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}
