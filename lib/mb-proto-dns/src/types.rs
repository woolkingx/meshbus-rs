use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("truncated DNS message at offset {0}")]
    Truncated(usize),
    #[error("compression pointer loop or budget exceeded")]
    CompressionLoop,
    #[error("invalid label length byte {0:#x}")]
    InvalidLabel(u8),
    #[error("message oversize: {0}")]
    Oversize(&'static str),
    #[error("invalid rdata for type {0}")]
    InvalidRData(u16),
    #[error("not utf-8 in TXT rdata")]
    NotUtf8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QType {
    A = 1,
    Cname = 5,
    Ptr = 12,
    Txt = 16,
    Aaaa = 28,
    Opt = 41,
    Any = 255,
}

impl QType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::A),
            5 => Some(Self::Cname),
            12 => Some(Self::Ptr),
            16 => Some(Self::Txt),
            28 => Some(Self::Aaaa),
            41 => Some(Self::Opt),
            255 => Some(Self::Any),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RClass {
    In = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    canonical: String, // always trailing dot, ASCII lower per RFC 4343
}

impl Name {
    pub fn from_ascii(s: &str) -> Result<Self, DecodeError> {
        if s.is_empty() {
            return Err(DecodeError::InvalidLabel(0));
        }
        let mut out = String::with_capacity(s.len() + 1);
        for c in s.chars() {
            if !c.is_ascii() {
                return Err(DecodeError::NotUtf8);
            }
            out.push(c.to_ascii_lowercase());
        }
        if !out.ends_with('.') {
            out.push('.');
        }
        Ok(Self { canonical: out })
    }

    pub fn as_ascii_lower(&self) -> &str {
        &self.canonical
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.canonical.split('.').filter(|s| !s.is_empty())
    }

    pub fn default_root() -> Self {
        Self {
            canonical: ".".to_string(),
        }
    }
}

impl Default for Name {
    fn default() -> Self {
        Self::default_root()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub id: u16,
    pub flags: u16,
    qd: u16,
    an: u16,
    ns: u16,
    ar: u16,
}

impl MessageHeader {
    pub fn qdcount(&self) -> u16 {
        self.qd
    }
    pub fn ancount(&self) -> u16 {
        self.an
    }
    pub fn nscount(&self) -> u16 {
        self.ns
    }
    pub fn arcount(&self) -> u16 {
        self.ar
    }

    pub fn set_counts(&mut self, qd: u16, an: u16, ns: u16, ar: u16) {
        self.qd = qd;
        self.an = an;
        self.ns = ns;
        self.ar = ar;
    }

    pub fn qr(&self) -> bool {
        (self.flags >> 15) & 1 == 1
    }
    pub fn tc(&self) -> bool {
        (self.flags >> 9) & 1 == 1
    }
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: QType,
    pub qclass: RClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(Name),
    Cname(Name),
    Txt(Vec<String>),
    Opt {
        udp_payload_size: u16,
        ext_rcode: u8,
        edns_version: u8,
        flags: u16,
        options: Vec<u8>,
    },
    Opaque {
        qtype: u16,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: Name,
    pub qtype: QType,
    pub qclass: RClass,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: MessageHeader,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

#[derive(Debug, Clone, Copy)]
pub struct EdnsConfig {
    pub udp_payload_size: u16,
    pub dnssec_ok: bool,
}

impl Default for EdnsConfig {
    fn default() -> Self {
        Self {
            udp_payload_size: 1232,
            dnssec_ok: false,
        } // DNS Flag Day 2020 recommendation
    }
}
