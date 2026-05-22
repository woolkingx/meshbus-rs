//! Endpoint parsing — pure, no I/O.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("empty host")]
    EmptyHost,
    #[error("missing colon between host and port")]
    MissingColon,
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("host too long: {0} bytes (max 255)")]
    HostTooLong(usize),
    #[error("malformed ipv6 address (missing closing bracket)")]
    MalformedIpv6,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ParseError> {
        let host = host.into();
        if host.is_empty() {
            return Err(ParseError::EmptyHost);
        }
        if host.len() > 255 {
            return Err(ParseError::HostTooLong(host.len()));
        }
        if port == 0 {
            return Err(ParseError::InvalidPort("0".into()));
        }
        Ok(Self { host, port })
    }

    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let (host, port) = if let Some(rest) = input.strip_prefix('[') {
            let close = rest.find(']').ok_or(ParseError::MalformedIpv6)?;
            let host = &rest[..close];
            let after = &rest[close + 1..];
            let port_str = after.strip_prefix(':').ok_or(ParseError::MissingColon)?;
            (host.to_string(), port_str)
        } else {
            let idx = input.rfind(':').ok_or(ParseError::MissingColon)?;
            (input[..idx].to_string(), &input[idx + 1..])
        };
        let port: u16 = port
            .parse()
            .map_err(|_| ParseError::InvalidPort(port.into()))?;
        Self::new(host, port)
    }

    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}
