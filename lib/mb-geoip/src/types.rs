use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoIpResult {
    /// ISO 3166-1 alpha-2 country code; "XX" when unknown.
    pub country: String,
    /// Autonomous System Number; 0 when unknown.
    pub asn: u32,
    /// AS organization label; empty when unknown.
    pub asn_org: String,
}

impl GeoIpResult {
    pub fn unknown() -> Self {
        Self {
            country: "XX".into(),
            asn: 0,
            asn_org: String::new(),
        }
    }
}
