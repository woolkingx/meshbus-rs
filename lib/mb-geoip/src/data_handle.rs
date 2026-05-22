use crate::types::GeoIpResult;
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeoIpError {
    #[error("mmdb open: {0}")]
    Open(String),
}

#[derive(Default)]
pub struct GeoIpDb {
    inner: Option<MmdbHandles>,
}

impl std::fmt::Debug for GeoIpDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpDb")
            .field("loaded", &self.inner.is_some())
            .finish()
    }
}

struct MmdbHandles {
    country: maxminddb::Reader<Vec<u8>>,
    asn: maxminddb::Reader<Vec<u8>>,
}

impl GeoIpDb {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn open(country_path: &Path, asn_path: &Path) -> Result<Self, GeoIpError> {
        let country = maxminddb::Reader::open_readfile(country_path)
            .map_err(|e| GeoIpError::Open(e.to_string()))?;
        let asn = maxminddb::Reader::open_readfile(asn_path)
            .map_err(|e| GeoIpError::Open(e.to_string()))?;
        Ok(Self {
            inner: Some(MmdbHandles { country, asn }),
        })
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoIpResult {
        let Some(h) = &self.inner else {
            return GeoIpResult::unknown();
        };
        let country = h
            .country
            .lookup::<maxminddb::geoip2::Country>(ip)
            .ok()
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code)
            .unwrap_or("XX")
            .to_string();
        let (asn, asn_org) = h
            .asn
            .lookup::<maxminddb::geoip2::Asn>(ip)
            .ok()
            .map(|a| {
                (
                    a.autonomous_system_number.unwrap_or(0),
                    a.autonomous_system_organization.unwrap_or("").to_string(),
                )
            })
            .unwrap_or((0, String::new()));
        GeoIpResult {
            country,
            asn,
            asn_org,
        }
    }
}
