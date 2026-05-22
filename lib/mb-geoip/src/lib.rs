//! mb-geoip — MMDB-backed country + ASN lookup with empty-DB fallback.

pub mod data_handle;
pub mod types;

pub use data_handle::{GeoIpDb, GeoIpError};
pub use types::GeoIpResult;
