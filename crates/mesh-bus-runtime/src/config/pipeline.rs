//! Event-pipeline operator config.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level event-pipeline block; when present, runtime assembles a
/// protocol-neutral `PipelineRuntime`. The selected `pipeline.source`
/// adapter uses that runtime; unselected ingresses keep their own
/// legacy/no-policy path.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PipelineCfg {
    #[serde(default)]
    pub rule_chain_path: Option<PathBuf>,
    #[serde(default)]
    pub rule_chain_forward: Option<PathBuf>,
    #[serde(default)]
    pub rule_chain_resolver: Option<PathBuf>,
    #[serde(default)]
    pub geoip: Option<GeoIpCfg>,
    #[serde(default)]
    pub geosite: Option<GeositeCfg>,
    #[serde(default)]
    pub dns_cache: Option<DnsCacheCfg>,
    #[serde(default)]
    pub source: PipelineSourceCfg,
}

impl PipelineCfg {
    pub fn forward_rule_chain_path(&self) -> Option<&PathBuf> {
        self.rule_chain_forward
            .as_ref()
            .or(self.rule_chain_path.as_ref())
    }
}

/// SourceSpec projection for the event-pipeline registry.
///
/// `ingress_index` selects which configured source adapter owns this source.
/// `id`, `kind`, and `initial_writes` describe the protocol-neutral metadata
/// contract the adapter supplies to the kernel registry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PipelineSourceCfg {
    #[serde(default)]
    pub ingress_index: Option<usize>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default = "default_pipeline_source_kind")]
    pub kind: String,
    #[serde(default = "default_pipeline_source_initial_writes")]
    pub initial_writes: Vec<String>,
}

impl Default for PipelineSourceCfg {
    fn default() -> Self {
        Self {
            ingress_index: None,
            id: None,
            kind: default_pipeline_source_kind(),
            initial_writes: default_pipeline_source_initial_writes(),
        }
    }
}

fn default_pipeline_source_kind() -> String {
    "application/source".into()
}

fn default_pipeline_source_initial_writes() -> Vec<String> {
    vec![
        "net.dst_host".into(),
        "net.dst_port".into(),
        "net.protocol".into(),
        "net.src_ip".into(),
        "auth.user".into(),
        "trace.flow_id".into(),
        "ext.operation".into(),
        "ext.dst_ip_primary".into(),
    ]
}

/// Optional GeoIP database paths consumed by `net.enrich_geo_asn` hook.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct GeoIpCfg {
    #[serde(default)]
    pub country_path: Option<PathBuf>,
    #[serde(default)]
    pub asn_path: Option<PathBuf>,
}

/// Optional domain-side geosite data consumed by `net.enrich_geo_asn`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct GeositeCfg {
    #[serde(default)]
    pub path: Option<PathBuf>,
}

/// Optional DNS cache knobs for the resolver-backed pipeline hook.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsCacheCfg {
    #[serde(default)]
    pub serve_stale_window_ms: Option<u64>,
}
