//! YAML config schema for the bus runtime.
//!
//! Pure deserialization + validation. No tokio, no I/O, no plugin assembly —
//! `run()` in `lib.rs` owns runtime wiring.

mod health;
mod meshsec;
mod observability;
mod pipeline;
mod plugins;
mod scheduler;

pub use crate::config_validate::validate_config;
pub use health::HealthCfg;
pub(crate) use meshsec::MeshSecKeyRoleCfg;
pub use meshsec::{MeshSecPeerCfg, MeshSecProfileCfg, NodeCfg, PeerCfg};
pub use observability::{LogFormat, LoggingCfg, MetricsCfg, OperatorAuthCfg, OperatorCfg};
pub use pipeline::{DnsCacheCfg, GeoIpCfg, GeositeCfg, PipelineCfg, PipelineSourceCfg};
pub use plugins::{
    AuthCfg, AuthUserCfg, EgressCfg, IngressCfg, Socks5UpstreamAuthCfg, TrafficClassCfg,
};
pub use scheduler::{LoadBalanceModeCfg, SchedulerCfg};

use anyhow::anyhow;
use serde::Deserialize;

/// Top-level config loaded from YAML.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub node: Option<NodeCfg>,
    #[serde(default)]
    pub peers: Vec<PeerCfg>,
    #[serde(default)]
    pub logging: LoggingCfg,
    #[serde(default)]
    pub health: HealthCfg,
    #[serde(default)]
    pub metrics: Option<MetricsCfg>,
    #[serde(default)]
    pub operator: Option<OperatorCfg>,
    #[serde(default)]
    pub scheduler: SchedulerCfg,
    pub ingresses: Vec<IngressCfg>,
    pub egresses: Vec<EgressCfg>,
    #[serde(default)]
    pub pipeline: Option<PipelineCfg>,
}

impl Config {
    /// Sender-side MeshSec material for the named adjacent peer. `boot_salt`
    /// is generated once per runtime boot by the caller. Returns `None` when
    /// the peer is unknown, has no `meshsec`, or `node.id` is absent
    /// (config validation already rejects meshsec without node.id).
    pub fn meshsec_seal_context(
        &self,
        peer_id: &str,
        boot_salt: [u8; 4],
    ) -> Option<mb_proto_mesh::MeshSecSealContext> {
        let local_node_id = self.node.as_ref()?.id.clone();
        let peer = self.peers.iter().find(|p| p.id == peer_id)?;
        let meshsec = peer.meshsec.as_ref()?;
        Some(mb_proto_mesh::MeshSecSealContext {
            local_node_id,
            remote_node_id: peer.node_id.clone(),
            static_key: meshsec.static_key()?,
            boot_salt,
        })
    }

    /// Receiver-side MeshSec keys for every configured peer that has
    /// `meshsec`. The opener resolves the right key per packet by
    /// `receiver_hint`, so all keys are offered together.
    pub fn meshsec_open_keys(&self) -> Vec<mb_proto_mesh::MeshSecOpenKey> {
        self.peers
            .iter()
            .flat_map(|peer| {
                let meshsec = peer.meshsec.as_ref()?;
                Some(meshsec.open_static_keys().into_iter().map(|static_key| {
                    mb_proto_mesh::MeshSecOpenKey {
                        peer_id: peer.id.clone(),
                        remote_node_id: peer.node_id.clone(),
                        static_key,
                    }
                }))
            })
            .flatten()
            .collect()
    }
}

/// Parse a `Config` from a YAML string.
pub fn parse_config(yaml: &str) -> anyhow::Result<Config> {
    let mut cfg: Config =
        serde_yaml::from_str(yaml).map_err(|e| anyhow!("config parse error: {e}"))?;
    for egress in &mut cfg.egresses {
        if let EgressCfg::ServiceTcp {
            route_group: Some(rg),
            groups,
            ..
        }
        | EgressCfg::ServiceUdp {
            route_group: Some(rg),
            groups,
            ..
        } = egress
        {
            if !rg.is_empty() && !groups.iter().any(|g| g == rg) {
                groups.push(rg.clone());
            }
        }
    }
    validate_config(&cfg)?;
    Ok(cfg)
}
