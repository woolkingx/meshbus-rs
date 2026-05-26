//! Scheduler operator config.

use mesh_bus_scheduler_loadbalance::{LoadBalanceMode, MaxAgePolicy, SourceLeaseRotateSettings};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum SchedulerCfg {
    Cake {},
    Replicate {},
    LoadBalance {
        mode: LoadBalanceModeCfg,
        #[serde(default = "default_sticky_ttl_secs")]
        sticky_ttl_secs: u64,
        #[serde(default)]
        source_lease_rotate: SourceLeaseRotateCfg,
    },
}

impl Default for SchedulerCfg {
    fn default() -> Self {
        Self::Cake {}
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceModeCfg {
    RoundRobin,
    StickySessions,
    ConsistentHashing,
    SourceLeaseRotate,
}

fn default_sticky_ttl_secs() -> u64 {
    600
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SourceLeaseRotateCfg {
    pub key_scope: SourceLeaseKeyScopeCfg,
    pub idle_timeout_secs: u64,
    pub max_age_secs: u64,
    pub max_age_policy: SourceLeaseMaxAgePolicyCfg,
    pub switch_cooldown_secs: u64,
}

impl Default for SourceLeaseRotateCfg {
    fn default() -> Self {
        Self {
            key_scope: SourceLeaseKeyScopeCfg::Source,
            idle_timeout_secs: 600,
            max_age_secs: 3_600,
            max_age_policy: SourceLeaseMaxAgePolicyCfg::Off,
            switch_cooldown_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceLeaseKeyScopeCfg {
    Source,
}

impl Default for SourceLeaseKeyScopeCfg {
    fn default() -> Self {
        Self::Source
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceLeaseMaxAgePolicyCfg {
    Off,
    Soft,
    Hard,
}

impl Default for SourceLeaseMaxAgePolicyCfg {
    fn default() -> Self {
        Self::Off
    }
}

impl SchedulerCfg {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cake { .. } => "Cake",
            Self::Replicate { .. } => "Replicate",
            Self::LoadBalance { .. } => "LoadBalance",
        }
    }
}

impl From<LoadBalanceModeCfg> for LoadBalanceMode {
    fn from(value: LoadBalanceModeCfg) -> Self {
        match value {
            LoadBalanceModeCfg::RoundRobin => Self::RoundRobin,
            LoadBalanceModeCfg::StickySessions => Self::StickySessions,
            LoadBalanceModeCfg::ConsistentHashing => Self::ConsistentHashing,
            LoadBalanceModeCfg::SourceLeaseRotate => Self::SourceLeaseRotate,
        }
    }
}

impl From<SourceLeaseMaxAgePolicyCfg> for MaxAgePolicy {
    fn from(value: SourceLeaseMaxAgePolicyCfg) -> Self {
        match value {
            SourceLeaseMaxAgePolicyCfg::Off => Self::Off,
            SourceLeaseMaxAgePolicyCfg::Soft => Self::Soft,
            SourceLeaseMaxAgePolicyCfg::Hard => Self::Hard,
        }
    }
}

impl From<SourceLeaseRotateCfg> for SourceLeaseRotateSettings {
    fn from(value: SourceLeaseRotateCfg) -> Self {
        Self {
            idle_timeout_ms: value.idle_timeout_secs.saturating_mul(1_000),
            max_age_ms: value.max_age_secs.saturating_mul(1_000),
            max_age_policy: value.max_age_policy.into(),
            switch_cooldown_ms: value.switch_cooldown_secs.saturating_mul(1_000),
        }
    }
}
