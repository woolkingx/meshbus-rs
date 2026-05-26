//! Health policy operator config.

use mb_health::HealthPolicy;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthCfg {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u8,
    #[serde(default = "default_recovery_window_ms")]
    pub recovery_window_ms: u64,
    #[serde(default = "default_probe_after_ms")]
    pub probe_after_ms: u64,
}

impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            recovery_window_ms: default_recovery_window_ms(),
            probe_after_ms: default_probe_after_ms(),
        }
    }
}

impl From<HealthCfg> for HealthPolicy {
    fn from(value: HealthCfg) -> Self {
        Self {
            failure_threshold: value.failure_threshold,
            recovery_window_ms: value.recovery_window_ms,
            probe_after_ms: value.probe_after_ms,
        }
    }
}

fn default_failure_threshold() -> u8 {
    HealthPolicy::default().failure_threshold
}

fn default_recovery_window_ms() -> u64 {
    HealthPolicy::default().recovery_window_ms
}

fn default_probe_after_ms() -> u64 {
    HealthPolicy::default().probe_after_ms
}
