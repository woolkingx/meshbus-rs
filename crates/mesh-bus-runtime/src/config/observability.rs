//! Logging, metrics, and operator API config.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoggingCfg {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    Compact,
    Pretty,
    Json,
}

impl Default for LoggingCfg {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::Compact,
        }
    }
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Compact
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum MetricsCfg {
    PrometheusTextfile {
        path: String,
        #[serde(default)]
        labels: HashMap<String, String>,
    },
    PrometheusHttp {
        listen: String,
        #[serde(default)]
        labels: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum OperatorCfg {
    LocalHttp {
        listen: String,
        #[serde(default)]
        auth: Option<OperatorAuthCfg>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum OperatorAuthCfg {
    BearerTokenFile { path: PathBuf },
}

impl LogFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }
}

impl MetricsCfg {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PrometheusTextfile { .. } => "PrometheusTextfile",
            Self::PrometheusHttp { .. } => "PrometheusHttp",
        }
    }
}
