//! Mesh identity and MeshSec operator config.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeCfg {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerCfg {
    pub id: String,
    pub node_id: String,
    #[serde(default)]
    pub route_groups: Vec<String>,
    #[serde(default)]
    pub meshsec: Option<MeshSecPeerCfg>,
}

/// Optional MeshSec secure UDP envelope material for one adjacent peer.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshSecPeerCfg {
    pub profile: MeshSecProfileCfg,
    #[serde(default)]
    pub static_key_hex: Option<String>,
    #[serde(default)]
    pub active_key_id: Option<String>,
    #[serde(default)]
    pub keyring: Vec<MeshSecKeyCfg>,
}

impl std::fmt::Debug for MeshSecPeerCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshSecPeerCfg")
            .field("profile", &self.profile)
            .field("static_key_hex", &"<redacted>")
            .field("active_key_id", &self.active_key_id)
            .field(
                "keyring",
                &format_args!("<{} redacted>", self.keyring.len()),
            )
            .finish()
    }
}

/// One MeshSec PSK entry. `active` seals new outbound packets; `accept` opens
/// old packets during a bounded operational rollover window.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshSecKeyCfg {
    pub id: String,
    pub static_key_hex: String,
    pub role: MeshSecKeyRoleCfg,
}

impl std::fmt::Debug for MeshSecKeyCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshSecKeyCfg")
            .field("id", &self.id)
            .field("static_key_hex", &"<redacted>")
            .field("role", &self.role)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MeshSecKeyRoleCfg {
    Active,
    Accept,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum MeshSecProfileCfg {
    #[serde(rename = "MeshSec-0RTT-PSK-XChaCha")]
    MeshSec0RttPskXChaCha,
}

impl MeshSecPeerCfg {
    /// Decode the 64-hex static key into raw 32 bytes. Shape is enforced by
    /// `validate_config`; this returns `None` only if validation was skipped.
    pub fn static_key(&self) -> Option<[u8; 32]> {
        self.active_static_key()
    }

    pub fn active_static_key(&self) -> Option<[u8; 32]> {
        if let Some(hex) = &self.static_key_hex {
            return decode_static_key_hex(hex);
        }
        let active_id = self.active_key_id.as_ref()?;
        let key = self
            .keyring
            .iter()
            .find(|key| key.id == *active_id && matches!(key.role, MeshSecKeyRoleCfg::Active))?;
        decode_static_key_hex(&key.static_key_hex)
    }

    pub fn open_static_keys(&self) -> Vec<[u8; 32]> {
        if let Some(hex) = &self.static_key_hex {
            return decode_static_key_hex(hex).into_iter().collect();
        }
        let Some(active_id) = self.active_key_id.as_ref() else {
            return Vec::new();
        };
        let mut keys = Vec::new();
        if let Some(active) = self.keyring.iter().find(|key| key.id == *active_id) {
            if let Some(key) = decode_static_key_hex(&active.static_key_hex) {
                keys.push(key);
            }
        }
        for accept in self
            .keyring
            .iter()
            .filter(|key| key.id != *active_id && matches!(key.role, MeshSecKeyRoleCfg::Accept))
        {
            if let Some(key) = decode_static_key_hex(&accept.static_key_hex) {
                keys.push(key);
            }
        }
        keys
    }
}

fn decode_static_key_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(key)
}
