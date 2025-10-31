use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeerRecord {
    pub did: String,
    pub endpoint: String,
    #[serde(default)]
    pub presence: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FederationRoster {
    #[serde(default)]
    pub peers: Vec<FederationPeerRecord>,
}

impl FederationRoster {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read federation roster at {}", path.display()))?;
        let roster: Self = toml::from_str(&data)
            .with_context(|| format!("failed to parse federation roster {}", path.display()))?;
        Ok(roster)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create roster directory {}", parent.display())
                })?;
            }
        }
        let data = toml::to_string_pretty(self)
            .context("failed to serialise federation roster to TOML")?;
        fs::write(path, data)
            .with_context(|| format!("failed to write roster file {}", path.display()))
    }

    pub fn roster_path(home: &Path) -> PathBuf {
        home.join("config").join("federation.toml")
    }

    pub fn find_peer_mut(&mut self, did: &str) -> Option<&mut FederationPeerRecord> {
        self.peers.iter_mut().find(|peer| peer.did == did)
    }

    pub fn remove_peer(&mut self, did: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|peer| peer.did != did);
        before != self.peers.len()
    }

    pub fn add_peer(&mut self, record: FederationPeerRecord) -> Result<()> {
        if self.peers.iter().any(|peer| peer.did == record.did) {
            anyhow::bail!("peer '{}' already exists in roster", record.did);
        }
        self.peers.push(record);
        Ok(())
    }
}
