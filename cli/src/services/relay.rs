use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHostRecord {
    pub did: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_push: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_expiry: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayRoster {
    #[serde(default)]
    pub hosts: Vec<RelayHostRecord>,
}

impl RelayRoster {
    pub fn roster_path(home: &Path) -> PathBuf {
        home.join("config").join("relay.toml")
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read relay roster at {}", path.display()))?;
        let roster: Self = toml::from_str(&data)
            .with_context(|| format!("failed to parse relay roster {}", path.display()))?;
        Ok(roster)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create directory {}", parent.display()))?;
            }
        }
        let data =
            toml::to_string_pretty(self).context("failed to serialise relay roster to TOML")?;
        fs::write(path, data)
            .with_context(|| format!("failed to write relay roster to {}", path.display()))
    }

    pub fn add_host(&mut self, host: RelayHostRecord) -> Result<()> {
        if self.hosts.iter().any(|existing| existing.did == host.did) {
            anyhow::bail!("relay host '{}' is already registered", host.did);
        }
        self.hosts.push(host);
        Ok(())
    }

    pub fn remove_host(&mut self, did: &str) -> bool {
        let before = self.hosts.len();
        self.hosts.retain(|host| host.did != did);
        before != self.hosts.len()
    }

    pub fn find_host(&self, did: &str) -> Option<&RelayHostRecord> {
        self.hosts.iter().find(|host| host.did == did)
    }

    pub fn find_host_mut(&mut self, did: &str) -> Option<&mut RelayHostRecord> {
        self.hosts.iter_mut().find(|host| host.did == did)
    }
}
