use crate::home::ensure_subdir;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryState {
    pub pid: u32,
    pub listen: String,
    pub log_path: String,
    #[serde(default)]
    pub alias: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
}

impl DiscoveryState {
    pub fn state_dir(home: &Path) -> Result<PathBuf> {
        let services_dir = ensure_subdir(home, "services")?;
        ensure_subdir(&services_dir, "discovery")
    }

    pub fn state_path(home: &Path) -> Result<PathBuf> {
        Ok(Self::state_dir(home)?.join("service.json"))
    }

    pub fn logs_dir(home: &Path) -> Result<PathBuf> {
        let dir = Self::state_dir(home)?;
        ensure_subdir(&dir, "logs")
    }

    pub fn load(home: &Path) -> Result<Option<Self>> {
        let path = Self::state_path(home)?;
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(&path)
            .with_context(|| format!("failed to read discovery state at {}", path.display()))?;
        let state: DiscoveryState =
            serde_json::from_slice(&data).context("failed to parse discovery state")?;
        Ok(Some(state))
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        let path = Self::state_path(home)?;
        let data = serde_json::to_vec_pretty(self)?;
        fs::write(&path, data)
            .with_context(|| format!("failed to write discovery state at {}", path.display()))
    }

    pub fn remove(home: &Path) -> Result<()> {
        let path = Self::state_path(home)?;
        if path.exists() {
            fs::remove_file(&path).with_context(|| {
                format!("failed to remove discovery state at {}", path.display())
            })?;
        }
        Ok(())
    }

    pub fn http_base(&self) -> Result<String> {
        let addr: std::net::SocketAddr = self
            .listen
            .parse()
            .with_context(|| format!("invalid listen address '{}'", self.listen))?;
        let host = match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                if v4.is_unspecified() {
                    "127.0.0.1".to_string()
                } else {
                    v4.to_string()
                }
            }
            std::net::IpAddr::V6(v6) => {
                let base = if v6.is_unspecified() {
                    "[::1]".to_string()
                } else {
                    format!("[{}]", v6)
                };
                base
            }
        };
        Ok(format!("{}:{}", host, addr.port()))
    }

    pub fn log_path(&self) -> PathBuf {
        PathBuf::from(&self.log_path)
    }

    pub fn is_running(&self) -> bool {
        #[cfg(unix)]
        {
            use nix::sys::signal::kill;
            use nix::unistd::Pid;
            match kill(Pid::from_raw(self.pid as i32), None) {
                Ok(_) => true,
                Err(nix::errno::Errno::ESRCH) => false,
                Err(_) => true,
            }
        }
        #[cfg(not(unix))]
        {
            // Fall back to optimistic assumption on non-Unix platforms.
            true
        }
    }
}

pub fn logs_tail(path: &Path, lines: usize) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read log file {}", path.display()))?;
    let mut all_lines = content.lines().map(|s| s.to_string()).collect::<Vec<_>>();
    if lines >= all_lines.len() {
        return Ok(all_lines);
    }
    let start = all_lines.len() - lines;
    Ok(all_lines.split_off(start))
}
