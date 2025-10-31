use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::federation::peer_cache_dir;

#[derive(Debug, Clone)]
pub struct RelayPresenceRecord {
    pub document: Value,
    pub expires_at: Option<OffsetDateTime>,
    pub source_expires_at: Option<OffsetDateTime>,
}

pub struct RelayRegistry {
    root: PathBuf,
    ttl: Option<Duration>,
}

impl RelayRegistry {
    pub fn new(root: PathBuf, ttl_seconds: u64) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create relay storage at {}", root.display()))?;
        let ttl = if ttl_seconds == 0 {
            None
        } else {
            Some(Duration::seconds(ttl_seconds as i64))
        };
        Ok(Self { root, ttl })
    }

    pub fn store_presence(&self, did: &str, presence: &Value) -> Result<Option<OffsetDateTime>> {
        let now = OffsetDateTime::now_utc();
        let dir = peer_cache_dir(&self.root, did);
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create relay directory {}", dir.display()))?;
        }

        let presence_path = dir.join("presence.json");
        let payload =
            serde_json::to_vec_pretty(presence).context("failed to serialise relay presence")?;
        fs::write(&presence_path, payload).with_context(|| {
            format!(
                "failed to write relay presence to {}",
                presence_path.display()
            )
        })?;

        let source_expires_at = parse_expires_at(presence)?;
        let ttl_deadline = self.ttl.and_then(|ttl| now.checked_add(ttl));
        let final_expires_at = match (source_expires_at, ttl_deadline) {
            (Some(source), Some(ttl)) => Some(source.min(ttl)),
            (Some(source), None) => Some(source),
            (None, Some(ttl)) => Some(ttl),
            (None, None) => None,
        };
        let meta = RelayPresenceMeta {
            stored_at: now,
            expires_at: final_expires_at,
            source_expires_at,
        };
        write_meta(&dir, &meta)?;

        // Opportunistically prune other expired relay entries.
        self.prune_expired(now)?;

        Ok(final_expires_at)
    }

    pub fn load_presence(&self, did: &str) -> Result<Option<RelayPresenceRecord>> {
        let now = OffsetDateTime::now_utc();
        let dir = peer_cache_dir(&self.root, did);
        let presence_path = dir.join("presence.json");
        if !presence_path.exists() {
            return Ok(None);
        }

        let meta = match read_meta(&dir)? {
            Some(meta) => meta,
            None => {
                // No metadata; treat as stale and remove.
                self.remove_peer_dir(&dir)?;
                return Ok(None);
            }
        };

        if let Some(expires_at) = meta.expires_at {
            if now >= expires_at {
                self.remove_peer_dir(&dir)?;
                return Ok(None);
            }
        }

        let file = fs::File::open(&presence_path).with_context(|| {
            format!("failed to open relay presence {}", presence_path.display())
        })?;
        let document = serde_json::from_reader::<_, Value>(file).with_context(|| {
            format!("failed to parse relay presence {}", presence_path.display())
        })?;

        Ok(Some(RelayPresenceRecord {
            document,
            expires_at: meta.expires_at,
            source_expires_at: meta.source_expires_at,
        }))
    }

    fn prune_expired(&self, now: OffsetDateTime) -> Result<()> {
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("failed to read relay directory {}", self.root.display()))?
        {
            let path = entry?.path();
            if !path.is_dir() {
                continue;
            }
            match read_meta(&path)? {
                Some(meta) => {
                    if let Some(expires_at) = meta.expires_at {
                        if now >= expires_at {
                            self.remove_peer_dir(&path)?;
                        }
                    }
                }
                None => {
                    // Legacy entries without metadata are removed to avoid indefinite retention.
                    self.remove_peer_dir(&path)?;
                }
            };
        }
        Ok(())
    }

    fn remove_peer_dir(&self, dir: &Path) -> Result<()> {
        if dir.exists() {
            fs::remove_dir_all(dir)
                .with_context(|| format!("failed to remove relay cache {}", dir.display()))?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RelayPresenceMeta {
    #[serde(with = "time::serde::rfc3339")]
    stored_at: OffsetDateTime,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    expires_at: Option<OffsetDateTime>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    source_expires_at: Option<OffsetDateTime>,
}

fn parse_expires_at(presence: &Value) -> Result<Option<OffsetDateTime>> {
    let Some(value) = presence.get("expires_at") else {
        return Ok(None);
    };
    let Some(timestamp) = value.as_str() else {
        return Err(anyhow!("presence expires_at must be string"));
    };
    let parsed = OffsetDateTime::parse(timestamp, &Rfc3339)
        .context("presence expires_at is invalid RFC3339")?;
    Ok(Some(parsed))
}

fn meta_path(dir: &Path) -> PathBuf {
    dir.join("meta.json")
}

fn write_meta(dir: &Path, meta: &RelayPresenceMeta) -> Result<()> {
    let path = meta_path(dir);
    let payload =
        serde_json::to_vec_pretty(meta).context("failed to serialise relay presence metadata")?;
    fs::write(&path, payload)
        .with_context(|| format!("failed to write relay metadata {}", path.display()))
}

fn read_meta(dir: &Path) -> Result<Option<RelayPresenceMeta>> {
    let path = meta_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let file = fs::File::open(&path)
        .with_context(|| format!("failed to open relay metadata {}", path.display()))?;
    let meta = serde_json::from_reader::<_, RelayPresenceMeta>(file)
        .with_context(|| format!("failed to parse relay metadata {}", path.display()))?;
    Ok(Some(meta))
}
