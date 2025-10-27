use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::types::ShardIndex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishArtifact {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishRequest {
    pub index: ShardIndex,
    #[serde(default)]
    pub artifacts: Vec<PublishArtifact>,
}

pub struct McpStorage {
    root: PathBuf,
}

impl McpStorage {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).with_context(|| {
            format!("failed to create MCP storage directory {}", root.display())
        })?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load_index(&self) -> Result<Option<ShardIndex>> {
        let path = self.root.join("index.json");
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path)
            .with_context(|| format!("failed to read MCP index at {}", path.display()))?;
        let index: ShardIndex = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse MCP index at {}", path.display()))?;
        Ok(Some(index))
    }

    pub fn read_artifact(&self, relative: &str) -> Result<Vec<u8>> {
        let path = self.resolve_relative(relative)?;
        let data = fs::read(&path)
            .with_context(|| format!("failed to read MCP artifact at {}", path.display()))?;
        Ok(data)
    }

    pub fn apply_publish(&self, request: PublishRequest) -> Result<ShardIndex> {
        let PublishRequest { index, artifacts } = request;
        index.verify_signature()?;

        let mut artifact_map: HashMap<String, PublishArtifact> = HashMap::new();
        for artifact in artifacts {
            if artifact_map
                .insert(artifact.path.clone(), artifact)
                .is_some()
            {
                return Err(anyhow!("duplicate artifact path detected"));
            }
        }

        self.prepare_dirs()?;

        for entry in &index.entries {
            let artifact = artifact_map
                .get(&entry.path)
                .ok_or_else(|| anyhow!("missing artifact for entry '{}'", entry.id))?;
            let bytes = Base64
                .decode(artifact.content.as_bytes())
                .context("failed to decode artifact content")?;
            let digest = blake3::hash(&bytes).to_hex().to_string();
            if digest != entry.digest {
                return Err(anyhow!(
                    "digest mismatch for entry '{}' (expected {}, computed {})",
                    entry.id,
                    entry.digest,
                    digest
                ));
            }
            let destination = self.resolve_relative(&entry.path)?;
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create artifact directory {}", parent.display())
                })?;
            }
            fs::write(&destination, &bytes).with_context(|| {
                format!(
                    "failed to write artifact '{}' to {}",
                    entry.id,
                    destination.display()
                )
            })?;
        }

        let index_path = self.root.join("index.json");
        let data = serde_json::to_vec_pretty(&index).context("failed to serialise MCP index")?;
        fs::write(&index_path, data)
            .with_context(|| format!("failed to write MCP index to {}", index_path.display()))?;

        debug!("stored index {}", index.id);
        Ok(index)
    }

    fn prepare_dirs(&self) -> Result<()> {
        for name in ["shards", "contracts", "events"] {
            let dir = self.root.join(name);
            if dir.exists() {
                fs::remove_dir_all(&dir).with_context(|| {
                    format!("failed to clear storage directory {}", dir.display())
                })?;
            }
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create storage directory {}", dir.display()))?;
        }
        Ok(())
    }

    fn resolve_relative(&self, relative: &str) -> Result<PathBuf> {
        let rel = Path::new(relative);
        if rel.is_absolute() {
            return Err(anyhow!("artifact path must be relative"));
        }
        for component in rel.components() {
            if matches!(component, Component::ParentDir) {
                return Err(anyhow!(
                    "artifact path '{}' contains parent directory segments",
                    relative
                ));
            }
        }
        Ok(self.root.join(rel))
    }
}
