use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::bundle::IdentityBundle;
use super::did::{DidDocument, IdentityKeys};

const CONFIG_FILE: &str = "config.json";
const IDENTITIES_DIR: &str = "identities";
const NODES_DIR: &str = "nodes";
const KEY_FILE: &str = "ed25519.key";
const PROFILE_FILE: &str = "identity.json";

#[derive(Clone)]
pub struct IdentityVault {
    root: PathBuf,
    identities_path: PathBuf,
    config_path: PathBuf,
    nodes_path: PathBuf,
}

impl IdentityVault {
    pub fn new(root: PathBuf) -> Result<Self> {
        let identities_path = root.join(IDENTITIES_DIR);
        if !identities_path.exists() {
            fs::create_dir_all(&identities_path)
                .with_context(|| format!("failed to create {}", identities_path.display()))?;
        }
        let nodes_path = root.join(NODES_DIR);
        if !nodes_path.exists() {
            fs::create_dir_all(&nodes_path)
                .with_context(|| format!("failed to create {}", nodes_path.display()))?;
        }
        let config_path = root.join(CONFIG_FILE);
        if !config_path.exists() {
            let config = VaultConfig::default();
            write_json(&config_path, &config)?;
        }
        Ok(Self {
            root,
            identities_path,
            config_path,
            nodes_path,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn active_identity(&self) -> Result<Option<ActiveIdentity>> {
        let config = self.load_config()?;
        if let Some(alias) = config.active_alias {
            let profile = self.load_identity(&alias)?;
            return Ok(Some(ActiveIdentity {
                alias,
                did: profile.profile.id.clone(),
            }));
        }
        Ok(None)
    }

    pub fn set_active_identity(&self, alias: &str) -> Result<()> {
        let mut config = self.load_config()?;
        config.active_alias = Some(alias.to_string());
        write_json(&self.config_path, &config)?;
        Ok(())
    }

    pub fn create_identity(
        &self,
        alias: &str,
        capabilities: Vec<String>,
        endpoints: HashMap<String, serde_json::Value>,
    ) -> Result<IdentityRecord> {
        let alias = alias.trim();
        let record = self.prepare_identity(alias, capabilities, endpoints)?;
        self.store_identity(&record)?;
        self.ensure_node_home(&record.profile.alias)?;

        // Ensure config has active alias.
        let mut config = self.load_config()?;
        if config.active_alias.is_none() {
            config.active_alias = Some(alias.to_string());
            write_json(&self.config_path, &config)?;
        }

        Ok(record)
    }

    pub fn import_identity(
        &self,
        bundle: &IdentityBundle,
        secret: [u8; 32],
        alias_override: Option<&str>,
    ) -> Result<IdentityRecord> {
        let record = self.prepare_import_identity(bundle, secret, alias_override)?;
        self.store_identity(&record)?;
        self.ensure_node_home(&record.profile.alias)?;

        // Maintain active alias if none set.
        let alias = record.profile.alias.clone();
        let mut config = self.load_config()?;
        if config.active_alias.is_none() {
            config.active_alias = Some(alias);
            write_json(&self.config_path, &config)?;
        }

        Ok(record)
    }

    pub fn prepare_import_identity(
        &self,
        bundle: &IdentityBundle,
        secret: [u8; 32],
        alias_override: Option<&str>,
    ) -> Result<IdentityRecord> {
        let alias = alias_override
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| bundle.profile.alias.clone());
        if alias.is_empty() {
            return Err(anyhow!("alias cannot be empty"));
        }
        if self.alias_exists(&alias)? {
            return Err(anyhow!("identity alias '{}' already exists", alias));
        }

        let keys = IdentityKeys::from_secret_bytes(&secret)?;
        if bundle.profile.id != keys.did() {
            return Err(anyhow!(
                "bundle DID {} does not match recovered keys {}",
                bundle.profile.id,
                keys.did()
            ));
        }
        if bundle.did_document.id != bundle.profile.id {
            return Err(anyhow!(
                "bundle profile DID {} does not match DID document {}",
                bundle.profile.id,
                bundle.did_document.id
            ));
        }

        let canonical = bundle.did_document.canonical_hash()?;
        if canonical != bundle.canonical_hash {
            return Err(anyhow!(
                "bundle canonical hash mismatch (expected {}, computed {})",
                bundle.canonical_hash,
                canonical
            ));
        }

        let mut profile = bundle.profile.clone();
        profile.alias = alias.clone();
        profile.updated_at = OffsetDateTime::now_utc();

        let record = IdentityRecord {
            profile,
            did_document: bundle.did_document.clone(),
            keys,
            canonical_hash: Some(canonical),
        };

        Ok(record)
    }

    pub fn prepare_identity(
        &self,
        alias: &str,
        capabilities: Vec<String>,
        endpoints: HashMap<String, serde_json::Value>,
    ) -> Result<IdentityRecord> {
        let alias = alias.trim();
        if alias.is_empty() {
            return Err(anyhow!("alias cannot be empty"));
        }
        if self.alias_exists(alias)? {
            return Err(anyhow!("identity alias '{}' already exists", alias));
        }

        let keys = IdentityKeys::generate()?;
        let created_at = OffsetDateTime::now_utc();
        let profile = IdentityProfile::new(alias, &keys.did(), capabilities, endpoints, created_at);
        let did_document = DidDocument::for_keys(&keys, &[]);
        // Validate canonicalization succeeds up-front.
        let canonical = did_document.canonical_hash()?;

        Ok(IdentityRecord {
            profile,
            did_document,
            keys,
            canonical_hash: Some(canonical),
        })
    }

    fn store_identity(&self, record: &IdentityRecord) -> Result<()> {
        if !self.identities_path.exists() {
            fs::create_dir_all(&self.identities_path)
                .with_context(|| format!("failed to create {}", self.identities_path.display()))?;
        }

        let alias = &record.profile.alias;

        if !self.identities_path.exists() {
            fs::create_dir_all(&self.identities_path)
                .with_context(|| format!("failed to create {}", self.identities_path.display()))?;
        }

        let identity_dir = self.identity_dir(alias);
        fs::create_dir_all(&identity_dir)
            .with_context(|| format!("failed to create {}", identity_dir.display()))?;

        let key_path = identity_dir.join(KEY_FILE);
        let profile_path = identity_dir.join(PROFILE_FILE);

        fs::write(&key_path, record.keys.secret_key_bytes())
            .with_context(|| format!("failed to write {}", key_path.display()))?;

        let canonical = match &record.canonical_hash {
            Some(hash) => hash.clone(),
            None => record.did_document.canonical_hash()?,
        };

        let disk = IdentityDiskRecord {
            profile: record.profile.clone(),
            did_document: record.did_document.clone(),
            canonical_hash: canonical,
        };
        write_json(&profile_path, &disk)?;

        Ok(())
    }

    pub fn alias_exists(&self, alias: &str) -> Result<bool> {
        let identity_dir = self.identity_dir(alias);
        Ok(identity_dir.exists())
    }

    pub fn delete_identity(&self, alias: &str, purge_node: bool) -> Result<()> {
        if !self.alias_exists(alias)? {
            return Err(anyhow!("identity '{alias}' not found"));
        }

        let dir = self.identity_dir(alias);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .with_context(|| format!("failed to delete identity at {}", dir.display()))?;
        }

        if purge_node {
            let node = self.nodes_path.join(alias);
            if node.exists() {
                fs::remove_dir_all(&node)
                    .with_context(|| format!("failed to delete node home {}", node.display()))?;
            }
        }

        let mut config = self.load_config()?;
        if config
            .active_alias
            .as_ref()
            .map(|current| current == alias)
            .unwrap_or(false)
        {
            config.active_alias = None;
            write_json(&self.config_path, &config)?;
        }

        Ok(())
    }

    pub fn list_identities(&self) -> Result<Vec<IdentitySummary>> {
        let mut summaries = Vec::new();
        let config = self.load_config()?;
        let entries = fs::read_dir(&self.identities_path)
            .with_context(|| format!("failed to read {}", self.identities_path.display()))?;
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let alias = entry.file_name().to_string_lossy().to_string();
            if let Ok(record) = self.load_identity(&alias) {
                let active = config
                    .active_alias
                    .as_ref()
                    .map(|a| a == &alias)
                    .unwrap_or(false);
                summaries.push(IdentitySummary {
                    alias,
                    did: record.profile.id.clone(),
                    updated_at: record.profile.updated_at,
                    active,
                });
            }
        }
        summaries.sort_by(|a, b| a.alias.cmp(&b.alias));
        Ok(summaries)
    }

    pub fn load_identity(&self, target: &str) -> Result<IdentityRecord> {
        if target.starts_with("did:") {
            if let Some(alias) = self.alias_for_did(target)? {
                return self.load_identity(&alias);
            }
            return Err(anyhow!("unknown DID {}", target));
        }

        let identity_dir = self.identity_dir(target);
        if !identity_dir.exists() {
            return Err(anyhow!("identity '{}' not found", target));
        }

        let profile_path = identity_dir.join(PROFILE_FILE);
        let key_path = identity_dir.join(KEY_FILE);

        let disk: IdentityDiskRecord = read_json(&profile_path)?;
        let secret = read_bytes(&key_path)?;
        let keys = IdentityKeys::from_secret_bytes(&secret)?;

        Ok(IdentityRecord {
            profile: disk.profile,
            did_document: disk.did_document,
            keys,
            canonical_hash: Some(disk.canonical_hash),
        })
    }

    pub fn alias_for_did(&self, did: &str) -> Result<Option<String>> {
        let entries = fs::read_dir(&self.identities_path)
            .with_context(|| format!("failed to read {}", self.identities_path.display()))?;
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let alias = entry.file_name().to_string_lossy().to_string();
            let profile_path = entry.path().join(PROFILE_FILE);
            if !profile_path.exists() {
                continue;
            }
            let disk: IdentityDiskRecord = read_json(&profile_path)?;
            if disk.profile.id == did {
                return Ok(Some(alias));
            }
        }
        Ok(None)
    }

    pub fn ensure_policy_dir(&self) -> Result<PathBuf> {
        let active = self
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity configured"))?;
        self.ensure_policy_dir_for(&active.alias)
    }

    pub fn ensure_policy_dir_for(&self, alias: &str) -> Result<PathBuf> {
        let home = self.ensure_node_home(alias)?;
        let policy_dir = home.join("policy");
        if !policy_dir.exists() {
            fs::create_dir_all(&policy_dir)
                .with_context(|| format!("failed to create {}", policy_dir.display()))?;
        }
        Ok(policy_dir)
    }

    fn identity_dir(&self, alias: &str) -> PathBuf {
        self.identities_path.join(alias)
    }

    pub fn ensure_node_home(&self, alias: &str) -> Result<PathBuf> {
        let path = self.nodes_path.join(alias);
        if !path.exists() {
            fs::create_dir_all(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
        }
        Ok(path)
    }

    pub fn node_home(&self, alias: &str) -> Result<PathBuf> {
        self.ensure_node_home(alias)
    }

    pub fn node_subdir(&self, alias: &str, sub: &str) -> Result<PathBuf> {
        let home = self.ensure_node_home(alias)?;
        let dir = home.join(sub);
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        Ok(dir)
    }

    fn load_config(&self) -> Result<VaultConfig> {
        read_json(&self.config_path)
    }
}

pub struct IdentityRecord {
    pub profile: IdentityProfile,
    pub did_document: DidDocument,
    pub keys: IdentityKeys,
    pub canonical_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProfile {
    pub id: String,
    pub alias: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub endpoints: HashMap<String, serde_json::Value>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl IdentityProfile {
    pub fn new(
        alias: &str,
        did: &str,
        capabilities: Vec<String>,
        endpoints: HashMap<String, serde_json::Value>,
        timestamp: OffsetDateTime,
    ) -> Self {
        Self {
            id: did.to_string(),
            alias: alias.to_string(),
            capabilities,
            endpoints,
            created_at: timestamp,
            updated_at: timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityDiskRecord {
    pub profile: IdentityProfile,
    pub did_document: DidDocument,
    pub canonical_hash: String,
}

#[derive(Debug, Clone)]
pub struct IdentitySummary {
    pub alias: String,
    pub did: String,
    pub updated_at: OffsetDateTime,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct ActiveIdentity {
    pub alias: String,
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VaultConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_alias: Option<String>,
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to move {} into place as {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(parsed)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}
