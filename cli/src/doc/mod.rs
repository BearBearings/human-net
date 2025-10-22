use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use blake3::Hasher;
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::identity::{IdentityRecord, IdentityVault};
use crate::policy::{PolicyDecision, PolicyEvaluator};

const DOC_ROOT: &str = "personal/docs";
const VIEWS_ROOT: &str = "views";

pub struct DocStore<'a> {
    vault: &'a IdentityVault,
    alias: String,
    did: String,
    identity: IdentityRecord,
}

impl<'a> DocStore<'a> {
    pub fn open(vault: &'a IdentityVault) -> Result<Self> {
        let active = vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity configured; run `hn id use <alias>`"))?;
        let identity = vault.load_identity(&active.alias)?;
        Ok(Self {
            vault,
            alias: active.alias,
            did: active.did,
            identity,
        })
    }

    pub fn import_from_file(
        &self,
        doc_type: &str,
        path: &Path,
        id: Option<String>,
    ) -> Result<StoredDoc> {
        let content: Value = serde_json::from_reader(
            fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", path.display()))?;
        self.store(doc_type, content, id)
    }

    pub fn store(&self, doc_type: &str, content: Value, id: Option<String>) -> Result<StoredDoc> {
        PolicyEvaluator::check_doc_write(self.vault, &self.alias, doc_type, &content)?;
        let doc_id = id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = OffsetDateTime::now_utc();
        let unsigned = UnsignedDoc {
            id: &doc_id,
            doc_type,
            signer: &self.did,
            content: &content,
            created_at: now,
            updated_at: now,
        };
        let canonical = serde_jcs::to_string(&unsigned)?;
        let mut hasher = Hasher::new();
        hasher.update(canonical.as_bytes());
        let canonical_hash = hasher.finalize().to_hex().to_string();
        let signature = self.identity.keys.signing_key().sign(canonical.as_bytes());
        let signature_b64 = Base64.encode(signature.to_bytes());

        let stored = StoredDoc {
            id: doc_id,
            doc_type: doc_type.to_string(),
            signer: self.did.clone(),
            content,
            created_at: now,
            updated_at: now,
            canonical_hash,
            signature: signature_b64,
            location: None,
        };
        let file_path = self.write_doc(doc_type, &stored)?;
        Ok(StoredDoc {
            location: Some(file_path),
            ..stored
        })
    }

    pub fn list(&self) -> Result<Vec<DocSummary>> {
        let root = self.docs_root()?;
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let doc_type = entry.file_name().to_string_lossy().to_string();
            for doc_entry in fs::read_dir(entry.path())? {
                let doc_entry = doc_entry?;
                if !doc_entry.file_type()?.is_file() {
                    continue;
                }
                if let Ok(mut doc) = self.read_file(doc_entry.path()) {
                    match PolicyEvaluator::doc_read_decision(
                        self.vault,
                        &self.alias,
                        &doc_type,
                        &doc.content,
                    ) {
                        Ok(PolicyDecision::Allow) => {
                            doc.location = doc.location.map(|p| p);
                            entries.push(DocSummary::from_doc(doc_type.clone(), doc));
                        }
                        _ => continue,
                    }
                }
            }
        }
        entries.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(entries)
    }

    pub fn all_docs(&self) -> Result<Vec<StoredDoc>> {
        let root = self.docs_root()?;
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut docs = Vec::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let doc_type = entry.file_name().to_string_lossy().to_string();
            for doc_entry in fs::read_dir(entry.path())? {
                let doc_entry = doc_entry?;
                if !doc_entry.file_type()?.is_file() {
                    continue;
                }
                if let Ok(mut doc) = self.read_file(doc_entry.path()) {
                    match PolicyEvaluator::doc_read_decision(
                        self.vault,
                        &self.alias,
                        &doc_type,
                        &doc.content,
                    )? {
                        PolicyDecision::Allow => {
                            doc.location = doc.location.map(|p| p);
                            docs.push(doc);
                        }
                        PolicyDecision::Deny(_) => continue,
                    }
                }
            }
        }
        Ok(docs)
    }

    pub fn get(&self, doc_id: &str) -> Result<StoredDoc> {
        let (doc_type, path) = self.locate(doc_id)?;
        let mut doc = self.read_file(path)?;
        PolicyEvaluator::check_doc_read(self.vault, &self.alias, &doc.doc_type, &doc.content)?;
        doc.location = Some(self.doc_path(&doc_type, doc_id));
        Ok(doc)
    }

    pub fn delete(&self, doc_id: &str) -> Result<()> {
        let (doc_type, path) = self.locate(doc_id)?;
        fs::remove_file(&path).with_context(|| format!("failed to delete {}", path.display()))?;
        let dir = self.type_dir(&doc_type)?;
        if dir.read_dir()?.next().is_none() {
            let _ = fs::remove_dir(dir);
        }
        Ok(())
    }

    pub fn replay(&self, doc_id: &str) -> Result<ReplayResult> {
        let (doc_type, path) = self.locate(doc_id)?;
        let stored = self.read_file(path)?;
        let unsigned = UnsignedDoc {
            id: &stored.id,
            doc_type: &stored.doc_type,
            signer: &stored.signer,
            content: &stored.content,
            created_at: stored.created_at,
            updated_at: stored.updated_at,
        };
        let canonical = serde_jcs::to_string(&unsigned)?;
        let mut hasher = Hasher::new();
        hasher.update(canonical.as_bytes());
        let computed_hash = hasher.finalize().to_hex().to_string();
        let signature_bytes: Vec<u8> = Base64
            .decode(stored.signature.as_bytes())
            .context("invalid signature encoding")?;
        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| anyhow!("invalid signature length"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
        let signature_valid = self
            .identity
            .keys
            .verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .is_ok();

        Ok(ReplayResult {
            id: stored.id,
            doc_type,
            canonical_hash: stored.canonical_hash,
            computed_hash,
            signature_valid,
        })
    }

    fn docs_root(&self) -> Result<PathBuf> {
        self.vault.node_subdir(&self.alias, DOC_ROOT)
    }

    fn type_dir(&self, doc_type: &str) -> Result<PathBuf> {
        let root = self.docs_root()?;
        let dir = root.join(doc_type);
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        Ok(dir)
    }

    fn doc_path(&self, doc_type: &str, doc_id: &str) -> PathBuf {
        self.vault
            .node_home(&self.alias)
            .expect("node home")
            .join(DOC_ROOT)
            .join(doc_type)
            .join(format!("{doc_id}.json"))
    }

    fn write_doc(&self, doc_type: &str, doc: &StoredDoc) -> Result<PathBuf> {
        let dir = self.type_dir(doc_type)?;
        let path = dir.join(format!("{}.json", doc.id));
        let data = serde_json::to_vec_pretty(doc)?;
        fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(path)
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    fn locate(&self, doc_id: &str) -> Result<(String, PathBuf)> {
        let root = self.docs_root()?;
        if !root.exists() {
            return Err(anyhow!("doc '{}' not found", doc_id));
        }
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let doc_type = entry.file_name().to_string_lossy().to_string();
            let candidate = entry.path().join(format!("{doc_id}.json"));
            if candidate.exists() {
                return Ok((doc_type, candidate));
            }
        }
        Err(anyhow!("doc '{}' not found", doc_id))
    }

    fn read_file(&self, path: PathBuf) -> Result<StoredDoc> {
        let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let mut doc: StoredDoc = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        doc.location = Some(path);
        Ok(doc)
    }
}

#[derive(Serialize)]
struct UnsignedDoc<'a> {
    pub id: &'a str,
    #[serde(rename = "type")]
    pub doc_type: &'a str,
    pub signer: &'a str,
    pub content: &'a Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredDoc {
    pub id: String,
    #[serde(rename = "type")]
    pub doc_type: String,
    pub signer: String,
    pub content: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub canonical_hash: String,
    pub signature: String,
    #[serde(skip)]
    pub location: Option<PathBuf>,
}

impl StoredDoc {
    pub fn as_payload(&self) -> Value {
        json!({
            "id": self.id,
            "type": self.doc_type,
            "signer": self.signer,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "canonical_hash": self.canonical_hash,
            "signature": self.signature,
            "content": self.content,
            "location": self.location.as_ref().map(|p| p.display().to_string()),
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DocSummary {
    pub id: String,
    #[serde(rename = "type")]
    pub doc_type: String,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub path: String,
}

impl DocSummary {
    fn from_doc(doc_type: String, doc: StoredDoc) -> Self {
        let path = doc
            .location
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        Self {
            id: doc.id,
            doc_type,
            updated_at: doc.updated_at,
            path,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReplayResult {
    pub id: String,
    #[serde(rename = "type")]
    pub doc_type: String,
    pub canonical_hash: String,
    pub computed_hash: String,
    pub signature_valid: bool,
}

pub struct ViewStore<'a> {
    vault: &'a IdentityVault,
    doc_store: DocStore<'a>,
    alias: String,
}

impl<'a> ViewStore<'a> {
    pub fn open(vault: &'a IdentityVault) -> Result<Self> {
        let doc_store = DocStore::open(vault)?;
        let alias = doc_store.alias().to_string();
        Ok(Self {
            vault,
            doc_store,
            alias,
        })
    }

    pub fn create(&self, name: &str, rule: String) -> Result<ViewDefinition> {
        Self::validate_name(name)?;
        let parsed = ViewRule::parse(&rule)?;
        let def = ViewDefinition {
            name: name.to_string(),
            rule: parsed.raw,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let dir = self.view_dir(name)?;
        if dir.exists() {
            return Err(anyhow!("view '{name}' already exists"));
        }
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        self.write_definition(&dir, &def)?;
        Ok(def)
    }

    pub fn list(&self) -> Result<Vec<ViewDefinition>> {
        let root = self.views_root()?;
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut views = Vec::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path().join("view.json");
            if path.exists() {
                let data = fs::read(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                let def: ViewDefinition = serde_json::from_slice(&data)
                    .with_context(|| format!("failed to parse {}", path.display()))?;
                views.push(def);
            }
        }
        views.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(views)
    }

    pub fn get(&self, name: &str) -> Result<ViewDefinition> {
        let dir = self.view_dir(name)?;
        if !dir.exists() {
            return Err(anyhow!("view '{name}' not found"));
        }
        let data = fs::read(dir.join("view.json"))
            .with_context(|| format!("failed to read view definition for '{name}'"))?;
        let mut def: ViewDefinition = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse view definition for '{name}'"))?;
        def.updated_at = def.updated_at;
        Ok(def)
    }

    pub fn run(&self, name: &str) -> Result<Vec<ViewRow>> {
        let definition = self.get(name)?;
        let rule = ViewRule::parse(&definition.rule)?;
        let docs = self.doc_store.all_docs()?;
        let mut rows = Vec::new();
        for doc in docs {
            if rule.matches(&doc) {
                rows.push(ViewRow::from_doc(&doc));
            }
        }
        Ok(rows)
    }

    pub fn snapshot(&self, name: &str) -> Result<ViewSnapshot> {
        let rows = self.run(name)?;
        let timestamp = OffsetDateTime::now_utc();
        let snapshot_core = json!({
            "view": name,
            "rows": rows,
            "captured_at": timestamp,
        });
        let canonical = serde_jcs::to_string(&snapshot_core)?;
        let canonical_hash = blake3::hash(canonical.as_bytes()).to_hex().to_string();
        let snapshot = ViewSnapshot {
            view: name.to_string(),
            captured_at: timestamp,
            canonical_hash: canonical_hash.clone(),
            rows: rows.clone(),
            location: None,
        };
        let dir = self.view_dir(name)?;
        let snap_dir = dir.join("snapshots");
        fs::create_dir_all(&snap_dir)
            .with_context(|| format!("failed to create {}", snap_dir.display()))?;
        let filename = format!("snapshot-{}.json", timestamp.unix_timestamp());
        let path = snap_dir.join(filename);
        fs::write(&path, serde_json::to_vec_pretty(&snapshot)?)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(ViewSnapshot {
            location: Some(path),
            ..snapshot
        })
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let dir = self.view_dir(name)?;
        if !dir.exists() {
            return Err(anyhow!("view '{name}' not found"));
        }
        fs::remove_dir_all(&dir).with_context(|| format!("failed to delete view '{}'", name))?;
        Ok(())
    }

    fn views_root(&self) -> Result<PathBuf> {
        self.vault.node_subdir(&self.alias, VIEWS_ROOT)
    }

    fn view_dir(&self, name: &str) -> Result<PathBuf> {
        Ok(self.views_root()?.join(name))
    }

    fn write_definition(&self, dir: &Path, def: &ViewDefinition) -> Result<()> {
        let path = dir.join("view.json");
        fs::write(&path, serde_json::to_vec_pretty(def)?)
            .with_context(|| format!("failed to write {}", path.display()))
    }

    fn validate_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(anyhow!("view name cannot be empty"));
        }
        if name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            Ok(())
        } else {
            Err(anyhow!(
                "invalid view name '{}'; use letters, numbers, dash or underscore",
                name
            ))
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ViewDefinition {
    pub name: String,
    pub rule: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ViewRow {
    pub id: String,
    #[serde(rename = "type")]
    pub doc_type: String,
    pub canonical_hash: String,
}

impl ViewRow {
    fn from_doc(doc: &StoredDoc) -> Self {
        Self {
            id: doc.id.clone(),
            doc_type: doc.doc_type.clone(),
            canonical_hash: doc.canonical_hash.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ViewSnapshot {
    pub view: String,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
    pub canonical_hash: String,
    pub rows: Vec<ViewRow>,
    #[serde(skip)]
    pub location: Option<PathBuf>,
}

struct ViewRule {
    doc_type: String,
    required_tags: Vec<String>,
    raw: String,
}

impl ViewRule {
    fn parse(rule: &str) -> Result<Self> {
        let mut doc_type = None;
        let mut tags = Vec::new();
        for token in rule.split("AND") {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Some(rest) = token.strip_prefix("type=") {
                doc_type = Some(rest.trim().to_string());
                continue;
            }
            if let Some(rest) = token.strip_prefix("tags:") {
                tags.push(Self::strip_quotes(rest.trim()).to_string());
                continue;
            }
            if let Some(rest) = token.strip_prefix("tags=") {
                tags.push(Self::strip_quotes(rest.trim()).to_string());
                continue;
            }
            return Err(anyhow!(
                "unsupported rule fragment '{}'; use type=... AND tags:\"value\"",
                token
            ));
        }
        let doc_type = doc_type.ok_or_else(|| anyhow!("rule must include type=..."))?;
        Ok(Self {
            doc_type,
            required_tags: tags,
            raw: rule.trim().to_string(),
        })
    }

    fn matches(&self, doc: &StoredDoc) -> bool {
        if doc.doc_type != self.doc_type {
            return false;
        }
        if self.required_tags.is_empty() {
            return true;
        }
        let tags = doc.content.get("tags");
        if let Some(Value::Array(values)) = tags {
            for required in &self.required_tags {
                let mut found = false;
                for value in values {
                    if let Some(s) = value.as_str() {
                        if s == required {
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    fn strip_quotes(input: &str) -> &str {
        input.trim_matches(|c| c == '"' || c == '\'')
    }
}
