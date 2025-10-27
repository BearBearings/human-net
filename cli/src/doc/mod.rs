use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::contract::{sanitize_component, timestamp_slug};
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

    pub fn for_alias(vault: &'a IdentityVault, alias: &str) -> Result<Self> {
        let identity = vault.load_identity(alias)?;
        Ok(Self {
            vault,
            alias: alias.to_string(),
            did: identity.profile.id.clone(),
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

    pub fn apply_remote_doc(&self, doc: &StoredDoc) -> Result<DocSyncStatus> {
        let path = self.doc_path(&doc.doc_type, &doc.id);
        let existed = path.exists();
        if existed {
            let existing = self.read_file(path.clone())?;
            if existing.canonical_hash == doc.canonical_hash {
                return Ok(DocSyncStatus::Skipped);
            }
            if existing.updated_at >= doc.updated_at {
                return Ok(DocSyncStatus::Skipped);
            }
        }
        let mut clone = doc.clone();
        clone.location = None;
        let _ = self.write_doc(&doc.doc_type, &clone)?;
        Ok(if existed {
            DocSyncStatus::Updated
        } else {
            DocSyncStatus::Created
        })
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

    pub fn identity_record(&self) -> &IdentityRecord {
        &self.identity
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocSyncStatus {
    Created,
    Updated,
    Skipped,
}

#[derive(Debug, Clone, Copy)]
pub enum ViewSource {
    Local,
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

    pub fn list_with_receipts(&self) -> Result<Vec<ViewSummary>> {
        let definitions = self.list()?;
        let mut summaries = Vec::new();
        for def in definitions {
            let latest_receipt = self
                .latest_receipt_optional(&def.name)?
                .map(ViewReceiptSummary::from_receipt);
            summaries.push(ViewSummary {
                name: def.name.clone(),
                rule: def.rule.clone(),
                created_at: def.created_at,
                updated_at: def.updated_at,
                latest_receipt,
            });
        }
        Ok(summaries)
    }

    pub fn materialize(&self, name: &str, source: ViewSource) -> Result<ViewMaterialization> {
        let rows = self.run(name)?;
        let captured_at = OffsetDateTime::now_utc();
        let canonical_snapshot = snapshot_canonical_payload(name, &rows, captured_at)?;
        let snapshot_hash = blake3::hash(canonical_snapshot.as_bytes())
            .to_hex()
            .to_string();

        let mut snapshot = ViewSnapshot {
            view: name.to_string(),
            captured_at,
            canonical_hash: snapshot_hash.clone(),
            rows: rows.clone(),
            location: None,
        };

        let identity = self.doc_store.identity_record();
        let signer_did = identity.profile.id.clone();
        let sources = match source {
            ViewSource::Local => vec![signer_did.clone()],
        };

        let slug = timestamp_slug(captured_at);
        let receipt_id = format!(
            "receipt:{}:{}:{}",
            sanitize_component(&self.alias),
            sanitize_component(name),
            slug
        );

        let mut receipt = ViewReceipt {
            id: receipt_id,
            view: name.to_string(),
            snapshot_canonical_hash: snapshot_hash.clone(),
            rows: rows.len(),
            signer: signer_did,
            source: sources,
            merkle_proof: None,
            captured_at,
            canonical_hash: String::new(),
            signature: String::new(),
            location: None,
        };

        let canonical_receipt = receipt.canonical_payload()?;
        receipt.canonical_hash = blake3::hash(canonical_receipt.as_bytes())
            .to_hex()
            .to_string();
        let signature = identity
            .keys
            .signing_key()
            .sign(canonical_receipt.as_bytes());
        receipt.signature = Base64.encode(signature.to_bytes());

        let dir = self.view_dir(name)?;
        let snapshots_dir = dir.join("snapshots");
        fs::create_dir_all(&snapshots_dir)
            .with_context(|| format!("failed to create {}", snapshots_dir.display()))?;
        let receipts_dir = dir.join("receipts");
        fs::create_dir_all(&receipts_dir)
            .with_context(|| format!("failed to create {}", receipts_dir.display()))?;

        let snapshot_path =
            snapshots_dir.join(format!("snapshot-{}.json", sanitize_component(&slug)));
        fs::write(&snapshot_path, serde_json::to_vec_pretty(&snapshot)?)
            .with_context(|| format!("failed to write {}", snapshot_path.display()))?;
        snapshot.location = Some(snapshot_path);

        let receipt_path = receipts_dir.join(format!("receipt-{}.json", sanitize_component(&slug)));
        fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt)?)
            .with_context(|| format!("failed to write {}", receipt_path.display()))?;
        receipt.location = Some(receipt_path);

        Ok(ViewMaterialization { snapshot, receipt })
    }

    pub fn verify_receipt(
        &self,
        name: &str,
        receipt_path: Option<&Path>,
    ) -> Result<ViewVerification> {
        let receipt = match receipt_path {
            Some(path) => self.read_receipt_file(path.to_path_buf())?,
            None => self.latest_receipt(name)?,
        };

        let verifying_key = self
            .doc_store
            .identity_record()
            .keys
            .signing_key()
            .verifying_key();
        let canonical = receipt.canonical_payload()?;
        let signature_bytes = Base64
            .decode(receipt.signature.as_bytes())
            .context("invalid receipt signature encoding")?;
        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("receipt signature must be 64 bytes"))?;
        let signature = Signature::from_bytes(&signature_array);
        let signature_valid = verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .is_ok();

        let rows = self.run(name)?;
        let current_canonical = snapshot_canonical_payload(name, &rows, receipt.captured_at)?;
        let current_hash = blake3::hash(current_canonical.as_bytes())
            .to_hex()
            .to_string();
        let matches_current = current_hash == receipt.snapshot_canonical_hash;

        Ok(ViewVerification {
            view: name.to_string(),
            receipt_id: receipt.id.clone(),
            receipt_path: receipt.location.as_ref().map(|p| p.display().to_string()),
            signature_valid,
            recorded_hash: receipt.snapshot_canonical_hash.clone(),
            current_hash,
            matches_current,
            rows_recorded: receipt.rows,
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

    fn receipts_dir(&self, name: &str) -> Result<PathBuf> {
        Ok(self.view_dir(name)?.join("receipts"))
    }

    fn read_receipt_file(&self, path: PathBuf) -> Result<ViewReceipt> {
        let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let mut receipt: ViewReceipt = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        receipt.location = Some(path);
        Ok(receipt)
    }

    fn latest_receipt(&self, name: &str) -> Result<ViewReceipt> {
        self.latest_receipt_optional(name)?
            .ok_or_else(|| anyhow!("no receipts materialised for view '{name}'"))
    }

    fn latest_receipt_optional(&self, name: &str) -> Result<Option<ViewReceipt>> {
        let dir = self.receipts_dir(name)?;
        if !dir.exists() {
            return Ok(None);
        }
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .with_context(|| format!("failed to read {}", dir.display()))?
            .filter_map(|res| res.ok())
            .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .collect();
        if entries.is_empty() {
            return Ok(None);
        }
        entries.sort_by_key(|entry| entry.file_name());
        let path = entries
            .last()
            .map(|entry| entry.path())
            .ok_or_else(|| anyhow!("no receipts materialised for view '{name}'"))?;
        self.read_receipt_file(path).map(Some)
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
pub struct ViewSummary {
    pub name: String,
    pub rule: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_receipt: Option<ViewReceiptSummary>,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct ViewReceipt {
    pub id: String,
    pub view: String,
    pub snapshot_canonical_hash: String,
    pub rows: usize,
    pub signer: String,
    pub source: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
    pub canonical_hash: String,
    pub signature: String,
    #[serde(skip)]
    pub location: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ViewReceiptSummary {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub captured_at: OffsetDateTime,
    pub canonical_hash: String,
    pub rows: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ViewMaterialization {
    pub snapshot: ViewSnapshot,
    pub receipt: ViewReceipt,
}

#[derive(Debug, Serialize)]
pub struct ViewVerification {
    pub view: String,
    pub receipt_id: String,
    pub signature_valid: bool,
    pub recorded_hash: String,
    pub current_hash: String,
    pub matches_current: bool,
    pub rows_recorded: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_path: Option<String>,
}

fn snapshot_canonical_payload(
    view: &str,
    rows: &[ViewRow],
    captured_at: OffsetDateTime,
) -> Result<String> {
    let sign_view = SnapshotSignView {
        view,
        captured_at,
        rows,
    };
    Ok(serde_jcs::to_string(&sign_view)?)
}

#[derive(Serialize)]
struct SnapshotSignView<'a> {
    view: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    captured_at: OffsetDateTime,
    rows: &'a [ViewRow],
}

impl ViewReceipt {
    fn canonical_payload(&self) -> Result<String> {
        let sign_view = ViewReceiptSignView {
            view: &self.view,
            snapshot_canonical_hash: &self.snapshot_canonical_hash,
            rows: self.rows,
            signer: &self.signer,
            source: &self.source,
            merkle_proof: self.merkle_proof.as_ref(),
            captured_at: self.captured_at,
        };
        Ok(serde_jcs::to_string(&sign_view)?)
    }
}

#[derive(Serialize)]
struct ViewReceiptSignView<'a> {
    view: &'a str,
    snapshot_canonical_hash: &'a str,
    rows: usize,
    signer: &'a str,
    source: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_proof: Option<&'a String>,
    #[serde(with = "time::serde::rfc3339")]
    captured_at: OffsetDateTime,
}

impl ViewReceiptSummary {
    fn from_receipt(receipt: ViewReceipt) -> Self {
        let file = receipt.location.as_ref().map(|p| p.display().to_string());
        Self {
            id: receipt.id,
            captured_at: receipt.captured_at,
            canonical_hash: receipt.canonical_hash,
            rows: receipt.rows,
            file,
        }
    }
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
