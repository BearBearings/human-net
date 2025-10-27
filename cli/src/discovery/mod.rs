use std::cmp;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_jcs;
use serde_json;
use time::{Duration as TimeDuration, OffsetDateTime};
use ureq::{Agent, AgentBuilder};

use crate::contract::{sanitize_component, timestamp_slug};
use crate::home::ensure_subdir;
use crate::identity::{IdentityRecord, IdentityVault};

const PRESENCE_DIR: &str = "presence";
const HINTS_DIR: &str = "hints";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceDoc {
    pub id: String,
    pub did: String,
    #[serde(default)]
    pub endpoints: BTreeMap<String, String>,
    pub merkle_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl PresenceDoc {
    pub fn canonical_payload(&self) -> Result<String> {
        let view = PresenceSignView {
            did: &self.did,
            endpoints: &self.endpoints,
            merkle_root: &self.merkle_root,
            proof: self.proof.as_deref(),
            expires_at: self.expires_at,
            issued_at: self.issued_at,
            ttl_seconds: self.ttl_seconds,
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let Some(signature_b64) = &self.signature else {
            return Err(anyhow!("presence document missing signature"));
        };
        let signature_bytes = Base64
            .decode(signature_b64.as_bytes())
            .context("invalid presence signature encoding")?;
        let signature = Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("presence signature must be 64 bytes"))?,
        );
        let canonical = self.canonical_payload()?;
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .context("presence signature verification failed")
    }
}

#[derive(Serialize)]
struct PresenceSignView<'a> {
    did: &'a str,
    endpoints: &'a BTreeMap<String, String>,
    merkle_root: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<&'a str>,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

pub fn generate_presence_doc(
    vault: &IdentityVault,
    alias: &str,
    endpoints: BTreeMap<String, String>,
    merkle_root: String,
    proof: Option<String>,
    ttl: Duration,
) -> Result<PresenceDoc> {
    let identity = vault.load_identity(alias)?;
    let issued_at = OffsetDateTime::now_utc();
    let ttl_secs = cmp::max(ttl.as_secs(), 60);
    let expires_at = issued_at + TimeDuration::seconds(ttl_secs as i64);
    let id = format!(
        "presence:{}:{}",
        sanitize_component(&identity.profile.id),
        timestamp_slug(issued_at)
    );

    let mut doc = PresenceDoc {
        id,
        did: identity.profile.id.clone(),
        endpoints,
        merkle_root,
        proof,
        expires_at,
        issued_at,
        ttl_seconds: Some(ttl_secs),
        signature: None,
    };

    sign_presence(&identity, &mut doc)?;
    Ok(doc)
}

fn sign_presence(identity: &IdentityRecord, doc: &mut PresenceDoc) -> Result<()> {
    let signing_key = identity.keys.signing_key();
    let canonical = doc.canonical_payload()?;
    let signature = signing_key.sign(canonical.as_bytes());
    doc.signature = Some(Base64.encode(signature.to_bytes()));
    Ok(())
}

pub fn save_presence_doc(home: &Path, alias: &str, doc: &PresenceDoc) -> Result<PathBuf> {
    let dir = presence_dir(home, alias)?;
    let path = dir.join(format!("{}.json", sanitize_filename(&doc.id)));
    let payload = serde_json::to_vec_pretty(doc)?;
    fs::write(&path, payload)
        .with_context(|| format!("failed to write presence doc to {}", path.display()))?;
    Ok(path)
}

pub fn presence_dir(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = ensure_subdir(home, PRESENCE_DIR)?;
    ensure_subdir(&dir, alias)
}

pub fn save_presence_hint(home: &Path, doc: &PresenceDoc) -> Result<PathBuf> {
    let dir = hints_dir(home)?;
    let path = dir.join(format!("{}.json", sanitize_filename(&doc.did)));
    let payload = serde_json::to_vec_pretty(doc)?;
    fs::write(&path, payload)
        .with_context(|| format!("failed to write presence hint to {}", path.display()))?;
    Ok(path)
}

pub fn load_presence_docs(home: &Path, alias: &str) -> Result<Vec<PresenceDoc>> {
    let dir = presence_dir(home, alias)?;
    load_docs_from(&dir)
}

pub fn load_presence_hints(home: &Path) -> Result<Vec<PresenceDoc>> {
    let dir = hints_dir(home)?;
    load_docs_from(&dir)
}

fn load_docs_from(dir: &Path) -> Result<Vec<PresenceDoc>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut docs = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file = fs::File::open(entry.path())
            .with_context(|| format!("failed to open presence doc {}", entry.path().display()))?;
        let doc: PresenceDoc = serde_json::from_reader(file)
            .with_context(|| format!("failed to parse presence doc {}", entry.path().display()))?;
        docs.push(doc);
    }
    docs.sort_by(|a, b| b.issued_at.cmp(&a.issued_at));
    Ok(docs)
}

fn hints_dir(home: &Path) -> Result<PathBuf> {
    let dir = ensure_subdir(home, PRESENCE_DIR)?;
    ensure_subdir(&dir, HINTS_DIR)
}

pub fn load_presence_hint(home: &Path, did: &str) -> Result<Option<PresenceDoc>> {
    let path = hints_dir(home)?.join(format!("{}.json", sanitize_filename(did)));
    if !path.exists() {
        return Ok(None);
    }
    let file = fs::File::open(&path)
        .with_context(|| format!("failed to open presence hint {}", path.display()))?;
    let doc: PresenceDoc = serde_json::from_reader(file)
        .with_context(|| format!("failed to parse presence hint {}", path.display()))?;
    Ok(Some(doc))
}

pub fn load_presence_for_did(home: &Path, did: &str) -> Result<Option<PresenceDoc>> {
    if let Some(doc) = load_presence_hint(home, did)? {
        if doc_is_fresh(&doc) {
            return Ok(Some(doc));
        }
    }

    let root = ensure_subdir(home, PRESENCE_DIR)?;
    for entry in
        fs::read_dir(&root).with_context(|| format!("failed to read {}", root.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if entry.file_name().to_string_lossy() == HINTS_DIR {
            continue;
        }
        let docs = load_docs_from(&entry.path())?;
        if let Some(doc) = docs
            .into_iter()
            .find(|doc| doc.did == did && doc_is_fresh(doc))
        {
            return Ok(Some(doc));
        }
    }

    Ok(None)
}

pub fn resolve_presence_endpoint(
    home: &Path,
    did: &str,
    key: &str,
) -> Result<Option<(PresenceDoc, String)>> {
    if let Some(doc) = load_presence_for_did(home, did)? {
        if doc_is_fresh(&doc) {
            if let Some(url) = doc.endpoints.get(key).cloned() {
                return Ok(Some((doc, url)));
            }
        }
    }
    Ok(None)
}

fn doc_is_fresh(doc: &PresenceDoc) -> bool {
    let now = OffsetDateTime::now_utc();
    doc.expires_at > now
}

fn sanitize_filename(value: &str) -> String {
    value.replace([':', '/', ' '], "_")
}

pub fn fetch_presence(url: &str) -> Result<PresenceDoc> {
    let agent: Agent = AgentBuilder::new().timeout(Duration::from_secs(15)).build();
    let response = agent
        .get(url)
        .call()
        .with_context(|| format!("failed to fetch presence from {url}"))?;
    let doc: PresenceDoc = serde_json::from_reader(response.into_reader())
        .with_context(|| format!("failed to parse presence JSON from {url}"))?;
    Ok(doc)
}
