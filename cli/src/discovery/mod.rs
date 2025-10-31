use std::cmp;
pub mod dht;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_jcs;
use serde_json;
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use ureq::{Agent, AgentBuilder};

use crate::contract::{sanitize_component, timestamp_slug};
use crate::discovery::dht::DhtHint;
use crate::home::ensure_subdir;
use crate::identity::{IdentityRecord, IdentityVault};

const PRESENCE_DIR: &str = "presence";
const HINTS_DIR: &str = "hints";
const DHT_DIR: &str = "dht";

fn discovery_base_url() -> String {
    env::var("HN_DISCOVERY_URL").unwrap_or_else(|_| "http://127.0.0.1:7710".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PresenceRelay {
    pub host: String,
    pub url: String,
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceDoc {
    pub id: String,
    pub did: String,
    #[serde(default)]
    pub endpoints: BTreeMap<String, String>,
    pub merkle_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<PresenceRelay>,
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
            relays: if self.relays.is_empty() {
                None
            } else {
                Some(&self.relays)
            },
            expires_at: self.expires_at,
            issued_at: self.issued_at,
            ttl_seconds: self.ttl_seconds,
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn canonical_hash(&self) -> Result<String> {
        let canonical = self.canonical_payload()?;
        Ok(blake3::hash(canonical.as_bytes()).to_hex().to_string())
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
    #[serde(skip_serializing_if = "Option::is_none")]
    relays: Option<&'a [PresenceRelay]>,
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
    relays: Vec<PresenceRelay>,
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
        relays,
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

pub fn dht_dir(home: &Path) -> Result<PathBuf> {
    let dir = ensure_subdir(home, "discovery")?;
    ensure_subdir(&dir, DHT_DIR)
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

pub fn fetch_presence_with_retry(
    url: &str,
    attempts: usize,
    delay: Duration,
) -> Result<PresenceDoc> {
    let attempts = attempts.max(1);
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..attempts {
        match fetch_presence(url) {
            Ok(doc) => return Ok(doc),
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < attempts {
                    thread::sleep(delay);
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("presence fetch failed")))
}

#[derive(Debug, Deserialize)]
struct PublishResponse {
    status: String,
    #[serde(default)]
    hint: Option<DhtHint>,
}

pub fn publish_dht_hint(
    doc: &PresenceDoc,
    presence_url: Option<String>,
) -> Result<Option<DhtHint>> {
    let agent: Agent = AgentBuilder::new().timeout(Duration::from_secs(10)).build();
    let base = discovery_base_url();
    let endpoint = format!("{}/dht/publish", base.trim_end_matches('/'));
    let request = agent.post(&endpoint);
    let body = json!({
        "presence": doc,
        "presence_url": presence_url,
    });
    let response = request
        .send_json(body)
        .map_err(|err| anyhow!("failed to publish DHT hint: {err}"))?;
    let parsed: PublishResponse = response
        .into_json()
        .map_err(|err| anyhow!("failed to parse DHT publish response: {err}"))?;
    if parsed.status != "ok" {
        return Err(anyhow!("DHT publish failed"));
    }
    Ok(parsed.hint)
}

pub fn fetch_dht_hint(did: &str) -> Result<Option<DhtHint>> {
    let agent: Agent = AgentBuilder::new().timeout(Duration::from_secs(10)).build();
    let base = discovery_base_url();
    let url = format!("{}/dht/{}", base.trim_end_matches('/'), did);
    let response = agent.get(&url).call();
    match response {
        Ok(resp) => {
            let hint: DhtHint = resp
                .into_json()
                .map_err(|err| anyhow!("failed to parse DHT hint: {err}"))?;
            Ok(Some(hint))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(err) => Err(anyhow!("failed to resolve dht hint: {err}")),
    }
}
