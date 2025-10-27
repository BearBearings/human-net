use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use ed25519_dalek::{Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_jcs;
use serde_json::{self, Value};
use time::OffsetDateTime;

use crate::contract::{sanitize_component, timestamp_slug};
use crate::home::ensure_subdir;
use crate::identity::{IdentityRecord, IdentityVault};

const PLANS_DIR: &str = "plans";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanDoc {
    pub id: String,
    pub prompt: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub version: u32,
    pub steps: Vec<PlanStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanStep {
    pub intent: String,
    pub params: Value,
}

impl PlanDoc {
    pub fn canonical_payload(&self) -> Result<String> {
        let view = PlanSignView {
            id: &self.id,
            prompt: &self.prompt,
            created_at: self.created_at,
            version: self.version,
            steps: &self.steps,
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let Some(signature_b64) = &self.signature else {
            return Err(anyhow!("plan missing signature"));
        };
        let signature_bytes = Base64
            .decode(signature_b64.as_bytes())
            .context("invalid plan signature encoding")?;
        let signature = ed25519_dalek::Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("plan signature must be 64 bytes"))?,
        );
        let canonical = self.canonical_payload()?;
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .context("plan signature verification failed")
    }
}

#[derive(Serialize)]
struct PlanSignView<'a> {
    id: &'a str,
    prompt: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    version: u32,
    steps: &'a [PlanStep],
}

pub struct PlanStore {
    home: PathBuf,
    alias: String,
    identity: IdentityRecord,
}

impl PlanStore {
    pub fn open(vault: &IdentityVault) -> Result<Self> {
        let active = vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
        let identity = vault.load_identity(&active.alias)?;
        Ok(Self {
            home: vault.root().to_path_buf(),
            alias: active.alias,
            identity,
        })
    }

    pub fn plans_dir(&self) -> Result<PathBuf> {
        let root = ensure_subdir(&self.home, PLANS_DIR)?;
        ensure_subdir(&root, &self.alias)
    }

    pub fn generate_plan(&self, prompt: &str, steps: Vec<PlanStep>) -> Result<PlanDoc> {
        let created_at = OffsetDateTime::now_utc();
        let slug = sanitize_component(&timestamp_slug(created_at));
        let id = format!("plan:{}:{}", sanitize_component(&self.alias), slug);

        let mut doc = PlanDoc {
            id,
            prompt: prompt.to_string(),
            created_at,
            version: 1,
            steps,
            signature: None,
        };
        self.sign(&mut doc)?;
        Ok(doc)
    }

    pub fn save(&self, doc: &PlanDoc) -> Result<PathBuf> {
        let dir = self.plans_dir()?;
        let path = dir.join(format!("{}.json", sanitize_filename(&doc.id)));
        let payload = serde_json::to_vec_pretty(doc)?;
        std::fs::write(&path, payload)
            .with_context(|| format!("failed to write plan to {}", path.display()))?;
        Ok(path)
    }

    pub fn load(&self, plan_id: &str) -> Result<PlanDoc> {
        let dir = self.plans_dir()?;
        let path = dir.join(format!("{}.json", sanitize_filename(plan_id)));
        let data = std::fs::read(&path)
            .with_context(|| format!("failed to read plan {}", path.display()))?;
        let doc: PlanDoc = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse plan {}", path.display()))?;
        Ok(doc)
    }

    pub fn list(&self) -> Result<Vec<PlanDoc>> {
        let dir = self.plans_dir()?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut docs = Vec::new();
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let data = std::fs::read(entry.path())
                .with_context(|| format!("failed to read plan {}", entry.path().display()))?;
            let doc: PlanDoc = serde_json::from_slice(&data)
                .with_context(|| format!("failed to parse plan {}", entry.path().display()))?;
            docs.push(doc);
        }
        docs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(docs)
    }

    fn sign(&self, doc: &mut PlanDoc) -> Result<()> {
        let canonical = doc.canonical_payload()?;
        let signature = self.identity.keys.signing_key().sign(canonical.as_bytes());
        doc.signature = Some(Base64.encode(signature.to_bytes()));
        Ok(())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.identity.keys.signing_key().verifying_key()
    }
}

fn sanitize_filename(value: &str) -> String {
    value.replace([':', '/', ' '], "_")
}

pub fn build_offer_plan_step(doc: &str, audience: &str, capability: &str) -> PlanStep {
    let mut params = serde_json::Map::new();
    params.insert("doc".to_string(), Value::String(doc.to_string()));
    params.insert("audience".to_string(), Value::String(audience.to_string()));
    params.insert(
        "capability".to_string(),
        Value::String(capability.to_string()),
    );
    PlanStep {
        intent: "contract.offer.create".to_string(),
        params: Value::Object(params),
    }
}

pub fn build_publish_plan_step() -> PlanStep {
    let mut params = serde_json::Map::new();
    params.insert(
        "command".to_string(),
        Value::String("shard.publish".to_string()),
    );
    PlanStep {
        intent: "shard.publish".to_string(),
        params: Value::Object(params),
    }
}
