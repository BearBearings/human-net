use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_jcs;
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::contract::sanitize_component;
use crate::identity::{IdentityRecord, IdentityVault};

const TRUST_ROOT: &str = "trust";
const LINKS_DIR: &str = "links";
const REPUTATION_DIR: &str = "reputation";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLink {
    pub id: String,
    pub from: String,
    pub to: String,
    pub based_on: Vec<String>,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    pub signature: String,
}

#[derive(Serialize)]
struct TrustLinkSignView<'a> {
    id: &'a str,
    from: &'a str,
    to: &'a str,
    based_on: &'a [String],
    confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a String>,
    #[serde(with = "time::serde::rfc3339")]
    last_seen: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationStats {
    pub avg_confidence: f64,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stddev: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reputation {
    pub id: String,
    pub observer: String,
    pub target: String,
    pub links: Vec<String>,
    pub aggregate: ReputationStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub signature: String,
}

#[derive(Serialize)]
struct ReputationSignView<'a> {
    id: &'a str,
    observer: &'a str,
    target: &'a str,
    links: &'a [String],
    aggregate: &'a ReputationStats,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_ref: Option<&'a String>,
}

pub struct TrustLinkStore {
    identity: IdentityRecord,
    alias: String,
    home: PathBuf,
}

impl TrustLinkStore {
    pub fn open(vault: &IdentityVault) -> Result<Self> {
        let active = vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
        let identity = vault.load_identity(&active.alias)?;
        Ok(Self {
            identity,
            alias: active.alias,
            home: vault.root().to_path_buf(),
        })
    }

    pub fn for_alias(vault: &IdentityVault, alias: &str) -> Result<Self> {
        let identity = vault.load_identity(alias)?;
        Ok(Self {
            identity,
            alias: alias.to_string(),
            home: vault.root().to_path_buf(),
        })
    }

    pub fn create_link(
        &self,
        to: &str,
        based_on: Vec<String>,
        confidence: f64,
        context: Option<String>,
        last_seen: Option<OffsetDateTime>,
        ttl: Option<Duration>,
    ) -> Result<TrustLink> {
        if based_on.is_empty() {
            return Err(anyhow!(
                "at least one evidence reference is required (--based-on)"
            ));
        }
        if !(0.0..=1.0).contains(&confidence) {
            return Err(anyhow!("confidence must be between 0.0 and 1.0"));
        }
        if to.trim().is_empty() {
            return Err(anyhow!("target DID (--to) cannot be empty"));
        }

        let now = OffsetDateTime::now_utc();
        let last_seen = last_seen.unwrap_or(now);
        let ttl_seconds = ttl.map(|value| value.as_secs());

        let from_did = self.identity.profile.id.clone();
        let from_slug = sanitize_component(&from_did);
        let to_slug = sanitize_component(to);
        let timestamp = last_seen
            .format(&Rfc3339)
            .unwrap_or_else(|_| last_seen.unix_timestamp().to_string());
        let id = format!("trust_link:{}:{}:{}", from_slug, to_slug, timestamp);

        let view = TrustLinkSignView {
            id: &id,
            from: &from_did,
            to,
            based_on: &based_on,
            confidence,
            context: context.as_ref(),
            last_seen,
            ttl_seconds,
        };

        let canonical = serde_jcs::to_string(&view)?;
        let signature = self.identity.keys.signing_key().sign(canonical.as_bytes());
        let signature_b64 = Base64.encode(signature.to_bytes());

        let link = TrustLink {
            id,
            from: from_did,
            to: to.to_string(),
            based_on,
            confidence,
            context,
            last_seen,
            ttl_seconds,
            signature: signature_b64,
        };
        Ok(link)
    }

    pub fn store(&self, link: &TrustLink) -> Result<PathBuf> {
        let dir = self.links_dir()?;
        let path = dir.join(format!("{}.json", sanitize_component(&link.id)));
        let payload = serde_json::to_vec_pretty(link)?;
        fs::write(&path, &payload)
            .with_context(|| format!("failed to write trust link at {}", path.display()))?;
        Ok(path)
    }

    pub fn list(&self) -> Result<Vec<TrustLink>> {
        let dir = self.links_dir()?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut links = Vec::new();
        for entry in fs::read_dir(&dir)
            .with_context(|| format!("failed to read trust directory {}", dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let file = fs::File::open(entry.path())
                .with_context(|| format!("failed to open {}", entry.path().display()))?;
            let link: TrustLink = serde_json::from_reader(file)
                .with_context(|| format!("failed to parse {}", entry.path().display()))?;
            links.push(link);
        }
        links.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        Ok(links)
    }

    pub fn compute_reputation(
        &self,
        target: &str,
        policy_ref: Option<String>,
        context_filter: Option<String>,
        min_links: Option<usize>,
    ) -> Result<Reputation> {
        if target.trim().is_empty() {
            return Err(anyhow!("target DID (--target) cannot be empty"));
        }
        let links = self.list()?;
        let filtered: Vec<TrustLink> = links
            .into_iter()
            .filter(|link| link.to == target)
            .filter(|link| match &context_filter {
                Some(ctx) => link.context.as_deref() == Some(ctx.as_str()),
                None => true,
            })
            .collect();

        if filtered.is_empty() {
            return Err(anyhow!("no trust links found for target {target}"));
        }
        if let Some(required) = min_links {
            if filtered.len() < required {
                return Err(anyhow!(
                    "only {} link(s) available for {}; --min-links={} required",
                    filtered.len(),
                    target,
                    required
                ));
            }
        }

        let mut sum = 0.0_f64;
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for link in &filtered {
            sum += link.confidence;
            if link.confidence < min {
                min = link.confidence;
            }
            if link.confidence > max {
                max = link.confidence;
            }
        }
        let count = filtered.len() as f64;
        let avg = (sum / count).clamp(0.0, 1.0);
        let variance = if filtered.len() > 1 {
            let mean = avg;
            let mut accum = 0.0_f64;
            for link in &filtered {
                let diff = link.confidence - mean;
                accum += diff * diff;
            }
            Some((accum / count).sqrt())
        } else {
            None
        };

        let stats = ReputationStats {
            avg_confidence: avg,
            count: filtered.len() as u64,
            min_confidence: if filtered.len() > 0 { Some(min) } else { None },
            max_confidence: if filtered.len() > 0 { Some(max) } else { None },
            stddev: variance,
        };

        let observer_did = self.identity.profile.id.clone();
        let observer_slug = sanitize_component(&observer_did);
        let target_slug = sanitize_component(target);
        let generated_at = OffsetDateTime::now_utc();
        let timestamp = generated_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| generated_at.unix_timestamp().to_string());
        let id = format!("reputation:{}:{}:{}", observer_slug, target_slug, timestamp);

        let mut link_ids: Vec<String> = filtered.iter().map(|link| link.id.clone()).collect();
        link_ids.sort();

        let view = ReputationSignView {
            id: &id,
            observer: &observer_did,
            target,
            links: &link_ids,
            aggregate: &stats,
            generated_at,
            policy_ref: policy_ref.as_ref(),
        };

        let canonical = serde_jcs::to_string(&view)?;
        let signature = self.identity.keys.signing_key().sign(canonical.as_bytes());
        let signature_b64 = Base64.encode(signature.to_bytes());

        Ok(Reputation {
            id,
            observer: observer_did,
            target: target.to_string(),
            links: link_ids,
            aggregate: stats,
            policy_ref,
            generated_at,
            signature: signature_b64,
        })
    }

    pub fn store_reputation(&self, reputation: &Reputation) -> Result<PathBuf> {
        let dir = self.reputation_dir()?;
        let path = dir.join(format!("{}.json", sanitize_component(&reputation.id)));
        let payload = serde_json::to_vec_pretty(reputation)?;
        fs::write(&path, &payload)
            .with_context(|| format!("failed to write reputation doc at {}", path.display()))?;
        Ok(path)
    }

    pub fn list_reputation(&self) -> Result<Vec<Reputation>> {
        let dir = self.reputation_dir()?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut reps = Vec::new();
        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let file = fs::File::open(entry.path())
                .with_context(|| format!("failed to open {}", entry.path().display()))?;
            let rep: Reputation = serde_json::from_reader(file)
                .with_context(|| format!("failed to parse {}", entry.path().display()))?;
            reps.push(rep);
        }
        reps.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));
        Ok(reps)
    }

    fn links_dir(&self) -> Result<PathBuf> {
        let dir = self.home.join(TRUST_ROOT).join(LINKS_DIR).join(&self.alias);
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        Ok(dir)
    }

    fn reputation_dir(&self) -> Result<PathBuf> {
        let dir = self
            .home
            .join(TRUST_ROOT)
            .join(REPUTATION_DIR)
            .join(&self.alias);
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        Ok(dir)
    }
}

pub fn trust_link_to_json(link: &TrustLink) -> serde_json::Value {
    json!({
        "id": link.id,
        "from": link.from,
        "to": link.to,
        "confidence": link.confidence,
        "based_on": link.based_on,
        "context": link.context,
        "last_seen": link.last_seen,
        "ttl_seconds": link.ttl_seconds,
        "signature": link.signature,
    })
}

pub fn reputation_to_json(rep: &Reputation) -> serde_json::Value {
    json!({
        "id": rep.id,
        "observer": rep.observer,
        "target": rep.target,
        "links": rep.links,
        "aggregate": {
            "avg_confidence": rep.aggregate.avg_confidence,
            "count": rep.aggregate.count,
            "min_confidence": rep.aggregate.min_confidence,
            "max_confidence": rep.aggregate.max_confidence,
            "stddev": rep.aggregate.stddev,
        },
        "policy_ref": rep.policy_ref,
        "generated_at": rep.generated_at,
        "signature": rep.signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityVault;
    use crate::policy::PolicyEvaluator;
    use serde_json::Value;
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[test]
    fn derive_and_compute_reputation() -> Result<()> {
        let temp = tempdir()?;
        let vault = IdentityVault::new(temp.path().to_path_buf())?;
        let _: IdentityRecord =
            vault.create_identity("alice", vec![], HashMap::<String, Value>::new())?;
        let store = TrustLinkStore::open(&vault)?;

        let link1 = store.create_link(
            "did:hn:bob",
            vec!["contract:test-001".to_string()],
            0.9,
            None,
            None,
            None,
        )?;
        store.store(&link1)?;
        let link2 = store.create_link(
            "did:hn:bob",
            vec!["payment:test-002".to_string()],
            0.7,
            Some("micropay".to_string()),
            None,
            None,
        )?;
        store.store(&link2)?;

        let rep = store.compute_reputation("did:hn:bob", None, None, Some(2))?;
        assert_eq!(rep.target, "did:hn:bob");
        assert_eq!(rep.aggregate.count, 2);
        assert!((rep.aggregate.avg_confidence - 0.8).abs() < 1e-6);
        assert!(rep.signature.len() > 40);
        PolicyEvaluator::check_trust_threshold(&vault, "alice", "did:hn:bob", 0.75, 2, None)?;
        assert!(PolicyEvaluator::check_trust_threshold(
            &vault,
            "alice",
            "did:hn:bob",
            0.85,
            2,
            None
        )
        .is_err());
        Ok(())
    }
}
