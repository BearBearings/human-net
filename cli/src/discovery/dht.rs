use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_jcs;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::discovery::{dht_dir, PresenceDoc};
use crate::identity::IdentityVault;

const HINT_SUFFIX: &str = ".json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtHint {
    pub id: String,
    pub did: String,
    pub presence_cid: String,
    pub presence_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub signature: String,
}

#[derive(Serialize)]
struct DhtHintSignView<'a> {
    id: &'a str,
    did: &'a str,
    presence_cid: &'a str,
    presence_url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<&'a String>,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

impl DhtHint {
    pub fn canonical_payload(&self) -> Result<String> {
        let view = DhtHintSignView {
            id: &self.id,
            did: &self.did,
            presence_cid: &self.presence_cid,
            presence_url: &self.presence_url,
            relay: self.relay.as_ref(),
            expires_at: self.expires_at,
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn verify(&self, vault: &IdentityVault) -> Result<()> {
        let identity = vault.load_identity(&self.did_alias()?)?;
        let canonical = self.canonical_payload()?;
        let signature_bytes = Base64
            .decode(self.signature.as_bytes())
            .context("invalid dht_hint signature encoding")?;
        let signature = ed25519_dalek::Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("signature must be 64 bytes"))?,
        );
        identity
            .keys
            .signing_key()
            .verify_strict(canonical.as_bytes(), &signature)
            .context("dht_hint signature verification failed")
    }

    fn did_alias(&self) -> Result<String> {
        let parts: Vec<&str> = self.did.rsplit(':').collect();
        if parts.is_empty() {
            return Err(anyhow!("invalid DID format"));
        }
        Ok(parts[0].to_string())
    }
}

pub fn publish_hint(
    vault: &IdentityVault,
    presence_doc: &PresenceDoc,
    presence_url: &str,
) -> Result<DhtHint> {
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity configured; run `hn id use <alias>`"))?;
    let identity = vault.load_identity(&active.alias)?;

    let did = identity.profile.id.clone();
    let presence_cid = presence_doc.canonical_hash()?;
    let expires_at = presence_doc.expires_at;

    let did_hash = compute_did_hash(&did);
    let timestamp = OffsetDateTime::now_utc();
    let timestamp_slug = timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.unix_timestamp().to_string());
    let id = format!("dht_hint:{}:{}", did_hash, timestamp_slug);

    let relay = presence_doc.relays.first().map(|relay| relay.host.clone());

    let hint = DhtHint {
        id,
        did,
        presence_cid,
        presence_url: presence_url.to_string(),
        relay,
        expires_at,
        signature: String::new(),
    };

    let canonical = hint.canonical_payload()?;
    let signature = identity.keys.signing_key().sign(canonical.as_bytes());
    let signature_b64 = Base64.encode(signature.to_bytes());

    Ok(DhtHint {
        signature: signature_b64,
        ..hint
    })
}

pub fn store_hint(home: &Path, hint: &DhtHint) -> Result<PathBuf> {
    let dir = dht_dir(home)?;
    let did_hash = compute_did_hash(&hint.did);
    let path = dir.join(format!("{}{}", did_hash, HINT_SUFFIX));
    let payload = serde_json::to_vec_pretty(hint)?;
    fs::write(&path, payload)
        .with_context(|| format!("failed to write DHT hint to {}", path.display()))?;
    Ok(path)
}

pub fn resolve_hint(home: &Path, did: &str) -> Result<Option<DhtHint>> {
    let dir = dht_dir(home)?;
    let did_hash = compute_did_hash(did);
    let path = dir.join(format!("{}{}", did_hash, HINT_SUFFIX));
    if !path.exists() {
        return Ok(None);
    }
    let data =
        fs::read(&path).with_context(|| format!("failed to read DHT hint {}", path.display()))?;
    let hint: DhtHint = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse DHT hint {}", path.display()))?;
    Ok(Some(hint))
}

pub fn compute_did_hash(did: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(did.as_bytes());
    let digest = hasher.finalize();
    digest.to_hex()[..32].to_string()
}

pub fn presence_url_from_doc(doc: &PresenceDoc) -> Result<String> {
    if let Some(url) = doc.endpoints.get("presence") {
        return Ok(url.clone());
    }
    if let Some(url) = doc.endpoints.get("mcp") {
        let mut normalized = url.trim_end_matches('/').to_string();
        normalized.push_str("/.well-known/hn/presence");
        return Ok(normalized);
    }
    Err(anyhow!(
        "presence document has no 'presence' or 'mcp' endpoint; specify --presence-url"
    ))
}

pub fn relay_host_from_doc(doc: &PresenceDoc) -> Option<String> {
    doc.relays.first().map(|relay| relay.host.clone())
}

pub fn presence_url_override(default: &str, override_url: Option<String>) -> String {
    override_url.unwrap_or_else(|| default.to_string())
}

pub fn build_presence_url(doc: &PresenceDoc, override_url: Option<String>) -> Result<String> {
    let default = presence_url_from_doc(doc)?;
    Ok(presence_url_override(&default, override_url))
}

pub fn to_json(hint: &DhtHint) -> serde_json::Value {
    serde_json::json!({
        "id": hint.id,
        "did": hint.did,
        "presence_cid": hint.presence_cid,
        "presence_url": hint.presence_url,
        "relay": hint.relay,
        "expires_at": hint.expires_at,
        "signature": hint.signature,
    })
}

pub fn suggested_dns_record(did: &str, presence_url: &str) -> Option<(String, String)> {
    let alias = did.rsplit(':').next()?.trim();
    if alias.is_empty() {
        return None;
    }
    let host_part = presence_url
        .splitn(2, "://")
        .nth(1)?
        .split('/')
        .next()?
        .split(':')
        .next()?
        .trim()
        .trim_end_matches('.');
    if host_part.is_empty() {
        return None;
    }
    let name = format!("_hn.did.{}.{}", alias, host_part);
    let value = format!("{}={}", did, presence_url);
    Some((name, value))
}
