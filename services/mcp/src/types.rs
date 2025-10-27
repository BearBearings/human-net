use std::fmt;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardIndexEntry {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub path: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardIndex {
    pub id: String,
    pub publisher: String,
    pub publisher_public_key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub entries: Vec<ShardIndexEntry>,
    pub merkle_root: String,
    pub canonical_hash: String,
    pub signature: String,
}

impl ShardIndex {
    pub fn canonical_payload(&self) -> Result<String> {
        let view = ShardIndexSignView {
            id: &self.id,
            publisher: &self.publisher,
            publisher_public_key: &self.publisher_public_key,
            generated_at: self.generated_at,
            entries: &self.entries,
            merkle_root: &self.merkle_root,
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn verify_signature(&self) -> Result<()> {
        let verifying_key_bytes = Base64
            .decode(self.publisher_public_key.as_bytes())
            .context("invalid publisher_public_key encoding")?;
        let verifying_key = VerifyingKey::from_bytes(
            verifying_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("publisher_public_key must be 32 bytes"))?,
        )
        .context("failed to parse publisher verifying key")?;
        let signature_bytes = Base64
            .decode(self.signature.as_bytes())
            .context("invalid shard index signature encoding")?;
        let signature = Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("expected 64-byte signature"))?,
        );
        let canonical = self.canonical_payload()?;
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .context("shard index signature verification failed")?;
        let mut hasher = Hasher::new();
        hasher.update(canonical.as_bytes());
        let computed_hash = hasher.finalize().to_hex().to_string();
        if computed_hash != self.canonical_hash {
            return Err(anyhow!(
                "shard index canonical hash mismatch (expected {}, computed {})",
                self.canonical_hash,
                computed_hash
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ShardIndexSignView<'a> {
    id: &'a str,
    publisher: &'a str,
    publisher_public_key: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    generated_at: OffsetDateTime,
    entries: &'a [ShardIndexEntry],
    merkle_root: &'a str,
}

pub fn compute_merkle_root(digests: &[String]) -> String {
    let mut sorted = digests.to_vec();
    sorted.sort();
    let mut hasher = Hasher::new();
    for digest in sorted {
        hasher.update(digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

impl fmt::Display for ShardIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (merkle={})", self.id, self.merkle_root)
    }
}
