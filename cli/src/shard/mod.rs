use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::contract::ShardEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardIndexEntry {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub path: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardReceipt {
    pub id: String,
    pub shard_id: String,
    pub contract_id: String,
    pub payload_cid: String,
    pub publisher: String,
    pub index_id: String,
    pub merkle_root: String,
    pub subscriber: String,
    pub subscriber_public_key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
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

impl ShardReceipt {
    pub fn canonical_payload(&self) -> Result<String> {
        let view = ShardReceiptSignView {
            id: &self.id,
            shard_id: &self.shard_id,
            contract_id: &self.contract_id,
            payload_cid: &self.payload_cid,
            publisher: &self.publisher,
            index_id: &self.index_id,
            merkle_root: &self.merkle_root,
            subscriber: &self.subscriber,
            subscriber_public_key: &self.subscriber_public_key,
            timestamp: self.timestamp,
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn verify_signature(&self) -> Result<()> {
        let verifying_key_bytes = Base64
            .decode(self.subscriber_public_key.as_bytes())
            .context("invalid subscriber_public_key encoding")?;
        let verifying_key = VerifyingKey::from_bytes(
            verifying_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("subscriber_public_key must be 32 bytes"))?,
        )
        .context("failed to parse subscriber verifying key")?;
        let signature_bytes = Base64
            .decode(self.signature.as_bytes())
            .context("invalid receipt signature encoding")?;
        let signature = Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("expected 64-byte signature"))?,
        );
        let canonical = self.canonical_payload()?;
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .context("receipt signature verification failed")?;
        let mut hasher = Hasher::new();
        hasher.update(canonical.as_bytes());
        let computed_hash = hasher.finalize().to_hex().to_string();
        if computed_hash != self.canonical_hash {
            return Err(anyhow!(
                "receipt canonical hash mismatch (expected {}, computed {})",
                self.canonical_hash,
                computed_hash
            ));
        }
        Ok(())
    }
}

pub fn create_index(
    publisher_did: &str,
    publisher_key: &SigningKey,
    generated_at: OffsetDateTime,
    entries: Vec<ShardIndexEntry>,
) -> Result<ShardIndex> {
    let verifying_key = publisher_key.verifying_key();
    let publisher_public_key = Base64.encode(verifying_key.to_bytes());
    let id = format!(
        "index:{}:{}",
        sanitize_component(publisher_did),
        timestamp_slug(generated_at)
    );

    let merkle_root = compute_merkle_root(
        &entries
            .iter()
            .map(|entry| entry.digest.clone())
            .collect::<Vec<_>>(),
    );

    let view = ShardIndexSignView {
        id: &id,
        publisher: publisher_did,
        publisher_public_key: &publisher_public_key,
        generated_at,
        entries: &entries,
        merkle_root: &merkle_root,
    };
    let canonical = serde_jcs::to_string(&view)?;
    let mut hasher = Hasher::new();
    hasher.update(canonical.as_bytes());
    let canonical_hash = hasher.finalize().to_hex().to_string();
    let signature = publisher_key.sign(canonical.as_bytes());
    let signature_b64 = Base64.encode(signature.to_bytes());

    Ok(ShardIndex {
        id,
        publisher: publisher_did.to_string(),
        publisher_public_key,
        generated_at,
        entries,
        merkle_root,
        canonical_hash,
        signature: signature_b64,
    })
}

pub fn create_receipt(
    shard: &ShardEnvelope,
    index: &ShardIndex,
    subscriber_did: &str,
    subscriber_key: &SigningKey,
    timestamp: OffsetDateTime,
) -> Result<ShardReceipt> {
    let verifying_key = subscriber_key.verifying_key();
    let subscriber_public_key = Base64.encode(verifying_key.to_bytes());
    let id = format!(
        "receipt:{}:{}",
        sanitize_component(subscriber_did),
        timestamp_slug(timestamp)
    );

    let view = ShardReceiptSignView {
        id: &id,
        shard_id: &shard.id,
        contract_id: &shard.contract_id,
        payload_cid: &shard.payload_cid,
        publisher: &index.publisher,
        index_id: &index.id,
        merkle_root: &index.merkle_root,
        subscriber: subscriber_did,
        subscriber_public_key: &subscriber_public_key,
        timestamp,
    };
    let canonical = serde_jcs::to_string(&view)?;
    let mut hasher = Hasher::new();
    hasher.update(canonical.as_bytes());
    let canonical_hash = hasher.finalize().to_hex().to_string();
    let signature = subscriber_key.sign(canonical.as_bytes());
    let signature_b64 = Base64.encode(signature.to_bytes());

    Ok(ShardReceipt {
        id,
        shard_id: shard.id.clone(),
        contract_id: shard.contract_id.clone(),
        payload_cid: shard.payload_cid.clone(),
        publisher: index.publisher.clone(),
        index_id: index.id.clone(),
        merkle_root: index.merkle_root.clone(),
        subscriber: subscriber_did.to_string(),
        subscriber_public_key,
        timestamp,
        canonical_hash,
        signature: signature_b64,
    })
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

#[derive(Serialize)]
struct ShardReceiptSignView<'a> {
    id: &'a str,
    shard_id: &'a str,
    contract_id: &'a str,
    payload_cid: &'a str,
    publisher: &'a str,
    index_id: &'a str,
    merkle_root: &'a str,
    subscriber: &'a str,
    subscriber_public_key: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
}

fn sanitize_component(input: &str) -> String {
    crate::contract::sanitize_component(input)
}

fn timestamp_slug(ts: OffsetDateTime) -> String {
    crate::contract::timestamp_slug(ts)
}
