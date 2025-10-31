use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use reqwest::{header::IF_NONE_MATCH, Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::time::sleep;

use crate::types::{compute_merkle_root, ShardIndex, ShardIndexEntry};

/// Opaque slice representing a Merkle-verified index segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederatedIndexSlice {
    pub id: String,
    pub publisher: String,
    pub publisher_public_key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub source: String,
    pub presence_digest: String,
    pub cursor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub entries: Vec<ShardIndexEntry>,
    pub merkle_root: String,
    pub canonical_hash: String,
    pub signature: String,
}

impl FederatedIndexSlice {
    /// Build a slice from the latest shard index and sign it with the supplied key.
    pub fn from_shard_index(
        index: &ShardIndex,
        source: &str,
        presence_digest: &str,
        cursor: &str,
        next_cursor: Option<String>,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        if presence_digest.trim().is_empty() {
            return Err(anyhow!(
                "presence digest is required to publish index slices"
            ));
        }

        let verifying_key = signing_key.verifying_key();
        let publisher_public_key = Base64.encode(verifying_key.to_bytes());
        if publisher_public_key != index.publisher_public_key {
            return Err(anyhow!(
                "publisher public key mismatch between shard index and signing key"
            ));
        }

        if index.entries.is_empty() {
            return Err(anyhow!("shard index contains no entries to federate"));
        }

        let merkle_root = compute_merkle_root(
            &index
                .entries
                .iter()
                .map(|entry| entry.digest.clone())
                .collect::<Vec<_>>(),
        );
        if merkle_root != index.merkle_root {
            return Err(anyhow!(
                "local shard index merkle_root mismatch (expected {}, computed {})",
                index.merkle_root,
                merkle_root
            ));
        }

        let cursor_slug = sanitize_component(cursor);
        let id = format!("{}:{}", index.id, cursor_slug);

        let view = FederatedIndexSignView {
            cursor,
            entries: &index.entries,
            generated_at: index.generated_at,
            merkle_root: &index.merkle_root,
            presence_digest,
            publisher: &index.publisher,
            publisher_public_key: &index.publisher_public_key,
            source,
            next_cursor: next_cursor.as_deref(),
        };

        let canonical = serde_jcs::to_string(&view)?;
        let mut hasher = Hasher::new();
        hasher.update(canonical.as_bytes());
        let canonical_hash = hasher.finalize().to_hex().to_string();
        let signature = signing_key.sign(canonical.as_bytes());
        let signature_b64 = Base64.encode(signature.to_bytes());

        Ok(Self {
            id,
            publisher: index.publisher.clone(),
            publisher_public_key: index.publisher_public_key.clone(),
            generated_at: index.generated_at,
            source: source.to_string(),
            presence_digest: presence_digest.to_string(),
            cursor: cursor.to_string(),
            next_cursor,
            entries: index.entries.clone(),
            merkle_root: index.merkle_root.clone(),
            canonical_hash,
            signature: signature_b64,
        })
    }

    pub fn canonical_payload(&self) -> Result<String> {
        let view = FederatedIndexSignView {
            cursor: &self.cursor,
            entries: &self.entries,
            generated_at: self.generated_at,
            merkle_root: &self.merkle_root,
            presence_digest: &self.presence_digest,
            publisher: &self.publisher,
            publisher_public_key: &self.publisher_public_key,
            source: &self.source,
            next_cursor: self.next_cursor.as_deref(),
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn verify(&self) -> Result<()> {
        if self.entries.is_empty() {
            return Err(anyhow!("federated index slice must include entries"));
        }

        let computed_merkle = compute_merkle_root(
            &self
                .entries
                .iter()
                .map(|entry| entry.digest.clone())
                .collect::<Vec<_>>(),
        );
        if computed_merkle != self.merkle_root {
            return Err(anyhow!(
                "federated index merkle root mismatch (expected {}, computed {})",
                self.merkle_root,
                computed_merkle
            ));
        }

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
            .context("invalid federated index signature encoding")?;
        let signature = Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("expected 64-byte signature"))?,
        );

        let canonical = self.canonical_payload()?;
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .context("federated index signature verification failed")?;

        let mut hasher = Hasher::new();
        hasher.update(canonical.as_bytes());
        let computed_hash = hasher.finalize().to_hex().to_string();
        if computed_hash != self.canonical_hash {
            return Err(anyhow!(
                "federated index canonical hash mismatch (expected {}, computed {})",
                self.canonical_hash,
                computed_hash
            ));
        }

        Ok(())
    }
}

#[derive(Serialize)]
struct FederatedIndexSignView<'a> {
    cursor: &'a str,
    entries: &'a [ShardIndexEntry],
    #[serde(with = "time::serde::rfc3339")]
    generated_at: OffsetDateTime,
    merkle_root: &'a str,
    presence_digest: &'a str,
    publisher: &'a str,
    publisher_public_key: &'a str,
    source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<&'a str>,
}

fn sanitize_component(input: &str) -> String {
    let sanitized: String = input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let trimmed = sanitized.trim_matches('-').to_lowercase();
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed
    }
}

fn timestamp_slug(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

pub fn default_slice_cursor(index: &ShardIndex) -> Result<String> {
    let slug = timestamp_slug(index.generated_at);
    Ok(format!("{}#{}", slug, index.entries.len()))
}

pub fn compute_presence_digest(path: &Path) -> Result<String> {
    let data = fs::read(path)
        .with_context(|| format!("failed to read presence document at {}", path.display()))?;
    compute_presence_digest_from_bytes(&data)
}

pub fn compute_presence_digest_from_bytes(bytes: &[u8]) -> Result<String> {
    let value: Value =
        serde_json::from_slice(bytes).context("presence document is not valid JSON")?;
    let canonical = serde_jcs::to_string(&value)?;
    let mut hasher = Hasher::new();
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

pub fn peer_cache_dir(root: &Path, did: &str) -> PathBuf {
    root.join(sanitize_component(did))
}

#[derive(Debug, Clone)]
pub struct FederationPeerConfig {
    pub did: String,
    pub endpoint: String,
    pub presence_url: Option<String>,
    pub cursor: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FederationSyncOptions {
    pub storage_root: PathBuf,
    pub peers: Vec<FederationPeerConfig>,
    pub user_agent: Option<String>,
    pub max_retries: u8,
    pub request_timeout: Duration,
    pub mirror_all: bool,
}

impl FederationSyncOptions {
    pub fn new(storage_root: PathBuf, peers: Vec<FederationPeerConfig>) -> Self {
        Self {
            storage_root,
            peers,
            user_agent: None,
            max_retries: 3,
            request_timeout: Duration::from_secs(10),
            mirror_all: false,
        }
    }
}

pub struct FederationSync {
    options: FederationSyncOptions,
    client: Client,
}

impl FederationSync {
    pub fn new(options: FederationSyncOptions) -> Result<Self> {
        if !options.storage_root.exists() {
            fs::create_dir_all(&options.storage_root).with_context(|| {
                format!(
                    "failed to create federation cache root at {}",
                    options.storage_root.display()
                )
            })?;
        }

        let mut client_builder = Client::builder().timeout(options.request_timeout);
        if let Some(agent) = &options.user_agent {
            client_builder = client_builder.user_agent(agent.clone());
        }
        let client = client_builder
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self { options, client })
    }

    pub async fn sync_once(&self) -> Vec<FederationPeerResult> {
        let mut results = Vec::new();
        for peer in &self.options.peers {
            let result = self.sync_peer(peer).await;
            results.push(result);
        }
        results
    }

    async fn sync_peer(&self, peer: &FederationPeerConfig) -> FederationPeerResult {
        let mut attempt: u8 = 0;
        loop {
            attempt += 1;
            match self.fetch_and_store(peer).await {
                Ok(result) => return result,
                Err(_) if attempt <= self.options.max_retries => {
                    sleep(Duration::from_millis(250 * attempt as u64)).await;
                    continue;
                }
                Err(err) => {
                    return FederationPeerResult {
                        did: peer.did.clone(),
                        status: FederationPeerStatus::Error(err.to_string()),
                        fetched_entries: 0,
                        latest_cursor: peer.cursor.clone(),
                        mirrored_artifacts: 0,
                        canonical_hash: peer.etag.clone(),
                    };
                }
            }
        }
    }

    async fn fetch_and_store(&self, peer: &FederationPeerConfig) -> Result<FederationPeerResult> {
        let base_url = peer.endpoint.trim_end_matches('/');
        let presence_url = peer
            .presence_url
            .clone()
            .unwrap_or_else(|| format!("{}/presence", base_url));
        let presence_response = self
            .client
            .get(&presence_url)
            .send()
            .await
            .with_context(|| format!("failed to fetch presence from {}", presence_url))?;

        if !presence_response.status().is_success() {
            return Err(anyhow!(
                "presence fetch failed from {} with status {}",
                presence_url,
                presence_response.status()
            ));
        }

        let presence_bytes = presence_response
            .bytes()
            .await
            .context("failed to read presence response body")?;
        let presence_digest = compute_presence_digest_from_bytes(&presence_bytes)?;

        let mut request = self.client.get(format!("{}/federate/index", base_url));
        if let Some(cursor) = &peer.cursor {
            request = request.query(&[("cursor", cursor)]);
        }
        if let Some(etag) = &peer.etag {
            request = request.header(IF_NONE_MATCH, format!("\"{etag}\""));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("failed to fetch federated index from {}", base_url))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(FederationPeerResult {
                did: peer.did.clone(),
                status: FederationPeerStatus::NotModified,
                fetched_entries: 0,
                latest_cursor: peer.cursor.clone(),
                mirrored_artifacts: 0,
                canonical_hash: peer.etag.clone(),
            });
        }

        if !response.status().is_success() {
            return Err(anyhow!(
                "federated index fetch failed from {} with status {}",
                base_url,
                response.status()
            ));
        }

        let slice: FederatedIndexSlice = response
            .json()
            .await
            .context("failed to parse federated index slice")?;

        if slice.publisher != peer.did {
            return Err(anyhow!(
                "publisher DID mismatch (expected {}, got {})",
                peer.did,
                slice.publisher
            ));
        }

        slice.verify()?;

        if slice.presence_digest != presence_digest {
            return Err(anyhow!(
                "presence digest mismatch for {} (slice={}, computed={})",
                peer.did,
                slice.presence_digest,
                presence_digest
            ));
        }

        let peer_dir = peer_cache_dir(&self.options.storage_root, &peer.did);
        if !peer_dir.exists() {
            fs::create_dir_all(&peer_dir).with_context(|| {
                format!("failed to create peer cache dir {}", peer_dir.display())
            })?;
        }

        let cursor_slug = sanitize_component(&slice.cursor);
        let slice_path = peer_dir.join(format!("index-{}.json", cursor_slug));
        let data = serde_json::to_vec_pretty(&slice)
            .context("failed to serialise federated index slice")?;
        fs::write(&slice_path, data).with_context(|| {
            format!(
                "failed to write federated slice for {} to {}",
                peer.did,
                slice_path.display()
            )
        })?;

        let mut mirrored_artifacts = 0usize;
        if self.options.mirror_all {
            mirrored_artifacts = self
                .mirror_artifacts(&slice, base_url, &peer_dir)
                .await
                .with_context(|| format!("failed to mirror artifacts for {}", peer.did))?;
        }

        Ok(FederationPeerResult {
            did: peer.did.clone(),
            status: FederationPeerStatus::Success,
            fetched_entries: slice.entries.len(),
            latest_cursor: Some(slice.cursor.clone()),
            mirrored_artifacts,
            canonical_hash: Some(slice.canonical_hash.clone()),
        })
    }

    async fn mirror_artifacts(
        &self,
        slice: &FederatedIndexSlice,
        base_url: &str,
        peer_dir: &Path,
    ) -> Result<usize> {
        let base = Url::parse(base_url)
            .or_else(|_| Url::parse(&format!("{}/", base_url)))
            .context("peer endpoint is not a valid URL")?;

        let artifacts_root = peer_dir.join("artifacts");
        let mut mirrored = 0usize;

        for entry in &slice.entries {
            let artifact_url = base
                .join(&format!("artifact/{}", entry.path))
                .with_context(|| format!("invalid artifact path '{}'", entry.path))?;

            let response = self
                .client
                .get(artifact_url.clone())
                .send()
                .await
                .with_context(|| {
                    format!("failed to fetch artifact {} from {}", entry.id, base_url)
                })?;

            if !response.status().is_success() {
                return Err(anyhow!(
                    "artifact fetch failed for {} with status {}",
                    entry.id,
                    response.status()
                ));
            }

            let bytes = response
                .bytes()
                .await
                .context("failed to read artifact response body")?;
            let digest = blake3::hash(&bytes).to_hex().to_string();
            if digest != entry.digest {
                return Err(anyhow!(
                    "artifact digest mismatch for {} (expected {}, computed {})",
                    entry.id,
                    entry.digest,
                    digest
                ));
            }

            let destination = artifacts_root.join(&entry.path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create artifact directory {}", parent.display())
                })?;
            }
            fs::write(&destination, &bytes).with_context(|| {
                format!(
                    "failed to write artifact {} to {}",
                    entry.id,
                    destination.display()
                )
            })?;
            mirrored += 1;
        }

        Ok(mirrored)
    }
}

#[derive(Debug, Clone)]
pub struct FederationPeerResult {
    pub did: String,
    pub status: FederationPeerStatus,
    pub fetched_entries: usize,
    pub latest_cursor: Option<String>,
    pub mirrored_artifacts: usize,
    pub canonical_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FederationPeerStatus {
    Success,
    NotModified,
    Error(String),
}
