use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use bs58;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::types::compute_merkle_root;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub path: String,
    pub digest: String,
    pub size: u64,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupDocument {
    pub id: String,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_backup: Option<String>,
    pub entries: Vec<BackupEntry>,
    pub merkle_root: String,
    pub payload_cid: String,
    pub algorithm: String,
    pub enc: String,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHeader {
    pub id: String,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_backup: Option<String>,
    pub entries: Vec<BackupEntry>,
    pub merkle_root: String,
    pub payload_cid: String,
    pub algorithm: String,
    pub enc: String,
    pub signature: String,
}

impl From<&BackupDocument> for BackupHeader {
    fn from(document: &BackupDocument) -> Self {
        Self {
            id: document.id.clone(),
            owner: document.owner.clone(),
            target: document.target.clone(),
            created_at: document.created_at,
            scope: document.scope.clone(),
            base_backup: document.base_backup.clone(),
            entries: document.entries.clone(),
            merkle_root: document.merkle_root.clone(),
            payload_cid: document.payload_cid.clone(),
            algorithm: document.algorithm.clone(),
            enc: document.enc.clone(),
            signature: document.signature.clone(),
        }
    }
}

pub fn canonical_payload(document: &BackupDocument) -> Result<String> {
    #[derive(Serialize)]
    struct SignView<'a> {
        id: &'a str,
        owner: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<&'a str>,
        #[serde(with = "time::serde::rfc3339")]
        created_at: OffsetDateTime,
        scope: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        base_backup: Option<&'a str>,
        entries: &'a [BackupEntry],
        merkle_root: &'a str,
        payload_cid: &'a str,
        algorithm: &'a str,
        enc: &'a str,
    }

    let view = SignView {
        id: &document.id,
        owner: &document.owner,
        target: document.target.as_deref(),
        created_at: document.created_at,
        scope: &document.scope,
        base_backup: document.base_backup.as_deref(),
        entries: &document.entries,
        merkle_root: &document.merkle_root,
        payload_cid: &document.payload_cid,
        algorithm: &document.algorithm,
        enc: &document.enc,
    };

    Ok(serde_jcs::to_string(&view)?)
}

pub fn verify_backup_document(document: &BackupDocument) -> Result<Vec<u8>> {
    ensure!(
        document.algorithm == "tar+zstd@1",
        "unsupported backup algorithm {}",
        document.algorithm
    );

    let canonical = canonical_payload(document)?;
    let verifying_key = verifying_key_from_did(&document.owner)?;
    let signature_bytes = Base64
        .decode(document.signature.as_bytes())
        .context("backup signature is not valid base64")?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("backup signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify_strict(canonical.as_bytes(), &signature)
        .context("backup signature verification failed")?;

    let ciphertext = Base64
        .decode(document.ciphertext.as_bytes())
        .context("backup ciphertext is not valid base64")?;
    let computed_cid = blake3::hash(&ciphertext).to_hex().to_string();
    ensure!(
        computed_cid == document.payload_cid,
        "payload CID mismatch (expected {}, computed {})",
        document.payload_cid,
        computed_cid
    );

    let merkle = compute_merkle_root(
        &document
            .entries
            .iter()
            .map(|entry| entry.digest.clone())
            .collect::<Vec<_>>(),
    );
    ensure!(
        merkle == document.merkle_root,
        "merkle root mismatch (expected {}, computed {})",
        document.merkle_root,
        merkle
    );

    Ok(ciphertext)
}

pub fn sanitize_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_lowercase()
}

pub fn backup_index_path(storage_root: &Path, storage_id: &str) -> PathBuf {
    storage_root
        .join("backups")
        .join("index")
        .join(format!("{storage_id}.json"))
}

pub fn backup_directory(storage_root: &Path, owner_slug: &str, storage_id: &str) -> PathBuf {
    storage_root
        .join("backups")
        .join(owner_slug)
        .join(storage_id)
}

pub fn owner_slug_from_did(did: &str) -> Result<String> {
    ensure!(
        did.starts_with("did:hn:"),
        "unsupported DID scheme in {did}"
    );
    Ok(sanitize_component(did))
}

fn verifying_key_from_did(did: &str) -> Result<VerifyingKey> {
    const PREFIX: &str = "did:hn:";
    ensure!(did.starts_with(PREFIX), "unsupported DID scheme in {did}");
    let slug = &did[PREFIX.len()..];
    let bytes = bs58::decode(slug)
        .into_vec()
        .context("failed to decode DID public key")?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("decoded DID key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&array).context("failed to parse verifying key from DID")
}

pub fn build_backup_header(document: &BackupDocument) -> BackupHeader {
    BackupHeader::from(document)
}

pub fn load_backup_header(path: &Path) -> Result<BackupHeader> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read backup header {}", path.display()))?;
    serde_json::from_str::<BackupHeader>(&data)
        .with_context(|| format!("backup header at {} is not valid JSON", path.display()))
}
