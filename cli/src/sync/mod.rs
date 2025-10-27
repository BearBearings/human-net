use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json;
use time::{Duration, OffsetDateTime};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::contract::{sanitize_component, timestamp_slug};
use crate::doc::{DocStore, DocSyncStatus, StoredDoc};
use crate::identity::{ActiveIdentity, IdentityVault};

const TOKEN_PREFIX: &str = "HNPAIR1:";
const RESPONSE_PREFIX: &str = "HNPAIR1-RESP:";
const TOKEN_VERSION: u32 = 1;
const BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairTokenKind {
    Ticket,
    Response,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct PairingPreparation {
    pub ticket: String,
    pub ticket_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct PairingAcceptance {
    pub ticket_id: String,
    pub response: String,
    pub pair: SyncPairInfo,
}

#[derive(Debug, Serialize)]
pub struct PairingFinalize {
    pub ticket_id: String,
    pub pair: SyncPairInfo,
}

#[derive(Debug, Serialize)]
pub struct PushBundle {
    pub pair: SyncPairInfo,
    pub bundle_path: String,
    pub doc_count: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct PullBundle {
    pub pair: SyncPairInfo,
    pub bundle_path: String,
    pub docs_applied: usize,
    pub docs_skipped: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub processed_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct SyncPairStatus {
    pub pair: SyncPairInfo,
    pub pending_inbox: usize,
    pub pending_outbox: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncPairInfo {
    pub id: String,
    pub remote_alias: String,
    pub remote_did: String,
    #[serde(with = "time::serde::rfc3339")]
    pub established_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_push_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pull_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_head: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_head: Option<OffsetDateTime>,
    pub inbox_dir: String,
    pub outbox_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncPairDisk {
    pub id: String,
    pub remote_alias: String,
    pub remote_did: String,
    pub shared_secret: String,
    #[serde(with = "time::serde::rfc3339")]
    pub established_at: OffsetDateTime,
    #[serde(default)]
    pub last_push_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub last_pull_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub local_head: Option<OffsetDateTime>,
    #[serde(default)]
    pub remote_head: Option<OffsetDateTime>,
}

impl SyncPairDisk {
    fn shared_secret_bytes(&self) -> Result<[u8; 32]> {
        let bytes = STANDARD
            .decode(self.shared_secret.as_bytes())
            .map_err(|err| anyhow!("invalid shared secret encoding: {err}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "shared secret must be 32 bytes (got {})",
                bytes.len()
            ));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    fn to_info(&self, inbox: &Path, outbox: &Path) -> SyncPairInfo {
        SyncPairInfo {
            id: self.id.clone(),
            remote_alias: self.remote_alias.clone(),
            remote_did: self.remote_did.clone(),
            established_at: self.established_at,
            last_push_at: self.last_push_at,
            last_pull_at: self.last_pull_at,
            local_head: self.local_head,
            remote_head: self.remote_head,
            inbox_dir: inbox.display().to_string(),
            outbox_dir: outbox.display().to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PairingTicket {
    version: u32,
    ticket_id: String,
    issuer_alias: String,
    issuer_did: String,
    issuer_public_key: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct PairingResponse {
    version: u32,
    ticket_id: String,
    responder_alias: String,
    responder_did: String,
    responder_public_key: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingPair {
    ticket_id: String,
    alias: String,
    did: String,
    secret: String,
    public_key: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncBundle {
    version: u32,
    pair_id: String,
    source_alias: String,
    source_did: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    docs: Vec<StoredDoc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBundle {
    version: u32,
    pair_id: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    nonce: String,
    ciphertext: String,
}

pub struct SyncPairStore<'a> {
    vault: &'a IdentityVault,
    alias: String,
    did: String,
}

impl<'a> SyncPairStore<'a> {
    pub fn open(vault: &'a IdentityVault) -> Result<Self> {
        let active: ActiveIdentity = vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity configured; run `hn id use <alias>`"))?;
        Ok(Self {
            vault,
            alias: active.alias,
            did: active.did,
        })
    }

    pub fn classify_token(token: &str) -> PairTokenKind {
        if token.starts_with(TOKEN_PREFIX) {
            PairTokenKind::Ticket
        } else if token.starts_with(RESPONSE_PREFIX) {
            PairTokenKind::Response
        } else {
            PairTokenKind::Unknown
        }
    }

    pub fn prepare_pairing(&self) -> Result<PairingPreparation> {
        let now = OffsetDateTime::now_utc();
        let expires = now + Duration::minutes(15);
        let ticket_id = format!(
            "pair:{}:{}",
            sanitize_component(&self.alias),
            timestamp_slug(now)
        );
        let mut rng = OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        let pending = PendingPair {
            ticket_id: ticket_id.clone(),
            alias: self.alias.clone(),
            did: self.did.clone(),
            secret: STANDARD.encode(secret.to_bytes()),
            public_key: STANDARD.encode(public.to_bytes()),
            created_at: now,
            expires_at: expires,
        };
        let ticket = PairingTicket {
            version: TOKEN_VERSION,
            ticket_id: ticket_id.clone(),
            issuer_alias: self.alias.clone(),
            issuer_did: self.did.clone(),
            issuer_public_key: pending.public_key.clone(),
            created_at: now,
            expires_at: expires,
        };
        let token = encode_token(TOKEN_PREFIX, &ticket)?;
        let path = self.pending_path(&ticket_id)?;
        write_json(&path, &pending)?;
        Ok(PairingPreparation {
            ticket: token,
            ticket_id,
            expires_at: expires,
        })
    }

    pub fn accept_pairing(&self, token: &str) -> Result<PairingAcceptance> {
        let ticket: PairingTicket = decode_token(TOKEN_PREFIX, token)?;
        if ticket.version != TOKEN_VERSION {
            return Err(anyhow!(
                "unsupported pairing ticket version {}",
                ticket.version
            ));
        }
        if ticket.expires_at < OffsetDateTime::now_utc() {
            return Err(anyhow!("pairing ticket expired"));
        }
        let issuer_public = decode_key(&ticket.issuer_public_key)?;
        let issuer_public = PublicKey::from(issuer_public);
        let mut rng = OsRng;
        let my_secret = StaticSecret::random_from_rng(&mut rng);
        let my_public = PublicKey::from(&my_secret);
        let shared = my_secret.diffie_hellman(&issuer_public);
        let record = SyncPairDisk {
            id: ticket.ticket_id.clone(),
            remote_alias: ticket.issuer_alias.clone(),
            remote_did: ticket.issuer_did.clone(),
            shared_secret: STANDARD.encode(shared.to_bytes()),
            established_at: OffsetDateTime::now_utc(),
            last_push_at: None,
            last_pull_at: None,
            local_head: None,
            remote_head: None,
        };
        let info = self.persist_pair(&record)?;
        let response = PairingResponse {
            version: TOKEN_VERSION,
            ticket_id: ticket.ticket_id.clone(),
            responder_alias: self.alias.clone(),
            responder_did: self.did.clone(),
            responder_public_key: STANDARD.encode(my_public.to_bytes()),
            created_at: OffsetDateTime::now_utc(),
        };
        let response_token = encode_token(RESPONSE_PREFIX, &response)?;
        Ok(PairingAcceptance {
            ticket_id: ticket.ticket_id,
            response: response_token,
            pair: info,
        })
    }

    pub fn finalize_pairing(&self, token: &str) -> Result<PairingFinalize> {
        let response: PairingResponse = decode_token(RESPONSE_PREFIX, token)?;
        if response.version != TOKEN_VERSION {
            return Err(anyhow!(
                "unsupported pairing response version {}",
                response.version
            ));
        }
        let pending = self.load_pending(&response.ticket_id)?;
        if pending.expires_at < OffsetDateTime::now_utc() {
            return Err(anyhow!("pairing token expired"));
        }
        let secret_bytes = decode_key(&pending.secret)?;
        let secret = StaticSecret::from(secret_bytes);
        let responder_public = decode_key(&response.responder_public_key)?;
        let responder_public = PublicKey::from(responder_public);
        let shared = secret.diffie_hellman(&responder_public);
        let record = SyncPairDisk {
            id: response.ticket_id.clone(),
            remote_alias: response.responder_alias.clone(),
            remote_did: response.responder_did.clone(),
            shared_secret: STANDARD.encode(shared.to_bytes()),
            established_at: OffsetDateTime::now_utc(),
            last_push_at: None,
            last_pull_at: None,
            local_head: None,
            remote_head: None,
        };
        let info = self.persist_pair(&record)?;
        let pending_path = self.pending_path(&response.ticket_id)?;
        let _ = fs::remove_file(&pending_path);
        Ok(PairingFinalize {
            ticket_id: response.ticket_id,
            pair: info,
        })
    }

    pub fn list_pairs(&self) -> Result<Vec<SyncPairInfo>> {
        let records = self.load_pairs()?;
        let mut pairs = Vec::new();
        for record in records {
            let (_, inbox, outbox) = self.ensure_pair_dirs(&record.id)?;
            pairs.push(record.to_info(&inbox, &outbox));
        }
        Ok(pairs)
    }

    pub fn push_all(&self) -> Result<Vec<PushBundle>> {
        let mut records = self.load_pairs()?;
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let doc_store = DocStore::open(self.vault)?;
        let docs = doc_store.all_docs()?;
        let mut bundles = Vec::new();
        for record in records.iter_mut() {
            let (_, _, outbox) = self.ensure_pair_dirs(&record.id)?;
            let timestamp = OffsetDateTime::now_utc();
            let bundle_path =
                self.write_encrypted_bundle(record, &outbox, &docs, timestamp.clone())?;
            record.last_push_at = Some(timestamp);
            record.local_head = Some(timestamp);
            let info = self.persist_pair(record)?;
            bundles.push(PushBundle {
                pair: info,
                bundle_path: bundle_path.display().to_string(),
                doc_count: docs.len(),
                generated_at: timestamp,
            });
        }
        Ok(bundles)
    }

    pub fn pull_all(&self) -> Result<Vec<PullBundle>> {
        let mut records = self.load_pairs()?;
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let doc_store = DocStore::open(self.vault)?;
        let mut processed = Vec::new();
        for record in records.iter_mut() {
            let (_, inbox, _) = self.ensure_pair_dirs(&record.id)?;
            let mut entries: Vec<_> = fs::read_dir(&inbox)
                .with_context(|| format!("failed to read {}", inbox.display()))?
                .filter_map(|res| res.ok())
                .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let envelope: EncryptedBundle = read_json(&path)?;
                if envelope.pair_id != record.id {
                    continue;
                }
                let bundle = self.decrypt_bundle(record, &envelope)?;
                let mut applied = 0usize;
                let mut skipped = 0usize;
                for doc in &bundle.docs {
                    match doc_store.apply_remote_doc(doc)? {
                        DocSyncStatus::Created | DocSyncStatus::Updated => applied += 1,
                        DocSyncStatus::Skipped => skipped += 1,
                    }
                }
                let processed_at = OffsetDateTime::now_utc();
                record.last_pull_at = Some(processed_at);
                record.remote_head = Some(bundle.created_at);
                let info = self.persist_pair(record)?;
                processed.push(PullBundle {
                    pair: info,
                    bundle_path: path.display().to_string(),
                    docs_applied: applied,
                    docs_skipped: skipped,
                    processed_at,
                });
                self.archive_bundle(&inbox, &path)?;
            }
        }
        Ok(processed)
    }

    pub fn status(&self) -> Result<Vec<SyncPairStatus>> {
        let records = self.load_pairs()?;
        let mut entries = Vec::new();
        for record in records {
            let (_, inbox, outbox) = self.ensure_pair_dirs(&record.id)?;
            let pending_inbox = count_json_files(&inbox)?;
            let pending_outbox = count_json_files(&outbox)?;
            let info = record.to_info(&inbox, &outbox);
            entries.push(SyncPairStatus {
                pair: info,
                pending_inbox,
                pending_outbox,
            });
        }
        Ok(entries)
    }

    fn sync_root(&self) -> Result<PathBuf> {
        self.vault.node_subdir(&self.alias, "sync")
    }

    fn pairs_root(&self) -> Result<PathBuf> {
        let root = self.sync_root()?.join("pairs");
        if !root.exists() {
            fs::create_dir_all(&root)
                .with_context(|| format!("failed to create {}", root.display()))?;
        }
        Ok(root)
    }

    fn pending_root(&self) -> Result<PathBuf> {
        let root = self.sync_root()?.join("pending");
        if !root.exists() {
            fs::create_dir_all(&root)
                .with_context(|| format!("failed to create {}", root.display()))?;
        }
        Ok(root)
    }

    fn pending_path(&self, ticket_id: &str) -> Result<PathBuf> {
        let dir = self.pending_root()?;
        Ok(dir.join(format!("{}.json", sanitize_component(ticket_id))))
    }

    fn pair_dir(&self, pair_id: &str) -> Result<PathBuf> {
        let root = self.pairs_root()?;
        Ok(root.join(sanitize_component(pair_id)))
    }

    fn ensure_pair_dirs(&self, pair_id: &str) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let dir = self.pair_dir(pair_id)?;
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let inbox = dir.join("inbox");
        if !inbox.exists() {
            fs::create_dir_all(&inbox)
                .with_context(|| format!("failed to create {}", inbox.display()))?;
        }
        let outbox = dir.join("outbox");
        if !outbox.exists() {
            fs::create_dir_all(&outbox)
                .with_context(|| format!("failed to create {}", outbox.display()))?;
        }
        Ok((dir, inbox, outbox))
    }

    fn load_pending(&self, ticket_id: &str) -> Result<PendingPair> {
        let path = self.pending_path(ticket_id)?;
        if !path.exists() {
            return Err(anyhow!("no pending pairing for ticket '{}'", ticket_id));
        }
        read_json(&path)
    }

    fn persist_pair(&self, record: &SyncPairDisk) -> Result<SyncPairInfo> {
        let (dir, inbox, outbox) = self.ensure_pair_dirs(&record.id)?;
        let path = dir.join("pair.json");
        write_json(&path, record)?;
        Ok(record.to_info(&inbox, &outbox))
    }

    fn load_pairs(&self) -> Result<Vec<SyncPairDisk>> {
        let root = self.pairs_root()?;
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let record_path = entry.path().join("pair.json");
            if !record_path.exists() {
                continue;
            }
            let record: SyncPairDisk = read_json(&record_path)?;
            records.push(record);
        }
        Ok(records)
    }

    fn write_encrypted_bundle(
        &self,
        record: &SyncPairDisk,
        outbox: &Path,
        docs: &[StoredDoc],
        timestamp: OffsetDateTime,
    ) -> Result<PathBuf> {
        let bundle = SyncBundle {
            version: BUNDLE_VERSION,
            pair_id: record.id.clone(),
            source_alias: self.alias.clone(),
            source_did: self.did.clone(),
            created_at: timestamp,
            docs: docs.to_vec(),
        };
        let plaintext = serde_json::to_vec(&bundle)?;
        let key_bytes = record.shared_secret_bytes()?;
        let key = Key::from(key_bytes);
        let cipher = ChaCha20Poly1305::new(&key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|err| anyhow!("failed to encrypt sync bundle: {err}"))?;
        let envelope = EncryptedBundle {
            version: BUNDLE_VERSION,
            pair_id: record.id.clone(),
            created_at: timestamp,
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        let filename = format!("bundle-{}.json", timestamp_slug(timestamp));
        let path = outbox.join(filename);
        write_json(&path, &envelope)?;
        Ok(path)
    }

    fn decrypt_bundle(
        &self,
        record: &SyncPairDisk,
        envelope: &EncryptedBundle,
    ) -> Result<SyncBundle> {
        let key_bytes = record.shared_secret_bytes()?;
        let key = Key::from(key_bytes);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(envelope.nonce.as_bytes())
            .map_err(|err| anyhow!("invalid bundle nonce encoding: {err}"))?;
        if nonce_bytes.len() != 12 {
            return Err(anyhow!(
                "bundle nonce must be 12 bytes (got {})",
                nonce_bytes.len()
            ));
        }
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(&nonce_bytes);
        let ciphertext = URL_SAFE_NO_PAD
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|err| anyhow!("invalid bundle ciphertext encoding: {err}"))?;
        let nonce = Nonce::from(nonce_array);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|err| anyhow!("failed to decrypt bundle: {err}"))?;
        let bundle: SyncBundle = serde_json::from_slice(&plaintext)?;
        Ok(bundle)
    }

    fn archive_bundle(&self, inbox: &Path, bundle_path: &Path) -> Result<()> {
        let processed = inbox.join("processed");
        if !processed.exists() {
            fs::create_dir_all(&processed)
                .with_context(|| format!("failed to create {}", processed.display()))?;
        }
        let Some(file_name) = bundle_path.file_name() else {
            return Err(anyhow!("invalid bundle path '{}'", bundle_path.display()));
        };
        let dest = processed.join(file_name);
        match fs::rename(bundle_path, &dest) {
            Ok(_) => Ok(()),
            Err(_) => {
                fs::copy(bundle_path, &dest).with_context(|| {
                    format!(
                        "failed to archive bundle {} -> {}",
                        bundle_path.display(),
                        dest.display()
                    )
                })?;
                fs::remove_file(bundle_path)
                    .with_context(|| format!("failed to remove {}", bundle_path.display()))?;
                Ok(())
            }
        }
    }
}

fn encode_token<T: Serialize>(prefix: &str, value: &T) -> Result<String> {
    let data = serde_json::to_vec(value)?;
    let encoded = URL_SAFE_NO_PAD.encode(data);
    Ok(format!("{prefix}{encoded}"))
}

fn decode_token<T: for<'de> Deserialize<'de>>(prefix: &str, token: &str) -> Result<T> {
    if !token.starts_with(prefix) {
        return Err(anyhow!("token missing expected prefix '{}'", prefix));
    }
    let data = token[prefix.len()..].as_bytes();
    let decoded = URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|err| anyhow!("invalid token encoding: {err}"))?;
    let value = serde_json::from_slice(&decoded)?;
    Ok(value)
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(value.as_bytes())
        .map_err(|err| anyhow!("invalid key encoding: {err}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "expected 32-byte key (received {} bytes)",
            bytes.len()
        ));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(value)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn count_json_files(dir: &Path) -> Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    Ok(count)
}
