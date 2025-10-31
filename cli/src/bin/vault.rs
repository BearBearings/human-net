use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3::Hasher;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::Signer;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tar::{Builder, EntryType, Header};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ureq;
use url::Url;
use walkdir::WalkDir;
use zstd::stream::{decode_all, Encoder};

use hn_cli::home::ensure_home_dir;
use hn_cli::identity::{IdentityRecord, IdentityVault};
use hn_mcp::{canonical_body_hash, canonical_request_message};

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const BACKUP_INFO_PREFIX: &str = "human-net backup@1:";
const BACKUP_AAD_PREFIX: &str = "backup:aad:";
const BACKUP_ALGORITHM: &str = "tar+zstd@1";

#[derive(Parser, Debug)]
#[command(
    name = "hn vault",
    version,
    about = "Manage vault lifecycle helpers (backups, restore, verification)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create, verify, and restore vault backups.
    #[command(subcommand)]
    Backup(BackupCommands),
}

#[derive(Subcommand, Debug)]
enum BackupCommands {
    /// Create a deterministic backup@1 snapshot.
    Create(CreateArgs),
    /// Verify the signature and payload integrity of a backup@1 file.
    Verify(VerifyArgs),
    /// Restore a backup@1 snapshot into a staging directory.
    Restore(RestoreArgs),
}

#[derive(Args, Debug)]
struct CreateArgs {
    /// Identity alias whose vault should be backed up (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Optional explicit DID to encrypt the backup for (defaults to owner DID).
    #[arg(long = "target-did", value_name = "DID")]
    target_did: Option<String>,

    /// Output path for the backup file (defaults to $HN_HOME/backups/<id>.json).
    #[arg(long = "output", value_name = "PATH")]
    output: Option<PathBuf>,

    /// Include cache directories (federation, discovery, etc.) in the snapshot.
    #[arg(long = "include-cache")]
    include_cache: bool,

    /// Push the resulting backup to the specified MCP base URL (env: HN_BACKUP_PUSH_URL).
    #[arg(long = "push-url", value_name = "URL")]
    push_url: Option<String>,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Path to the backup@1 JSON file to verify.
    #[arg(long = "path", value_name = "PATH")]
    path: PathBuf,

    /// Alias whose keys should be used for verification (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug)]
struct RestoreArgs {
    /// Path to the backup@1 JSON file to restore.
    #[arg(long = "path", value_name = "PATH")]
    path: PathBuf,

    /// Destination directory for restored content (must be empty or absent).
    #[arg(long = "into", value_name = "PATH")]
    into: PathBuf,

    /// Alias whose keys should decrypt the backup (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Validate only (decrypt + verify lists) without writing files.
    #[arg(long = "verify-only")]
    verify_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEntry {
    pub path: String,
    pub digest: String,
    pub size: u64,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupDocument {
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

impl BackupDocument {
    fn canonical_payload(&self) -> Result<String> {
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
            id: &self.id,
            owner: &self.owner,
            target: self.target.as_deref(),
            created_at: self.created_at,
            scope: &self.scope,
            base_backup: self.base_backup.as_deref(),
            entries: &self.entries,
            merkle_root: &self.merkle_root,
            payload_cid: &self.payload_cid,
            algorithm: &self.algorithm,
            enc: &self.enc,
        };
        Ok(serde_jcs::to_string(&view)?)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Backup(sub) => match sub {
            BackupCommands::Create(args) => backup_create(args)?,
            BackupCommands::Verify(args) => backup_verify(args)?,
            BackupCommands::Restore(args) => backup_restore(args)?,
        },
    }
    Ok(())
}

fn backup_create(args: CreateArgs) -> Result<()> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let push_target = args
        .push_url
        .clone()
        .or_else(|| env::var("HN_BACKUP_PUSH_URL").ok());
    let alias = if let Some(alias) = args.alias.clone() {
        alias
    } else {
        vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
            .alias
    };
    let record = vault.load_identity(&alias)?;
    let owner_did = record.profile.id.clone();
    let target_did = args.target_did.clone().unwrap_or_else(|| owner_did.clone());

    if target_did != owner_did {
        return Err(anyhow!(
            "backup encryption targeting peers is not implemented yet (target DID {})",
            target_did
        ));
    }

    let timestamp = OffsetDateTime::now_utc();
    let backup_id = format!(
        "backup:{}:{}",
        sanitize_component(&owner_did),
        timestamp_slug(timestamp)
    );

    let (entries, tar_bytes) = build_backup_payload(&home, args.include_cache)?;
    let merkle_root = compute_merkle_root(
        &entries
            .iter()
            .map(|entry| entry.digest.clone())
            .collect::<Vec<_>>(),
    );

    let compressed = compress_payload(&tar_bytes)?;
    let recipient_pk = record.keys.hpke_public_key_bytes();
    let (encapsulated, ciphertext) = encrypt_payload(&recipient_pk, &owner_did, &compressed)?;

    let payload_cid = blake3::hash(&ciphertext).to_hex().to_string();
    let enc_b64 = Base64.encode(&encapsulated);
    let ciphertext_b64 = Base64.encode(&ciphertext);

    let mut document = BackupDocument {
        id: backup_id.clone(),
        owner: owner_did.clone(),
        target: Some(target_did.clone()),
        created_at: timestamp,
        scope: "full".to_string(),
        base_backup: None,
        entries,
        merkle_root,
        payload_cid,
        algorithm: BACKUP_ALGORITHM.to_string(),
        enc: enc_b64,
        ciphertext: ciphertext_b64,
        signature: String::new(),
    };

    let canonical = document.canonical_payload()?;
    let signature = record.keys.signing_key().sign(canonical.as_bytes());
    document.signature = Base64.encode(signature.to_bytes());

    let output_path = resolve_output_path(&home, args.output, &backup_id)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create backup directory {}", parent.display()))?;
    }
    let payload = serde_json::to_vec_pretty(&document)?;
    fs::write(&output_path, payload)
        .with_context(|| format!("failed to write backup to {}", output_path.display()))?;

    if let Some(url) = push_target {
        push_backup(&document, &url, &record)?;
    }

    println!(
        "Created backup {} for {} at {}",
        backup_id,
        owner_did,
        output_path.display()
    );
    Ok(())
}

fn backup_verify(args: VerifyArgs) -> Result<()> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = if let Some(alias) = args.alias.clone() {
        alias
    } else {
        vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
            .alias
    };
    let record = vault.load_identity(&alias)?;

    let data = fs::read(&args.path)
        .with_context(|| format!("failed to read backup file {}", args.path.display()))?;
    let document: BackupDocument = serde_json::from_slice(&data)
        .context("backup file is not valid JSON (expected backup@1)")?;

    ensure!(
        document.algorithm == BACKUP_ALGORITHM,
        "unsupported backup algorithm {}",
        document.algorithm
    );

    // Verify signature.
    let canonical = document.canonical_payload()?;
    let verifying_key = record.keys.verifying_key();
    let signature_bytes = Base64
        .decode(document.signature.as_bytes())
        .context("backup signature is not valid base64")?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("backup signature must be 64 bytes"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    verifying_key
        .verify_strict(canonical.as_bytes(), &signature)
        .context("backup signature verification failed")?;

    // Verify ciphertext digest.
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

    // Decrypt payload.
    let secret = record.keys.hpke_static_secret();
    let secret_bytes = secret.to_bytes();
    let plaintext = decrypt_payload(&ciphertext, &document.enc, &secret_bytes, &document.owner)?;
    let decompressed = decode_all(Cursor::new(plaintext))
        .context("failed to decompress backup tar (zstd decode failed)")?;
    let verification = verify_entries(&document.entries, &decompressed)?;

    let recomputed_root = compute_merkle_root(
        &document
            .entries
            .iter()
            .map(|e| e.digest.clone())
            .collect::<Vec<_>>(),
    );
    ensure!(
        recomputed_root == document.merkle_root,
        "merkle root mismatch (expected {}, computed {})",
        document.merkle_root,
        recomputed_root
    );

    println!(
        "Backup {} verified successfully ({} files, {} directories)",
        document.id, verification.file_count, verification.directory_count
    );
    Ok(())
}

fn backup_restore(args: RestoreArgs) -> Result<()> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = if let Some(alias) = args.alias.clone() {
        alias
    } else {
        vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
            .alias
    };
    let record = vault.load_identity(&alias)?;

    let data = fs::read(&args.path)
        .with_context(|| format!("failed to read backup file {}", args.path.display()))?;
    let document: BackupDocument = serde_json::from_slice(&data)
        .context("backup file is not valid JSON (expected backup@1)")?;

    ensure!(
        document.algorithm == BACKUP_ALGORITHM,
        "unsupported backup algorithm {}",
        document.algorithm
    );

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

    let secret = record.keys.hpke_static_secret();
    let plaintext = decrypt_payload(
        &ciphertext,
        &document.enc,
        &secret.to_bytes(),
        &document.owner,
    )?;
    let decompressed = decode_all(Cursor::new(&plaintext))
        .context("failed to decompress backup tar (zstd decode failed)")?;
    let verification = verify_entries(&document.entries, &decompressed)?;

    if args.verify_only {
        println!(
            "Backup {} verified ({} files, {} directories). No files written (verify-only).",
            document.id, verification.file_count, verification.directory_count
        );
        return Ok(());
    }

    if args.into.exists() {
        if args.into.is_dir() {
            let mut dir_iter = fs::read_dir(&args.into)?;
            ensure!(
                dir_iter.next().is_none(),
                "restore destination {} is not empty",
                args.into.display()
            );
        } else {
            return Err(anyhow!(
                "restore destination {} exists and is not a directory",
                args.into.display()
            ));
        }
    } else {
        fs::create_dir_all(&args.into)
            .with_context(|| format!("failed to create restore target {}", args.into.display()))?;
    }

    extract_archive(&decompressed, &args.into)?;

    println!(
        "Restored backup {} into {} ({} files, {} directories).",
        document.id,
        args.into.display(),
        verification.file_count,
        verification.directory_count
    );
    Ok(())
}

struct VerificationStats {
    file_count: usize,
    directory_count: usize,
}

fn verify_entries(entries: &[BackupEntry], tar_payload: &[u8]) -> Result<VerificationStats> {
    let entries_by_path: BTreeMap<String, &BackupEntry> = entries
        .iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut archive = tar::Archive::new(Cursor::new(tar_payload));
    archive.set_preserve_permissions(true);

    let mut file_count = 0usize;
    let mut directory_count = 0usize;

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry
            .path()?
            .to_str()
            .ok_or_else(|| anyhow!("backup archive contained a non-UTF8 path"))?
            .to_string();

        let header = entry.header();
        let entry_type = header.entry_type();
        let expected = entries_by_path
            .get(&path)
            .ok_or_else(|| anyhow!("backup tar entry '{}' missing from manifest", path))?;

        match entry_type {
            EntryType::Directory => {
                ensure!(
                    expected.mode == "dir",
                    "manifest expects '{}' to be {}, but archive has directory",
                    path,
                    expected.mode
                );
                directory_count += 1;
            }
            EntryType::Regular => {
                ensure!(
                    expected.mode == "file",
                    "manifest expects '{}' to be {}, but archive has file",
                    path,
                    expected.mode
                );
                let mut buffer = Vec::new();
                entry.read_to_end(&mut buffer)?;
                ensure!(
                    buffer.len() as u64 == expected.size,
                    "size mismatch for '{}' (expected {}, got {})",
                    path,
                    expected.size,
                    buffer.len()
                );
                let digest = blake3::hash(&buffer).to_hex().to_string();
                ensure!(
                    digest == expected.digest,
                    "digest mismatch for '{}' (expected {}, got {})",
                    path,
                    expected.digest,
                    digest
                );
                file_count += 1;
            }
            _ => {
                return Err(anyhow!(
                    "unsupported tar entry '{}' (only regular files and directories are permitted)",
                    path
                ));
            }
        }
        seen.insert(path);
    }

    for entry in entries {
        if !seen.contains(&entry.path) && entry.mode == "file" {
            return Err(anyhow!(
                "manifest entry '{}' missing from archive payload",
                entry.path
            ));
        }
    }

    Ok(VerificationStats {
        file_count,
        directory_count,
    })
}

fn extract_archive(tar_payload: &[u8], destination: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(Cursor::new(tar_payload));
    archive.set_preserve_permissions(true);
    archive
        .unpack(destination)
        .with_context(|| format!("failed to unpack backup into {}", destination.display()))?;
    Ok(())
}

fn push_backup(document: &BackupDocument, endpoint: &str, identity: &IdentityRecord) -> Result<()> {
    let mut url_string = endpoint.trim().to_string();
    if url_string.is_empty() {
        return Err(anyhow!("push URL must not be empty"));
    }
    if !url_string.ends_with("/backup") {
        url_string = format!("{}/backup", url_string.trim_end_matches('/'));
    }

    let parsed = Url::parse(&url_string)
        .context("push URL must include scheme (e.g. http://localhost:7733)")?;
    let request_path = parsed.path();

    let body = serde_json::to_string(document)?;
    let body_hash = canonical_body_hash(document)?;
    let timestamp = OffsetDateTime::now_utc();
    let timestamp_secs = timestamp.unix_timestamp();
    let message = canonical_request_message("POST", request_path, timestamp_secs, &body_hash);
    let signature = identity.keys.signing_key().sign(message.as_bytes());
    let signature_b64 = Base64.encode(signature.to_bytes());

    let response = ureq::post(parsed.as_str())
        .set("Content-Type", "application/json")
        .set("X-HN-DID", &identity.profile.id)
        .set("X-HN-Timestamp", &timestamp_secs.to_string())
        .set("X-HN-Signature", &signature_b64)
        .set("Digest", &format!("blake3={}", body_hash))
        .send_string(&body);

    match response {
        Ok(resp) if (200..300).contains(&resp.status()) => {
            println!("Pushed backup {} to {}", document.id, parsed);
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            let details = resp.into_string().unwrap_or_default();
            Err(anyhow!(
                "backup push failed with status {}: {}",
                status,
                details
            ))
        }
        Err(err) => Err(anyhow!("backup push failed: {err}")),
    }
}

fn build_backup_payload(home: &Path, include_cache: bool) -> Result<(Vec<BackupEntry>, Vec<u8>)> {
    let mut files = Vec::new();
    let mut directories: BTreeSet<String> = BTreeSet::new();

    for relative in backup_roots(include_cache) {
        let root = home.join(&relative);
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(&root).follow_links(false) {
            let entry = entry?;
            let path = entry.path();
            let rel = path
                .strip_prefix(home)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            if entry.file_type().is_dir() {
                if !rel.is_empty() {
                    directories.insert(rel.clone());
                }
                continue;
            }
            if entry.file_type().is_file() {
                let mut file = fs::File::open(path)
                    .with_context(|| format!("failed to read file {}", path.display()))?;
                let mut hasher = Hasher::new();
                let mut buffer = [0u8; 8192];
                loop {
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                let digest = hasher.finalize().to_hex().to_string();
                let size = entry.metadata()?.len();
                let mut cur = Path::new(&rel);
                while let Some(parent) = cur.parent() {
                    if parent.as_os_str().is_empty() {
                        break;
                    }
                    if let Some(parent_str) = parent.to_str() {
                        directories.insert(parent_str.replace('\\', "/"));
                    }
                    cur = parent;
                }
                files.push(BackupEntry {
                    path: rel,
                    digest,
                    size,
                    mode: "file".to_string(),
                });
            }
        }
    }

    // Clean directory set; remove empty strings (root).
    let mut dir_entries = Vec::new();
    for dir in directories {
        if dir.is_empty() {
            continue;
        }
        dir_entries.push(BackupEntry {
            path: dir.trim_end_matches('/').to_string(),
            digest: ZERO_DIGEST.to_string(),
            size: 0,
            mode: "dir".to_string(),
        });
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    dir_entries.sort_by(|a, b| a.path.cmp(&b.path));

    let mut tar_data = Vec::new();
    {
        let cursor = Cursor::new(&mut tar_data);
        let mut builder = Builder::new(cursor);
        builder.mode(tar::HeaderMode::Deterministic);

        for dir in &dir_entries {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Directory);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, dir.path.as_str(), &mut Cursor::new(Vec::new()))?;
        }

        for file in &files {
            let full_path = home.join(&file.path);
            let mut data = fs::File::open(&full_path)
                .with_context(|| format!("failed to read {}", full_path.display()))?;
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Regular);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(file.size);
            header.set_cksum();
            builder.append_data(&mut header, file.path.as_str(), &mut data)?;
        }

        builder.finish()?;
    }

    let mut entries = Vec::new();
    entries.extend(dir_entries);
    entries.extend(files);

    Ok((entries, tar_data))
}

fn compress_payload(tar_data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new(), 0)?;
    encoder.write_all(tar_data)?;
    let compressed = encoder.finish()?;
    Ok(compressed)
}

fn encrypt_payload(
    recipient_pk_bytes: &[u8; 32],
    owner_did: &str,
    payload: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let recipient_pk =
        <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(recipient_pk_bytes)
            .map_err(|_| anyhow!("failed to parse HPKE public key"))?;
    let info = format!("{BACKUP_INFO_PREFIX}{owner_did}");
    let aad = format!("{BACKUP_AAD_PREFIX}{owner_did}");
    let mut rng = OsRng;
    let (enc, mut sender_ctx) = hpke::setup_sender::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &recipient_pk, info.as_bytes(), &mut rng)
    .map_err(|_| anyhow!("failed to initialise HPKE sender"))?;
    let ciphertext = sender_ctx
        .seal(payload, aad.as_bytes())
        .map_err(|_| anyhow!("failed to HPKE-seal backup payload"))?;
    Ok((enc.to_bytes().to_vec(), ciphertext))
}

fn decrypt_payload(
    ciphertext: &[u8],
    enc_b64: &str,
    recipient_sk_bytes: &[u8; 32],
    owner_did: &str,
) -> Result<Vec<u8>> {
    let enc_bytes = Base64
        .decode(enc_b64.as_bytes())
        .context("backup encapsulated key is not valid base64")?;
    let enc = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(&enc_bytes)
        .map_err(|_| anyhow!("failed to parse backup encapsulated key"))?;
    let sk = <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(recipient_sk_bytes)
        .map_err(|_| anyhow!("failed to parse HPKE private key"))?;
    let info = format!("{BACKUP_INFO_PREFIX}{owner_did}");
    let aad = format!("{BACKUP_AAD_PREFIX}{owner_did}");
    let mut receiver_ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        info.as_bytes(),
    )
    .map_err(|_| anyhow!("failed to initialise HPKE receiver"))?;
    let plaintext = receiver_ctx
        .open(ciphertext, aad.as_bytes())
        .map_err(|_| anyhow!("failed to HPKE-open backup payload"))?;
    Ok(plaintext)
}

fn compute_merkle_root(digests: &[String]) -> String {
    let mut list = digests.to_vec();
    list.sort();
    let mut hasher = Hasher::new();
    for digest in list {
        hasher.update(digest.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn resolve_output_path(home: &Path, explicit: Option<PathBuf>, backup_id: &str) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if path.is_absolute() {
            Ok(path)
        } else {
            Ok(home.join(path))
        }
    } else {
        Ok(home.join("backups").join(format!("{backup_id}.json")))
    }
}

fn backup_roots(include_cache: bool) -> Vec<&'static str> {
    let mut roots = vec![
        "identities",
        "personal",
        "contracts",
        "events",
        "shards",
        "receipts",
        "presence",
        "config",
        "sync",
    ];
    if include_cache {
        roots.push("cache");
    }
    roots
}

fn sanitize_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
}

fn timestamp_slug(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}
