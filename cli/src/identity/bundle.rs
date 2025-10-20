use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use time::OffsetDateTime;

use super::did::DidDocument;
use super::storage::IdentityProfile;

const CIPHER: &str = "chacha20poly1305";
const KDF: &str = "argon2id";
const EXPORT_VERSION: u8 = 1;

#[derive(Debug)]
pub struct IdentityExportOptions {
    pub passphrase: String,
    pub destination: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBundle {
    pub version: u8,
    pub profile: IdentityProfile,
    pub did_document: DidDocument,
    pub canonical_hash: String,
    pub encrypted_key: EncryptedSecret,
    pub exported_at: OffsetDateTime,
}

impl IdentityBundle {
    pub fn from_identity(
        record: &super::storage::IdentityRecord,
        passphrase: &str,
    ) -> Result<Self> {
        let secret = record.keys.secret_key_bytes();
        let canonical_hash = record.did_document.canonical_hash()?;
        let encrypted_key = encrypt_secret(&secret, passphrase)?;
        Ok(Self {
            version: EXPORT_VERSION,
            profile: record.profile.clone(),
            did_document: record.did_document.clone(),
            canonical_hash,
            encrypted_key,
            exported_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn decrypt_secret(&self, passphrase: &str) -> Result<[u8; 32]> {
        decrypt_secret(&self.encrypted_key, passphrase)
    }

    pub fn to_pretty_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn write_to_path(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self)?;
        fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let bundle: IdentityBundle = serde_json::from_slice(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        if bundle.version != EXPORT_VERSION {
            return Err(anyhow!(
                "unsupported export version {} (expected {})",
                bundle.version,
                EXPORT_VERSION
            ));
        }
        Ok(bundle)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub cipher: String,
    pub nonce: String,
    pub salt: String,
    pub kdf: KdfParams,
    pub ciphertext: String,
    pub checksum_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_size: u32,
}

fn encrypt_secret(secret: &[u8; 32], passphrase: &str) -> Result<EncryptedSecret> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let kdf_params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|err| anyhow!("failed to configure argon2 params: {err}"))?;
    let memory_kib = kdf_params.m_cost();
    let iterations = kdf_params.t_cost();
    let parallelism = kdf_params.p_cost();
    let output_len = kdf_params.output_len().unwrap_or(32) as u32;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, kdf_params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)
        .map_err(|err| anyhow!("argon2 key derivation failed: {err}"))?;

    let key = Key::from(key_bytes);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_slice())
        .map_err(|err| anyhow!("encryption failed: {err}"))?;

    let mut hasher = Hasher::new();
    hasher.update(secret);
    let checksum = hasher.finalize().to_hex().to_string();

    Ok(EncryptedSecret {
        cipher: CIPHER.to_string(),
        nonce: Base64.encode(nonce_bytes),
        salt: Base64.encode(salt),
        kdf: KdfParams {
            algorithm: KDF.to_string(),
            memory_kib,
            iterations,
            parallelism,
            output_size: output_len,
        },
        ciphertext: Base64.encode(ciphertext),
        checksum_blake3: checksum,
    })
}

fn decrypt_secret(secret: &EncryptedSecret, passphrase: &str) -> Result<[u8; 32]> {
    if secret.cipher != CIPHER {
        return Err(anyhow!("unsupported cipher {}", secret.cipher));
    }
    if secret.kdf.algorithm != KDF {
        return Err(anyhow!("unsupported kdf {}", secret.kdf.algorithm));
    }

    let salt = Base64
        .decode(secret.salt.as_bytes())
        .map_err(|err| anyhow!("invalid salt encoding: {err}"))?;
    let nonce_bytes = Base64
        .decode(secret.nonce.as_bytes())
        .map_err(|err| anyhow!("invalid nonce encoding: {err}"))?;
    let ciphertext = Base64
        .decode(secret.ciphertext.as_bytes())
        .map_err(|err| anyhow!("invalid ciphertext encoding: {err}"))?;

    let params = Params::new(
        secret.kdf.memory_kib,
        secret.kdf.iterations,
        secret.kdf.parallelism,
        Some(secret.kdf.output_size as usize),
    )
    .map_err(|err| anyhow!("invalid argon2 params: {err}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = vec![0u8; secret.kdf.output_size as usize];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut derived)
        .map_err(|err| anyhow!("argon2 key derivation failed: {err}"))?;

    let key_array: [u8; 32] = derived
        .try_into()
        .map_err(|_| anyhow!("unexpected derived key length; expected 32 bytes"))?;
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| anyhow!("unexpected nonce length; expected 12 bytes"))?;

    let key = Key::from(key_array);
    let nonce = Nonce::from(nonce_array);
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|err| anyhow!("decryption failed: {err}"))?;

    if plaintext.len() != 32 {
        return Err(anyhow!(
            "unexpected decrypted key length {}; expected 32",
            plaintext.len()
        ));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&plaintext);

    let mut hasher = Hasher::new();
    hasher.update(&array);
    let checksum = hasher.finalize().to_hex().to_string();
    if checksum != secret.checksum_blake3 {
        return Err(anyhow!(
            "checksum mismatch after decrypt (expected {}, computed {})",
            secret.checksum_blake3,
            checksum
        ));
    }

    Ok(array)
}
