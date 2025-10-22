use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

/// Holds the Ed25519 key material for an identity.
pub struct IdentityKeys {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl IdentityKeys {
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("expected 32 bytes for Ed25519 secret key"))?;
        let signing_key = SigningKey::from_bytes(&array);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn did(&self) -> String {
        format!("did:hn:{}", self.did_slug())
    }

    pub fn did_slug(&self) -> String {
        bs58::encode(self.public_key_bytes())
            .into_string()
            .to_lowercase()
    }

    pub fn hpke_static_secret(&self) -> X25519Secret {
        X25519Secret::from(self.secret_key_bytes())
    }

    pub fn hpke_public_key_bytes(&self) -> [u8; 32] {
        let secret = self.hpke_static_secret();
        let public = X25519PublicKey::from(&secret);
        public.to_bytes()
    }

    pub fn hpke_public_key_base64(&self) -> String {
        Base64.encode(self.hpke_public_key_bytes())
    }
}

/// Representation of the DID document stored for each identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service: Vec<ServiceEntry>,
}

impl DidDocument {
    pub fn for_keys(keys: &IdentityKeys, endpoints: &[ServiceEndpointInput]) -> Self {
        let did = keys.did();
        let verification = VerificationMethod::for_keys(&did, keys.verifying_key());

        let service = endpoints
            .iter()
            .map(|entry| ServiceEntry {
                id: format!("{}#{}", did, entry.id_suffix),
                r#type: entry.service_type.clone(),
                service_endpoint: entry.service_endpoint.clone(),
            })
            .collect();

        Self {
            id: did.clone(),
            verification_method: vec![verification],
            authentication: vec![format!("{}#key-ed25519", did)],
            service,
        }
    }

    pub fn to_canonical_json(&self) -> Result<String> {
        let value = serde_json::to_value(self)?;
        let canonical = serde_jcs::to_string(&value)?;
        Ok(canonical)
    }

    pub fn canonical_hash(&self) -> Result<String> {
        let canonical = self.to_canonical_json()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(canonical.as_bytes());
        Ok(hasher.finalize().to_hex().to_string())
    }
}

/// Input structure to generate service endpoints.
pub struct ServiceEndpointInput {
    pub id_suffix: String,
    pub service_type: String,
    pub service_endpoint: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl VerificationMethod {
    fn for_keys(did: &str, verifying_key: &VerifyingKey) -> Self {
        let pubkey = verifying_key.to_bytes();
        Self {
            id: format!("{}#key-ed25519", did),
            method_type: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_multibase: format!("z{}", bs58::encode(pubkey).into_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: Value,
}
