use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityProof {
    pub id: String,
    pub provider: String,
    pub issuer: String,
    pub subject: String,
    pub format: String,
    #[serde(default)]
    pub claims: Value,
    pub issued_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<OffsetDateTime>,
    pub digest: String,
}

impl IdentityProof {
    pub fn new(
        provider: &str,
        issuer: &str,
        subject: &str,
        format: &str,
        claims: Value,
        issued_at: OffsetDateTime,
        expires_at: Option<OffsetDateTime>,
        payload: &str,
    ) -> Result<Self> {
        let digest = blake3::hash(payload.as_bytes()).to_hex().to_string();
        // Anchor the identifier on the digest so deterministic replays remain stable.
        let id = format!("proof:{}-{}", provider, &digest[..12]);
        Ok(Self {
            id,
            provider: provider.to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            format: format.to_string(),
            claims,
            issued_at,
            expires_at,
            digest,
        })
    }

    pub fn summary(&self) -> Value {
        serde_json::json!({
            "id": self.id,
            "provider": self.provider,
            "issuer": self.issuer,
            "subject": self.subject,
            "format": self.format,
            "claims": self.claims,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "digest": self.digest,
        })
    }
}
