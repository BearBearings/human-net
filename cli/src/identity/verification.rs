use anyhow::Result;
use base64::engine::general_purpose::STANDARD as Base64Standard;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt;
use time::{Duration, OffsetDateTime};

use super::proof::IdentityProof;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityVerificationEntry {
    pub provider: String,
    pub issuer: String,
    pub proof_id: String,
    pub format: String,
    pub verified_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityVerificationLedger {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<IdentityVerificationEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_refreshed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationFact {
    pub provider: String,
    pub proof_id: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<OffsetDateTime>,
}

impl IdentityVerificationLedger {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.last_refreshed_at.is_none()
    }

    pub fn upsert(&mut self, entry: IdentityVerificationEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|candidate| candidate.provider == entry.provider)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        self.entries
            .sort_by(|a, b| a.provider.to_lowercase().cmp(&b.provider.to_lowercase()));
        self.last_refreshed_at = self.entries.iter().map(|item| item.verified_at).max();
    }

    pub fn entry(&self, provider: &str) -> Option<&IdentityVerificationEntry> {
        self.entries
            .iter()
            .find(|entry| entry.provider.eq_ignore_ascii_case(provider))
    }

    pub fn needs_refresh(&self, provider: &str, now: OffsetDateTime, within: Duration) -> bool {
        match self.entry(provider) {
            None => true,
            Some(entry) => entry
                .expires_at
                .map(|expiry| {
                    let threshold = now.checked_add(within).unwrap_or(now);
                    expiry <= threshold
                })
                .unwrap_or(false),
        }
    }

    pub fn to_policy_facts(&self) -> Vec<VerificationFact> {
        self.entries
            .iter()
            .map(|entry| VerificationFact {
                provider: entry.provider.clone(),
                proof_id: entry.proof_id.clone(),
                issuer: entry.issuer.clone(),
                valid_until: entry.expires_at,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    pub alias: String,
    pub did: String,
    pub force_refresh: bool,
    pub existing: Option<IdentityVerificationEntry>,
}

impl VerificationRequest {
    pub fn new(alias: String, did: String) -> Self {
        Self {
            alias,
            did,
            force_refresh: false,
            existing: None,
        }
    }

    pub fn with_existing(mut self, existing: Option<IdentityVerificationEntry>) -> Self {
        self.existing = existing;
        self
    }

    pub fn force_refresh(mut self, flag: bool) -> Self {
        self.force_refresh = flag;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub entry: IdentityVerificationEntry,
    pub proof: Option<IdentityProof>,
    pub refreshed: bool,
}

pub trait VerificationProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn verify(&self, request: &VerificationRequest) -> Result<VerificationResult>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinVerifier {
    MockEntra,
    Didkit,
}

impl BuiltinVerifier {
    pub const fn name(self) -> &'static str {
        match self {
            BuiltinVerifier::MockEntra => "mock-entra",
            BuiltinVerifier::Didkit => "mock-didkit",
        }
    }

    pub fn all() -> &'static [BuiltinVerifier] {
        &[BuiltinVerifier::MockEntra, BuiltinVerifier::Didkit]
    }

    pub fn from_str(provider: &str) -> Option<Self> {
        let normalized = provider.trim().to_ascii_lowercase();
        Self::all()
            .iter()
            .copied()
            .find(|candidate| candidate.name() == normalized)
    }

    pub fn build(self) -> Box<dyn VerificationProvider> {
        match self {
            BuiltinVerifier::MockEntra => Box::new(MockEntraIdVerifier::default()),
            BuiltinVerifier::Didkit => Box::new(DidkitVerifier::default()),
        }
    }
}

impl fmt::Display for BuiltinVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Default)]
struct MockEntraIdVerifier;

impl VerificationProvider for MockEntraIdVerifier {
    fn name(&self) -> &'static str {
        BuiltinVerifier::MockEntra.name()
    }

    fn verify(&self, request: &VerificationRequest) -> Result<VerificationResult> {
        if !request.force_refresh {
            if let Some(existing) = &request.existing {
                if existing.provider.eq_ignore_ascii_case(self.name()) {
                    if let Some(expires_at) = existing.expires_at {
                        let now = OffsetDateTime::now_utc();
                        let threshold = now.checked_add(Duration::minutes(5)).unwrap_or(now);
                        if expires_at > threshold {
                            return Ok(VerificationResult {
                                entry: existing.clone(),
                                proof: None,
                                refreshed: false,
                            });
                        }
                    }
                }
            }
        }

        let now = OffsetDateTime::now_utc();
        let expires_at = now.checked_add(Duration::days(30)).unwrap_or(now);
        let token_payload = format!(
            "entra::{did}::{alias}::{ts}",
            did = request.did,
            alias = request.alias,
            ts = now.unix_timestamp()
        );
        let issuer = "https://entra.mock/human-net";
        let token_snapshot = Base64Standard.encode(token_payload.as_bytes());
        let claims = json!({
            "scope": "entra/basic",
            "alias": request.alias,
            "token_snapshot": token_snapshot,
        });
        let proof_doc = IdentityProof::new(
            self.name(),
            issuer,
            &request.did,
            "mock_jwt",
            claims,
            now,
            Some(expires_at),
            &token_payload,
        )?;
        let entry = IdentityVerificationEntry {
            provider: self.name().to_string(),
            issuer: issuer.to_string(),
            proof_id: proof_doc.id.clone(),
            format: proof_doc.format.clone(),
            verified_at: now,
            expires_at: Some(expires_at),
        };

        Ok(VerificationResult {
            entry,
            proof: Some(proof_doc),
            refreshed: true,
        })
    }
}

#[derive(Debug, Default)]
struct DidkitVerifier;

impl VerificationProvider for DidkitVerifier {
    fn name(&self) -> &'static str {
        BuiltinVerifier::Didkit.name()
    }

    fn verify(&self, request: &VerificationRequest) -> Result<VerificationResult> {
        if !request.force_refresh {
            if let Some(existing) = &request.existing {
                if existing.provider.eq_ignore_ascii_case(self.name()) {
                    if let Some(expires_at) = existing.expires_at {
                        let now = OffsetDateTime::now_utc();
                        let threshold = now.checked_add(Duration::minutes(5)).unwrap_or(now);
                        if expires_at > threshold {
                            return Ok(VerificationResult {
                                entry: existing.clone(),
                                proof: None,
                                refreshed: false,
                            });
                        }
                    }
                }
            }
        }

        let now = OffsetDateTime::now_utc();
        let expires_at = now.checked_add(Duration::days(90)).unwrap_or(now);
        let payload = json!({
            "subject": request.did,
            "alias": request.alias,
            "issued": now,
        });
        let payload_string = serde_json::to_string(&payload)?;
        let issuer = "https://didkit.mock/human-net";
        let claims = json!({
            "schema": "mock-didkit/basic",
            "attributes": {
                "alias": request.alias,
            },
        });
        let proof_doc = IdentityProof::new(
            self.name(),
            issuer,
            &request.did,
            "mock_ldp",
            claims,
            now,
            Some(expires_at),
            &payload_string,
        )?;
        let entry = IdentityVerificationEntry {
            provider: self.name().to_string(),
            issuer: issuer.to_string(),
            proof_id: proof_doc.id.clone(),
            format: proof_doc.format.clone(),
            verified_at: now,
            expires_at: Some(expires_at),
        };

        Ok(VerificationResult {
            entry,
            proof: Some(proof_doc),
            refreshed: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_upsert_and_lookup() {
        let mut ledger = IdentityVerificationLedger::default();
        let entry = IdentityVerificationEntry {
            provider: "mock-entra".into(),
            issuer: "issuer".into(),
            proof_id: "proof:mock-entra-abc123".into(),
            format: "mock_jwt".into(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: None,
        };
        ledger.upsert(entry.clone());
        assert_eq!(ledger.entry("mock-entra"), Some(&entry));
        assert!(ledger.entry("unknown").is_none());

        let newer_time = entry.verified_at + Duration::hours(1);
        let newer = IdentityVerificationEntry {
            verified_at: newer_time,
            ..entry.clone()
        };
        ledger.upsert(newer.clone());
        assert_eq!(ledger.entry("mock-entra"), Some(&newer));
    }

    #[test]
    fn ledger_needs_refresh_logic() {
        let mut ledger = IdentityVerificationLedger::default();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let entry = IdentityVerificationEntry {
            provider: "mock-entra".into(),
            issuer: "issuer".into(),
            proof_id: "proof:mock-entra-xyz789".into(),
            format: "mock_jwt".into(),
            verified_at: now,
            expires_at: Some(now + Duration::days(1)),
        };
        ledger.upsert(entry);
        assert!(!ledger.needs_refresh("mock-entra", now, Duration::hours(1)));
        assert!(ledger.needs_refresh("mock-entra", now + Duration::hours(23), Duration::hours(2)));
        assert!(ledger.needs_refresh("other", now, Duration::hours(1)));
    }

    #[test]
    fn mock_entra_reuses_fresh_entry() {
        let verifier = MockEntraIdVerifier::default();
        let issued = OffsetDateTime::now_utc();
        let existing = IdentityVerificationEntry {
            provider: verifier.name().into(),
            issuer: "issuer".into(),
            proof_id: "proof:mock-entra-cache".into(),
            format: "mock_jwt".into(),
            verified_at: issued,
            expires_at: Some(issued + Duration::days(10)),
        };
        let request = VerificationRequest::new("alice".into(), "did:hn:alice".into())
            .with_existing(Some(existing.clone()));
        let result = verifier.verify(&request).unwrap();
        assert!(!result.refreshed);
        assert!(result.proof.is_none());
        assert_eq!(result.entry, existing);
    }

    #[test]
    fn didkit_produces_payload() {
        let verifier = DidkitVerifier::default();
        let request = VerificationRequest::new("bob".into(), "did:hn:bob".into());
        let result = verifier.verify(&request).unwrap();
        assert!(result.refreshed);
        let proof = result.proof.expect("proof expected");
        assert_eq!(result.entry.provider, verifier.name());
        assert_eq!(result.entry.issuer, "https://didkit.mock/human-net");
        assert_eq!(result.entry.proof_id, proof.id);
        assert_eq!(proof.subject, "did:hn:bob");
        assert_eq!(proof.format, "mock_ldp");
        assert_eq!(proof.provider, verifier.name());
    }

    #[test]
    fn ledger_policy_facts() {
        let mut ledger = IdentityVerificationLedger::default();
        let now = OffsetDateTime::now_utc();
        ledger.upsert(IdentityVerificationEntry {
            provider: "mock-entra".into(),
            issuer: "issuer".into(),
            proof_id: "proof:mock-entra-demo".into(),
            format: "mock_jwt".into(),
            verified_at: now,
            expires_at: Some(now + Duration::days(5)),
        });
        let facts = ledger.to_policy_facts();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].provider, "mock-entra");
        assert_eq!(facts[0].proof_id, "proof:mock-entra-demo");
    }
}
