use std::fs;
use std::path::Path;

use anyhow::{anyhow, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeR,
    OpModeS, Serializable,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use x25519_dalek::StaticSecret;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsiderationType {
    Reciprocal,
    Payment,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consideration {
    #[serde(rename = "type")]
    pub r#type: ConsiderationType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offer {
    pub id: String,
    pub issuer: String,
    pub audience: String,
    #[serde(alias = "unit")]
    pub doc: String,
    pub capability: String,
    #[serde(default)]
    pub policy_refs: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub valid_until: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consideration: Option<Consideration>,
    pub proof_id: String,
    pub issuer_hpke_public_key: String,
    pub terms_digest: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i64>,
}

impl Offer {
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read offer file {}", path.display()))?;
        let mut offer: Offer = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse offer JSON {}", path.display()))?;
        offer.normalise();
        Ok(offer)
    }

    fn normalise(&mut self) {
        self.policy_refs.sort();
    }

    pub fn compute_terms_digest(&self) -> Result<String> {
        let canonical = serde_jcs::to_string(&OfferDigestView::from(self))?;
        Ok(blake3::hash(canonical.as_bytes()).to_hex().to_string())
    }

    pub fn compute_legacy_terms_digest(&self) -> Result<String> {
        let canonical = serde_jcs::to_string(&OfferDigestViewLegacy::from(self))?;
        Ok(blake3::hash(canonical.as_bytes()).to_hex().to_string())
    }

    pub fn digest_matches(&self) -> Result<bool> {
        let current = self.compute_terms_digest()?;
        if current == self.terms_digest {
            return Ok(true);
        }
        Ok(self.compute_legacy_terms_digest()? == self.terms_digest)
    }
}

#[derive(Serialize)]
struct OfferDigestViewLegacy<'a> {
    issuer: &'a str,
    audience: &'a str,
    unit: &'a str,
    capability: &'a str,
    policy_refs: &'a [String],
    valid_from: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_until: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consideration: Option<&'a Consideration>,
    proof_id: &'a str,
    issuer_hpke_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention_days: Option<i64>,
}

#[derive(Serialize)]
struct OfferDigestView<'a> {
    issuer: &'a str,
    audience: &'a str,
    doc: &'a str,
    capability: &'a str,
    policy_refs: &'a [String],
    valid_from: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_until: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consideration: Option<&'a Consideration>,
    proof_id: &'a str,
    issuer_hpke_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention_days: Option<i64>,
}

impl<'a> From<&'a Offer> for OfferDigestView<'a> {
    fn from(value: &'a Offer) -> Self {
        OfferDigestView {
            issuer: &value.issuer,
            audience: &value.audience,
            doc: &value.doc,
            capability: &value.capability,
            policy_refs: &value.policy_refs,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            consideration: value.consideration.as_ref(),
            proof_id: &value.proof_id,
            issuer_hpke_public_key: &value.issuer_hpke_public_key,
            retention_days: value.retention_days,
        }
    }
}

impl<'a> From<&'a Offer> for OfferDigestViewLegacy<'a> {
    fn from(value: &'a Offer) -> Self {
        OfferDigestViewLegacy {
            issuer: &value.issuer,
            audience: &value.audience,
            unit: &value.doc,
            capability: &value.capability,
            policy_refs: &value.policy_refs,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            consideration: value.consideration.as_ref(),
            proof_id: &value.proof_id,
            issuer_hpke_public_key: &value.issuer_hpke_public_key,
            retention_days: value.retention_days,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractParty {
    pub did: String,
    pub proof_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hpke_public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub hpke_suite: String,
    pub enc: String,
    pub ciphertext: String,
    pub cid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ContractState {
    Proposed,
    #[serde(alias = "RESERVED")]
    Accepted,
    Fulfilled,
    Revoked,
    Expired,
}

impl ContractState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContractState::Proposed => "PROPOSED",
            ContractState::Accepted => "ACCEPTED",
            ContractState::Fulfilled => "FULFILLED",
            ContractState::Revoked => "REVOKED",
            ContractState::Expired => "EXPIRED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStateEntry {
    pub state: ContractState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub id: String,
    pub offer_id: String,
    pub terms_digest: String,
    pub issuer: ContractParty,
    pub counterparty: ContractParty,
    pub capability: String,
    #[serde(alias = "unit")]
    pub doc: String,
    pub state: ContractState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<ContractRetention>,
    #[serde(default)]
    pub state_history: Vec<ContractStateEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<EncryptedPayload>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractRetention {
    #[serde(with = "time::serde::rfc3339::option")]
    pub archive_after: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub delete_after: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub archived_at: Option<OffsetDateTime>,
}

impl Contract {
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read contract file {}", path.display()))?;
        let mut contract: Contract = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse contract JSON {}", path.display()))?;
        contract
            .state_history
            .sort_by(|a, b| match (a.sequence, b.sequence) {
                (Some(sa), Some(sb)) => sa.cmp(&sb),
                _ => a.timestamp.cmp(&b.timestamp),
            });
        for (idx, entry) in contract.state_history.iter_mut().enumerate() {
            if entry.sequence.is_none() {
                entry.sequence = Some((idx + 1) as u32);
            }
        }
        Ok(contract)
    }

    pub fn verify_against(&self, offer: &Offer) -> ContractVerification {
        let offer_digest = offer.compute_terms_digest().ok();
        let offer_legacy_digest = offer.compute_legacy_terms_digest().ok();
        let offer_digest_match = offer_digest
            .as_ref()
            .map(|expected| expected == &offer.terms_digest)
            .unwrap_or_else(|| {
                offer_legacy_digest
                    .as_ref()
                    .map(|legacy| legacy == &offer.terms_digest)
                    .unwrap_or(false)
            });
        let events_signed = self
            .state_history
            .iter()
            .all(|entry| entry.signature.is_some());
        ContractVerification {
            offer_id_match: self.offer_id == offer.id,
            terms_digest_match: self.terms_digest == offer.terms_digest,
            offer_digest_match,
            capability_match: self.capability == offer.capability,
            doc_match: self.doc == offer.doc,
            issuer_proof_match: self.issuer.proof_id == offer.proof_id,
            state_history_present: !self.state_history.is_empty(),
            events_signed,
        }
    }

    pub fn participants(&self) -> [&ContractParty; 2] {
        [&self.issuer, &self.counterparty]
    }

    pub fn required_proof_ids(&self) -> [&str; 2] {
        [
            &self.issuer.proof_id.as_str(),
            &self.counterparty.proof_id.as_str(),
        ]
    }

    pub fn fulfill(
        &self,
        payload: &[u8],
        publisher_did: &str,
        timestamp: OffsetDateTime,
    ) -> Result<(Contract, ShardEnvelope)> {
        ensure!(
            matches!(
                self.state,
                ContractState::Accepted | ContractState::Proposed
            ),
            "contract must be in ACCEPTED/PROPOSED state before fulfilment"
        );

        let hpke_pub = self
            .counterparty
            .hpke_public_key
            .as_ref()
            .ok_or_else(|| anyhow!("counterparty missing hpke public key"))?;
        let peer_bytes = Base64
            .decode(hpke_pub)
            .map_err(|_| anyhow!("invalid counterparty hpke public key"))?;
        let peer_pk = <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(&peer_bytes)
            .map_err(|_| anyhow!("failed to parse counterparty hpke public key"))?;

        let info = self.id.as_bytes();
        let aad = self.id.as_bytes();
        let mut rng = OsRng;
        let (enc, mut sender_ctx) = hpke::setup_sender::<
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
            _,
        >(&OpModeS::Base, &peer_pk, info, &mut rng)
        .map_err(|_| anyhow!("failed to initialise HPKE sender"))?;
        let ciphertext = sender_ctx
            .seal(payload, aad)
            .map_err(|_| anyhow!("failed to HPKE-seal payload"))?;

        let payload_cid = blake3::hash(&ciphertext).to_hex().to_string();

        let enc_b64 = Base64.encode(enc.to_bytes());
        let ciphertext_b64 = Base64.encode(&ciphertext);

        let mut updated = self.clone();
        let next_sequence = updated
            .state_history
            .iter()
            .filter_map(|entry| entry.sequence)
            .max()
            .unwrap_or(0)
            + 1;
        updated.state = ContractState::Fulfilled;
        updated.state_history.push(ContractStateEntry {
            state: ContractState::Fulfilled,
            event_id: None,
            sequence: Some(next_sequence),
            timestamp,
            actor: None,
            proof_id: None,
            signature: None,
            canonical_hash: None,
            reason: None,
        });
        updated.encrypted_payload = Some(EncryptedPayload {
            hpke_suite: "X25519HkdfSha256+ChaCha20Poly1305".to_string(),
            enc: enc_b64.clone(),
            ciphertext: ciphertext_b64.clone(),
            cid: payload_cid.clone(),
        });
        updated.metadata = merge_metadata(
            &updated.metadata,
            json!({
                "shard": {
                    "payload_cid": payload_cid.clone(),
                    "algorithm": "ChaCha20Poly1305",
                    "hpke_suite": "X25519HkdfSha256+ChaCha20Poly1305",
                }
            }),
        );

        let shard_id = format!(
            "shard:{}:{}:{}",
            sanitize_component(publisher_did),
            sanitize_component(&self.id),
            timestamp_slug(timestamp)
        );

        let envelope = ShardEnvelope {
            id: shard_id,
            contract_id: self.id.clone(),
            publisher: publisher_did.to_string(),
            created_at: timestamp,
            algorithm: "ChaCha20Poly1305".to_string(),
            payload_cid,
            ciphertext: ciphertext_b64,
            enc: enc_b64,
        };

        Ok((updated, envelope))
    }
}

#[derive(Debug)]
pub struct ContractVerification {
    pub offer_id_match: bool,
    pub terms_digest_match: bool,
    pub offer_digest_match: bool,
    pub capability_match: bool,
    pub doc_match: bool,
    pub issuer_proof_match: bool,
    pub state_history_present: bool,
    pub events_signed: bool,
}

impl ContractVerification {
    pub fn success(&self) -> bool {
        self.offer_id_match
            && self.terms_digest_match
            && self.offer_digest_match
            && self.capability_match
            && self.doc_match
            && self.issuer_proof_match
            && self.state_history_present
            && self.events_signed
    }

    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "offer_id_match": self.offer_id_match,
            "terms_digest_match": self.terms_digest_match,
            "offer_digest_match": self.offer_digest_match,
            "capability_match": self.capability_match,
            "doc_match": self.doc_match,
            "issuer_proof_match": self.issuer_proof_match,
            "state_history_present": self.state_history_present,
            "events_signed": self.events_signed,
            "success": self.success(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardEnvelope {
    pub id: String,
    pub contract_id: String,
    pub publisher: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub algorithm: String,
    pub payload_cid: String,
    pub ciphertext: String,
    pub enc: String,
}

impl ShardEnvelope {
    pub fn decrypt(&self, secret: &StaticSecret, contract_id: &str) -> Result<Vec<u8>> {
        ensure!(
            self.algorithm == "ChaCha20Poly1305",
            "unsupported shard algorithm {}",
            self.algorithm
        );
        let sk_bytes = secret.to_bytes();
        let sk = <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(&sk_bytes)
            .map_err(|_| anyhow!("invalid HPKE private key"))?;
        let enc_bytes = Base64
            .decode(&self.enc)
            .map_err(|_| anyhow!("invalid shard encapsulated key"))?;
        let enc = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(&enc_bytes)
            .map_err(|_| anyhow!("failed to parse encapsulated key"))?;
        let ciphertext = Base64
            .decode(&self.ciphertext)
            .map_err(|_| anyhow!("invalid shard ciphertext"))?;
        let aad = contract_id.as_bytes();
        let mut receiver_ctx =
            hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &sk,
                &enc,
                contract_id.as_bytes(),
            )
            .map_err(|_| anyhow!("failed to initialise HPKE receiver"))?;
        receiver_ctx
            .open(&ciphertext, aad)
            .map_err(|_| anyhow!("failed to HPKE-open shard ciphertext"))
    }
}

pub fn merge_metadata(existing: &Value, addition: Value) -> Value {
    match (existing, addition) {
        (Value::Object(existing_map), Value::Object(add_map)) => {
            let mut merged = existing_map.clone();
            for (k, v) in add_map {
                merged.insert(k, v);
            }
            Value::Object(merged)
        }
        (_, addition) => addition,
    }
}

pub fn sanitize_component(input: &str) -> String {
    let sanitized: String = input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_lowercase();
    if sanitized.is_empty() {
        "item".to_string()
    } else {
        sanitized
    }
}

pub fn timestamp_slug(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}
