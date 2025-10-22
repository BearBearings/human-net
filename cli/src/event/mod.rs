use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::contract::{sanitize_component, timestamp_slug, ContractState, ContractStateEntry};
use crate::identity::IdentityKeys;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEvent {
    pub id: String,
    pub contract_id: String,
    pub sequence: u32,
    pub state: ContractState,
    pub actor: String,
    pub proof_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    pub canonical_hash: String,
    pub signature: String,
}

impl ContractEvent {
    pub fn canonical_payload(&self) -> Result<String> {
        let view = EventSignView {
            contract_id: &self.contract_id,
            sequence: self.sequence,
            state: &self.state,
            actor: &self.actor,
            proof_id: &self.proof_id,
            timestamp: self.timestamp,
            reason: self.reason.as_deref(),
            metadata: self.metadata.as_ref(),
        };
        Ok(serde_jcs::to_string(&view)?)
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let signature_bytes = Base64
            .decode(self.signature.as_bytes())
            .context("invalid event signature encoding")?;
        let signature_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| anyhow!("expected 64-byte signature"))?;
        let signature = Signature::from_bytes(&signature_array);
        let canonical = self.canonical_payload()?;
        verifying_key
            .verify_strict(canonical.as_bytes(), &signature)
            .context("event signature verification failed")
    }

    pub fn to_state_entry(&self) -> ContractStateEntry {
        ContractStateEntry {
            state: self.state.clone(),
            event_id: Some(self.id.clone()),
            sequence: Some(self.sequence),
            timestamp: self.timestamp,
            actor: Some(self.actor.clone()),
            proof_id: Some(self.proof_id.clone()),
            signature: Some(self.signature.clone()),
            canonical_hash: Some(self.canonical_hash.clone()),
            reason: self.reason.clone(),
        }
    }
}

pub fn build_contract_event(
    contract_id: &str,
    sequence: u32,
    state: ContractState,
    keys: &IdentityKeys,
    proof_id: &str,
    timestamp: OffsetDateTime,
    reason: Option<String>,
    metadata: Option<Value>,
) -> Result<ContractEvent> {
    let actor = keys.did();
    let view = EventSignView {
        contract_id,
        sequence,
        state: &state,
        actor: &actor,
        proof_id,
        timestamp,
        reason: reason.as_deref(),
        metadata: metadata.as_ref(),
    };
    let canonical = serde_jcs::to_string(&view)?;
    let mut hasher = Hasher::new();
    hasher.update(canonical.as_bytes());
    let canonical_hash = hasher.finalize().to_hex().to_string();
    let signature = keys.signing_key().sign(canonical.as_bytes());
    let signature_b64 = Base64.encode(signature.to_bytes());
    let event_id = format!(
        "event:{}:{}:{}",
        sanitize_component(contract_id),
        sequence,
        timestamp_slug(timestamp)
    );

    Ok(ContractEvent {
        id: event_id,
        contract_id: contract_id.to_string(),
        sequence,
        state,
        actor,
        proof_id: proof_id.to_string(),
        timestamp,
        reason,
        metadata,
        canonical_hash,
        signature: signature_b64,
    })
}

#[derive(Serialize)]
struct EventSignView<'a> {
    contract_id: &'a str,
    sequence: u32,
    state: &'a ContractState,
    actor: &'a str,
    proof_id: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a Value>,
}
