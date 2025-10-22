use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::identity::IdentityVault;

const POLICY_FILE: &str = "policy@1.json";
const POLICY_LOG: &str = "log.jsonl";

pub struct PolicyStore {
    alias: String,
    policy_path: PathBuf,
    log_path: PathBuf,
}

impl PolicyStore {
    pub fn new(vault: &IdentityVault) -> Result<Self> {
        let active = vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity selected; run `hn id use <alias>`"))?;
        Self::for_alias(vault, &active.alias)
    }

    pub fn for_alias(vault: &IdentityVault, alias: &str) -> Result<Self> {
        let dir = vault.ensure_policy_dir_for(alias)?;
        let policy_path = dir.join(POLICY_FILE);
        let log_path = dir.join(POLICY_LOG);
        if !policy_path.exists() {
            let default = PolicyDocument::default();
            write_policy(&policy_path, &default)?;
        }
        if !log_path.exists() {
            fs::File::create(&log_path)
                .with_context(|| format!("failed to create {}", log_path.display()))?;
        }
        Ok(Self {
            alias: alias.to_string(),
            policy_path,
            log_path,
        })
    }

    pub fn load(&self) -> Result<PolicyDocument> {
        read_policy(&self.policy_path)
    }

    pub fn save(&self, document: &PolicyDocument) -> Result<()> {
        write_policy(&self.policy_path, document)?;
        self.append_log(document)?;
        Ok(())
    }

    pub fn patch_gate<F>(&self, gate: &str, mutator: F) -> Result<PolicyDocument>
    where
        F: FnOnce(&mut PolicyGate),
    {
        let mut doc = self.load()?;
        let entry = doc.gates.entry(gate.to_string()).or_default();
        mutator(entry);
        doc.last_applied = OffsetDateTime::now_utc();
        doc.version += 1;
        self.save(&doc)?;
        Ok(doc)
    }

    fn append_log(&self, document: &PolicyDocument) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .with_context(|| format!("failed to open {}", self.log_path.display()))?;
        let entry = PolicyLogEntry {
            version: document.version,
            timestamp: document.last_applied,
            snapshot_jcs: serde_jcs::to_string(document)?,
        };
        let line = serde_json::to_string(&entry)? + "\n";
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub version: u32,
    pub gates: BTreeMap<String, PolicyGate>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_applied: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_by: Option<String>,
    #[serde(default)]
    pub banners: BTreeMap<String, String>,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        let now = OffsetDateTime::now_utc();
        let mut gates = BTreeMap::new();
        gates.insert(
            "doc.write".to_string(),
            PolicyGate::new(GateMode::Allow, None, true),
        );
        gates.insert(
            "doc.read".to_string(),
            PolicyGate::new(GateMode::Allow, Some("type=*".to_string()), false),
        );
        gates.insert(
            "offer.create".to_string(),
            PolicyGate::new(GateMode::Allow, Some("provider=*".to_string()), false),
        );
        gates.insert(
            "contract.accept".to_string(),
            PolicyGate::new(GateMode::Allow, Some("provider=*".to_string()), false),
        );
        Self {
            version: 1,
            gates,
            last_applied: now,
            applied_by: None,
            banners: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

pub struct PolicyEvaluator;

impl PolicyEvaluator {
    pub fn check_doc_write(
        vault: &IdentityVault,
        alias: &str,
        doc_type: &str,
        _content: &serde_json::Value,
    ) -> Result<()> {
        match Self::doc_write_decision(vault, alias, doc_type, _content)? {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny(reason) => Err(anyhow!(reason)),
        }
    }

    pub fn doc_write_decision(
        vault: &IdentityVault,
        alias: &str,
        doc_type: &str,
        content: &serde_json::Value,
    ) -> Result<PolicyDecision> {
        let _ = content; // reserved for future content-based rules
        let store = PolicyStore::for_alias(vault, alias)?;
        store.evaluate_doc_write(doc_type)
    }

    pub fn check_doc_read(
        vault: &IdentityVault,
        alias: &str,
        doc_type: &str,
        content: &serde_json::Value,
    ) -> Result<()> {
        match Self::doc_read_decision(vault, alias, doc_type, content)? {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny(reason) => Err(anyhow!(reason)),
        }
    }

    pub fn doc_read_decision(
        vault: &IdentityVault,
        alias: &str,
        doc_type: &str,
        content: &serde_json::Value,
    ) -> Result<PolicyDecision> {
        let _ = content;
        let store = PolicyStore::for_alias(vault, alias)?;
        store.evaluate_doc_read(doc_type)
    }

    pub fn check_provider_gate(
        vault: &IdentityVault,
        alias: &str,
        gate: &str,
        provider: &str,
    ) -> Result<()> {
        let store = PolicyStore::for_alias(vault, alias)?;
        match store.evaluate_provider_gate(gate, provider)? {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny(reason) => Err(anyhow!(reason)),
        }
    }
}

impl PolicyStore {
    pub fn evaluate_doc_write(&self, doc_type: &str) -> Result<PolicyDecision> {
        let policy = self.load()?;
        if let Some(gate) = policy.gates.get("doc.write") {
            match gate.mode {
                GateMode::Deny => {
                    return Ok(PolicyDecision::Deny(format!(
                        "policy denied doc.write for type '{}'",
                        doc_type
                    )))
                }
                GateMode::Prompt => {
                    return Ok(PolicyDecision::Deny(format!(
                        "policy requires confirmation for doc.write type '{}'",
                        doc_type
                    )))
                }
                GateMode::Allow => {
                    if Self::matches_conditions(gate, doc_type) {
                        Ok(PolicyDecision::Allow)
                    } else {
                        Ok(PolicyDecision::Deny(format!(
                            "policy blocked doc.write; type '{}' not permitted",
                            doc_type
                        )))
                    }
                }
            }
        } else {
            Ok(PolicyDecision::Allow)
        }
    }

    pub fn evaluate_doc_read(&self, doc_type: &str) -> Result<PolicyDecision> {
        let policy = self.load()?;
        if let Some(gate) = policy.gates.get("doc.read") {
            match gate.mode {
                GateMode::Deny => {
                    return Ok(PolicyDecision::Deny(format!(
                        "policy denied doc.read for type '{}'",
                        doc_type
                    )))
                }
                GateMode::Prompt => {
                    return Ok(PolicyDecision::Deny(format!(
                        "policy requires confirmation for doc.read type '{}'",
                        doc_type
                    )))
                }
                GateMode::Allow => {
                    if Self::matches_conditions(gate, doc_type) {
                        Ok(PolicyDecision::Allow)
                    } else {
                        Ok(PolicyDecision::Deny(format!(
                            "policy blocked doc.read; type '{}' not permitted",
                            doc_type
                        )))
                    }
                }
            }
        } else {
            Ok(PolicyDecision::Allow)
        }
    }

    fn matches_conditions(gate: &PolicyGate, doc_type: &str) -> bool {
        let Some(ref cond) = gate.conditions else {
            return true;
        };
        if cond.trim().is_empty() {
            return true;
        }
        let mut allowed = false;
        for token in cond.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Some(rest) = token.strip_prefix("type=") {
                if rest.trim() == "*" || rest.trim() == doc_type {
                    allowed = true;
                    break;
                }
            }
        }
        allowed
    }

    pub fn evaluate_provider_gate(
        &self,
        gate_name: &str,
        provider: &str,
    ) -> Result<PolicyDecision> {
        let policy = self.load()?;
        let Some(gate) = policy.gates.get(gate_name) else {
            return Ok(PolicyDecision::Allow);
        };
        match gate.mode {
            GateMode::Deny => Ok(PolicyDecision::Deny(format!(
                "policy gate '{}' denied for provider '{}'",
                gate_name, provider
            ))),
            GateMode::Prompt => Ok(PolicyDecision::Deny(format!(
                "policy gate '{}' requires confirmation for provider '{}'",
                gate_name, provider
            ))),
            GateMode::Allow => {
                if matches_provider(gate, provider) {
                    Ok(PolicyDecision::Allow)
                } else {
                    Ok(PolicyDecision::Deny(format!(
                        "policy gate '{}' does not allow provider '{}'",
                        gate_name, provider
                    )))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGate {
    pub mode: GateMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<String>,
    #[serde(default)]
    pub audit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

impl PolicyGate {
    pub fn new(mode: GateMode, conditions: Option<String>, audit: bool) -> Self {
        Self {
            mode,
            conditions,
            audit,
            banner: None,
        }
    }
}

impl Default for PolicyGate {
    fn default() -> Self {
        Self {
            mode: GateMode::Prompt,
            conditions: None,
            audit: false,
            banner: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GateMode {
    Allow,
    Deny,
    Prompt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyLogEntry {
    pub version: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub snapshot_jcs: String,
}

fn read_policy(path: &Path) -> Result<PolicyDocument> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let doc: PolicyDocument = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(doc)
}

fn write_policy(path: &Path, document: &PolicyDocument) -> Result<()> {
    let data = serde_json::to_vec_pretty(document)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &data).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to move {} into place", tmp.display()))?;
    Ok(())
}

fn matches_provider(gate: &PolicyGate, provider: &str) -> bool {
    let Some(ref cond) = gate.conditions else {
        return true;
    };
    if cond.trim().is_empty() {
        return true;
    }
    let provider = provider.trim();
    for token in cond.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some(rest) = token.strip_prefix("provider=") {
            for candidate in rest.split('|') {
                let candidate = candidate.trim();
                if candidate == "*" || candidate.eq_ignore_ascii_case(provider) {
                    return true;
                }
            }
        }
    }
    false
}
