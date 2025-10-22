use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use hn_cli::contract::{
    merge_metadata, sanitize_component, timestamp_slug, Consideration, ConsiderationType, Contract,
    ContractParty, ContractRetention, ContractState, Offer,
};
use hn_cli::event::build_contract_event;
use hn_cli::home::{ensure_home_dir, ensure_subdir};
use hn_cli::identity::{IdentityRecord, IdentityVault, IdentityVerificationEntry};
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::policy::PolicyEvaluator;

const OFFERS_DIR: &str = "offers";
const CONTRACTS_DIR: &str = "contracts";
const SHARDS_DIR: &str = "shards";

#[derive(Parser, Debug)]
#[command(
    name = "hn contract",
    version,
    about = "Manage offers and contracts (M3 preview)"
)]
struct Cli {
    #[arg(
        short = 'o',
        long = "output",
        value_enum,
        default_value_t = OutputFormat::Text,
        global = true
    )]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage offer@1 documents owned by the active identity.
    #[command(subcommand)]
    Offer(OfferCommands),

    /// Accept an offer@1 to produce a contract@1 skeleton.
    Accept(AcceptArgs),

    /// Fulfil a reserved contract and emit a shard@1 payload.
    Fulfill(FulfillArgs),

    /// Validate that an offer and contract align (digest, capability, proofs).
    Verify(VerifyArgs),

    /// Revoke a reserved contract prior to fulfilment.
    Revoke(RevokeArgs),

    /// Expire contracts whose offer window elapsed.
    #[command(subcommand)]
    Expire(ExpireCommands),
}

#[derive(Subcommand, Debug)]
enum OfferCommands {
    /// Create a new offer@1 for the active identity.
    Create(OfferCreateArgs),

    /// List stored offers for the active identity (or a specific alias).
    List(OfferListArgs),

    /// Show a stored offer by id.
    Show(OfferShowArgs),
}

#[derive(Args, Debug)]
struct OfferCreateArgs {
    /// Audience DID invited to accept.
    #[arg(long = "audience", value_name = "DID")]
    audience: String,

    /// Doc identifier (e.g. doc:finance-folder@1).
    #[arg(long = "doc", value_name = "DOC", visible_alias = "unit")]
    doc: String,

    /// Capability being granted (read/write/...)
    #[arg(long = "capability", value_name = "CAP")]
    capability: String,

    /// Policy references that must hold during acceptance.
    #[arg(long = "policy-ref", value_name = "NAME", num_args = 0.., action = clap::ArgAction::Append)]
    policy_refs: Vec<String>,

    /// Explicit expiry timestamp (RFC3339). Overrides --ttl-days if provided.
    #[arg(long = "valid-until", value_name = "RFC3339")]
    valid_until: Option<String>,

    /// Validity window in days (default 30) when --valid-until is not supplied.
    #[arg(long = "ttl-days", value_name = "DAYS")]
    ttl_days: Option<i64>,

    /// Archive retention duration in days.
    #[arg(long = "retention-days", value_name = "DAYS")]
    retention_days: Option<i64>,

    /// Override generated offer id.
    #[arg(long = "id", value_name = "ID")]
    id: Option<String>,

    /// Optional consideration note stored as metadata.
    #[arg(long = "consideration-note", value_name = "TEXT")]
    consideration_note: Option<String>,

    /// Select a specific verification provider proof (defaults to most recent).
    #[arg(long = "proof-provider", value_name = "PROVIDER")]
    proof_provider: Option<String>,

    /// Write a copy of the offer to an additional path (besides the vault).
    #[arg(long = "emit", value_name = "PATH")]
    emit_path: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct OfferListArgs {
    /// Alias to inspect (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug)]
struct OfferShowArgs {
    /// Offer id to display.
    #[arg(long = "id", value_name = "ID")]
    id: String,

    /// Alias that owns the offer (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug)]
struct AcceptArgs {
    /// Path to the offer@1 JSON file being accepted.
    #[arg(long = "offer", value_name = "PATH")]
    offer_path: PathBuf,

    /// Override generated contract id.
    #[arg(long = "contract-id", value_name = "ID")]
    contract_id: Option<String>,

    /// Select a specific proof provider (defaults to most recent entry).
    #[arg(long = "proof-provider", value_name = "PROVIDER")]
    proof_provider: Option<String>,

    /// Emit copy of the contract JSON to this path.
    #[arg(long = "emit", value_name = "PATH")]
    emit_path: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct FulfillArgs {
    /// Contract id stored under ~/.human-net/contracts/<alias>/
    #[arg(long = "contract-id", value_name = "ID")]
    contract_id: String,

    /// Path to payload data that will be encrypted and shared.
    #[arg(long = "payload", value_name = "PATH")]
    payload_path: PathBuf,

    /// Emit copy of the updated contract JSON to this path.
    #[arg(long = "emit", value_name = "PATH")]
    emit_path: Option<PathBuf>,

    /// Emit copy of the shard@1 JSON to this path.
    #[arg(long = "emit-shard", value_name = "PATH")]
    emit_shard: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct RevokeArgs {
    /// Contract id to revoke.
    #[arg(long = "contract-id", value_name = "ID")]
    contract_id: String,

    /// Reason recorded in the revocation event metadata.
    #[arg(long = "reason", value_name = "TEXT")]
    reason: Option<String>,
}

#[derive(Subcommand, Debug)]
enum ExpireCommands {
    /// Sweep contracts that have exceeded their validity window.
    Sweep(ExpireSweepArgs),
}

#[derive(Args, Debug)]
struct ExpireSweepArgs {
    /// Alias whose contracts should be evaluated (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// RFC3339 timestamp treated as "now" for expiry comparisons.
    #[arg(long = "before", value_name = "RFC3339")]
    before: Option<String>,

    /// Preview actions without writing updates.
    #[arg(long = "dry-run")]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Path to the offer@1 JSON file.
    #[arg(long = "offer", value_name = "PATH")]
    offer_path: PathBuf,

    /// Path to the contract@1 JSON file.
    #[arg(long = "contract", value_name = "PATH")]
    contract_path: PathBuf,

    /// Vault aliases to search for required proof@1 files (repeatable).
    #[arg(long = "check-proof-alias", value_name = "ALIAS")]
    proof_aliases: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::Offer(cmd) => handle_offer(cmd)?,
        Commands::Accept(args) => handle_accept(args)?,
        Commands::Fulfill(args) => handle_fulfill(args)?,
        Commands::Verify(args) => handle_verify(args)?,
        Commands::Revoke(args) => handle_revoke(args)?,
        Commands::Expire(sub) => match sub {
            ExpireCommands::Sweep(args) => handle_expire_sweep(args)?,
        },
    };
    output.render(cli.output)?;
    Ok(())
}

fn handle_offer(cmd: OfferCommands) -> Result<CommandOutput> {
    match cmd {
        OfferCommands::Create(args) => handle_offer_create(args),
        OfferCommands::List(args) => handle_offer_list(args),
        OfferCommands::Show(args) => handle_offer_show(args),
    }
}

fn handle_offer_create(args: OfferCreateArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
    let record = vault.load_identity(&active.alias)?;
    let proof = select_proof(&record, args.proof_provider.as_deref())?;
    PolicyEvaluator::check_provider_gate(&vault, &active.alias, "offer.create", &proof.provider)?;

    let now = OffsetDateTime::now_utc();
    let valid_until = resolve_valid_until(&args, now)?;
    let policy_refs = unique_sorted(args.policy_refs.clone());

    let consideration = args.consideration_note.as_ref().map(|note| Consideration {
        r#type: ConsiderationType::Custom,
        value: None,
        notes: Some(note.clone()),
    });

    let mut offer = Offer {
        id: args
            .id
            .clone()
            .unwrap_or_else(|| generate_offer_id(&active.alias, &args.doc, now)),
        issuer: record.profile.id.clone(),
        audience: args.audience.clone(),
        doc: args.doc.clone(),
        capability: args.capability.clone(),
        policy_refs,
        valid_from: now,
        valid_until,
        consideration,
        proof_id: proof.proof_id.clone(),
        issuer_hpke_public_key: record.keys.hpke_public_key_base64(),
        terms_digest: String::new(),
        state: Some("PROPOSED".to_string()),
        created_at: Some(now),
        retention_days: args.retention_days,
    };

    offer.terms_digest = offer.compute_terms_digest()?;

    let offers_dir = offer_dir_for(&home, &active.alias)?;
    let offer_path = offers_dir.join(file_name_for(&offer.id));
    write_json(&offer_path, &offer)?;

    if let Some(extra) = args.emit_path {
        write_json(&extra, &offer)?;
    }

    let message = format!(
        "Created offer '{}' for audience '{}' (capability={}, doc={})",
        offer.id, offer.audience, offer.capability, offer.doc
    );

    let payload = json!({
        "command": "offer.create",
        "alias": active.alias,
        "path": offer_path,
        "offer": {
            "id": offer.id,
            "audience": offer.audience,
            "doc": offer.doc,
            "capability": offer.capability,
            "policy_refs": offer.policy_refs,
            "valid_from": offer.valid_from,
            "valid_until": offer.valid_until,
            "proof_id": offer.proof_id,
            "terms_digest": offer.terms_digest,
            "retention_days": offer.retention_days,
        }
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_offer_list(args: OfferListArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = match args.alias {
        Some(alias) => alias,
        None => {
            vault
                .active_identity()?
                .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
                .alias
        }
    };

    let dir = offer_dir_for(&home, &alias)?;
    let mut entries = Vec::new();
    if dir.exists() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            match Offer::from_path(&entry.path()) {
                Ok(offer) => entries.push(offer),
                Err(err) => {
                    eprintln!(
                        "warning: skipping offer at {}: {}",
                        entry.path().display(),
                        err
                    );
                }
            }
        }
    }

    entries.sort_by(|a, b| b.valid_from.cmp(&a.valid_from));

    if entries.is_empty() {
        return Ok(CommandOutput::new(
            format!("No offers stored for alias '{}'", alias),
            json!({
                "command": "offer.list",
                "alias": alias,
                "offers": Vec::<Value>::new(),
            }),
        ));
    }

    let payload = json!({
        "command": "offer.list",
        "alias": alias,
        "offers": entries.iter().map(|offer| json!({
            "id": offer.id,
            "audience": offer.audience,
            "doc": offer.doc,
            "capability": offer.capability,
            "valid_from": offer.valid_from,
            "valid_until": offer.valid_until,
            "proof_id": offer.proof_id,
            "issuer_hpke_public_key": offer.issuer_hpke_public_key,
            "retention_days": offer.retention_days,
        })).collect::<Vec<_>>(),
    });

    Ok(CommandOutput::new(
        format!("{} offer(s) for alias '{}'", entries.len(), alias),
        payload,
    ))
}

fn handle_offer_show(args: OfferShowArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = match args.alias {
        Some(alias) => alias,
        None => {
            vault
                .active_identity()?
                .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
                .alias
        }
    };

    let path = offer_dir_for(&home, &alias)?.join(file_name_for(&args.id));
    if !path.exists() {
        return Err(anyhow!(
            "offer '{}' not found under alias '{}'",
            args.id,
            alias
        ));
    }
    let offer = Offer::from_path(&path)?;

    let payload = json!({
        "command": "offer.show",
        "alias": alias,
        "path": path,
        "offer": offer,
    });

    Ok(CommandOutput::new(
        format!("Offer '{}' for audience '{}'", offer.id, offer.audience),
        payload,
    ))
}

fn handle_accept(args: AcceptArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
    let record = vault.load_identity(&active.alias)?;
    let counterparty_proof = select_proof(&record, args.proof_provider.as_deref())?;
    PolicyEvaluator::check_provider_gate(
        &vault,
        &active.alias,
        "contract.accept",
        &counterparty_proof.provider,
    )?;

    let offer = Offer::from_path(&args.offer_path)?;
    if offer.audience != record.profile.id {
        return Err(anyhow!(
            "offer audience {} does not match active identity {}",
            offer.audience,
            record.profile.id
        ));
    }
    if !offer.digest_matches()? {
        return Err(anyhow!(
            "offer terms_digest does not match canonical digest"
        ));
    }

    let now = OffsetDateTime::now_utc();
    let contract_id = args
        .contract_id
        .clone()
        .unwrap_or_else(|| generate_contract_id(&offer, &active.alias, now));

    let mut metadata = json!({
        "source_offer": offer.id,
        "offer_valid_from": offer.valid_from,
    });
    if let Some(valid_until) = offer.valid_until {
        if let Some(map) = metadata.as_object_mut() {
            map.insert("offer_valid_until".to_string(), json!(valid_until));
        }
    }
    if let Some(days) = offer.retention_days {
        if let Some(map) = metadata.as_object_mut() {
            map.insert("retention_days".to_string(), json!(days));
        }
    }

    let mut contract = Contract {
        id: contract_id.clone(),
        offer_id: offer.id.clone(),
        terms_digest: offer.terms_digest.clone(),
        issuer: ContractParty {
            did: offer.issuer.clone(),
            proof_id: offer.proof_id.clone(),
            hpke_public_key: Some(offer.issuer_hpke_public_key.clone()),
        },
        counterparty: ContractParty {
            did: record.profile.id.clone(),
            proof_id: counterparty_proof.proof_id.clone(),
            hpke_public_key: Some(record.keys.hpke_public_key_base64()),
        },
        capability: offer.capability.clone(),
        doc: offer.doc.clone(),
        state: ContractState::Accepted,
        retention: offer.retention_days.and_then(|days| {
            if days > 0 {
                Some(ContractRetention {
                    archive_after: Some(now + Duration::days(days)),
                    delete_after: None,
                    archived_at: None,
                })
            } else {
                None
            }
        }),
        state_history: Vec::new(),
        encrypted_payload: None,
        metadata,
    };

    let reserve_event = build_contract_event(
        &contract.id,
        1,
        ContractState::Accepted,
        &record.keys,
        &counterparty_proof.proof_id,
        now,
        None,
        None,
    )?;
    contract.state_history.push(reserve_event.to_state_entry());

    let contracts_dir = contract_dir_for(&home, &active.alias)?;
    let contract_path = contracts_dir.join(file_name_for(&contract.id));
    if contract_path.exists() {
        return Err(anyhow!(
            "contract '{}' already exists at {}",
            contract.id,
            contract_path.display()
        ));
    }
    let events_dir = event_dir_for(&home, &active.alias)?;
    let event_path = events_dir.join(file_name_for(&reserve_event.id));

    write_json(&contract_path, &contract)?;
    write_json(&event_path, &reserve_event)?;
    if let Some(extra) = args.emit_path {
        write_json(&extra, &contract)?;
    }

    let message = format!(
        "Accepted offer '{}' -> contract '{}' (state=ACCEPTED)",
        offer.id, contract.id
    );

    let payload = json!({
        "command": "contract.accept",
        "alias": active.alias,
        "offer": offer.id,
        "contract": {
            "id": contract.id,
            "path": contract_path,
            "capability": contract.capability,
            "doc": contract.doc,
            "state": "ACCEPTED",
            "counterparty_proof": counterparty_proof.proof_id,
            "state_event": {
                "id": reserve_event.id,
                "path": event_path,
            }
        }
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_fulfill(args: FulfillArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
    let record = vault.load_identity(&active.alias)?;

    let contracts_dir = contract_dir_for(&home, &active.alias)?;
    let contract_path = contracts_dir.join(file_name_for(&args.contract_id));
    if !contract_path.exists() {
        return Err(anyhow!(
            "contract '{}' not found under alias '{}'",
            args.contract_id,
            active.alias
        ));
    }
    let contract = Contract::from_path(&contract_path)?;
    if contract.issuer.did != record.profile.id {
        return Err(anyhow!(
            "only issuer '{}' may fulfil contract '{}'",
            contract.issuer.did,
            contract.id
        ));
    }

    let payload = fs::read(&args.payload_path)
        .with_context(|| format!("failed to read payload at {}", args.payload_path.display()))?;
    if payload.is_empty() {
        return Err(anyhow!(
            "payload '{}' is empty",
            args.payload_path.display()
        ));
    }

    let timestamp = OffsetDateTime::now_utc();
    let (mut updated_contract, shard) =
        contract.fulfill(&payload, &record.profile.id, timestamp)?;

    let sequence = updated_contract
        .state_history
        .last()
        .and_then(|entry| entry.sequence)
        .unwrap_or(updated_contract.state_history.len() as u32);
    let fulfill_event = build_contract_event(
        &updated_contract.id,
        sequence,
        ContractState::Fulfilled,
        &record.keys,
        &updated_contract.issuer.proof_id,
        timestamp,
        None,
        Some(json!({
            "shard_id": shard.id,
            "payload_cid": shard.payload_cid,
        })),
    )?;
    if let Some(entry) = updated_contract.state_history.last_mut() {
        *entry = fulfill_event.to_state_entry();
    }

    write_json(&contract_path, &updated_contract)?;
    if let Some(extra) = &args.emit_path {
        write_json(extra, &updated_contract)?;
    }

    let shards_dir = shard_dir_for(&home, &active.alias)?;
    let shard_path = shards_dir.join(file_name_for(&shard.id));
    write_json(&shard_path, &shard)?;
    if let Some(extra) = &args.emit_shard {
        write_json(extra, &shard)?;
    }

    let events_dir = event_dir_for(&home, &active.alias)?;
    let event_path = events_dir.join(file_name_for(&fulfill_event.id));
    write_json(&event_path, &fulfill_event)?;

    let message = format!(
        "Fulfilled contract '{}' -> shard '{}' (cid={})",
        updated_contract.id, shard.id, shard.payload_cid
    );

    let payload = json!({
        "command": "contract.fulfill",
        "alias": active.alias,
        "contract": {
            "id": updated_contract.id,
            "path": contract_path,
            "state": "FULFILLED",
            "state_event": {
                "id": fulfill_event.id,
                "path": event_path,
            }
        },
        "shard": {
            "id": shard.id,
            "path": shard_path,
            "payload_cid": shard.payload_cid,
            "algorithm": shard.algorithm,
        }
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_revoke(args: RevokeArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
    let record = vault.load_identity(&active.alias)?;

    let contracts_dir = contract_dir_for(&home, &active.alias)?;
    let contract_path = contracts_dir.join(file_name_for(&args.contract_id));
    if !contract_path.exists() {
        return Err(anyhow!(
            "contract '{}' not found under alias '{}'",
            args.contract_id,
            active.alias
        ));
    }

    let mut contract = Contract::from_path(&contract_path)?;
    if contract.state != ContractState::Accepted {
        return Err(anyhow!(
            "contract '{}' is in state {:?}; only ACCEPTED contracts can be revoked",
            contract.id,
            contract.state
        ));
    }

    let (actor_proof, actor_role) = if record.profile.id == contract.issuer.did {
        (contract.issuer.proof_id.clone(), "issuer")
    } else if record.profile.id == contract.counterparty.did {
        (contract.counterparty.proof_id.clone(), "counterparty")
    } else {
        return Err(anyhow!(
            "active identity '{}' does not participate in contract '{}'",
            record.profile.id,
            contract.id
        ));
    };

    let next_sequence = contract
        .state_history
        .iter()
        .filter_map(|entry| entry.sequence)
        .max()
        .unwrap_or(0)
        + 1;
    let timestamp = OffsetDateTime::now_utc();
    let reason = args.reason.clone();

    let mut event_metadata = json!({
        "actor_role": actor_role,
    });
    if let Some(reason_str) = &reason {
        if let Some(map) = event_metadata.as_object_mut() {
            map.insert("reason".to_string(), json!(reason_str));
        }
    }

    let revoke_event = build_contract_event(
        &contract.id,
        next_sequence,
        ContractState::Revoked,
        &record.keys,
        &actor_proof,
        timestamp,
        reason.clone(),
        Some(event_metadata.clone()),
    )?;

    contract.state = ContractState::Revoked;
    contract.state_history.push(revoke_event.to_state_entry());

    let mut revocation_meta = json!({
        "actor": record.profile.id,
        "actor_role": actor_role,
        "timestamp": timestamp,
    });
    if let Some(reason_str) = &reason {
        if let Some(map) = revocation_meta.as_object_mut() {
            map.insert("reason".to_string(), json!(reason_str));
        }
    }
    contract.metadata = merge_metadata(
        &contract.metadata,
        json!({
            "revocation": revocation_meta,
        }),
    );

    write_json(&contract_path, &contract)?;
    let events_dir = event_dir_for(&home, &active.alias)?;
    let event_path = events_dir.join(file_name_for(&revoke_event.id));
    write_json(&event_path, &revoke_event)?;

    let payload = json!({
        "command": "contract.revoke",
        "alias": active.alias,
        "contract": {
            "id": contract.id,
            "path": contract_path,
            "state": "REVOKED",
            "state_event": {
                "id": revoke_event.id,
                "path": event_path,
            }
        },
        "reason": reason,
    });

    let message = format!(
        "Revoked contract '{}' (event {})",
        contract.id, revoke_event.id
    );

    Ok(CommandOutput::new(message, payload))
}

fn handle_expire_sweep(args: ExpireSweepArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = match args.alias {
        Some(alias) => alias,
        None => {
            vault
                .active_identity()?
                .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?
                .alias
        }
    };
    let record = vault.load_identity(&alias)?;

    let reference_time = if let Some(ref ts) = args.before {
        OffsetDateTime::parse(ts, &Rfc3339)
            .with_context(|| format!("failed to parse --before '{}': expected RFC3339", ts))?
    } else {
        OffsetDateTime::now_utc()
    };

    let contracts_dir = contract_dir_for(&home, &alias)?;
    if !contracts_dir.exists() {
        return Ok(CommandOutput::new(
            format!("No contracts found for alias '{}'", alias),
            json!({
                "command": "contract.expire.sweep",
                "alias": alias,
                "dry_run": args.dry_run,
                "reference_time": reference_time,
                "expired": Vec::<Value>::new(),
                "skipped": Vec::<Value>::new(),
            }),
        ));
    }

    let mut expired = Vec::new();
    let mut skipped = Vec::new();

    for entry in fs::read_dir(&contracts_dir)
        .with_context(|| format!("failed to read {}", contracts_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let mut contract = match Contract::from_path(&path) {
            Ok(contract) => contract,
            Err(err) => {
                skipped.push(json!({
                    "path": path,
                    "error": err.to_string(),
                }));
                continue;
            }
        };

        if contract.state != ContractState::Accepted && contract.state != ContractState::Proposed {
            continue;
        }

        let Some(valid_until) = contract_valid_until(&contract) else {
            continue;
        };
        if valid_until > reference_time {
            continue;
        }

        let (actor_proof, actor_role) = if record.profile.id == contract.issuer.did {
            (contract.issuer.proof_id.clone(), "issuer")
        } else if record.profile.id == contract.counterparty.did {
            (contract.counterparty.proof_id.clone(), "counterparty")
        } else {
            skipped.push(json!({
                "contract": contract.id,
                "path": path,
                "reason": "identity not a participant",
            }));
            continue;
        };

        let next_sequence = contract
            .state_history
            .iter()
            .filter_map(|entry| entry.sequence)
            .max()
            .unwrap_or(0)
            + 1;

        let reason = format!("offer validity window elapsed ({})", valid_until);
        let event_metadata = json!({
            "actor_role": actor_role,
            "valid_until": valid_until,
        });
        let expire_event = build_contract_event(
            &contract.id,
            next_sequence,
            ContractState::Expired,
            &record.keys,
            &actor_proof,
            reference_time,
            Some(reason.clone()),
            Some(event_metadata.clone()),
        )?;

        let mut expiry_meta = json!({
            "actor": record.profile.id,
            "actor_role": actor_role,
            "timestamp": reference_time,
            "valid_until": valid_until,
        });

        let mut event_path_value = Value::Null;

        if !args.dry_run {
            contract.state = ContractState::Expired;
            contract.state_history.push(expire_event.to_state_entry());
            if let Some(map) = expiry_meta.as_object_mut() {
                map.insert("reason".to_string(), json!(reason.clone()));
            }
            contract.metadata = merge_metadata(
                &contract.metadata,
                json!({
                    "expiry": expiry_meta,
                }),
            );
            write_json(&path, &contract)?;
            let events_dir = event_dir_for(&home, &alias)?;
            let event_path = events_dir.join(file_name_for(&expire_event.id));
            write_json(&event_path, &expire_event)?;
            event_path_value = json!(event_path);
        }

        expired.push(json!({
            "contract": contract.id,
            "path": path,
            "dry_run": args.dry_run,
            "state_event": {
                "id": expire_event.id,
                "path": event_path_value,
            },
            "reason": reason,
        }));
    }

    let message = if expired.is_empty() {
        format!(
            "No contracts required expiry for alias '{}' (checked up to {})",
            alias, reference_time
        )
    } else if args.dry_run {
        format!(
            "{} contract(s) would be marked EXPIRED for alias '{}'",
            expired.len(),
            alias
        )
    } else {
        format!(
            "Marked {} contract(s) as EXPIRED for alias '{}'",
            expired.len(),
            alias
        )
    };

    let payload = json!({
        "command": "contract.expire.sweep",
        "alias": alias,
        "dry_run": args.dry_run,
        "reference_time": reference_time,
        "expired": expired,
        "skipped": skipped,
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_verify(args: VerifyArgs) -> Result<CommandOutput> {
    let offer = Offer::from_path(&args.offer_path)?;
    let contract = Contract::from_path(&args.contract_path)?;

    let computed_digest = offer.compute_terms_digest()?;
    let legacy_digest = offer.compute_legacy_terms_digest().ok();
    let digest_match = offer.digest_matches()?;
    let contract_report = contract.verify_against(&offer);

    let proofs_required: HashSet<&str> = [offer.proof_id.as_str()]
        .into_iter()
        .chain(contract.required_proof_ids().into_iter())
        .collect();

    let mut proof_results: HashMap<String, Vec<String>> = HashMap::new();
    let mut alias_levels: HashMap<String, u8> = HashMap::new();
    let mut proof_errors = Vec::new();
    if !args.proof_aliases.is_empty() {
        let home = ensure_home_dir()?;
        let vault = IdentityVault::new(home)?;
        for alias in &args.proof_aliases {
            if !vault.alias_exists(alias)? {
                proof_errors.push(format!("identity alias '{}' not found", alias));
                continue;
            }
            let record = vault.load_identity(alias)?;
            alias_levels.insert(alias.clone(), identity_level(&record));
            let proofs = vault.list_proofs_for(alias)?;
            for proof in proofs {
                if proofs_required.contains(proof.id.as_str()) {
                    proof_results
                        .entry(proof.id.clone())
                        .or_insert_with(Vec::new)
                        .push(alias.clone());
                }
            }
        }
    }

    let unresolved_proofs: Vec<&str> = proofs_required
        .iter()
        .copied()
        .filter(|id| !proof_results.keys().any(|key| key == *id))
        .collect();

    let mut proof_status = Vec::new();
    let mut sorted_proofs: Vec<&str> = proofs_required.iter().copied().collect();
    sorted_proofs.sort_unstable();
    for proof_id in sorted_proofs {
        let aliases = proof_results.get(proof_id).cloned().unwrap_or_default();
        let resolved = !aliases.is_empty();
        let mut level_map = serde_json::Map::new();
        for alias in &aliases {
            if let Some(level) = alias_levels.get(alias) {
                level_map.insert(alias.clone(), json!(level));
            }
        }
        proof_status.push(json!({
            "proof_id": proof_id,
            "resolved": resolved,
            "aliases": aliases,
            "alias_levels": level_map,
            "expected_level": 2,
        }));
    }

    let proof_check_passed = if args.proof_aliases.is_empty() {
        proof_errors.is_empty()
    } else {
        proof_errors.is_empty()
            && proof_status
                .iter()
                .all(|entry| entry["resolved"].as_bool().unwrap_or(false))
    };

    let success = contract_report.success() && digest_match && proof_check_passed;

    let mut message = if success {
        format!(
            "Contract '{}' matches offer '{}' (capability={}, doc={}, state={:?})",
            contract.id, offer.id, contract.capability, contract.doc, contract.state
        )
    } else {
        format!(
            "Contract '{}' verification found issues (offer '{}')",
            contract.id, offer.id
        )
    };
    if !alias_levels.is_empty() {
        let mut parts: Vec<_> = alias_levels.iter().collect();
        parts.sort_by(|a, b| a.0.cmp(b.0));
        let summary = parts
            .into_iter()
            .map(|(alias, level)| format!("{alias}:id.level={level}"))
            .collect::<Vec<_>>()
            .join(", ");
        if !summary.is_empty() {
            message.push_str(" [");
            message.push_str(&summary);
            message.push(']');
        }
    }

    let payload = json!({
        "command": "contract.verify",
        "offer": {
            "id": offer.id,
            "digest_matches": digest_match,
            "terms_digest": offer.terms_digest,
            "computed_digest": computed_digest,
            "legacy_digest": legacy_digest,
            "doc": offer.doc,
        },
        "contract": {
            "id": contract.id,
            "state": format!("{:?}", contract.state),
            "doc": contract.doc,
            "capability": contract.capability,
            "report": contract_report.to_value(),
        },
        "proofs": {
            "aliases": args.proof_aliases,
            "resolved": proof_results,
            "unresolved": unresolved_proofs,
            "errors": proof_errors,
            "status": proof_status,
            "id_levels": alias_levels,
        },
        "success": success,
    });

    Ok(CommandOutput::new(message, payload))
}

fn select_proof<'a>(
    record: &'a IdentityRecord,
    provider: Option<&str>,
) -> Result<&'a IdentityVerificationEntry> {
    let ledger = &record.profile.verification;
    if ledger.entries.is_empty() {
        return Err(anyhow!(
            "identity '{}' has no verification entries; run `hn id verify` first",
            record.profile.alias
        ));
    }
    if let Some(provider) = provider {
        ledger
            .entries
            .iter()
            .find(|entry| entry.provider.eq_ignore_ascii_case(provider))
            .ok_or_else(|| anyhow!("no verification entry for provider '{}'", provider))
    } else {
        ledger
            .entries
            .iter()
            .max_by_key(|entry| entry.verified_at)
            .ok_or_else(|| anyhow!("unable to select verification entry"))
    }
}

fn identity_level(record: &IdentityRecord) -> u8 {
    if record.profile.verification.entries.is_empty() {
        1
    } else {
        2
    }
}

fn resolve_valid_until(
    args: &OfferCreateArgs,
    now: OffsetDateTime,
) -> Result<Option<OffsetDateTime>> {
    if let Some(ref ts) = args.valid_until {
        let parsed = OffsetDateTime::parse(ts, &Rfc3339)
            .with_context(|| format!("failed to parse --valid-until '{}': expected RFC3339", ts))?;
        Ok(Some(parsed))
    } else {
        let days = args.ttl_days.unwrap_or(30);
        if days <= 0 {
            return Ok(None);
        }
        Ok(Some(now + Duration::days(days)))
    }
}

fn generate_offer_id(alias: &str, doc: &str, now: OffsetDateTime) -> String {
    let slug = sanitize_component(doc);
    format!("offer:{alias}:{slug}:{}", timestamp_slug(now))
}

fn generate_contract_id(offer: &Offer, counterparty_alias: &str, now: OffsetDateTime) -> String {
    let doc_slug = sanitize_component(&offer.doc);
    let issuer_slug = sanitize_component(&offer.issuer);
    let counter_slug = sanitize_component(counterparty_alias);
    format!(
        "contract:{issuer_slug}:{counter_slug}:{doc_slug}:{}",
        timestamp_slug(now)
    )
}

fn unique_sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort_unstable();
    values.dedup();
    values
}

fn offer_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let offers_root = ensure_subdir(home, OFFERS_DIR)?;
    ensure_subdir(&offers_root, alias)
}

fn contract_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let contracts_root = ensure_subdir(home, CONTRACTS_DIR)?;
    ensure_subdir(&contracts_root, alias)
}

fn shard_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let shards_root = ensure_subdir(home, SHARDS_DIR)?;
    ensure_subdir(&shards_root, alias)
}

fn event_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let events_root = ensure_subdir(home, "events")?;
    ensure_subdir(&events_root, alias)
}

fn file_name_for(id: &str) -> String {
    format!("{}.json", id.replace([':', '/', ' '], "_"))
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn contract_valid_until(contract: &Contract) -> Option<OffsetDateTime> {
    contract
        .metadata
        .as_object()
        .and_then(|obj| obj.get("offer_valid_until"))
        .and_then(|value| serde_json::from_value::<OffsetDateTime>(value.clone()).ok())
}
