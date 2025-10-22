use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use hn_cli::contract::{merge_metadata, Contract, ShardEnvelope};
use hn_cli::doc::{DocStore, StoredDoc};
use hn_cli::event::ContractEvent;
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::shard::{
    compute_merkle_root, create_index, create_receipt, ShardIndex, ShardIndexEntry, ShardReceipt,
};

#[derive(Parser, Debug)]
#[command(name = "hn shard", version, about = "Inspect local shard@1 payloads")]
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
    /// List shard@1 files stored for an identity.
    List(ListArgs),

    /// Show the contents of a stored shard@1 file.
    Show(ShowArgs),

    /// Import a shard file and optionally decrypt it.
    Fetch(FetchArgs),

    /// Publish local contracts/events/shards into a shareable directory.
    Publish(PublishArgs),

    /// Subscribe to a published directory and import new shards automatically.
    Subscribe(SubscribeArgs),

    /// Verify a published shard index (and optional receipts).
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Alias to inspect (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug)]
struct ShowArgs {
    /// Shard id to display.
    #[arg(long = "id", value_name = "ID")]
    id: String,

    /// Alias that owns the shard (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug)]
struct FetchArgs {
    /// Path to the shard@1 JSON file to import.
    #[arg(long = "from", value_name = "PATH")]
    from: PathBuf,

    /// Alias that should own the imported shard (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Decrypt the shard payload to this file using the alias' HPKE secret.
    #[arg(long = "decrypt-out", value_name = "PATH")]
    decrypt_out: Option<PathBuf>,

    /// Optional event@1 file that accompanied the shard transfer.
    #[arg(long = "event", value_name = "PATH")]
    event: Option<PathBuf>,

    /// Skip automatic doc import (stores shard only).
    #[arg(long = "no-import")]
    no_import: bool,
}

struct ShardImportOutcome {
    message: String,
    payload: Value,
}

struct SubscriptionBatch {
    events: Vec<Value>,
    contracts: Vec<Value>,
    shards: Vec<Value>,
    shard_messages: Vec<String>,
    index: Option<Value>,
}

#[derive(Args, Debug)]
struct PublishArgs {
    /// Destination directory where shard bundles will be written.
    #[arg(long = "target", value_name = "PATH")]
    target: PathBuf,

    /// Alias to publish (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug)]
struct SubscribeArgs {
    /// Source directory published by a peer.
    #[arg(long = "source", value_name = "PATH")]
    source: PathBuf,

    /// Alias that should import the published data (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Continuously poll the source for new shards.
    #[arg(long = "watch")]
    watch: bool,

    /// Number of polling iterations when --watch is used (default 1).
    #[arg(long = "iterations", default_value_t = 1)]
    iterations: usize,

    /// Seconds to sleep between polling iterations.
    #[arg(long = "interval-seconds", default_value_t = 5)]
    interval_seconds: u64,

    /// Skip automatic doc import for incoming shards.
    #[arg(long = "no-import")]
    no_import: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Source directory containing index.json and artefacts.
    #[arg(long = "source", value_name = "PATH")]
    source: PathBuf,

    /// Alias whose receipts should be verified (uses ~/.human-net/receipts/<alias>/).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Explicit receipts directory to verify (overrides --alias).
    #[arg(long = "receipts", value_name = "PATH")]
    receipts: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::List(args) => handle_list(args)?,
        Commands::Show(args) => handle_show(args)?,
        Commands::Fetch(args) => handle_fetch(args)?,
        Commands::Publish(args) => handle_publish(args)?,
        Commands::Subscribe(args) => handle_subscribe(args)?,
        Commands::Verify(args) => handle_verify(args)?,
    };
    output.render(cli.output)?;
    Ok(())
}

fn handle_list(args: ListArgs) -> Result<CommandOutput> {
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

    let dir = shard_dir_for(&home, &alias)?;
    let mut entries = Vec::new();
    if dir.exists() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            match read_shard(&entry.path()) {
                Ok(shard) => entries.push(shard),
                Err(err) => eprintln!(
                    "warning: skipping shard at {}: {}",
                    entry.path().display(),
                    err
                ),
            }
        }
    }

    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let message = if entries.is_empty() {
        format!("No shards stored for alias '{}'", alias)
    } else {
        format!("{} shard(s) for alias '{}'", entries.len(), alias)
    };

    let payload = json!({
        "command": "shard.list",
        "alias": alias,
        "shards": entries
            .iter()
            .map(|shard| json!({
                "id": shard.id,
                "contract_id": shard.contract_id,
                "created_at": shard.created_at,
                "payload_cid": shard.payload_cid,
                "algorithm": shard.algorithm,
            }))
            .collect::<Vec<_>>(),
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_show(args: ShowArgs) -> Result<CommandOutput> {
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

    let path = shard_dir_for(&home, &alias)?.join(file_name_for(&args.id));
    if !path.exists() {
        return Err(anyhow!(
            "shard '{}' not found for alias '{}'",
            args.id,
            alias
        ));
    }
    let shard = read_shard(&path)?;

    let payload = json!({
        "command": "shard.show",
        "alias": alias,
        "path": path,
        "shard": shard,
    });

    Ok(CommandOutput::new(
        format!("Shard '{}' (contract '{}')", args.id, shard.contract_id),
        payload,
    ))
}

fn read_shard(path: &Path) -> Result<ShardEnvelope> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read shard file {}", path.display()))?;
    let shard: ShardEnvelope = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse shard JSON {}", path.display()))?;
    Ok(shard)
}

fn handle_fetch(args: FetchArgs) -> Result<CommandOutput> {
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
    let outcome = import_shard_into_vault(
        &vault,
        &home,
        &alias,
        &args.from,
        args.event.as_deref(),
        args.decrypt_out.as_deref(),
        args.no_import,
        None,
    )?;

    Ok(CommandOutput::new(outcome.message, outcome.payload))
}

fn import_shard_into_vault(
    vault: &IdentityVault,
    home: &Path,
    alias: &str,
    src: &Path,
    event_path: Option<&Path>,
    decrypt_out: Option<&Path>,
    no_import: bool,
    index: Option<&ShardIndex>,
) -> Result<ShardImportOutcome> {
    let shard = read_shard(src)?;
    let dir = shard_dir_for(home, alias)?;
    let shard_path = dir.join(file_name_for(&shard.id));
    write_json(&shard_path, &shard)?;

    let record = vault.load_identity(alias)?;
    let subscriber_did = record.profile.id.clone();
    let signing_key = record.keys.signing_key();
    let secret = record.keys.hpke_static_secret();
    let plaintext = shard.decrypt(&secret, &shard.contract_id)?;

    let mut decrypted_path: Option<String> = None;
    if let Some(out) = decrypt_out {
        fs::write(out, &plaintext)
            .with_context(|| format!("failed to write decrypted payload to {}", out.display()))?;
        decrypted_path = Some(out.display().to_string());
    }

    let contracts_dir = contract_dir_for(home, alias)?;
    let contract_path = contracts_dir.join(file_name_for(&shard.contract_id));
    let mut warnings: Vec<String> = Vec::new();
    let mut contract = if contract_path.exists() {
        match Contract::from_path(&contract_path) {
            Ok(contract) => Some(contract),
            Err(err) => {
                warnings.push(format!(
                    "failed to load contract {}: {}",
                    contract_path.display(),
                    err
                ));
                None
            }
        }
    } else {
        None
    };

    let mut doc_result: Option<Value> = None;
    if !no_import {
        match serde_json::from_slice::<Value>(&plaintext) {
            Ok(doc_value) => {
                let doc_type = infer_doc_type(contract.as_ref(), &doc_value)?;
                let doc_id = doc_value
                    .get("id")
                    .and_then(|value| value.as_str())
                    .map(|s| s.to_string());
                let store = DocStore::for_alias(vault, alias)?;
                let stored: StoredDoc = store.store(&doc_type, doc_value, doc_id)?;
                doc_result = Some(json!({
                    "doc_id": stored.id,
                    "doc_type": stored.doc_type,
                    "location": stored.location,
                }));
                if let Some(contract_ref) = contract.as_mut() {
                    contract_ref.metadata = merge_metadata(
                        &contract_ref.metadata,
                        json!({
                            "receiver": {
                                "alias": alias,
                                "imported_doc_id": stored.id,
                            }
                        }),
                    );
                }
            }
            Err(err) => warnings.push(format!(
                "payload could not be parsed as JSON for doc import: {}",
                err
            )),
        }
    }

    let mut event_info: Option<Value> = None;
    if let Some(path) = event_path {
        let event = read_event(path)?;
        if event.contract_id != shard.contract_id {
            return Err(anyhow!(
                "event '{}' does not match shard contract '{}'",
                event.id,
                shard.contract_id
            ));
        }
        let events_dir = event_dir_for(home, alias)?;
        let local_event_path = events_dir.join(file_name_for(&event.id));
        write_json(&local_event_path, &event)?;
        if let Some(contract_ref) = contract.as_mut() {
            if !contract_ref
                .state_history
                .iter()
                .any(|entry| entry.event_id.as_deref() == Some(&event.id))
            {
                contract_ref.state = event.state.clone();
                contract_ref.state_history.push(event.to_state_entry());
                contract_ref
                    .state_history
                    .sort_by(|a, b| match (a.sequence, b.sequence) {
                        (Some(sa), Some(sb)) => sa.cmp(&sb),
                        _ => a.timestamp.cmp(&b.timestamp),
                    });
                for (idx, entry) in contract_ref.state_history.iter_mut().enumerate() {
                    if entry.sequence.is_none() {
                        entry.sequence = Some((idx + 1) as u32);
                    }
                }
            }
        } else {
            warnings.push(format!(
                "received event '{}' but local contract '{}' is missing",
                event.id, event.contract_id
            ));
        }
        event_info = Some(json!({
            "id": event.id,
            "path": local_event_path,
            "state": event.state.as_str(),
        }));
    }

    let mut contract_info: Option<Value> = None;
    if let Some(contract_ref) = contract.as_mut() {
        write_json(&contract_path, contract_ref)?;
        contract_info = Some(json!({
            "id": contract_ref.id,
            "path": contract_path,
            "state": contract_ref.state.as_str(),
        }));
    }

    let mut receipt_info: Option<Value> = None;
    if let Some(index) = index {
        let receipt_timestamp = OffsetDateTime::now_utc();
        match create_receipt(
            &shard,
            index,
            &subscriber_did,
            signing_key,
            receipt_timestamp,
        ) {
            Ok(receipt) => {
                let receipts_dir = receipt_dir_for(home, alias)?;
                let receipt_path = receipts_dir.join(file_name_for(&receipt.id));
                write_json(&receipt_path, &receipt)?;
                receipt_info = Some(json!({
                    "id": receipt.id,
                    "path": receipt_path,
                    "canonical_hash": receipt.canonical_hash,
                }));
            }
            Err(err) => warnings.push(format!("failed to create receipt@1: {}", err)),
        }
    }

    let payload = json!({
        "command": "shard.fetch",
        "alias": alias,
        "imported_from": src,
        "stored_at": shard_path,
        "decrypted_to": decrypted_path,
        "shard": {
            "id": shard.id,
            "contract_id": shard.contract_id,
            "payload_cid": shard.payload_cid,
            "algorithm": shard.algorithm,
        },
        "doc": doc_result,
        "event": event_info,
        "contract": contract_info,
        "receipt": receipt_info,
        "warnings": warnings,
    });

    let message = if let Some(doc) = payload.get("doc").and_then(|v| v.as_object()) {
        if let Some(doc_id) = doc.get("doc_id").and_then(|v| v.as_str()) {
            format!(
                "Imported shard '{}' for alias '{}' and materialised doc '{}'",
                shard.id, alias, doc_id
            )
        } else {
            format!("Imported shard '{}' for alias '{}'", shard.id, alias)
        }
    } else {
        format!("Imported shard '{}' for alias '{}'", shard.id, alias)
    };

    Ok(ShardImportOutcome { message, payload })
}

fn handle_publish(args: PublishArgs) -> Result<CommandOutput> {
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
    let publisher_did = record.profile.id.clone();
    let signing_key = record.keys.signing_key();
    let generated_at = OffsetDateTime::now_utc();

    let target = args.target;
    fs::create_dir_all(&target)
        .with_context(|| format!("failed to create publish target {}", target.display()))?;

    let shards_dir = shard_dir_for(&home, &alias)?;
    let events_dir = event_dir_for(&home, &alias)?;
    let contracts_dir = contract_dir_for(&home, &alias)?;

    let target_shards = target.join("shards");
    let target_events = target.join("events");
    let target_contracts = target.join("contracts");
    fs::create_dir_all(&target_shards)?;
    fs::create_dir_all(&target_events)?;
    fs::create_dir_all(&target_contracts)?;

    let mut index_entries = Vec::new();
    let mut shard_count = 0usize;
    let mut event_count = 0usize;
    let mut contract_count = 0usize;
    let mut event_by_shard: HashMap<String, String> = HashMap::new();

    if events_dir.exists() {
        for entry in fs::read_dir(&events_dir)
            .with_context(|| format!("failed to read events dir {}", events_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let event = read_event(&entry.path())?;
            let file_name = entry.file_name();
            let target_path = target_events.join(&file_name);
            let digest = compute_file_digest(&entry.path())?;
            fs::copy(&entry.path(), &target_path).with_context(|| {
                format!(
                    "failed to copy event {} -> {}",
                    entry.path().display(),
                    target_path.display()
                )
            })?;
            if let Some(meta) = event.metadata.as_ref() {
                if let Some(shard_id) = meta.get("shard_id").and_then(|v| v.as_str()) {
                    event_by_shard.insert(shard_id.to_string(), event.id.clone());
                }
            }
            index_entries.push(ShardIndexEntry {
                kind: "event".to_string(),
                id: event.id.clone(),
                path: format!("events/{}", file_name.to_string_lossy()),
                digest,
                metadata: Some(json!({
                    "state": event.state.as_str(),
                    "contract_id": event.contract_id,
                })),
            });
            event_count += 1;
        }
    }

    if contracts_dir.exists() {
        for entry in fs::read_dir(&contracts_dir)
            .with_context(|| format!("failed to read contracts dir {}", contracts_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let contract = Contract::from_path(&entry.path())?;
            let file_name = entry.file_name();
            let target_path = target_contracts.join(&file_name);
            let digest = compute_file_digest(&entry.path())?;
            fs::copy(&entry.path(), &target_path).with_context(|| {
                format!(
                    "failed to copy contract {} -> {}",
                    entry.path().display(),
                    target_path.display()
                )
            })?;
            index_entries.push(ShardIndexEntry {
                kind: "contract".to_string(),
                id: contract.id.clone(),
                path: format!("contracts/{}", file_name.to_string_lossy()),
                digest,
                metadata: Some(json!({
                    "state": contract.state.as_str(),
                    "doc": contract.doc,
                })),
            });
            contract_count += 1;
        }
    }

    if shards_dir.exists() {
        for entry in fs::read_dir(&shards_dir)
            .with_context(|| format!("failed to read shards dir {}", shards_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let shard = read_shard(&entry.path())?;
            let file_name = entry.file_name();
            let target_path = target_shards.join(&file_name);
            let digest = compute_file_digest(&entry.path())?;
            fs::copy(&entry.path(), &target_path).with_context(|| {
                format!(
                    "failed to copy shard {} -> {}",
                    entry.path().display(),
                    target_path.display()
                )
            })?;
            let event_id = event_by_shard.get(&shard.id).cloned();
            let metadata = json!({
                "contract_id": shard.contract_id,
                "payload_cid": shard.payload_cid,
                "event_id": event_id,
            });
            index_entries.push(ShardIndexEntry {
                kind: "shard".to_string(),
                id: shard.id.clone(),
                path: format!("shards/{}", file_name.to_string_lossy()),
                digest,
                metadata: Some(metadata),
            });
            shard_count += 1;
        }
    }

    index_entries.sort_by(|a, b| a.id.cmp(&b.id));
    let index = create_index(&publisher_did, signing_key, generated_at, index_entries)?;
    index.verify_signature()?;
    write_json(&target.join("index.json"), &index)?;

    let message = format!(
        "Published {} shard(s), {} contract(s), {} event(s) for alias '{}' (index={}, merkle={})",
        shard_count, contract_count, event_count, alias, index.id, index.merkle_root
    );
    let payload = json!({
        "command": "shard.publish",
        "alias": alias,
        "publisher_did": publisher_did,
        "target": target,
        "counts": {
            "shards": shard_count,
            "contracts": contract_count,
            "events": event_count,
        },
        "index": {
            "id": index.id,
            "generated_at": index.generated_at,
            "merkle_root": index.merkle_root,
            "canonical_hash": index.canonical_hash,
        }
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_subscribe(args: SubscribeArgs) -> Result<CommandOutput> {
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

    let iterations = if args.watch { args.iterations } else { 1 };
    if args.watch && iterations == 0 {
        return Err(anyhow!("--iterations must be >= 1 when --watch is enabled"));
    }

    let mut seen = load_seen(&home, &alias)?;
    let mut all_events = Vec::new();
    let mut all_contracts = Vec::new();
    let mut all_shards = Vec::new();
    let mut shard_messages = Vec::new();
    let mut index_summaries = Vec::new();

    for iteration in 0..iterations {
        let batch = process_subscription_iteration(
            &vault,
            &home,
            &alias,
            &args.source,
            args.no_import,
            &mut seen,
        )?;
        shard_messages.extend(batch.shard_messages.iter().cloned());
        all_events.extend(batch.events);
        all_contracts.extend(batch.contracts);
        all_shards.extend(batch.shards);
        if let Some(summary) = batch.index {
            index_summaries.push(summary);
        }

        if !args.watch {
            break;
        }
        if iteration + 1 < iterations {
            sleep(Duration::from_secs(args.interval_seconds));
        }
    }

    save_seen(&home, &alias, &seen)?;

    let message = if all_shards.is_empty() && all_events.is_empty() && all_contracts.is_empty() {
        format!("No new artefacts discovered for alias '{}'", alias)
    } else {
        format!(
            "Imported {} shard(s), {} contract(s), {} event(s) for alias '{}'",
            all_shards.len(),
            all_contracts.len(),
            all_events.len(),
            alias
        )
    };

    let payload = json!({
        "command": "shard.subscribe",
        "alias": alias,
        "source": args.source,
        "processed": {
            "shards": all_shards,
            "contracts": all_contracts,
            "events": all_events,
        },
        "messages": shard_messages,
        "index": index_summaries,
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_verify(args: VerifyArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let source = args.source;
    let index_path = source.join("index.json");
    if !index_path.exists() {
        return Err(anyhow!("index file not found at {}", index_path.display()));
    }

    let index_text = fs::read_to_string(&index_path)
        .with_context(|| format!("failed to read index at {}", index_path.display()))?;
    let index: ShardIndex = serde_json::from_str(&index_text)
        .with_context(|| format!("failed to parse index at {}", index_path.display()))?;
    index.verify_signature()?;

    let mut entry_results = Vec::new();
    let mut computed_digests = Vec::new();
    let mut warnings = Vec::new();

    for entry in &index.entries {
        let source_path = source.join(&entry.path);
        let path_str = source_path.display().to_string();
        if !source_path.exists() {
            warnings.push(format!(
                "artifact missing for entry '{}' ({})",
                entry.id, path_str
            ));
            entry_results.push(json!({
                "id": entry.id,
                "type": entry.kind,
                "path": path_str,
                "exists": false,
                "digest_ok": false,
                "expected_digest": entry.digest,
                "computed_digest": Value::Null,
            }));
            computed_digests.push(None);
            continue;
        }
        let computed = compute_file_digest(&source_path)?;
        let digest_ok = computed == entry.digest;
        if !digest_ok {
            warnings.push(format!(
                "digest mismatch for entry '{}' (expected {}, computed {})",
                entry.id, entry.digest, computed
            ));
        }
        entry_results.push(json!({
            "id": entry.id,
            "type": entry.kind,
            "path": path_str,
            "exists": true,
            "digest_ok": digest_ok,
            "expected_digest": entry.digest,
            "computed_digest": computed,
        }));
        computed_digests.push(Some(computed));
    }

    let mut merkle_ok = false;
    if computed_digests.iter().all(|item| item.is_some()) {
        let actual_root = compute_merkle_root(
            &computed_digests
                .iter()
                .map(|item| item.clone().unwrap())
                .collect::<Vec<_>>(),
        );
        merkle_ok = actual_root == index.merkle_root;
        if !merkle_ok {
            warnings.push(format!(
                "merkle root mismatch (expected {}, computed {})",
                index.merkle_root, actual_root
            ));
        }
    }

    let mut receipts_path = args.receipts.clone();
    if receipts_path.is_none() {
        if let Some(alias) = &args.alias {
            receipts_path = Some(home.join("receipts").join(alias));
        }
    }

    let mut receipt_results = Vec::new();
    if let Some(path) = receipts_path.as_ref() {
        if path.exists() {
            for entry in fs::read_dir(path)
                .with_context(|| format!("failed to read receipts dir {}", path.display()))?
            {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let data = fs::read_to_string(entry.path()).with_context(|| {
                    format!("failed to read receipt {}", entry.path().display())
                })?;
                let receipt: ShardReceipt = serde_json::from_str(&data).with_context(|| {
                    format!("failed to parse receipt {}", entry.path().display())
                })?;
                let mut valid = true;
                if receipt.index_id != index.id {
                    warnings.push(format!(
                        "receipt '{}' references index '{}' (expected '{}')",
                        receipt.id, receipt.index_id, index.id
                    ));
                    valid = false;
                }
                if receipt.merkle_root != index.merkle_root {
                    warnings.push(format!("receipt '{}' merkle root mismatch", receipt.id));
                    valid = false;
                }
                if let Err(err) = receipt.verify_signature() {
                    warnings.push(format!(
                        "receipt '{}' signature invalid: {}",
                        receipt.id, err
                    ));
                    valid = false;
                }
                receipt_results.push(json!({
                    "id": receipt.id,
                    "path": entry.path().display().to_string(),
                    "index_id": receipt.index_id,
                    "valid": valid,
                }));
            }
        } else {
            warnings.push(format!("receipts directory '{}' not found", path.display()));
        }
    }

    let digest_failures = entry_results
        .iter()
        .filter(|value| value["digest_ok"].as_bool() == Some(false))
        .count();
    let receipt_failures = receipt_results
        .iter()
        .filter(|value| value["valid"].as_bool() == Some(false))
        .count();
    let success = digest_failures == 0 && receipt_failures == 0 && warnings.is_empty();

    let message = if success {
        format!("Shard index '{}' verified", index.id)
    } else {
        format!(
            "Shard index '{}' verification yielded {} digest issue(s) and {} receipt issue(s)",
            index.id, digest_failures, receipt_failures
        )
    };

    let payload = json!({
        "command": "shard.verify",
        "source": source,
        "index": {
            "id": index.id,
            "publisher": index.publisher,
            "generated_at": index.generated_at,
            "merkle_root": index.merkle_root,
            "canonical_hash": index.canonical_hash,
            "signature_valid": true,
            "merkle_valid": merkle_ok,
        },
        "entries": entry_results,
        "receipts_path": receipts_path.map(|p| p.display().to_string()),
        "receipts": receipt_results,
        "warnings": warnings,
        "success": success,
    });

    Ok(CommandOutput::new(message, payload))
}

fn process_subscription_iteration(
    vault: &IdentityVault,
    home: &Path,
    alias: &str,
    source: &Path,
    no_import: bool,
    seen: &mut HashSet<String>,
) -> Result<SubscriptionBatch> {
    let index_path = source.join("index.json");
    if !index_path.exists() {
        return Err(anyhow!(
            "publish index not found at {}; run `hn shard publish` on the peer first",
            index_path.display()
        ));
    }
    let index_text = fs::read_to_string(&index_path)
        .with_context(|| format!("failed to read index at {}", index_path.display()))?;
    let index: ShardIndex = serde_json::from_str(&index_text)
        .with_context(|| format!("failed to parse index at {}", index_path.display()))?;
    index.verify_signature()?;
    let recomputed_root = compute_merkle_root(
        &index
            .entries
            .iter()
            .map(|entry| entry.digest.clone())
            .collect::<Vec<_>>(),
    );
    if recomputed_root != index.merkle_root {
        return Err(anyhow!(
            "shard index merkle root mismatch (expected {}, computed {})",
            index.merkle_root,
            recomputed_root
        ));
    }

    let events_dir = event_dir_for(home, alias)?;
    let contracts_dir = contract_dir_for(home, alias)?;
    let _ = shard_dir_for(home, alias)?;

    let mut event_path_map: HashMap<String, PathBuf> = HashMap::new();
    let mut new_events = Vec::new();
    let mut new_contracts = Vec::new();
    let mut new_shards = Vec::new();
    let mut shard_messages = Vec::new();

    for entry in index
        .entries
        .iter()
        .filter(|entry| entry.kind.eq_ignore_ascii_case("event"))
    {
        let source_path = source.join(&entry.path);
        let digest = compute_file_digest(&source_path)?;
        if digest != entry.digest {
            return Err(anyhow!(
                "event '{}' digest mismatch (expected {}, computed {})",
                entry.id,
                entry.digest,
                digest
            ));
        }
        let event = read_event(&source_path)?;
        if event.id != entry.id {
            return Err(anyhow!(
                "event id mismatch (index={}, file={})",
                entry.id,
                event.id
            ));
        }
        let file_name = Path::new(&entry.path)
            .file_name()
            .ok_or_else(|| anyhow!("invalid event path '{}'", entry.path))?;
        let local_path = events_dir.join(file_name);
        fs::copy(&source_path, &local_path).with_context(|| {
            format!(
                "failed to copy event {} -> {}",
                source_path.display(),
                local_path.display()
            )
        })?;
        event_path_map.insert(event.id.clone(), local_path.clone());
        new_events.push(json!({
            "id": event.id,
            "path": local_path,
            "state": event.state.as_str(),
            "digest": entry.digest,
        }));
    }

    for entry in index
        .entries
        .iter()
        .filter(|entry| entry.kind.eq_ignore_ascii_case("contract"))
    {
        let source_path = source.join(&entry.path);
        let digest = compute_file_digest(&source_path)?;
        if digest != entry.digest {
            return Err(anyhow!(
                "contract '{}' digest mismatch (expected {}, computed {})",
                entry.id,
                entry.digest,
                digest
            ));
        }
        let contract = Contract::from_path(&source_path)?;
        if contract.id != entry.id {
            return Err(anyhow!(
                "contract id mismatch (index={}, file={})",
                entry.id,
                contract.id
            ));
        }
        let file_name = Path::new(&entry.path)
            .file_name()
            .ok_or_else(|| anyhow!("invalid contract path '{}'", entry.path))?;
        let local_path = contracts_dir.join(file_name);
        fs::copy(&source_path, &local_path).with_context(|| {
            format!(
                "failed to copy contract {} -> {}",
                source_path.display(),
                local_path.display()
            )
        })?;
        new_contracts.push(json!({
            "id": contract.id,
            "path": local_path,
            "state": format!("{:?}", contract.state),
            "digest": entry.digest,
        }));
    }

    for entry in index
        .entries
        .iter()
        .filter(|entry| entry.kind.eq_ignore_ascii_case("shard"))
    {
        let shard_id = entry.id.as_str();
        let seen_key = format!("shard:{shard_id}");
        if seen.contains(&seen_key) {
            continue;
        }

        let source_path = source.join(&entry.path);
        let digest = compute_file_digest(&source_path)?;
        if digest != entry.digest {
            return Err(anyhow!(
                "shard '{}' digest mismatch (expected {}, computed {})",
                entry.id,
                entry.digest,
                digest
            ));
        }

        let event_path = entry
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("event_id"))
            .and_then(|value| value.as_str())
            .and_then(|event_id| event_path_map.get(event_id).cloned());

        let outcome = import_shard_into_vault(
            vault,
            home,
            alias,
            &source_path,
            event_path.as_deref(),
            None,
            no_import,
            Some(&index),
        )?;
        shard_messages.push(outcome.message.clone());
        new_shards.push(outcome.payload);
        seen.insert(seen_key);
    }

    let index_summary = json!({
        "id": index.id,
        "publisher": index.publisher,
        "generated_at": index.generated_at,
        "merkle_root": index.merkle_root,
        "canonical_hash": index.canonical_hash,
    });

    Ok(SubscriptionBatch {
        events: new_events,
        contracts: new_contracts,
        shards: new_shards,
        shard_messages,
        index: Some(index_summary),
    })
}
fn shard_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("shards").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn contract_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("contracts").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn event_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("events").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn receipt_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("receipts").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn compute_file_digest(path: &Path) -> Result<String> {
    let data =
        fs::read(path).with_context(|| format!("failed to read artifact at {}", path.display()))?;
    Ok(blake3::hash(&data).to_hex().to_string())
}

fn file_name_for(id: &str) -> String {
    format!("{}.json", id.replace([':', '/', ' '], "_"))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn sync_state_dir(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("sync").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create sync dir {}", dir.display()))?;
    }
    Ok(dir)
}

fn seen_state_path(home: &Path, alias: &str) -> Result<PathBuf> {
    Ok(sync_state_dir(home, alias)?.join("seen.json"))
}

fn load_seen(home: &Path, alias: &str) -> Result<HashSet<String>> {
    let path = seen_state_path(home, alias)?;
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let data =
        fs::read(&path).with_context(|| format!("failed to read seen state {}", path.display()))?;
    let list: Vec<String> = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse seen state {}", path.display()))?;
    Ok(list.into_iter().collect())
}

fn save_seen(home: &Path, alias: &str, seen: &HashSet<String>) -> Result<()> {
    let path = seen_state_path(home, alias)?;
    let mut sorted: Vec<_> = seen.iter().cloned().collect();
    sorted.sort();
    write_json(&path, &sorted)
}

fn read_event(path: &Path) -> Result<ContractEvent> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read event file {}", path.display()))?;
    let event: ContractEvent = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse event JSON {}", path.display()))?;
    Ok(event)
}

fn infer_doc_type(contract: Option<&Contract>, payload: &Value) -> Result<String> {
    if let Some(contract) = contract {
        if let Some(rest) = contract.doc.strip_prefix("doc:") {
            if !rest.is_empty() {
                return Ok(rest.to_string());
            }
        }
    }
    if let Some(kind) = payload.get("doc_type").and_then(|v| v.as_str()) {
        return Ok(kind.to_string());
    }
    if let Some(kind) = payload.get("type").and_then(|v| v.as_str()) {
        return Ok(kind.to_string());
    }
    Err(anyhow!(
        "unable to determine document type; provide --no-import to skip doc ingestion"
    ))
}
