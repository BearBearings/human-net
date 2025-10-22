use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};

use hn_cli::contract::Contract;
use hn_cli::event::ContractEvent;
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};

#[derive(Parser, Debug)]
#[command(name = "hn audit", about = "State reconstruction helpers")]
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
    /// Rebuild state from event@1 transcripts.
    Replay(ReplayArgs),
}

#[derive(Args, Debug)]
struct ReplayArgs {
    /// Replay contract@1 state machines.
    #[arg(long = "contracts")]
    contracts: bool,

    /// Alias to operate on (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::Replay(args) => handle_replay(args)?,
    };
    output.render(cli.output)?;
    Ok(())
}

fn handle_replay(args: ReplayArgs) -> Result<CommandOutput> {
    if !args.contracts {
        return Err(anyhow!("specify --contracts"));
    }
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = resolve_alias(&vault, args.alias)?;

    let events_dir = events_dir_for(&home, &alias)?;
    let mut events_by_contract: HashMap<String, Vec<ContractEvent>> = HashMap::new();

    if events_dir.exists() {
        for entry in fs::read_dir(&events_dir)
            .with_context(|| format!("failed to read {}", events_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let event_path = entry.path();
            let event: ContractEvent = serde_json::from_reader(
                fs::File::open(&event_path)
                    .with_context(|| format!("failed to open {}", event_path.display()))?,
            )
            .with_context(|| format!("failed to parse event {}", event_path.display()))?;
            events_by_contract
                .entry(event.contract_id.clone())
                .or_default()
                .push(event);
        }
    }

    let contracts_dir = contracts_dir_for(&home, &alias)?;
    let mut summaries = Vec::new();
    if contracts_dir.exists() {
        for entry in fs::read_dir(&contracts_dir)
            .with_context(|| format!("failed to read {}", contracts_dir.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            let contract: Contract = serde_json::from_reader(
                fs::File::open(&path)
                    .with_context(|| format!("failed to open contract {}", path.display()))?,
            )
            .with_context(|| format!("failed to parse contract {}", path.display()))?;
            let events = events_by_contract.remove(&contract.id).unwrap_or_default();
            summaries.push(replay_contract(&contract, events, &path)?);
        }
    }

    // Include contracts that only have events (no on-disk contract yet)
    for (contract_id, events) in events_by_contract {
        summaries.push(replay_contract_without_file(contract_id, events)?);
    }

    let mismatches = summaries
        .iter()
        .filter(|summary| summary["match"].as_bool() == Some(false))
        .count();
    let message = if mismatches == 0 {
        format!("Replay completed for {} contract(s)", summaries.len())
    } else {
        format!(
            "Replay detected {} divergence(s) across {} contract(s)",
            mismatches,
            summaries.len()
        )
    };

    let payload = json!({
        "command": "audit.replay",
        "alias": alias,
        "contracts": summaries,
        "divergences": mismatches,
    });

    Ok(CommandOutput::new(message, payload))
}

fn replay_contract(
    contract: &Contract,
    mut events: Vec<ContractEvent>,
    path: &Path,
) -> Result<serde_json::Value> {
    events.sort_by_key(|evt| (evt.sequence, evt.timestamp));
    let (expected_state, sequence_ok) = compute_final_state(&events);
    let stored_state = contract.state.as_str().to_string();
    let match_state = expected_state.as_deref() == Some(&stored_state[..]);

    Ok(json!({
        "id": contract.id,
        "path": path.display().to_string(),
        "events": events.len(),
        "sequence_ok": sequence_ok,
        "final_state": expected_state,
        "stored_state": stored_state,
        "match": match_state,
    }))
}

fn replay_contract_without_file(
    contract_id: String,
    mut events: Vec<ContractEvent>,
) -> Result<serde_json::Value> {
    events.sort_by_key(|evt| (evt.sequence, evt.timestamp));
    let (expected_state, sequence_ok) = compute_final_state(&events);

    Ok(json!({
        "id": contract_id,
        "path": Value::Null,
        "events": events.len(),
        "sequence_ok": sequence_ok,
        "final_state": expected_state,
        "stored_state": Value::Null,
        "match": expected_state.is_none(),
    }))
}

fn compute_final_state(events: &[ContractEvent]) -> (Option<String>, bool) {
    if events.is_empty() {
        return (None, true);
    }
    let mut expected_sequence = 1u32;
    let mut sequence_ok = true;
    let mut last_state: Option<String> = None;
    for event in events {
        if event.sequence != expected_sequence {
            sequence_ok = false;
        }
        expected_sequence = event.sequence.saturating_add(1);
        last_state = Some(event.state.as_str().to_string());
    }
    (last_state, sequence_ok)
}

fn resolve_alias(vault: &IdentityVault, hint: Option<String>) -> Result<String> {
    if let Some(alias) = hint {
        return Ok(alias);
    }
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
    Ok(active.alias)
}

fn contracts_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("contracts").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn events_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("events").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}
