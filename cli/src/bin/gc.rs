use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;

use hn_cli::contract::{merge_metadata, Contract, ContractRetention};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};

#[derive(Parser, Debug)]
#[command(name = "hn gc", about = "Garbage collection helpers")]
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
    /// Preview retention actions without mutating files.
    Plan(GcArgs),
    /// Apply retention actions (emit archive@1 records).
    Apply(GcArgs),
}

#[derive(Args, Debug)]
struct GcArgs {
    /// Operate on contract@1 retention windows.
    #[arg(long = "contracts")]
    contracts: bool,

    /// Alias to operate on (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::Plan(args) => handle_plan(args)?,
        Commands::Apply(args) => handle_apply(args)?,
    };
    output.render(cli.output)?;
    Ok(())
}

fn handle_plan(args: GcArgs) -> Result<CommandOutput> {
    if !args.contracts {
        return Err(anyhow!("specify --contracts"));
    }
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = resolve_alias(&vault, args.alias)?;
    let now = OffsetDateTime::now_utc();

    let (due, warnings) = collect_due_contracts(&home, &alias, now)?;
    let message = if due.is_empty() {
        format!("No contracts require archival for alias '{}'", alias)
    } else {
        format!(
            "{} contract(s) ready for archival for alias '{}'",
            due.len(),
            alias
        )
    };

    let payload = json!({
        "command": "gc.plan",
        "alias": alias,
        "contracts": due
            .iter()
            .map(|item| json!({
                "id": item.contract_id,
                "path": item.path,
                "archive_after": item.archive_after,
            }))
            .collect::<Vec<_>>(),
        "warnings": warnings,
    });

    Ok(CommandOutput::new(message, payload))
}

fn handle_apply(args: GcArgs) -> Result<CommandOutput> {
    if !args.contracts {
        return Err(anyhow!("specify --contracts"));
    }
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let alias = resolve_alias(&vault, args.alias)?;
    let now = OffsetDateTime::now_utc();

    let (due, mut warnings) = collect_due_contracts(&home, &alias, now)?;

    let mut archived = Vec::new();
    for due_item in due {
        match archive_contract(&home, &alias, due_item, now) {
            Ok(info) => archived.push(info),
            Err(err) => warnings.push(err.to_string()),
        }
    }

    let message = if archived.is_empty() {
        format!("No contracts archived for alias '{}'", alias)
    } else {
        format!(
            "Archived {} contract(s) for alias '{}'",
            archived.len(),
            alias
        )
    };

    let payload = json!({
        "command": "gc.apply",
        "alias": alias,
        "contracts": archived,
        "warnings": warnings,
    });

    Ok(CommandOutput::new(message, payload))
}

#[derive(Serialize)]
struct DueContract {
    contract_id: String,
    path: String,
    #[serde(with = "time::serde::rfc3339")]
    archive_after: OffsetDateTime,
}

#[derive(Serialize)]
struct ArchivedContractInfo {
    contract_id: String,
    contract_path: String,
    archive_record: String,
    #[serde(with = "time::serde::rfc3339")]
    archived_at: OffsetDateTime,
}

#[derive(Serialize)]
struct ContractArchiveRecord {
    id: String,
    contract_id: String,
    #[serde(with = "time::serde::rfc3339")]
    archived_at: OffsetDateTime,
    reason: String,
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

fn contract_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("contracts").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn archive_dir_for(home: &Path, alias: &str) -> Result<PathBuf> {
    let dir = home.join("archive").join("contracts").join(alias);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(dir)
}

fn collect_due_contracts(
    home: &Path,
    alias: &str,
    now: OffsetDateTime,
) -> Result<(Vec<DueContract>, Vec<String>)> {
    let contracts_dir = contract_dir_for(home, alias)?;
    let mut due = Vec::new();
    let mut warnings = Vec::new();

    if !contracts_dir.exists() {
        return Ok((due, warnings));
    }

    for entry in fs::read_dir(&contracts_dir)
        .with_context(|| format!("failed to read {}", contracts_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let contract: Contract = match serde_json::from_reader(
            fs::File::open(&path)
                .with_context(|| format!("failed to open contract {}", path.display()))?,
        ) {
            Ok(contract) => contract,
            Err(err) => {
                warnings.push(format!(
                    "failed to parse contract {}: {}",
                    path.display(),
                    err
                ));
                continue;
            }
        };

        let Some(retention) = contract.retention.as_ref() else {
            continue;
        };
        let Some(archive_after) = retention.archive_after else {
            continue;
        };
        if retention.archived_at.is_some() {
            continue;
        }
        if archive_after <= now {
            due.push(DueContract {
                contract_id: contract.id.clone(),
                path: path.display().to_string(),
                archive_after,
            });
        }
    }

    Ok((due, warnings))
}

fn archive_contract(
    home: &Path,
    alias: &str,
    due: DueContract,
    now: OffsetDateTime,
) -> Result<ArchivedContractInfo> {
    let path = PathBuf::from(&due.path);
    let mut contract: Contract = serde_json::from_reader(
        fs::File::open(&path).with_context(|| format!("failed to open {}", path.display()))?,
    )?;

    let record = ContractArchiveRecord {
        id: format!(
            "archive:contract:{}:{}",
            sanitize_component(&due.contract_id),
            timestamp_slug(now)
        ),
        contract_id: due.contract_id.clone(),
        archived_at: now,
        reason: "retention.archive_after".to_string(),
    };

    let archive_dir = archive_dir_for(home, alias)?;
    let archive_path = archive_dir.join(file_name_for(&record.id));
    write_json(&archive_path, &record)?;

    if let Some(retention) = contract.retention.as_mut() {
        retention.archived_at = Some(now);
    } else {
        contract.retention = Some(ContractRetention {
            archive_after: None,
            delete_after: None,
            archived_at: Some(now),
        });
    }
    contract.metadata = merge_metadata(
        &contract.metadata,
        json!({
            "archive": {
                "archived_at": now,
                "reason": "retention.archive_after",
            }
        }),
    );
    write_json(&path, &contract)?;

    Ok(ArchivedContractInfo {
        contract_id: due.contract_id,
        contract_path: path.display().to_string(),
        archive_record: archive_path.display().to_string(),
        archived_at: now,
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn file_name_for(id: &str) -> String {
    format!("{}.json", id.replace([':', '/', ' '], "_"))
}

fn sanitize_component(input: &str) -> String {
    hn_cli::contract::sanitize_component(input)
}

fn timestamp_slug(ts: OffsetDateTime) -> String {
    hn_cli::contract::timestamp_slug(ts)
}
