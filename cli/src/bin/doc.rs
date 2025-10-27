use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use hn_cli::doc::{DocStore, DocSummary, ViewSource, ViewStore};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

#[derive(Parser, Debug)]
#[command(name = "hn doc", version, about = "Manage local Human.Net docs")]
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
    /// Import a doc from a JSON file and sign it.
    Import {
        /// Doc type identifier (e.g. folder@1).
        #[arg(long = "type", value_name = "TYPE")]
        doc_type: String,

        /// Path to the JSON file.
        #[arg(long = "file", value_name = "PATH")]
        file: PathBuf,

        /// Optional explicit doc id.
        #[arg(long = "id", value_name = "ID")]
        id: Option<String>,
    },
    /// List signed docs in the active vault.
    List,
    /// Show the full contents of a doc.
    Get {
        /// Doc id.
        id: String,
    },
    /// Delete a doc without confirmation.
    Delete {
        /// Doc id.
        id: String,
    },
    /// Replay canonical hash & signature for a doc.
    Replay {
        /// Doc id.
        id: String,
    },
    /// Manage views over docs.
    View {
        #[command(subcommand)]
        command: ViewCommands,
    },
}

#[derive(Subcommand, Debug)]
enum ViewCommands {
    /// Create a new view with a rule (e.g. "type=folder@1 AND tags:\"finance\"").
    Create {
        name: String,
        #[arg(long = "rule", value_name = "RULE")]
        rule: String,
    },
    /// List existing views.
    List,
    /// Show the stored definition for a view.
    Show { name: String },
    /// Run a view and report the number of matching docs.
    Run { name: String },
    /// Output the matching rows in JSON.
    Rows { name: String },
    /// Materialize a snapshot of the current rows.
    Snapshot { name: String },
    /// Delete a view (definitions and snapshots).
    Delete { name: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = CommandContext { output: cli.output };

    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home)?;

    let output = match cli.command {
        Commands::Import { doc_type, file, id } => handle_import(&ctx, &vault, doc_type, file, id),
        Commands::List => handle_list(&ctx, &vault),
        Commands::Get { id } => handle_get(&ctx, &vault, id),
        Commands::Delete { id } => handle_delete(&ctx, &vault, id),
        Commands::Replay { id } => handle_replay(&ctx, &vault, id),
        Commands::View { command } => handle_view(&ctx, &vault, command),
    }?;

    output.render(ctx.output)?;
    Ok(())
}

struct CommandContext {
    output: OutputFormat,
}

fn handle_import(
    _ctx: &CommandContext,
    vault: &IdentityVault,
    doc_type: String,
    file: PathBuf,
    id: Option<String>,
) -> Result<CommandOutput> {
    let store = DocStore::open(vault)?;
    let stored = store.import_from_file(&doc_type, &file, id)?;
    let message = format!(
        "Stored doc '{}' ({})\ncanonical hash: {}",
        stored.id, stored.doc_type, stored.canonical_hash
    );
    Ok(CommandOutput::new(message, stored.as_payload()))
}

fn handle_list(_ctx: &CommandContext, vault: &IdentityVault) -> Result<CommandOutput> {
    let store = DocStore::open(vault)?;
    let docs = store.list()?;
    let message = render_list_message(&docs);
    Ok(CommandOutput::new(message, json!({ "docs": docs })))
}

fn handle_get(_ctx: &CommandContext, vault: &IdentityVault, id: String) -> Result<CommandOutput> {
    let store = DocStore::open(vault)?;
    let doc = store.get(&id)?;
    let payload = doc.as_payload();
    let message = serde_json::to_string_pretty(&payload)?;
    Ok(CommandOutput::new(message, payload))
}

fn handle_delete(
    _ctx: &CommandContext,
    vault: &IdentityVault,
    id: String,
) -> Result<CommandOutput> {
    let store = DocStore::open(vault)?;
    store.delete(&id)?;
    Ok(CommandOutput::new(
        format!("Deleted doc '{id}'"),
        json!({ "deleted": id }),
    ))
}

fn handle_replay(
    _ctx: &CommandContext,
    vault: &IdentityVault,
    id: String,
) -> Result<CommandOutput> {
    let store = DocStore::open(vault)?;
    let replay = store.replay(&id)?;
    let message = format!(
        "Doc '{}' ({})\nstored hash: {}\ncomputed hash: {}\nsignature valid: {}",
        replay.id,
        replay.doc_type,
        replay.canonical_hash,
        replay.computed_hash,
        replay.signature_valid
    );
    Ok(CommandOutput::new(message, json!({ "replay": replay })))
}

fn render_list_message(docs: &[DocSummary]) -> String {
    if docs.is_empty() {
        return "No docs found".to_string();
    }
    let mut lines = Vec::with_capacity(docs.len() + 1);
    lines.push(format!("{} docs", docs.len()));
    for doc in docs {
        let updated = doc
            .updated_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| doc.updated_at.to_string());
        lines.push(format!(
            "- {} ({}) updated {}",
            doc.id, doc.doc_type, updated
        ));
    }
    lines.join("\n")
}

fn handle_view(
    ctx: &CommandContext,
    vault: &IdentityVault,
    command: ViewCommands,
) -> Result<CommandOutput> {
    let store = ViewStore::open(vault)?;
    match command {
        ViewCommands::Create { name, rule } => handle_view_create(ctx, &store, name, rule),
        ViewCommands::List => handle_view_list(ctx, &store),
        ViewCommands::Show { name } => handle_view_show(ctx, &store, name),
        ViewCommands::Run { name } => handle_view_run(ctx, &store, name),
        ViewCommands::Rows { name } => handle_view_rows(ctx, &store, name),
        ViewCommands::Snapshot { name } => handle_view_snapshot(ctx, &store, name),
        ViewCommands::Delete { name } => handle_view_delete(ctx, &store, name),
    }
}

fn handle_view_create(
    _ctx: &CommandContext,
    store: &ViewStore,
    name: String,
    rule: String,
) -> Result<CommandOutput> {
    let def = store.create(&name, rule)?;
    let payload = serde_json::to_value(&def)?;
    Ok(CommandOutput::new(
        format!("Created view '{}'", def.name),
        payload,
    ))
}

fn handle_view_list(_ctx: &CommandContext, store: &ViewStore) -> Result<CommandOutput> {
    let views = store.list()?;
    let payload = serde_json::to_value(&views)?;
    let message = if views.is_empty() {
        "No views defined".to_string()
    } else {
        let mut lines = vec![format!("{} views", views.len())];
        for view in &views {
            lines.push(format!("- {} :: {}", view.name, view.rule));
        }
        lines.join("\n")
    };
    Ok(CommandOutput::new(message, payload))
}

fn handle_view_show(
    _ctx: &CommandContext,
    store: &ViewStore,
    name: String,
) -> Result<CommandOutput> {
    let def = store.get(&name)?;
    let payload = serde_json::to_value(&def)?;
    let message = serde_json::to_string_pretty(&payload)?;
    Ok(CommandOutput::new(message, payload))
}

fn handle_view_run(
    _ctx: &CommandContext,
    store: &ViewStore,
    name: String,
) -> Result<CommandOutput> {
    let rows = store.run(&name)?;
    let view_name = name.clone();
    let payload = json!({
        "view": name,
        "rows": rows,
        "count": rows.len(),
    });
    let message = format!("View '{}' returned {} docs", view_name, rows.len());
    Ok(CommandOutput::new(message, payload))
}

fn handle_view_rows(
    ctx: &CommandContext,
    store: &ViewStore,
    name: String,
) -> Result<CommandOutput> {
    let rows = store.run(&name)?;
    let payload = json!({ "view": name, "rows": rows });
    let message = if ctx.output == OutputFormat::Json {
        String::new()
    } else {
        serde_json::to_string_pretty(&payload)?
    };
    Ok(CommandOutput::new(message, payload))
}

fn handle_view_snapshot(
    _ctx: &CommandContext,
    store: &ViewStore,
    name: String,
) -> Result<CommandOutput> {
    let materialization = store.materialize(&name, ViewSource::Local)?;
    let snapshot = materialization.snapshot;
    let receipt = materialization.receipt;

    let snapshot_path = snapshot
        .location
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let receipt_path = receipt
        .location
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let payload = json!({
        "view": snapshot.view,
        "snapshot": {
            "captured_at": snapshot.captured_at,
            "canonical_hash": snapshot.canonical_hash,
            "file": snapshot_path,
            "rows": snapshot.rows,
        },
        "receipt": {
            "id": receipt.id,
            "captured_at": receipt.captured_at,
            "canonical_hash": receipt.canonical_hash,
            "signature": receipt.signature,
            "source": receipt.source,
            "file": receipt_path,
        }
    });
    let message = format!(
        "Snapshot saved for view '{}' (hash {}) with receipt {}",
        payload["view"].as_str().unwrap_or(""),
        payload["snapshot"]["canonical_hash"].as_str().unwrap_or(""),
        payload["receipt"]["file"].as_str().unwrap_or("")
    );
    Ok(CommandOutput::new(message, payload))
}

fn handle_view_delete(
    _ctx: &CommandContext,
    store: &ViewStore,
    name: String,
) -> Result<CommandOutput> {
    store.delete(&name)?;
    Ok(CommandOutput::new(
        format!("Deleted view '{name}'"),
        json!({ "view": name }),
    ))
}
