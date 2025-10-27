use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use hn_cli::doc::{ViewSource, ViewStore};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

#[derive(Parser, Debug)]
#[command(
    name = "hn view",
    version,
    about = "Materialise doc views and verify materialisation receipts."
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
    /// Materialise a named view and produce a signed receipt.
    Run(RunArgs),
    /// Verify the latest (or supplied) receipt for a view.
    Verify(VerifyArgs),
    /// List configured view definitions.
    List(ListArgs),
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Name of the view to materialise.
    name: String,

    /// Data source to use when materialising the view.
    #[arg(
        long = "source",
        value_enum,
        default_value_t = ViewSourceCli::Local,
        value_name = "SOURCE"
    )]
    source: ViewSourceCli,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum ViewSourceCli {
    Local,
    Mcp,
}

impl ViewSourceCli {
    fn label(self) -> &'static str {
        match self {
            ViewSourceCli::Local => "local",
            ViewSourceCli::Mcp => "mcp",
        }
    }
}

impl From<ViewSourceCli> for ViewSource {
    fn from(value: ViewSourceCli) -> Self {
        match value {
            ViewSourceCli::Local => ViewSource::Local,
            ViewSourceCli::Mcp => ViewSource::Local,
        }
    }
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Name of the view whose receipt should be verified.
    name: String,

    /// Optional explicit receipt file to verify.
    #[arg(long = "receipt", value_name = "PATH")]
    receipt: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Include latest receipt metadata for each view.
    #[arg(long = "with-receipts")]
    with_receipts: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home)?;
    let store = ViewStore::open(&vault)?;

    let output = match cli.command {
        Commands::Run(args) => handle_run(&store, args)?,
        Commands::Verify(args) => handle_verify(&store, args)?,
        Commands::List(args) => handle_list(&store, args)?,
    };

    output.render(cli.output)?;
    Ok(())
}

fn handle_run(store: &ViewStore, args: RunArgs) -> Result<CommandOutput> {
    let requested_mcp = matches!(args.source, ViewSourceCli::Mcp);
    let materialization = store.materialize(&args.name, args.source.into())?;
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
        "command": "view.run",
        "view": snapshot.view,
        "source": args.source.label(),
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

    let mut message = format!(
        "Materialised view '{}' (hash {})",
        payload["view"].as_str().unwrap_or(""),
        payload["snapshot"]["canonical_hash"].as_str().unwrap_or("")
    );
    if requested_mcp {
        message.push_str(" using local data (MCP source not yet available)");
    }
    Ok(CommandOutput::new(message, payload))
}

fn handle_verify(store: &ViewStore, args: VerifyArgs) -> Result<CommandOutput> {
    let verification = store.verify_receipt(&args.name, args.receipt.as_deref())?;
    let payload = json!({
        "command": "view.verify",
        "view": verification.view,
        "receipt_id": verification.receipt_id,
        "signature_valid": verification.signature_valid,
        "recorded_hash": verification.recorded_hash,
        "current_hash": verification.current_hash,
        "matches_current": verification.matches_current,
        "rows_recorded": verification.rows_recorded,
        "receipt_path": verification.receipt_path,
    });
    let verdict = if verification.signature_valid && verification.matches_current {
        "verified"
    } else {
        "failed"
    };
    let message = format!(
        "Receipt '{}' {} for view '{}'",
        verification.receipt_id,
        verdict,
        payload["view"].as_str().unwrap_or("")
    );
    Ok(CommandOutput::new(message, payload))
}

fn handle_list(store: &ViewStore, args: ListArgs) -> Result<CommandOutput> {
    if args.with_receipts {
        let views = store.list_with_receipts()?;
        let count = views.len();
        let message = if count == 0 {
            "No views defined".to_string()
        } else {
            let mut lines = vec![format!("{} view(s)", count)];
            for view in &views {
                if let Some(receipt) = &view.latest_receipt {
                    lines.push(format!(
                        "- {} :: {} [rows {} at {}]",
                        view.name,
                        view.rule,
                        receipt.rows,
                        receipt
                            .captured_at
                            .format(&Rfc3339)
                            .unwrap_or_else(|_| receipt.captured_at.to_string())
                    ));
                } else {
                    lines.push(format!("- {} :: {} [no receipts]", view.name, view.rule));
                }
            }
            lines.join("\n")
        };
        let payload = json!({
            "command": "view.list",
            "views": views,
        });
        return Ok(CommandOutput::new(message, payload));
    }

    let views = store.list()?;
    let count = views.len();
    let message = if count == 0 {
        "No views defined".to_string()
    } else {
        let mut lines = vec![format!("{} view(s)", count)];
        for view in &views {
            lines.push(format!("- {} :: {}", view.name, view.rule));
        }
        lines.join("\n")
    };
    let payload = json!({
        "command": "view.list",
        "views": views,
    });
    Ok(CommandOutput::new(message, payload))
}
