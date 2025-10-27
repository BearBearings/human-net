use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::sync::{PairTokenKind, SyncPairInfo, SyncPairStore};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

#[derive(Parser, Debug)]
#[command(
    name = "hn sync",
    version,
    about = "Replicate vault data between paired devices."
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
    /// Generate or consume a pairing QR token.
    Pair(PairArgs),
    /// Produce encrypted bundles for all paired devices.
    Push,
    /// Apply incoming bundles from paired devices.
    Pull,
    /// List configured sync pairs.
    List,
    /// Show sync status across paired devices.
    Status,
}

#[derive(Args, Debug)]
struct PairArgs {
    /// Require QR mode to avoid accidental plaintext pairing.
    #[arg(long = "qr")]
    qr: bool,

    /// Pairing token to accept or finalize.
    #[arg(long = "token", value_name = "TOKEN")]
    token: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home)?;
    let store = SyncPairStore::open(&vault)?;

    let output = match cli.command {
        Commands::Pair(args) => handle_pair(&store, args)?,
        Commands::Push => handle_push(&store)?,
        Commands::Pull => handle_pull(&store)?,
        Commands::List => handle_list(&store)?,
        Commands::Status => handle_status(&store)?,
    };

    output.render(cli.output)?;
    Ok(())
}

fn handle_pair(store: &SyncPairStore, args: PairArgs) -> Result<CommandOutput> {
    if !args.qr {
        return Err(anyhow!(
            "QR mode required; rerun with `hn sync pair --qr` (optionally providing --token)"
        ));
    }

    if let Some(token) = args.token.as_deref() {
        match SyncPairStore::classify_token(token) {
            PairTokenKind::Ticket => {
                let acceptance = store.accept_pairing(token)?;
                let remote = acceptance.pair.remote_alias.clone();
                let payload = json!({
                    "command": "sync.pair.accept",
                    "ticket_id": acceptance.ticket_id,
                    "response": acceptance.response,
                    "pair": acceptance.pair,
                });
                let message = format!(
                    "Paired with '{remote}'. Share the response token with the origin device to complete setup."
                );
                Ok(CommandOutput::new(message, payload))
            }
            PairTokenKind::Response => {
                let finalize = store.finalize_pairing(token)?;
                let remote = finalize.pair.remote_alias.clone();
                let payload = json!({
                    "command": "sync.pair.finalize",
                    "ticket_id": finalize.ticket_id,
                    "pair": finalize.pair,
                });
                let message = format!("Pairing completed with '{remote}'.");
                Ok(CommandOutput::new(message, payload))
            }
            PairTokenKind::Unknown => Err(anyhow!("unrecognised sync pairing token")),
        }
    } else {
        let prep = store.prepare_pairing()?;
        let payload = json!({
            "command": "sync.pair.prepare",
            "ticket_id": prep.ticket_id,
            "ticket": prep.ticket,
            "expires_at": prep.expires_at,
        });
        let message = "Pairing ticket created. Scan the QR code or share the token with the companion device.";
        Ok(CommandOutput::new(message, payload))
    }
}

fn handle_push(store: &SyncPairStore) -> Result<CommandOutput> {
    let bundles = store.push_all()?;
    let total_docs: usize = bundles.iter().map(|bundle| bundle.doc_count).sum();
    let message = if bundles.is_empty() {
        "No sync pairs configured; nothing to push.".to_string()
    } else {
        format!(
            "Generated {} bundle(s) covering {} doc(s).",
            bundles.len(),
            total_docs
        )
    };
    let payload = json!({
        "command": "sync.push",
        "bundles": bundles,
    });
    Ok(CommandOutput::new(message, payload))
}

fn handle_pull(store: &SyncPairStore) -> Result<CommandOutput> {
    let processed = store.pull_all()?;
    let applied: usize = processed.iter().map(|bundle| bundle.docs_applied).sum();
    let message = if processed.is_empty() {
        "No incoming bundles detected.".to_string()
    } else {
        format!(
            "Applied {} doc updates across {} bundle(s).",
            applied,
            processed.len()
        )
    };
    let payload = json!({
        "command": "sync.pull",
        "bundles": processed,
    });
    Ok(CommandOutput::new(message, payload))
}

fn handle_list(store: &SyncPairStore) -> Result<CommandOutput> {
    let pairs = store.list_pairs()?;
    let message = render_list_message(&pairs);
    let payload = json!({
        "command": "sync.list",
        "pairs": pairs,
    });
    Ok(CommandOutput::new(message, payload))
}

fn handle_status(store: &SyncPairStore) -> Result<CommandOutput> {
    let entries = store.status()?;
    let message = if entries.is_empty() {
        "No sync pairs configured".to_string()
    } else {
        let mut lines = vec![format!("{} pair(s)", entries.len())];
        for entry in &entries {
            let pair = &entry.pair;
            lines.push(format!(
                "- {} ({}) push={} pull={} local={} remote={} lag(in={}, out={})",
                pair.remote_alias,
                pair.remote_did,
                format_timestamp(pair.last_push_at),
                format_timestamp(pair.last_pull_at),
                format_timestamp(pair.local_head),
                format_timestamp(pair.remote_head),
                entry.pending_inbox,
                entry.pending_outbox
            ));
        }
        lines.join("\n")
    };
    let payload = json!({
        "command": "sync.status",
        "status": entries,
    });
    Ok(CommandOutput::new(message, payload))
}

fn format_timestamp(value: Option<time::OffsetDateTime>) -> String {
    match value {
        Some(ts) => ts.format(&Rfc3339).unwrap_or_else(|_| ts.to_string()),
        None => "never".to_string(),
    }
}

fn render_list_message(pairs: &[SyncPairInfo]) -> String {
    if pairs.is_empty() {
        return "No sync pairs configured".to_string();
    }
    let mut lines = vec![format!("{} pair(s)", pairs.len())];
    for pair in pairs {
        lines.push(format!(
            "- {} (remote DID {})",
            pair.remote_alias, pair.remote_did
        ));
    }
    lines.join("\n")
}
