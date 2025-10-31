use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::trust::{trust_link_to_json, TrustLinkStore};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Parser, Debug)]
#[command(
    name = "hn trust",
    author = "Human.Net",
    version,
    about = "Manage trust links and reputation aggregates."
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
    /// Work with trust_link@1 documents.
    #[command(subcommand)]
    Link(LinkCommands),
    /// Compute and manage reputation@1 aggregates.
    #[command(subcommand)]
    Reputation(ReputationCommands),
}

#[derive(Subcommand, Debug)]
enum LinkCommands {
    /// Derive and store a trust link based on evidence.
    Derive(LinkDeriveArgs),
    /// List locally stored trust links.
    List(LinkListArgs),
}

#[derive(Subcommand, Debug)]
enum ReputationCommands {
    /// Compute a reputation aggregate for a given target DID.
    Compute(ReputationComputeArgs),
    /// List stored reputation aggregates.
    List(ReputationListArgs),
}

#[derive(Args, Debug)]
struct LinkDeriveArgs {
    /// Counterparty DID this link targets.
    #[arg(long = "to", value_name = "DID")]
    to: String,

    /// Evidence document IDs (contract:, payment:, receipt:, ...).
    #[arg(
        long = "based-on",
        value_name = "ID",
        required = true,
        num_args = 1..,
        action = clap::ArgAction::Append
    )]
    based_on: Vec<String>,

    /// Confidence score between 0.0 and 1.0.
    #[arg(long = "confidence", value_parser = clap::value_parser!(f64))]
    confidence: f64,

    /// Optional context label (e.g., micropay, lending).
    #[arg(long = "context", value_name = "LABEL")]
    context: Option<String>,

    /// Override last-seen timestamp (RFC3339). Defaults to now.
    #[arg(long = "last-seen", value_name = "RFC3339")]
    last_seen: Option<String>,

    /// TTL in seconds for consumers (optional).
    #[arg(long = "ttl-seconds", value_name = "SECONDS")]
    ttl_seconds: Option<u64>,

    /// Alias whose identity should sign the trust link (defaults to active).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug, Default)]
struct LinkListArgs {
    /// Alias whose trust links should be listed (defaults to active).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug)]
struct ReputationComputeArgs {
    /// Target DID whose reputation is being evaluated.
    #[arg(long = "target", value_name = "DID")]
    target: String,

    /// Minimum number of links required to emit reputation.
    #[arg(long = "min-links", value_name = "COUNT")]
    min_links: Option<usize>,

    /// Optional context filter (only links with this context are considered).
    #[arg(long = "context", value_name = "LABEL")]
    context: Option<String>,

    /// Optional policy reference recorded inside reputation@1.
    #[arg(long = "policy-ref", value_name = "STRING")]
    policy_ref: Option<String>,

    /// Alias whose identity should sign the reputation document (defaults to active).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

#[derive(Args, Debug, Default)]
struct ReputationListArgs {
    /// Alias whose reputation aggregates should be listed (defaults to active).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::Link(command) => handle_link(command)?,
        Commands::Reputation(command) => handle_reputation(command)?,
    };
    output.render(cli.output)?;
    Ok(())
}

fn handle_link(command: LinkCommands) -> Result<CommandOutput> {
    match command {
        LinkCommands::Derive(args) => handle_link_derive(args),
        LinkCommands::List(args) => handle_link_list(args),
    }
}

fn handle_reputation(command: ReputationCommands) -> Result<CommandOutput> {
    match command {
        ReputationCommands::Compute(args) => handle_reputation_compute(args),
        ReputationCommands::List(args) => handle_reputation_list(args),
    }
}

fn handle_link_derive(args: LinkDeriveArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let store = match &args.alias {
        Some(alias) => TrustLinkStore::for_alias(&vault, alias)?,
        None => TrustLinkStore::open(&vault)?,
    };

    let last_seen = match args.last_seen {
        Some(ref value) => Some(
            OffsetDateTime::parse(value, &Rfc3339)
                .with_context(|| format!("invalid --last-seen timestamp '{value}'"))?,
        ),
        None => None,
    };
    let ttl = args.ttl_seconds.map(Duration::from_secs);

    let link = store.create_link(
        &args.to,
        args.based_on.clone(),
        args.confidence,
        args.context.clone(),
        last_seen,
        ttl,
    )?;
    let path = store.store(&link)?;

    let payload = json!({
        "command": "trust.link.derive",
        "path": path,
        "link": trust_link_to_json(&link),
    });

    Ok(CommandOutput::new(
        format!("Stored trust link {} → {}", link.from, link.to),
        payload,
    ))
}

fn handle_link_list(args: LinkListArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let vault = IdentityVault::new(home.clone())?;
    let store = match &args.alias {
        Some(alias) => TrustLinkStore::for_alias(&vault, alias)?,
        None => TrustLinkStore::open(&vault)?,
    };

    let links = store.list()?;
    let payload = json!({
        "command": "trust.link.list",
        "count": links.len(),
        "links": links.iter().map(trust_link_to_json).collect::<Vec<_>>(),
    });

    let message = if links.is_empty() {
        "No trust links found".to_string()
    } else {
        format!("{} trust link(s)", links.len())
    };

    Ok(CommandOutput::new(message, payload))
}

fn handle_reputation_compute(args: ReputationComputeArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?
        .canonicalize()
        .unwrap_or_else(|_| ensure_home_dir().expect("home dir"));
    let vault = IdentityVault::new(home.clone())?;
    let store = match &args.alias {
        Some(alias) => TrustLinkStore::for_alias(&vault, alias)?,
        None => TrustLinkStore::open(&vault)?,
    };

    let reputation = store.compute_reputation(
        &args.target,
        args.policy_ref.clone(),
        args.context.clone(),
        args.min_links,
    )?;
    let path = store.store_reputation(&reputation)?;

    let payload = json!({
        "command": "trust.reputation.compute",
        "path": path,
        "reputation": hn_cli::trust::reputation_to_json(&reputation),
    });

    Ok(CommandOutput::new(
        format!(
            "Stored reputation for {} observing {} ({} link(s))",
            reputation.observer, reputation.target, reputation.aggregate.count
        ),
        payload,
    ))
}

fn handle_reputation_list(args: ReputationListArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?
        .canonicalize()
        .unwrap_or_else(|_| ensure_home_dir().expect("home dir"));
    let vault = IdentityVault::new(home.clone())?;
    let store = match &args.alias {
        Some(alias) => TrustLinkStore::for_alias(&vault, alias)?,
        None => TrustLinkStore::open(&vault)?,
    };

    let reps = store.list_reputation()?;
    let payload = json!({
        "command": "trust.reputation.list",
        "count": reps.len(),
        "reputation": reps.iter().map(hn_cli::trust::reputation_to_json).collect::<Vec<_>>(),
    });

    let message = if reps.is_empty() {
        "No reputation aggregates found".to_string()
    } else {
        format!("{} reputation aggregate(s)", reps.len())
    };

    Ok(CommandOutput::new(message, payload))
}
