use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use hn_cli::discovery::{
    fetch_presence, generate_presence_doc, load_presence_docs, load_presence_hints,
    resolve_presence_endpoint, save_presence_doc, save_presence_hint, PresenceDoc,
};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use serde_json::json;

#[derive(Parser, Debug)]
#[command(
    name = "hn discover",
    author = "Human.Net",
    version,
    about = "Manage WAN discovery and presence hints."
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
    /// Publish a signed presence@2 document for this vault.
    Publish(PublishArgs),
    /// List stored presence documents (local or remote hints).
    List(ListArgs),
    /// Import a remote presence document (hint) from disk.
    Import(ImportArgs),
    /// Refresh a remote presence@2 document via HTTP and cache the hint.
    Refresh(RefreshArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = match cli.command {
        Commands::Publish(args) => handle_publish(args)?,
        Commands::List(args) => handle_list(args)?,
        Commands::Import(args) => handle_import(args)?,
        Commands::Refresh(args) => handle_refresh(args)?,
    };
    output.render(cli.output)?;
    Ok(())
}

#[derive(Args, Debug)]
struct PublishArgs {
    /// Alias whose identity should sign the presence document (defaults to active).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Current index Merkle root for this vault (e.g. from `hn shard publish`).
    #[arg(long = "merkle-root", value_name = "HASH")]
    merkle_root: String,

    /// Optional Merkle proof blob (base64).
    #[arg(long = "proof", value_name = "BASE64")]
    proof: Option<String>,

    /// Endpoint entries `name=url` (repeatable).
    #[arg(long = "endpoint", value_name = "KEY=URL", num_args = 0.., action = clap::ArgAction::Append)]
    endpoints: Vec<String>,

    /// TTL in seconds (default 600).
    #[arg(long = "ttl-seconds", default_value_t = 600)]
    ttl_seconds: u64,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Alias whose local presence docs should be listed.
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// List cached hints (remote peers) instead of local publications.
    #[arg(long = "hints")]
    hints: bool,
}

#[derive(Args, Debug)]
struct ImportArgs {
    /// Path to a presence@2 JSON document.
    #[arg(long = "file", value_name = "PATH")]
    file: PathBuf,
}

#[derive(Args, Debug)]
struct RefreshArgs {
    /// DID whose presence should be fetched.
    #[arg(long = "did", value_name = "DID")]
    did: String,

    /// Explicit URL to fetch presence from (overrides cached endpoints).
    #[arg(long = "url", value_name = "URL")]
    url: Option<String>,

    /// Endpoint key to look up in cached presence docs when --url is omitted.
    #[arg(long = "endpoint", default_value = "presence")]
    endpoint: String,
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

    let endpoints = parse_endpoints(args.endpoints)?;
    let doc = generate_presence_doc(
        &vault,
        &alias,
        endpoints.clone(),
        args.merkle_root.clone(),
        args.proof.clone(),
        Duration::from_secs(args.ttl_seconds.max(60)),
    )?;
    let path = save_presence_doc(&home, &alias, &doc)?;

    let payload = json!({
        "command": "discover.publish",
        "alias": alias,
        "path": path,
        "presence": &doc,
    });

    Ok(CommandOutput::new(
        format!("Published presence document {}", doc.id),
        payload,
    ))
}

fn handle_list(args: ListArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let docs = if args.hints {
        load_presence_hints(&home)?
    } else {
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
        load_presence_docs(&home, &alias)?
    };

    let message = if docs.is_empty() {
        if args.hints {
            "No presence hints stored".to_string()
        } else {
            "No local presence documents stored".to_string()
        }
    } else {
        format!("{} presence document(s)", docs.len())
    };

    let payload = json!({
        "command": "discover.list",
        "scope": if args.hints { "hints" } else { "local" },
        "presence": docs,
    });
    Ok(CommandOutput::new(message, payload))
}

fn handle_import(args: ImportArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let data = std::fs::read_to_string(&args.file)
        .with_context(|| format!("failed to read {}", args.file.display()))?;
    let doc: PresenceDoc = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", args.file.display()))?;
    let path = save_presence_hint(&home, &doc)?;

    let payload = json!({
        "command": "discover.import",
        "path": path,
        "presence": doc,
    });
    Ok(CommandOutput::new(
        format!(
            "Imported presence hint for {}",
            payload["presence"]["did"].as_str().unwrap_or("<unknown>")
        ),
        payload,
    ))
}

fn handle_refresh(args: RefreshArgs) -> Result<CommandOutput> {
    let home = ensure_home_dir()?;
    let (prior_hint, url) = match args.url {
        Some(url) => (None, url),
        None => {
            let (doc, url) = resolve_presence_endpoint(&home, &args.did, &args.endpoint)?
                .ok_or_else(|| {
                    anyhow!(
                        "no cached presence endpoint '{}' for {}; use --url to override",
                        args.endpoint,
                        args.did
                    )
                })?;
            (Some(doc), url)
        }
    };

    let fetched = fetch_presence(&url)?;
    let path = save_presence_hint(&home, &fetched)?;

    let payload = json!({
        "command": "discover.refresh",
        "did": args.did,
        "url": url,
        "presence": fetched,
        "path": path,
        "prior_hint": prior_hint,
    });

    Ok(CommandOutput::new(
        format!(
            "Refreshed presence for {}",
            payload["did"].as_str().unwrap_or("<unknown>")
        ),
        payload,
    ))
}

fn parse_endpoints(entries: Vec<String>) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for entry in entries {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(anyhow!("endpoint must be key=value, got '{entry}'"));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(anyhow!("endpoint must provide non-empty key and value"));
        }
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}
