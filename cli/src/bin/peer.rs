use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::output::{CommandOutput, OutputFormat};
use hn_cli::services::discovery::DiscoveryState;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;

#[derive(Parser, Debug)]
#[command(
    name = "hn peer",
    author = "Human.Net",
    version,
    about = "Inspect peers discovered on the local network."
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

    #[arg(long = "dry-run", global = true)]
    _dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all discovered peers.
    List,
    /// Show details for a specific peer by alias or DID.
    Get {
        /// Alias or DID to inspect.
        target: String,
    },
}

struct CommandContext {
    output: OutputFormat,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = CommandContext { output: cli.output };

    let home = ensure_home_dir()?;

    let output = match cli.command {
        Commands::List => handle_list(&ctx, &home),
        Commands::Get { target } => handle_get(&ctx, &home, target),
    }?;

    output.render(ctx.output)?;
    Ok(())
}

fn handle_list(ctx: &CommandContext, home: &PathBuf) -> Result<CommandOutput> {
    let (state, peers) = fetch_peers(home)?;

    if peers.is_empty() && ctx.output == OutputFormat::Text {
        println!("No peers discovered yet.");
    }

    if ctx.output == OutputFormat::Text {
        for peer in &peers {
            println!(
                "- {} ({}) — last seen {}",
                peer.alias, peer.did, peer.last_seen
            );
            if !peer.endpoints.is_empty() {
                println!("  endpoints: {}", peer.endpoints.join(", "));
            }
            if !peer.capabilities.is_empty() {
                println!("  capabilities: {}", peer.capabilities.join(", "));
            }
        }
    }

    Ok(CommandOutput::new(
        format!("{} peer(s) discovered", peers.len()),
        json!({
            "command": "list",
            "service": "discovery",
            "mode": "execute",
            "listen": state.listen,
            "peers": peers,
        }),
    ))
}

fn handle_get(ctx: &CommandContext, home: &PathBuf, target: String) -> Result<CommandOutput> {
    let (_state, peers) = fetch_peers(home)?;
    let target_lower = target.to_ascii_lowercase();

    let peer = peers
        .into_iter()
        .find(|peer| peer.did == target || peer.alias.to_ascii_lowercase() == target_lower)
        .ok_or_else(|| anyhow!("peer '{}' not found", target))?;

    if ctx.output == OutputFormat::Text {
        println!("Alias: {}", peer.alias);
        println!("DID: {}", peer.did);
        println!("Last seen: {}", peer.last_seen);
        if !peer.addresses.is_empty() {
            println!("Addresses: {}", peer.addresses.join(", "));
        }
        if !peer.endpoints.is_empty() {
            println!("Endpoints: {}", peer.endpoints.join(", "));
        }
        if !peer.capabilities.is_empty() {
            println!("Capabilities: {}", peer.capabilities.join(", "));
        }
    }

    Ok(CommandOutput::new(
        format!("Peer '{}' ({})", peer.alias, peer.did),
        json!({
            "command": "get",
            "service": "discovery",
            "mode": "execute",
            "peer": peer,
        }),
    ))
}

fn fetch_peers(home: &PathBuf) -> Result<(DiscoveryState, Vec<PeerInfo>)> {
    let vault = IdentityVault::new(home.clone())
        .context("failed to open identity vault; run `hn id` first")?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity configured; run `hn id use <alias>` first"))?;
    let node_home = vault.node_home(&active.alias)?;

    let mut state = DiscoveryState::load(&node_home)?
        .ok_or_else(|| anyhow!("discovery service is not running for '{}'", active.alias))?;
    if state.alias.is_empty() {
        state.alias = active.alias;
    }
    let base = state.http_base()?;
    let url = format!("http://{}/peers", base);

    let response = ureq::get(&url)
        .call()
        .map_err(|err| anyhow!("failed to contact discovery service at {}: {}", url, err))?;

    if !(200..=299).contains(&response.status()) {
        bail!("discovery service returned status {}", response.status());
    }

    let peers: Vec<PeerInfo> = response
        .into_json()
        .context("failed to decode discovery response")?;

    Ok((state, peers))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct PeerInfo {
    pub did: String,
    pub alias: String,
    pub addresses: Vec<String>,
    pub endpoints: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen: OffsetDateTime,
}
