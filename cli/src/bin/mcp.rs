use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use hn_cli::discovery::{load_presence_docs, PresenceDoc};
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_cli::services::federation::{FederationPeerRecord, FederationRoster};
use hn_cli::services::relay::{RelayHostRecord, RelayRoster};
use hn_mcp::federation::{
    FederationPeerConfig, FederationPeerResult, FederationPeerStatus, FederationSync,
    FederationSyncOptions,
};
use hn_mcp::{
    canonical_body_hash, canonical_request_message, McpConfig, McpMode, McpServer, PublishRequest,
    TlsConfig,
};
use serde::Serialize;
use serde_json::{self, json};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use ureq;

#[derive(Parser, Debug)]
#[command(
    name = "hn mcp",
    author = "Human.Net",
    version,
    about = "Run the embedded Human.Net MCP server."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Serve the MCP API locally.
    Serve(ServeArgs),
    /// Produce signed headers for an MCP request body.
    Auth(AuthArgs),
    /// Manage the federation roster and cached slices.
    #[command(subcommand)]
    Federate(FederateCommands),
    /// Manage relay hosts and proxy publishing for mobile peers.
    #[command(subcommand)]
    Relay(RelayCommands),
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Optional path to MCP configuration JSON (defaults to $HN_HOME/mcp.json).
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Predefined profile to load (e.g. federation).
    #[arg(long = "profile", value_name = "NAME")]
    profile: Option<String>,

    /// Override listen address (e.g. 0.0.0.0:7733).
    #[arg(long = "listen", value_name = "HOST:PORT")]
    listen: Option<SocketAddr>,

    /// Override mode (friends or public).
    #[arg(long = "mode", value_name = "MODE")]
    mode: Option<McpMode>,

    /// Override storage directory for shard cache.
    #[arg(long = "storage", value_name = "PATH")]
    storage: Option<PathBuf>,

    /// Optional max TTL override in seconds.
    #[arg(long = "max-ttl", value_name = "SECONDS")]
    max_ttl_seconds: Option<u64>,

    /// Path to a presence@2 document served via /presence.
    #[arg(long = "presence-path", value_name = "PATH")]
    presence_path: Option<PathBuf>,

    /// Identity alias used to sign federated index slices (defaults to active identity).
    #[arg(long = "signing-alias", value_name = "ALIAS")]
    signing_alias: Option<String>,

    /// Optional path where trust_link@1 and reputation@1 documents are stored.
    #[arg(long = "trust-path", value_name = "PATH")]
    trust_path: Option<PathBuf>,

    /// Override the retention window for relayed presences (in seconds, 0 disables pruning).
    #[arg(long = "relay-ttl", value_name = "SECONDS")]
    relay_ttl_seconds: Option<u64>,
}

#[derive(Args, Debug)]
struct AuthArgs {
    /// Path to the JSON body that will be sent.
    #[arg(long = "body", value_name = "PATH")]
    body: PathBuf,

    /// HTTP method (default POST).
    #[arg(long = "method", value_name = "METHOD", default_value = "POST")]
    method: String,

    /// HTTP path (default /publish).
    #[arg(long = "path", value_name = "PATH", default_value = "/publish")]
    path: String,

    /// Alias whose signing key should be used (defaults to active identity).
    #[arg(long = "alias", value_name = "ALIAS")]
    alias: Option<String>,

    /// Override timestamp (Unix seconds). Defaults to now.
    #[arg(long = "timestamp", value_name = "EPOCH")]
    timestamp: Option<i64>,
}

#[derive(Subcommand, Debug)]
enum FederateCommands {
    /// Add a federation peer to the local roster.
    Add(FederateAddArgs),
    /// Remove a federation peer from the roster.
    Remove(FederateRemoveArgs),
    /// List current federation peers.
    List,
    /// Fetch the latest slices from configured peers.
    Refresh(FederateRefreshArgs),
}

#[derive(Args, Debug)]
struct FederateAddArgs {
    /// Peer DID to add to the roster.
    #[arg(value_name = "DID")]
    did: String,
    /// Base MCP endpoint for the peer (e.g. https://example.net:7733).
    #[arg(value_name = "URL")]
    endpoint: String,
    /// Optional explicit presence URL (defaults to <endpoint>/presence).
    #[arg(long = "presence", value_name = "URL")]
    presence: Option<String>,
}

#[derive(Args, Debug)]
struct FederateRemoveArgs {
    /// Peer DID to remove from the roster.
    #[arg(value_name = "DID")]
    did: String,
}

#[derive(Args, Debug, Default)]
struct FederateRefreshArgs {
    /// Download all artifacts referenced by the latest index slice.
    #[arg(long)]
    mirror: bool,
}

#[derive(Subcommand, Debug)]
enum RelayCommands {
    /// Register a relay host that can proxy traffic for this node.
    Register(RelayRegisterArgs),
    /// Remove a relay host from the local roster.
    Remove(RelayRemoveArgs),
    /// List registered relay hosts.
    List,
    /// Push the latest presence@2 document to a relay host.
    Push(RelayPushArgs),
}

#[derive(Args, Debug)]
struct RelayRegisterArgs {
    /// Relay host DID to trust.
    #[arg(value_name = "DID")]
    host: String,
    /// Base URL for the relay MCP (e.g. https://relay.example.net:7733).
    #[arg(long = "url", value_name = "URL")]
    url: String,
}

#[derive(Args, Debug)]
struct RelayRemoveArgs {
    /// Relay host DID to remove.
    #[arg(value_name = "DID")]
    host: String,
}

#[derive(Args, Debug)]
struct RelayPushArgs {
    /// Relay host DID to receive the presence document.
    #[arg(long = "to", value_name = "DID")]
    to: String,
}

#[derive(Serialize)]
struct RelayPublishRequest<'a> {
    did: &'a str,
    presence: &'a PresenceDoc,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing()?;

    let cli = Cli::parse();
    match cli.command {
        Commands::Serve(args) => serve(args).await?,
        Commands::Auth(args) => auth(args)?,
        Commands::Federate(cmd) => federate(cmd).await?,
        Commands::Relay(cmd) => relay(cmd).await?,
    }

    Ok(())
}

fn init_tracing() -> Result<()> {
    if tracing::dispatcher::has_been_set() {
        return Ok(());
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .ok();
    Ok(())
}

async fn federate(command: FederateCommands) -> Result<()> {
    let home = ensure_home_dir()?;
    let roster_path = FederationRoster::roster_path(&home);

    match command {
        FederateCommands::Add(args) => handle_federate_add(&home, &roster_path, args)?,
        FederateCommands::Remove(args) => handle_federate_remove(&roster_path, args)?,
        FederateCommands::List => handle_federate_list(&roster_path)?,
        FederateCommands::Refresh(args) => {
            handle_federate_refresh(&home, &roster_path, args).await?
        }
    }

    Ok(())
}

fn handle_federate_add(home: &Path, roster_path: &Path, args: FederateAddArgs) -> Result<()> {
    let mut roster = FederationRoster::load(roster_path)?;
    roster.add_peer(FederationPeerRecord {
        did: args.did.clone(),
        endpoint: args.endpoint.clone(),
        presence: args.presence.clone(),
        cursor: None,
        etag: None,
    })?;
    roster.save(roster_path)?;

    let cache_root = home.join("cache").join("federation");
    if !cache_root.exists() {
        fs::create_dir_all(&cache_root).with_context(|| {
            format!(
                "failed to create federation cache directory {}",
                cache_root.display()
            )
        })?;
    }

    println!(
        "Added federation peer {} (endpoint {}). Cache directory: {}",
        args.did,
        args.endpoint,
        cache_root.display()
    );
    Ok(())
}

fn handle_federate_remove(roster_path: &Path, args: FederateRemoveArgs) -> Result<()> {
    let mut roster = FederationRoster::load(roster_path)?;
    if roster.remove_peer(&args.did) {
        roster.save(roster_path)?;
        println!("Removed federation peer {}", args.did);
        Ok(())
    } else {
        Err(anyhow!("peer '{}' not found in roster", args.did))
    }
}

fn handle_federate_list(roster_path: &Path) -> Result<()> {
    let roster = FederationRoster::load(roster_path)?;
    if roster.peers.is_empty() {
        println!("No federation peers configured.");
        return Ok(());
    }

    println!("{:<36} {:<48} {:<24}", "DID", "Endpoint", "Cursor");
    for peer in roster.peers {
        println!(
            "{:<36} {:<48} {:<24}",
            peer.did,
            peer.endpoint,
            peer.cursor.unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

async fn handle_federate_refresh(
    home: &Path,
    roster_path: &Path,
    args: FederateRefreshArgs,
) -> Result<()> {
    let mut roster = FederationRoster::load(roster_path)?;
    if roster.peers.is_empty() {
        println!("No federation peers configured.");
        return Ok(());
    }

    let (results, changed) = perform_federation_sync(home, &mut roster, args.mirror).await?;

    for result in &results {
        match result.status {
            FederationPeerStatus::Success => {
                if result.latest_cursor.is_some() {
                    if args.mirror {
                        println!(
                            "{}: fetched {} entries, mirrored {} artifacts",
                            result.did, result.fetched_entries, result.mirrored_artifacts
                        );
                    } else {
                        println!("{}: fetched {} entries", result.did, result.fetched_entries);
                    }
                    continue;
                }
                println!("{}: fetched {} entries", result.did, result.fetched_entries);
            }
            FederationPeerStatus::NotModified => {
                println!("{}: up-to-date", result.did);
            }
            FederationPeerStatus::Error(ref err) => {
                println!("{}: ERROR {}", result.did, err);
            }
        }
    }

    if changed {
        roster.save(roster_path)?;
    }
    Ok(())
}

async fn perform_federation_sync(
    home: &Path,
    roster: &mut FederationRoster,
    mirror: bool,
) -> Result<(Vec<FederationPeerResult>, bool)> {
    let cache_root = home.join("cache").join("federation");
    let peers: Vec<FederationPeerConfig> = roster
        .peers
        .iter()
        .map(|peer| FederationPeerConfig {
            did: peer.did.clone(),
            endpoint: peer.endpoint.clone(),
            presence_url: peer.presence.clone(),
            cursor: peer.cursor.clone(),
            etag: peer.etag.clone(),
        })
        .collect();

    if peers.is_empty() {
        return Ok((Vec::new(), false));
    }

    let mut options = FederationSyncOptions::new(cache_root, peers);
    options.user_agent = Some(format!("hn-cli/{}", env!("CARGO_PKG_VERSION")));
    options.mirror_all = mirror;

    let sync = FederationSync::new(options)?;
    let results = sync.sync_once().await;

    let mut changed = false;
    for result in &results {
        if let Some(peer) = roster.find_peer_mut(&result.did) {
            match &result.status {
                FederationPeerStatus::Success => {
                    if let Some(cursor) = result.latest_cursor.clone() {
                        if peer.cursor.as_deref() != Some(cursor.as_str()) {
                            peer.cursor = Some(cursor);
                            changed = true;
                        }
                    }
                    if let Some(hash) = result.canonical_hash.clone() {
                        if peer.etag.as_deref() != Some(hash.as_str()) {
                            peer.etag = Some(hash);
                            changed = true;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok((results, changed))
}

async fn relay(command: RelayCommands) -> Result<()> {
    let home = ensure_home_dir()?;
    let roster_path = RelayRoster::roster_path(&home);

    match command {
        RelayCommands::Register(args) => handle_relay_register(&roster_path, args)?,
        RelayCommands::Remove(args) => handle_relay_remove(&roster_path, args)?,
        RelayCommands::List => handle_relay_list(&roster_path)?,
        RelayCommands::Push(args) => handle_relay_push(&home, &roster_path, args)?,
    }

    Ok(())
}

fn handle_relay_register(roster_path: &Path, args: RelayRegisterArgs) -> Result<()> {
    let mut roster = RelayRoster::load(roster_path)?;
    roster.add_host(RelayHostRecord {
        did: args.host.clone(),
        url: args.url.clone(),
        last_push: None,
        last_expiry: None,
    })?;
    roster.save(roster_path)?;
    println!("Registered relay {} at {}", args.host, args.url);
    Ok(())
}

fn handle_relay_remove(roster_path: &Path, args: RelayRemoveArgs) -> Result<()> {
    let mut roster = RelayRoster::load(roster_path)?;
    if roster.remove_host(&args.host) {
        roster.save(roster_path)?;
        println!("Removed relay host {}", args.host);
        Ok(())
    } else {
        Err(anyhow!("relay host '{}' not found", args.host))
    }
}

fn handle_relay_list(roster_path: &Path) -> Result<()> {
    let roster = RelayRoster::load(roster_path)?;
    if roster.hosts.is_empty() {
        println!("No relay hosts registered.");
        return Ok(());
    }

    println!(
        "{:<36} {:<48} {:<25} {:<25}",
        "Host DID", "URL", "Last Push", "Last Expires"
    );
    for host in roster.hosts {
        println!(
            "{:<36} {:<48} {:<25} {:<25}",
            host.did,
            host.url,
            host.last_push.unwrap_or_else(|| "-".to_string()),
            host.last_expiry.unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

fn handle_relay_push(home: &Path, roster_path: &Path, args: RelayPushArgs) -> Result<()> {
    let mut roster = RelayRoster::load(roster_path)?;
    let host = roster
        .find_host(&args.to)
        .ok_or_else(|| anyhow!("relay host '{}' not registered", args.to))?
        .clone();

    let base_url = host.url.trim_end_matches('/');
    if base_url.is_empty() {
        anyhow::bail!("relay URL for {} is empty", host.did);
    }

    let vault = IdentityVault::new(home.to_path_buf())?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity; run `hn id use <alias>`"))?;
    let identity = vault.load_identity(&active.alias)?;

    let mut docs = load_presence_docs(home, &active.alias)?;
    if docs.is_empty() {
        anyhow::bail!("no local presence documents found for {}", active.alias);
    }
    docs.sort_by(|a, b| b.issued_at.cmp(&a.issued_at));
    let presence = docs.first().unwrap();
    if presence.signature.is_none() {
        anyhow::bail!(
            "latest presence document is unsigned; run `hn discover publish` before pushing"
        );
    }

    if !presence.relays.is_empty() && !presence.relays.iter().any(|relay| relay.host == host.did) {
        println!(
            "warning: presence document does not advertise relay {}; peers may ignore it",
            host.did
        );
    }

    let request = RelayPublishRequest {
        did: &identity.profile.id,
        presence,
    };
    let body = serde_json::to_string(&request)?;
    let timestamp = OffsetDateTime::now_utc();
    let timestamp_secs = timestamp.unix_timestamp();
    let body_hash = canonical_body_hash(&request)?;
    let message = canonical_request_message("POST", "/relay/publish", timestamp_secs, &body_hash);
    let signature = identity.keys.signing_key().sign(message.as_bytes());
    let signature_b64 = Base64.encode(signature.to_bytes());

    let url = format!("{}/relay/publish", base_url);
    let response = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set("X-HN-DID", &identity.profile.id)
        .set("X-HN-Timestamp", &timestamp_secs.to_string())
        .set("X-HN-Signature", &signature_b64)
        .set("Digest", &format!("blake3={}", body_hash))
        .send_string(&body)
        .map_err(|err| anyhow!("relay publish failed: {err}"))?;

    let status = response.status();
    if !(200..300).contains(&status) {
        let details = response.into_string().unwrap_or_default();
        anyhow::bail!("relay publish failed with status {}: {}", status, details);
    }

    let payload: serde_json::Value = response
        .into_json()
        .map_err(|err| anyhow!("relay publish returned invalid JSON: {err}"))?;
    let final_expiry = payload
        .get("expires_at")
        .and_then(|value| value.as_str())
        .map(|s| s.to_string());
    let source_expiry = payload
        .get("source_expires_at")
        .and_then(|value| value.as_str())
        .map(|s| s.to_string());

    if let Some(record) = roster.find_host_mut(&args.to) {
        record.last_push = Some(timestamp.format(&Rfc3339)?);
        record.last_expiry = final_expiry.clone();
    }
    roster.save(roster_path)?;

    println!(
        "Pushed presence for {} to relay {}",
        identity.profile.id, host.did
    );
    if let Some(expiry) = final_expiry {
        match source_expiry {
            Some(ref src) if src != &expiry => {
                println!(
                    "Relay retention ends at {} (source presence expires at {})",
                    expiry, src
                );
            }
            _ => println!("Relay retention ends at {}", expiry),
        }
    }
    Ok(())
}

async fn serve(args: ServeArgs) -> Result<()> {
    let home = ensure_home_dir()?;
    let config_path = resolve_config_path(&home, args.config.as_ref());
    let mut config = read_or_create_config(&home, &config_path)?;

    if let Some(profile) = args.profile.as_deref() {
        apply_profile(profile, &mut config, &home)?;
    }

    if let Some(listen) = args.listen {
        config.listen = listen;
    }
    if let Some(mode) = args.mode {
        config.mode = mode;
    }
    if let Some(storage) = args.storage {
        config.storage = if storage.is_relative() {
            home.join(&storage)
        } else {
            storage
        };
    }
    if let Some(ttl) = args.max_ttl_seconds {
        config.max_ttl_seconds = ttl;
    }
    if let Some(presence) = args.presence_path {
        config.presence_path = Some(if presence.is_relative() {
            home.join(presence)
        } else {
            presence
        });
    }
    if let Some(trust_path) = args.trust_path {
        config.trust_path = Some(if trust_path.is_relative() {
            home.join(trust_path)
        } else {
            trust_path
        });
    }

    if let Ok(value) = env::var("HN_RELAY_TTL_SECS") {
        match value.parse::<u64>() {
            Ok(ttl) => config.relay_ttl_seconds = ttl,
            Err(_) => warn!(
                "ignoring invalid HN_RELAY_TTL_SECS value '{}' (expected unsigned integer)",
                value
            ),
        }
    }

    if let Some(relay_ttl) = args.relay_ttl_seconds {
        config.relay_ttl_seconds = relay_ttl;
    }

    ensure_dir(&config.storage, "MCP storage")?;
    if let Some(path) = config.presence_path.as_ref() {
        if let Some(parent) = path.parent() {
            ensure_dir(parent, "presence directory")?;
        }
    }
    if let Some(path) = config.trust_path.as_ref() {
        ensure_dir(path, "trust directory root")?;
    }

    let vault = IdentityVault::new(home.clone())?;
    let signing_alias = if let Some(alias) = args.signing_alias.clone() {
        alias
    } else {
        vault
            .active_identity()?
            .ok_or_else(|| anyhow!("no active identity; specify --signing-alias"))?
            .alias
    };
    let record = vault.load_identity(&signing_alias)?;
    let signing_key = SigningKey::from_bytes(&record.keys.signing_key().to_bytes());

    info!(
        "starting MCP server on {} (mode={}, storage={}, presence_path={:?})",
        config.listen,
        config.mode,
        config.storage.display(),
        config
            .presence_path
            .as_ref()
            .map(|p| p.display().to_string())
    );

    let scheme = if config.tls.is_some() {
        "https"
    } else {
        "http"
    };
    let base_url = config
        .public_url
        .clone()
        .unwrap_or_else(|| format!("{scheme}://{}", config.listen));
    let presence_url = format!("{}/.well-known/hn/presence", base_url.trim_end_matches('/'));
    let readiness = json!({
        "status": "ready",
        "did": record.profile.id,
        "listen": config.listen.to_string(),
        "base_url": base_url,
        "presence_url": presence_url,
        "mode": config.mode.to_string(),
    });
    println!("MCP_READY {}", readiness);
    let _ = io::stdout().flush();

    let server = McpServer::new(config, Some(signing_key))?;
    let worker_handle = spawn_federation_worker(home.clone());

    let result = server.run().await;

    if let Some(handle) = worker_handle {
        handle.abort();
        let _ = handle.await;
    }

    result
}

fn spawn_federation_worker(home: PathBuf) -> Option<JoinHandle<()>> {
    if env_flag("HN_DISABLE_FEDERATION_WORKER") {
        debug!("federation worker disabled via environment");
        return None;
    }

    let interval_secs = env::var("HN_FEDERATION_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(300);
    let mirror = env_flag("HN_FEDERATION_WORKER_MIRROR");

    info!(
        "starting federation worker (interval={}s, mirror={})",
        interval_secs, mirror
    );

    Some(tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs);
        run_federation_worker(home, interval, mirror).await;
    }))
}

async fn run_federation_worker(home: PathBuf, interval: Duration, mirror: bool) {
    let roster_path = FederationRoster::roster_path(&home);
    loop {
        match federation_worker_iteration(&home, &roster_path, mirror).await {
            Ok(Some(results)) => {
                for result in results {
                    match &result.status {
                        FederationPeerStatus::Success => info!(
                            event = "federation.sync.success",
                            peer = %result.did,
                            entries = result.fetched_entries,
                            mirrored = result.mirrored_artifacts,
                            "federation sync succeeded"
                        ),
                        FederationPeerStatus::NotModified => debug!(
                            event = "federation.sync.skipped",
                            peer = %result.did,
                            "federation peer already up-to-date"
                        ),
                        FederationPeerStatus::Error(err) => warn!(
                            event = "federation.sync.failure",
                            peer = %result.did,
                            error = %err,
                            "federation sync failed"
                        ),
                    }
                }
            }
            Ok(None) => {
                debug!(
                    event = "federation.sync.idle",
                    "no federation peers configured; worker idle"
                );
            }
            Err(err) => warn!(
                event = "federation.sync.failure",
                error = %err,
                "federation sync iteration failed"
            ),
        }

        sleep(interval).await;
    }
}

async fn federation_worker_iteration(
    home: &Path,
    roster_path: &Path,
    mirror: bool,
) -> Result<Option<Vec<FederationPeerResult>>> {
    if !roster_path.exists() {
        return Ok(None);
    }

    let mut roster = FederationRoster::load(roster_path)?;
    if roster.peers.is_empty() {
        return Ok(None);
    }

    let (results, changed) = perform_federation_sync(home, &mut roster, mirror).await?;
    if changed {
        roster.save(roster_path)?;
    }

    Ok(Some(results))
}

fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn resolve_config_path(home: &Path, explicit: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = explicit {
        if path.is_absolute() {
            return path.clone();
        }
        return home.join(path);
    }
    home.join("mcp.json")
}

fn read_or_create_config(home: &Path, path: &Path) -> Result<McpConfig> {
    if path.exists() {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read MCP config at {}", path.display()))?;
        let mut cfg: McpConfig =
            serde_json::from_str(&data).context("MCP config is not valid JSON")?;
        if cfg.storage.is_relative() {
            cfg.storage = home.join(&cfg.storage);
        }
        if let Some(presence) = cfg.presence_path.clone() {
            if presence.is_relative() {
                cfg.presence_path = Some(home.join(presence));
            }
        }
        if let Some(trust_path) = cfg.trust_path.clone() {
            if trust_path.is_relative() {
                cfg.trust_path = Some(home.join(trust_path));
            }
        } else {
            cfg.trust_path = Some(home.join("trust"));
        }
        return Ok(cfg);
    }

    let mut cfg = McpConfig::for_home(home);
    cfg.storage = home.join("mcp/storage");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create MCP config directory {}", parent.display())
        })?;
    }

    let json = serde_json::to_string_pretty(&cfg).expect("serialising default MCP config failed");
    fs::write(path, json)
        .with_context(|| format!("failed to write default MCP config to {}", path.display()))?;
    info!("created default MCP config at {}", path.display());
    Ok(cfg)
}

fn ensure_dir(path: &Path, label: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(path).with_context(|| format!("failed to create {label} {}", path.display()))
}

fn apply_profile(name: &str, config: &mut McpConfig, home: &Path) -> Result<()> {
    match name {
        "federation" => {
            let default_storage = home.join("mcp/storage");
            if config.storage == default_storage {
                config.storage = home.join("mcp/federation/storage");
            }
            config.mode = McpMode::Public;
            config.max_ttl_seconds = 60 * 60 * 24 * 7;
            if config.presence_path.is_none() {
                config.presence_path = Some(home.join("presence/latest.json"));
            }
            if config.trust_path.is_none() {
                config.trust_path = Some(home.join("trust"));
            }
            if config.public_url.is_none() {
                match std::env::var("HN_PUBLIC_URL") {
                    Ok(url) => config.public_url = Some(url),
                    Err(_) => warn!(
                        "HN_PUBLIC_URL not set; federation profile will advertise {}",
                        config.listen
                    ),
                }
            }
            if config.tls.is_none() {
                match (
                    std::env::var("HN_TLS_CERT").ok(),
                    std::env::var("HN_TLS_KEY").ok(),
                ) {
                    (Some(cert), Some(key)) => {
                        config.tls = Some(TlsConfig {
                            cert_path: home.join(cert),
                            key_path: home.join(key),
                        });
                    }
                    _ => {}
                }
            }
            info!("applied federation profile defaults");
            Ok(())
        }
        other => Err(anyhow!(format!("unknown profile '{other}'"))),
    }
}

fn auth(args: AuthArgs) -> Result<()> {
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
    let did = record.profile.id.clone();
    let signing_key = record.keys.signing_key();

    let body_text = fs::read_to_string(&args.body)
        .with_context(|| format!("failed to read body file {}", args.body.display()))?;
    let request: PublishRequest =
        serde_json::from_str(&body_text).context("failed to parse body as MCP publish request")?;

    let timestamp = args
        .timestamp
        .unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());

    let body_hash = canonical_body_hash(&request)?;
    let message = canonical_request_message(&args.method, &args.path, timestamp, &body_hash);
    let signature = signing_key.sign(message.as_bytes());
    let signature_b64 = Base64.encode(signature.to_bytes());

    let headers = json!({
        "X-HN-DID": did,
        "X-HN-Timestamp": timestamp,
        "X-HN-Signature": signature_b64,
        "Digest": format!("blake3={}", body_hash),
        "Canonical-Message": message,
    });

    println!("{}", serde_json::to_string_pretty(&headers)?);
    Ok(())
}
