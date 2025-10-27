use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::Signer;
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use hn_mcp::{
    canonical_body_hash, canonical_request_message, McpConfig, McpMode, McpServer, PublishRequest,
};
use serde_json::{self, json};
use time::OffsetDateTime;
use tracing::info;
use tracing_subscriber::EnvFilter;

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
}

#[derive(Args, Debug)]
struct ServeArgs {
    /// Optional path to MCP configuration JSON (defaults to $HN_HOME/mcp.json).
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

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

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing()?;

    let cli = Cli::parse();
    match cli.command {
        Commands::Serve(args) => serve(args).await?,
        Commands::Auth(args) => auth(args)?,
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

async fn serve(args: ServeArgs) -> Result<()> {
    let home = ensure_home_dir()?;
    let config_path = resolve_config_path(&home, args.config.as_ref());
    let mut config = read_or_create_config(&home, &config_path)?;

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

    if !config.storage.exists() {
        fs::create_dir_all(&config.storage).with_context(|| {
            format!(
                "failed to create MCP storage directory {}",
                config.storage.display()
            )
        })?;
    }

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

    let server = McpServer::new(config)?;
    server.run().await
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
