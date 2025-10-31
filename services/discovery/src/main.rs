//! Human.Net discovery service: announces the local node via mDNS, tracks peers,
//! and serves a lightweight HTTP API for CLI consumers.

mod dht;
mod http_api;
mod mdns;
mod peer_table;
mod types;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use crate::dht::{spawn as spawn_dht, DhtConfig};
use crate::http_api::serve_http;
use crate::mdns::MdnsHandle;
use crate::peer_table::{spawn_purge_task, PeerTable};
use crate::types::LocalPeer;

#[derive(Parser, Debug)]
#[command(
    name = "hn-discovery",
    version,
    about = "Human.Net local discovery daemon"
)]
struct Cli {
    /// Address for the HTTP status server (host:port).
    #[arg(long = "listen", default_value = "127.0.0.1:7710")]
    listen: SocketAddr,

    /// TTL (seconds) before a peer entry is considered stale.
    #[arg(long = "peer-ttl", default_value_t = 180)]
    peer_ttl: u64,

    /// Service type advertised over mDNS.
    #[arg(long = "service-type", default_value = "_human-net._tcp.local.")]
    service_type: String,

    /// Disable mDNS announcements and discovery.
    #[arg(long = "no-mdns")]
    no_mdns: bool,

    /// Override Human.Net home directory.
    #[arg(long = "home")]
    home: Option<PathBuf>,

    /// Disable Kademlia DHT worker.
    #[arg(long = "no-dht")]
    no_dht: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let home = match cli.home {
        Some(path) => path,
        None => ensure_home_dir()?,
    };

    let vault = Arc::new(
        IdentityVault::new(home.clone())
            .context("failed to open Human.Net identity vault; run `hn id` first")?,
    );
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity configured; run `hn id use <alias>`"))?;
    let identity = vault
        .load_identity(&active.alias)
        .with_context(|| format!("failed to load identity '{}'", active.alias))?;

    let local_peer = LocalPeer::from_identity(identity, cli.listen, cli.service_type.clone())?;
    info!(alias = %local_peer.alias, did = %local_peer.did, "discovery service starting");

    let peer_table = PeerTable::new();
    let mdns_handle = if cli.no_mdns {
        info!("mDNS disabled via --no-mdns");
        None
    } else {
        match MdnsHandle::start(local_peer.clone(), peer_table.clone()) {
            Ok(handle) => Some(handle),
            Err(err) => {
                warn!(%err, "mDNS unavailable; continuing without LAN discovery");
                None
            }
        }
    };

    let dht_config = if cli.no_dht {
        DhtConfig {
            enabled: false,
            ..Default::default()
        }
    } else {
        read_dht_config(&home).unwrap_or_else(|err| {
            tracing::warn!(%err, "failed to read DHT config; using defaults");
            DhtConfig {
                enabled: true,
                listen: Vec::new(),
                bootstrap: Vec::new(),
            }
        })
    };
    let identity_for_dht = vault
        .load_identity(&active.alias)
        .with_context(|| format!("failed to load identity '{}'", active.alias))?;
    let (mut dht_handle, mut dht_task) = match spawn_dht(&identity_for_dht, dht_config, &home)? {
        Some((handle, task)) => (Some(handle), Some(task)),
        None => (None, None),
    };
    let (http_shutdown_tx, http_shutdown_rx) = oneshot::channel();
    let http_task = tokio::spawn(serve_http(
        local_peer.clone(),
        peer_table.clone(),
        cli.listen,
        dht_handle.clone(),
        Arc::clone(&vault),
        http_shutdown_rx,
    ));

    let purge_handle = spawn_purge_task(peer_table.clone(), Duration::from_secs(cli.peer_ttl));

    signal::ctrl_c()
        .await
        .context("failed to receive shutdown signal")?;
    info!("shutdown signal received; stopping discovery");

    if let Some(handle) = mdns_handle {
        handle.shutdown();
    }
    if let Some(handle) = dht_handle.take() {
        if let Err(err) = handle.shutdown().await {
            error!(%err, "failed to shutdown DHT worker");
        }
    }
    if let Some(task) = dht_task.as_mut() {
        let _ = task.await;
    }
    let _ = http_shutdown_tx.send(());

    if let Err(err) = http_task.await {
        error!(%err, "http task terminated unexpectedly");
    }

    purge_handle.abort();

    info!("discovery service stopped");
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::filter::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn read_dht_config(home: &Path) -> Result<DhtConfig> {
    let path = home.join("discovery").join("dht.toml");
    if !path.exists() {
        return Ok(DhtConfig {
            enabled: true,
            listen: vec![],
            bootstrap: vec![],
        });
    }
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read DHT config at {}", path.display()))?;
    let cfg: DhtConfig = toml::from_str(&data)
        .with_context(|| format!("DHT config {} is invalid", path.display()))?;
    Ok(cfg)
}
