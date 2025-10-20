//! Human.Net discovery service: announces the local node via mDNS, tracks peers,
//! and serves a lightweight HTTP API for CLI consumers.

mod http_api;
mod mdns;
mod peer_table;
mod types;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hn_cli::home::ensure_home_dir;
use hn_cli::identity::IdentityVault;
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{error, info};

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

    /// Override Human.Net home directory.
    #[arg(long = "home")]
    home: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let home = match cli.home {
        Some(path) => path,
        None => ensure_home_dir()?,
    };

    let vault = IdentityVault::new(home)
        .context("failed to open Human.Net identity vault; run `hn id` first")?;
    let active = vault
        .active_identity()?
        .ok_or_else(|| anyhow!("no active identity configured; run `hn id use <alias>`"))?;
    let identity = vault
        .load_identity(&active.alias)
        .with_context(|| format!("failed to load identity '{}'", active.alias))?;

    let local_peer = LocalPeer::from_identity(identity, cli.listen, cli.service_type.clone())?;
    info!(alias = %local_peer.alias, did = %local_peer.did, "discovery service starting");

    let peer_table = PeerTable::new();
    let mdns_handle = MdnsHandle::start(local_peer.clone(), peer_table.clone())?;

    let (http_shutdown_tx, http_shutdown_rx) = oneshot::channel();
    let http_task = tokio::spawn(serve_http(
        local_peer.clone(),
        peer_table.clone(),
        cli.listen,
        http_shutdown_rx,
    ));

    let purge_handle = spawn_purge_task(peer_table.clone(), Duration::from_secs(cli.peer_ttl));

    signal::ctrl_c()
        .await
        .context("failed to receive shutdown signal")?;
    info!("shutdown signal received; stopping discovery");

    mdns_handle.shutdown();
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
