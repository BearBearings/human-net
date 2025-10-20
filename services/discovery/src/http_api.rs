use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;

use crate::peer_table::PeerTable;
use crate::types::{LocalPeer, PeerPayload};

pub async fn serve_http(
    local_peer: LocalPeer,
    peer_table: PeerTable,
    listen_addr: SocketAddr,
    shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let state = Arc::new(AppState {
        local_peer,
        peer_table,
        start_time: Instant::now(),
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/peers", get(list_peers))
        .with_state(state.clone());

    let listener = TcpListener::bind(listen_addr).await?;
    info!(address = %listen_addr, "http server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.await;
            info!("http shutdown signal received");
        })
        .await
        .map_err(Into::into)
}

#[derive(Clone)]
struct AppState {
    local_peer: LocalPeer,
    peer_table: PeerTable,
    start_time: Instant,
}

async fn healthz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let peer_count = state.peer_table.len();
    let payload = HealthResponse {
        status: "ok",
        uptime_seconds: uptime,
        peer_count,
        self_alias: state.local_peer.alias.clone(),
        self_did: state.local_peer.did.clone(),
    };
    (StatusCode::OK, Json(payload))
}

async fn list_peers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let peers = state
        .peer_table
        .list()
        .into_iter()
        .map(PeerPayload::from)
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(peers))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_seconds: u64,
    peer_count: usize,
    self_alias: String,
    self_did: String,
}
