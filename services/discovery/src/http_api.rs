use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use hn_cli::discovery::dht::{presence_url_from_doc, publish_hint as sign_hint};
use hn_cli::discovery::PresenceDoc;
use hn_cli::identity::IdentityVault;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;

use crate::dht::DhtHandle;
use crate::peer_table::PeerTable;
use crate::types::{LocalPeer, PeerPayload};

pub async fn serve_http(
    local_peer: LocalPeer,
    peer_table: PeerTable,
    listen_addr: SocketAddr,
    dht_handle: Option<DhtHandle>,
    vault: Arc<IdentityVault>,
    shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let state = Arc::new(AppState {
        local_peer,
        peer_table,
        start_time: Instant::now(),
        dht: dht_handle,
        vault,
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/peers", get(list_peers))
        .route("/dht/publish", post(publish_hint))
        .route("/dht/:did", get(fetch_hint))
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
    dht: Option<DhtHandle>,
    vault: Arc<IdentityVault>,
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

#[derive(Debug, Deserialize)]
struct PublishRequest {
    presence: PresenceDoc,
    #[serde(default)]
    presence_url: Option<String>,
}

async fn publish_hint(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PublishRequest>,
) -> impl IntoResponse {
    let Some(dht) = &state.dht else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "dht disabled"})),
        );
    };

    let doc = body.presence;
    let presence_url = match body.presence_url {
        Some(url) => url,
        None => match presence_url_from_doc(&doc) {
            Ok(url) => url,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("{err}") })),
                )
            }
        },
    };

    let hint = match sign_hint(&state.vault, &doc, &presence_url) {
        Ok(hint) => hint,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("{err}") })),
            )
        }
    };

    match dht.publish(hint.clone()).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "hint": to_value(&hint).unwrap_or(json!({})) })),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("{err}") })),
        ),
    }
}

async fn fetch_hint(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let Some(dht) = &state.dht else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "dht disabled"})),
        );
    };
    match dht.resolve(did).await {
        Ok(Some(hint)) => (StatusCode::OK, Json(to_value(&hint).unwrap_or(json!({})))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "hint not found" })),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("{err}") })),
        ),
    }
}
