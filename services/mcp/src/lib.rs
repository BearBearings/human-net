mod storage;
mod types;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use axum::extract::Path as AxumPath;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize as SerdeSerialize;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub use storage::{McpStorage, PublishArtifact, PublishRequest};
pub use types::{compute_merkle_root, ShardIndex, ShardIndexEntry};

const AUTH_WINDOW_SECS: i64 = 5 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpMode {
    Friends,
    Public,
}

impl Default for McpMode {
    fn default() -> Self {
        McpMode::Friends
    }
}

impl FromStr for McpMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "friends" => Ok(McpMode::Friends),
            "public" => Ok(McpMode::Public),
            other => Err(format!(
                "unknown MCP mode '{other}' (expected 'friends' or 'public')"
            )),
        }
    }
}

impl std::fmt::Display for McpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpMode::Friends => write!(f, "friends"),
            McpMode::Public => write!(f, "public"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerConfig {
    pub did: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    pub listen: SocketAddr,
    #[serde(default)]
    pub mode: McpMode,
    #[serde(default = "default_max_ttl_seconds")]
    pub max_ttl_seconds: u64,
    #[serde(default = "default_storage_path")]
    pub storage: PathBuf,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub allow: Vec<PeerConfig>,
}

fn default_max_ttl_seconds() -> u64 {
    60 * 60 * 24 * 7
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("./mcp-cache")
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 7733)),
            mode: McpMode::default(),
            max_ttl_seconds: default_max_ttl_seconds(),
            storage: default_storage_path(),
            tls: None,
            allow: Vec::new(),
        }
    }
}

impl McpConfig {
    pub fn for_home(home: &Path) -> Self {
        let mut cfg = Self::default();
        cfg.storage = home.join("mcp/storage");
        cfg
    }
}

#[derive(Debug, Clone, Serialize)]
struct HealthzResponse {
    status: &'static str,
    mode: McpMode,
    uptime_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle_root: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct IndexResponse {
    merkle_root: Option<String>,
    entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<ShardIndex>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishResponse {
    accepted: bool,
    index_id: String,
    merkle_root: String,
    entries: usize,
}

struct ServerState {
    started: Instant,
    mode: McpMode,
    storage: Arc<McpStorage>,
    last_index: RwLock<Option<ShardIndex>>,
    allowlist: HashMap<String, VerifyingKey>,
}

impl ServerState {
    fn requires_auth(&self) -> bool {
        matches!(self.mode, McpMode::Friends)
    }
}

pub struct McpServer {
    config: McpConfig,
    state: Arc<ServerState>,
}

impl McpServer {
    pub fn new(config: McpConfig) -> Result<Self> {
        let storage = Arc::new(McpStorage::new(config.storage.clone())?);
        let initial_index = storage.load_index()?;
        let allowlist = build_allowlist(&config.allow)?;
        if matches!(config.mode, McpMode::Friends) && allowlist.is_empty() {
            warn!("MCP friends mode enabled but allowlist is empty");
        }

        let state = Arc::new(ServerState {
            started: Instant::now(),
            mode: config.mode.clone(),
            storage,
            last_index: RwLock::new(initial_index),
            allowlist,
        });

        Ok(Self { config, state })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            "MCP server listening on {} (mode={}, storage={})",
            self.config.listen,
            self.state.mode,
            self.config.storage.display()
        );

        if let Some(tls) = &self.config.tls {
            let rustls_config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to load TLS material (cert={}, key={})",
                        tls.cert_path.display(),
                        tls.key_path.display()
                    )
                })?;
            let router = self.router();
            let make_service = router.into_make_service();
            let handle = Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
            });

            axum_server::bind_rustls(self.config.listen, rustls_config)
                .handle(handle)
                .serve(make_service)
                .await
                .context("MCP server (TLS) terminated unexpectedly")?;
        } else {
            let router = self.router();
            let make_service = router.into_make_service();
            let listener = TcpListener::bind(self.config.listen)
                .await
                .with_context(|| format!("failed to bind MCP server on {}", self.config.listen))?;

            axum::serve(listener, make_service)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .context("MCP server terminated unexpectedly")?;
        }

        Ok(())
    }

    fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(healthz_handler))
            .route("/index", get(index_handler))
            .route("/shard/:id", get(shard_handler))
            .route("/artifact/*path", get(artifact_handler))
            .route("/publish", post(publish_handler))
            .layer(Extension(self.state.clone()))
    }
}

async fn healthz_handler(Extension(state): Extension<Arc<ServerState>>) -> Json<HealthzResponse> {
    let uptime = state.started.elapsed().as_secs();
    let merkle = state
        .last_index
        .read()
        .await
        .as_ref()
        .map(|index| index.merkle_root.clone());
    Json(HealthzResponse {
        status: "ok",
        mode: state.mode.clone(),
        uptime_seconds: uptime,
        merkle_root: merkle,
    })
}

async fn index_handler(Extension(state): Extension<Arc<ServerState>>) -> Json<IndexResponse> {
    let index = state.last_index.read().await.clone();
    let entries = index.as_ref().map(|idx| idx.entries.len()).unwrap_or(0);
    Json(IndexResponse {
        merkle_root: index.as_ref().map(|idx| idx.merkle_root.clone()),
        entries,
        index,
    })
}

async fn shard_handler(
    Extension(state): Extension<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let index = match state.last_index.read().await.clone() {
        Some(index) => index,
        None => return api_error(StatusCode::NOT_FOUND, "no index published yet"),
    };

    let entry = match index
        .entries
        .iter()
        .find(|entry| entry.kind == "shard" && entry.id == id)
    {
        Some(entry) => entry.clone(),
        None => {
            return api_error(
                StatusCode::NOT_FOUND,
                format!("shard '{}' not found in index", id),
            )
        }
    };

    stream_artifact(state, entry.path, "application/json").await
}

async fn artifact_handler(
    Extension(state): Extension<Arc<ServerState>>,
    AxumPath(path): AxumPath<String>,
) -> Response {
    let index = match state.last_index.read().await.clone() {
        Some(index) => index,
        None => return api_error(StatusCode::NOT_FOUND, "no index published yet"),
    };

    if !index.entries.iter().any(|entry| entry.path == path) {
        return api_error(
            StatusCode::NOT_FOUND,
            format!("artifact '{}' not found in index", path),
        );
    }

    let content_type = detect_content_type(&path);
    stream_artifact(state, path, content_type).await
}

async fn publish_handler(
    Extension(state): Extension<Arc<ServerState>>,
    headers: HeaderMap,
    Json(body): Json<PublishRequest>,
) -> Result<Json<PublishResponse>, Response> {
    authorize_publish(&state, &headers, &body)?;

    let storage = state.storage.clone();
    let request = body.clone();
    let publish_result = tokio::task::spawn_blocking(move || storage.apply_publish(request)).await;

    let index = match publish_result {
        Ok(Ok(index)) => index,
        Ok(Err(err)) => {
            warn!(error = %err, "publish payload rejected");
            return Err(api_error(StatusCode::BAD_REQUEST, err.to_string()));
        }
        Err(err) => {
            error!(?err, "publish task panicked");
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "publish worker failed",
            ));
        }
    };

    {
        let mut guard = state.last_index.write().await;
        *guard = Some(index.clone());
    }

    Ok(Json(PublishResponse {
        accepted: true,
        index_id: index.id.clone(),
        merkle_root: index.merkle_root.clone(),
        entries: index.entries.len(),
    }))
}

fn authorize_publish(
    state: &ServerState,
    headers: &HeaderMap,
    payload: &PublishRequest,
) -> Result<(), Response> {
    if !state.requires_auth() {
        return Ok(());
    }

    let did = headers
        .get("x-hn-did")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing x-hn-did header"))?;

    let verifying_key = state.allowlist.get(did).ok_or_else(|| {
        api_error(
            StatusCode::UNAUTHORIZED,
            format!("DID '{}' not allowed to publish", did),
        )
    })?;

    let timestamp_raw = headers
        .get("x-hn-timestamp")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing x-hn-timestamp header"))?;
    let timestamp: i64 = timestamp_raw
        .parse()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid x-hn-timestamp header"))?;

    let ts = OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "x-hn-timestamp out of range"))?;
    let now = OffsetDateTime::now_utc();
    let window = TimeDuration::seconds(AUTH_WINDOW_SECS);
    let skew = (now - ts).abs();
    if skew > window {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "timestamp outside allowed window (±5m)",
        ));
    }

    let signature_raw = headers
        .get("x-hn-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing x-hn-signature header"))?;
    let signature_bytes = Base64
        .decode(signature_raw.as_bytes())
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "signature must be base64"))?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);

    let body_hash = canonical_body_hash(payload).map_err(|err| {
        api_error(
            StatusCode::BAD_REQUEST,
            format!("failed to canonicalise payload: {err}"),
        )
    })?;
    let message = canonical_request_message("POST", "/publish", timestamp, &body_hash);

    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "signature verification failed"))
}

async fn stream_artifact(
    state: Arc<ServerState>,
    path: String,
    content_type: &'static str,
) -> Response {
    let storage = state.storage.clone();
    let read = tokio::task::spawn_blocking(move || storage.read_artifact(&path)).await;

    let data = match read {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            error!(error = %err, "failed to read artifact");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to read artifact");
        }
        Err(err) => {
            error!(?err, "artifact read task panicked");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "artifact loader worker failed",
            );
        }
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, HeaderValue::from_static(content_type))],
        data,
    )
        .into_response()
}

fn detect_content_type(path: &str) -> &'static str {
    if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn build_allowlist(peers: &[PeerConfig]) -> Result<HashMap<String, VerifyingKey>> {
    let mut map = HashMap::new();
    for peer in peers {
        if peer.did.trim().is_empty() {
            return Err(anyhow!("allowlist entry missing DID"));
        }
        let key_bytes = Base64
            .decode(peer.public_key.as_bytes())
            .with_context(|| format!("invalid public key encoding for {}", peer.did))?;
        let verifying_key = VerifyingKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("public key must be 32 bytes for {}", peer.did))?,
        )
        .with_context(|| format!("failed to parse verifying key for {}", peer.did))?;
        map.insert(peer.did.clone(), verifying_key);
    }
    Ok(map)
}

pub fn canonical_body_hash<T: SerdeSerialize>(value: &T) -> Result<String> {
    let canonical = serde_jcs::to_string(value)?;
    Ok(blake3::hash(canonical.as_bytes()).to_hex().to_string())
}

pub fn canonical_request_message(
    method: &str,
    path: &str,
    timestamp: i64,
    body_hash: &str,
) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        timestamp,
        body_hash
    )
}

fn api_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("received Ctrl+C");
        }
        _ = terminate => {
            info!("received terminate signal");
        }
    }
}
