mod backup;
pub mod federation;
pub mod relay;
mod storage;
pub mod trust;
mod types;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use axum::extract::{Path as AxumPath, Query};
use axum::http::header::{HeaderName, CONTENT_DISPOSITION, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use blake3;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::Serialize as SerdeSerialize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::backup::{
    backup_directory, backup_index_path, build_backup_header, owner_slug_from_did,
    sanitize_component as backup_sanitize_component, verify_backup_document, BackupDocument,
    BackupHeader,
};
use crate::federation::{compute_presence_digest, default_slice_cursor, FederatedIndexSlice};
use crate::relay::RelayRegistry;
use crate::trust::load_latest_reputation;

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
    #[serde(default)]
    pub presence_path: Option<PathBuf>,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub trust_path: Option<PathBuf>,
    #[serde(default = "default_relay_ttl_seconds")]
    pub relay_ttl_seconds: u64,
}

fn default_max_ttl_seconds() -> u64 {
    60 * 60 * 24 * 7
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("./mcp-cache")
}

fn default_relay_ttl_seconds() -> u64 {
    900
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
            presence_path: None,
            public_url: None,
            trust_path: None,
            relay_ttl_seconds: default_relay_ttl_seconds(),
        }
    }
}

impl McpConfig {
    pub fn for_home(home: &Path) -> Self {
        let mut cfg = Self::default();
        cfg.storage = home.join("mcp/storage");
        cfg.trust_path = Some(home.join("trust"));
        cfg.relay_ttl_seconds = default_relay_ttl_seconds();
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayPublishRequest {
    did: String,
    presence: Value,
}

#[derive(Debug, Clone, Serialize)]
struct RelayPublishResponse {
    stored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BackupUploadResponse {
    stored: bool,
    id: String,
    owner: String,
}

#[derive(Debug, Clone, Deserialize)]
struct BackupQuery {
    #[serde(default)]
    include: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupIndexRecord {
    owner: String,
}

struct ServerState {
    started: Instant,
    mode: McpMode,
    storage: Arc<McpStorage>,
    last_index: RwLock<Option<ShardIndex>>,
    allowlist: HashMap<String, VerifyingKey>,
    presence_path: Option<PathBuf>,
    signing_key: Option<[u8; 32]>,
    public_url: String,
    relay_registry: Arc<RelayRegistry>,
    trust_path: Option<PathBuf>,
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
    pub fn new(config: McpConfig, signing_key: Option<SigningKey>) -> Result<Self> {
        let storage = Arc::new(McpStorage::new(config.storage.clone())?);
        let initial_index = storage.load_index()?;
        let allowlist = build_allowlist(&config.allow)?;
        if matches!(config.mode, McpMode::Friends) && allowlist.is_empty() {
            warn!("MCP friends mode enabled but allowlist is empty");
        }

        let signing_key_bytes = signing_key.map(|key| key.to_bytes());
        let relay_registry = Arc::new(RelayRegistry::new(
            config.storage.join("relay"),
            config.relay_ttl_seconds,
        )?);
        let trust_path = config.trust_path.clone();
        let public_url = config
            .public_url
            .clone()
            .unwrap_or_else(|| format!("http://{}", config.listen));

        let state = Arc::new(ServerState {
            started: Instant::now(),
            mode: config.mode.clone(),
            storage,
            last_index: RwLock::new(initial_index),
            allowlist,
            presence_path: config.presence_path.clone(),
            signing_key: signing_key_bytes,
            public_url,
            relay_registry,
            trust_path,
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
            .route("/presence", get(presence_handler))
            .route("/.well-known/hn/presence", get(presence_handler))
            .route("/trust/:target", get(trust_handler))
            .route("/relay/publish", post(relay_publish_handler))
            .route("/relay/:did/presence", get(relay_presence_handler))
            .route("/backup", post(backup_upload_handler))
            .route("/backup/:id", get(backup_header_handler))
            .route("/backup/:id/blob", get(backup_blob_handler))
            .route("/federate/index", get(federate_index_handler))
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
    authorize_request(&state, &headers, "/publish", &body)?;

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

async fn presence_handler(Extension(state): Extension<Arc<ServerState>>) -> Response {
    let Some(path) = state.presence_path.clone() else {
        return api_error(StatusCode::NOT_FOUND, "presence not configured");
    };

    let read = tokio::task::spawn_blocking(move || std::fs::read(&path)).await;
    let data = match read {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            error!(error = %err, "failed to read presence doc");
            return api_error(StatusCode::NOT_FOUND, "presence document unavailable");
        }
        Err(err) => {
            error!(?err, "presence read task panicked");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "presence loader worker failed",
            );
        }
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        data,
    )
        .into_response()
}

async fn trust_handler(
    Extension(state): Extension<Arc<ServerState>>,
    AxumPath(target): AxumPath<String>,
) -> Response {
    let Some(trust_path) = state.trust_path.clone() else {
        return api_error(StatusCode::NOT_FOUND, "trust data not configured");
    };

    let result =
        tokio::task::spawn_blocking(move || load_latest_reputation(&trust_path, &target)).await;
    let data = match result {
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Ok(None)) => return api_error(StatusCode::NOT_FOUND, "reputation not found"),
        Ok(Err(err)) => {
            error!(error = %err, "failed to load reputation");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to load reputation",
            );
        }
        Err(err) => {
            error!(?err, "reputation loader task panicked");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "reputation loader failed",
            );
        }
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        data,
    )
        .into_response()
}

async fn relay_publish_handler(
    Extension(state): Extension<Arc<ServerState>>,
    headers: HeaderMap,
    Json(body): Json<RelayPublishRequest>,
) -> Result<Json<RelayPublishResponse>, Response> {
    let auth_did = authorize_request(&state, &headers, "/relay/publish", &body)?;
    let effective_did = auth_did.unwrap_or_else(|| body.did.clone());
    if effective_did != body.did {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "x-hn-did header does not match payload did",
        ));
    }

    let presence_did = body
        .presence
        .get("did")
        .and_then(|value| value.as_str())
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "presence payload missing did"))?;
    if presence_did != body.did {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "presence did does not match payload did",
        ));
    }

    let source_expires_at = body
        .presence
        .get("expires_at")
        .and_then(|value| value.as_str())
        .map(|s| s.to_string());

    let registry = state.relay_registry.clone();
    let did = body.did.clone();
    let presence = body.presence.clone();
    let store_result =
        tokio::task::spawn_blocking(move || registry.store_presence(&did, &presence)).await;

    match store_result {
        Ok(Ok(final_expiry)) => {
            let final_string = match final_expiry {
                Some(ts) => match ts.format(&Rfc3339) {
                    Ok(s) => Some(s),
                    Err(err) => {
                        error!(error = %err, "failed to format relay expiry timestamp");
                        None
                    }
                },
                None => None,
            };
            Ok(Json(RelayPublishResponse {
                stored: true,
                expires_at: final_string,
                source_expires_at,
            }))
        }
        Ok(Err(err)) => {
            error!(error = %err, "failed to store relay presence");
            Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist relay presence",
            ))
        }
        Err(err) => {
            error!(?err, "relay presence store task panicked");
            Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "relay registry worker failed",
            ))
        }
    }
}

async fn relay_presence_handler(
    Extension(state): Extension<Arc<ServerState>>,
    AxumPath(did): AxumPath<String>,
) -> Response {
    let registry = state.relay_registry.clone();
    let load = tokio::task::spawn_blocking(move || registry.load_presence(&did)).await;
    let record = match load {
        Ok(Ok(Some(record))) => record,
        Ok(Ok(None)) => {
            return api_error(StatusCode::NOT_FOUND, "relay presence not found");
        }
        Ok(Err(err)) => {
            error!(error = %err, "failed to load relay presence");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to load relay presence",
            );
        }
        Err(err) => {
            error!(?err, "relay presence load task panicked");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "relay presence loader failed",
            );
        }
    };

    let payload = match serde_json::to_vec(&record.document) {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(error = %err, "failed to serialise relay presence");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialise relay presence",
            );
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(expires_at) = record.expires_at {
        if let Ok(value) = expires_at.format(&Rfc3339) {
            if let Ok(header_value) = HeaderValue::from_str(&value) {
                let name = HeaderName::from_static("x-hn-relay-expires-at");
                headers.insert(name, header_value);
            }
        }
    }

    (StatusCode::OK, headers, payload).into_response()
}

async fn backup_upload_handler(
    Extension(state): Extension<Arc<ServerState>>,
    headers: HeaderMap,
    Json(document): Json<BackupDocument>,
) -> Result<(StatusCode, Json<BackupUploadResponse>), Response> {
    let auth_did = authorize_request(&state, &headers, "/backup", &document)?;
    if let Some(did) = auth_did {
        if did != document.owner {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "x-hn-did header does not match backup owner",
            ));
        }
    }

    let storage_root = state.storage.root().to_path_buf();
    let owner = document.owner.clone();
    let backup_id = document.id.clone();
    let result = tokio::task::spawn_blocking(move || store_backup(&storage_root, &document)).await;

    match result {
        Ok(Ok(())) => Ok((
            StatusCode::CREATED,
            Json(BackupUploadResponse {
                stored: true,
                id: backup_id,
                owner,
            }),
        )),
        Ok(Err(err)) => {
            error!(error = %err, "failed to store backup");
            Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist backup",
            ))
        }
        Err(err) => {
            error!(?err, "backup storage task panicked");
            Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backup storage worker failed",
            ))
        }
    }
}

async fn backup_header_handler(
    Extension(state): Extension<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<BackupQuery>,
) -> Response {
    let storage_root = state.storage.root().to_path_buf();
    let storage_id = backup_sanitize_component(&id);
    let include_payload = matches!(query.include.as_deref(), Some("payload") | Some("all"));

    let result = tokio::task::spawn_blocking(move || {
        load_backup_header_value(&storage_root, &storage_id, include_payload)
    })
    .await;

    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(err)) => {
            error!(error = %err, "failed to load backup header");
            api_error(StatusCode::NOT_FOUND, "backup not found")
        }
        Err(err) => {
            error!(?err, "backup header task panicked");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backup header worker failed",
            )
        }
    }
}

async fn backup_blob_handler(
    Extension(state): Extension<Arc<ServerState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let storage_root = state.storage.root().to_path_buf();
    let storage_id = backup_sanitize_component(&id);

    let result =
        tokio::task::spawn_blocking(move || load_backup_blob(&storage_root, &storage_id)).await;

    match result {
        Ok(Ok((owner_slug, bytes))) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            let disposition = format!("attachment; filename=\"{}-payload.bin\"", owner_slug);
            if let Ok(value) = HeaderValue::from_str(&disposition) {
                headers.insert(CONTENT_DISPOSITION, value);
            }
            (StatusCode::OK, headers, bytes).into_response()
        }
        Ok(Err(err)) => {
            error!(error = %err, "failed to load backup payload");
            api_error(StatusCode::NOT_FOUND, "backup payload not found")
        }
        Err(err) => {
            error!(?err, "backup payload task panicked");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backup payload worker failed",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
struct FederateQuery {
    #[serde(default)]
    cursor: Option<String>,
}

async fn federate_index_handler(
    Extension(state): Extension<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<FederateQuery>,
) -> Response {
    let signing_key_bytes = match state.signing_key {
        Some(bytes) => bytes,
        None => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "federation signing not configured",
            )
        }
    };

    let if_none_match = headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_string());

    let presence_path = match state.presence_path.clone() {
        Some(path) => path,
        None => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "presence document required for federation",
            )
        }
    };

    let presence_digest =
        match tokio::task::spawn_blocking(move || compute_presence_digest(&presence_path)).await {
            Ok(Ok(digest)) => digest,
            Ok(Err(err)) => {
                error!(error = %err, "failed to compute presence digest");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to compute presence digest",
                );
            }
            Err(err) => {
                error!(?err, "presence digest task panicked");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "presence digest worker failed",
                );
            }
        };

    let index = match state.last_index.read().await.clone() {
        Some(index) => index,
        None => return api_error(StatusCode::NOT_FOUND, "no index published yet"),
    };

    let cursor = match default_slice_cursor(&index) {
        Ok(cursor) => cursor,
        Err(err) => {
            error!(error = %err, "failed to compute index cursor");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to compute federated cursor",
            );
        }
    };

    if query.cursor.as_deref() == Some(cursor.as_str()) {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    let slice = match FederatedIndexSlice::from_shard_index(
        &index,
        &state.public_url,
        &presence_digest,
        &cursor,
        None,
        &signing_key,
    ) {
        Ok(slice) => slice,
        Err(err) => {
            error!(error = %err, "failed to produce federated index slice");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to produce federated index slice",
            );
        }
    };

    if let Some(tag) = if_none_match.as_deref() {
        if tag == slice.canonical_hash {
            return StatusCode::NOT_MODIFIED.into_response();
        }
    }

    let etag_raw = format!("\"{}\"", slice.canonical_hash);
    let etag_header = match HeaderValue::from_str(&etag_raw) {
        Ok(value) => value,
        Err(err) => {
            error!(error = %err, "failed to construct ETag header");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialise index slice",
            );
        }
    };

    match serde_json::to_vec(&slice) {
        Ok(payload) => (
            StatusCode::OK,
            [
                (CONTENT_TYPE, HeaderValue::from_static("application/json")),
                (ETAG, etag_header),
            ],
            payload,
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to serialise federated index slice");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialise index slice",
            )
        }
    }
}

fn store_backup(storage_root: &Path, document: &BackupDocument) -> Result<()> {
    let ciphertext = verify_backup_document(document)?;
    let owner_slug = owner_slug_from_did(&document.owner)?;
    let storage_id = backup_sanitize_component(&document.id);
    let backup_dir = backup_directory(storage_root, &owner_slug, &storage_id);

    if backup_dir.exists() {
        return Err(anyhow!("backup {} already exists", document.id));
    }

    std::fs::create_dir_all(&backup_dir)
        .with_context(|| format!("failed to create backup directory {}", backup_dir.display()))?;

    let header = build_backup_header(document);
    let header_payload = serde_json::to_vec_pretty(&header)?;
    std::fs::write(backup_dir.join("header.json"), header_payload).with_context(|| {
        format!(
            "failed to write backup header {}/header.json",
            backup_dir.display()
        )
    })?;
    std::fs::write(backup_dir.join("payload.bin"), &ciphertext).with_context(|| {
        format!(
            "failed to write backup payload {}/payload.bin",
            backup_dir.display()
        )
    })?;

    let index_dir = storage_root.join("backups").join("index");
    std::fs::create_dir_all(&index_dir).with_context(|| {
        format!(
            "failed to create backup index directory {}",
            index_dir.display()
        )
    })?;
    let record = BackupIndexRecord { owner: owner_slug };
    let index_payload = serde_json::to_vec_pretty(&record)?;
    std::fs::write(backup_index_path(storage_root, &storage_id), index_payload).with_context(
        || {
            format!(
                "failed to write backup index {}",
                backup_index_path(storage_root, &storage_id).display()
            )
        },
    )?;

    Ok(())
}

fn load_backup_header_value(
    storage_root: &Path,
    storage_id: &str,
    include_payload: bool,
) -> Result<Value> {
    let index_path = backup_index_path(storage_root, storage_id);
    if !index_path.exists() {
        return Err(anyhow!("unknown backup id"));
    }

    let record: BackupIndexRecord = serde_json::from_reader(std::fs::File::open(&index_path)?)
        .context("failed to parse backup index record")?;
    let backup_dir = backup_directory(storage_root, &record.owner, storage_id);
    let header: BackupHeader = crate::backup::load_backup_header(&backup_dir.join("header.json"))?;
    let mut value = serde_json::to_value(&header)?;
    if include_payload {
        let payload = std::fs::read(backup_dir.join("payload.bin"))
            .context("failed to read backup payload")?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("ciphertext".to_string(), json!(Base64.encode(payload)));
        }
    }
    Ok(value)
}

fn load_backup_blob(storage_root: &Path, storage_id: &str) -> Result<(String, Vec<u8>)> {
    let index_path = backup_index_path(storage_root, storage_id);
    if !index_path.exists() {
        return Err(anyhow!("unknown backup id"));
    }

    let record: BackupIndexRecord = serde_json::from_reader(std::fs::File::open(&index_path)?)
        .context("failed to parse backup index record")?;
    let backup_dir = backup_directory(storage_root, &record.owner, storage_id);
    let payload =
        std::fs::read(backup_dir.join("payload.bin")).context("failed to read backup payload")?;
    Ok((record.owner, payload))
}

fn authorize_request<T: SerdeSerialize>(
    state: &ServerState,
    headers: &HeaderMap,
    path: &str,
    payload: &T,
) -> Result<Option<String>, Response> {
    let requires = state.requires_auth();

    let did = headers
        .get("x-hn-did")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());

    if requires && did.is_none() {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "missing x-hn-did header",
        ));
    }

    let Some(did_value) = did else {
        return Ok(None);
    };

    let Some(verifying_key) = state.allowlist.get(&did_value) else {
        if requires {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                format!("DID '{}' not allowed to publish", did_value),
            ));
        }
        debug!(
            event = "mcp.auth.skip",
            did = %did_value,
            path,
            "skipping signature verification for public mode"
        );
        return Ok(None);
    };

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
    let message = canonical_request_message("POST", path, timestamp, &body_hash);

    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "signature verification failed"))?;

    Ok(Some(did_value))
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
