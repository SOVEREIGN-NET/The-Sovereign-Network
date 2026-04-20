//! Semantic Search HTTP API Server
//!
//! A lightweight axum HTTP server that bridges the browser frontend to
//! the real lib-neural-mesh SemanticChannelingEngine. Runs on port 9381
//! alongside the main ZHTP node.
//!
//! # Core Endpoints (Sovereign Network graph)
//!
//! - `POST /api/v1/semantic/search`  — Channeling search
//! - `GET  /api/v1/semantic/stats`   — Graph stats
//! - `GET  /api/v1/semantic/health`  — Health check
//!
//! # Plugin API (private data sources)
//!
//! Developers and companies can register their own datasets as plugins,
//! each with its own private TagGraph. All data stays encrypted and
//! private via ZHTP's ZKP + encryption layer.
//!
//! - `POST   /api/v1/semantic/plugins`              — Register plugin
//! - `GET    /api/v1/semantic/plugins`              — List plugins
//! - `DELETE /api/v1/semantic/plugins/:id`           — Remove plugin
//! - `POST   /api/v1/semantic/plugins/:id/ingest`   — Ingest data items
//! - `POST   /api/v1/semantic/plugins/:id/search`   — Search plugin graph
//! - `GET    /api/v1/semantic/plugins/:id/stats`     — Plugin graph stats
//! - `POST   /api/v1/semantic/unified`              — Search all sources
//!
//! # Neural Compression Learning
//!
//! When data is ingested into a plugin, compression signatures are computed.
//! Content with similar compression profiles gets automatically linked —
//! this is the feedback loop from neural compression to semantic search.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

use lib_neural_mesh::{
    parallel_semantic_channel, ChannelStrategy, TagGraph, DEFAULT_CHANNEL_STRATEGIES,
};

use crate::api::handlers::semantic::{
    self, SemanticSearchRequest, SemanticSearchResponse,
};
use crate::api::handlers::semantic_plugin::{
    self, IngestRequest, PluginRegistry, RegisterPluginRequest,
};

/// Shared state for the semantic API — network graph + plugin registry
#[derive(Clone)]
pub struct SemanticApiState {
    pub graph: Arc<RwLock<TagGraph>>,
    pub plugins: Arc<RwLock<PluginRegistry>>,
}

/// Start the standalone semantic search HTTP API server.
///
/// This runs on port 9381 and provides the real channeling engine
/// endpoints for the browser frontend, plus the plugin API for
/// custom private datasets.
pub async fn start_semantic_api_server(graph: Arc<RwLock<TagGraph>>) {
    let state = SemanticApiState {
        graph,
        plugins: Arc::new(RwLock::new(PluginRegistry::new())),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // ── Core network graph endpoints ──
        .route("/api/v1/semantic/search", post(handle_search))
        .route("/api/v1/semantic/stats", get(handle_stats))
        .route("/api/v1/semantic/health", get(handle_health))
        // ── Unified multi-source search ──
        .route("/api/v1/semantic/unified", post(handle_unified_search))
        // ── Plugin CRUD ──
        .route("/api/v1/semantic/plugins", post(handle_register_plugin))
        .route("/api/v1/semantic/plugins", get(handle_list_plugins))
        .route(
            "/api/v1/semantic/plugins/:id",
            delete(handle_remove_plugin),
        )
        // ── Plugin data operations ──
        .route(
            "/api/v1/semantic/plugins/:id/ingest",
            post(handle_plugin_ingest),
        )
        .route(
            "/api/v1/semantic/plugins/:id/search",
            post(handle_plugin_search),
        )
        .route(
            "/api/v1/semantic/plugins/:id/stats",
            get(handle_plugin_stats),
        )
        // ── Health ──
        .route("/health", get(|| async { "OK" }))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 9381));
    info!("🧠 Semantic Search API starting on 0.0.0.0:9381 (network + plugin API)");

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Semantic API server error: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to bind semantic API server on port 9381: {}", e);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// CORE NETWORK GRAPH HANDLERS
// ═══════════════════════════════════════════════════════════════

/// POST /api/v1/semantic/search — Run real semantic channeling on the network graph
async fn handle_search(
    State(state): State<SemanticApiState>,
    Json(req): Json<SemanticSearchRequest>,
) -> impl IntoResponse {
    if req.query.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Query cannot be empty"})),
        )
            .into_response();
    }

    let query_vector = semantic::text_to_query_vector(&req.query);

    let strategies: Vec<ChannelStrategy> = if req.strategies.is_empty() {
        DEFAULT_CHANNEL_STRATEGIES.to_vec()
    } else {
        let parsed: Vec<ChannelStrategy> = req
            .strategies
            .iter()
            .filter_map(|s| semantic::parse_strategy(s))
            .collect();
        if parsed.is_empty() {
            DEFAULT_CHANNEL_STRATEGIES.to_vec()
        } else {
            parsed
        }
    };

    let max_steps = req.max_steps.unwrap_or(50);

    let graph = state.graph.read().await;
    let result = parallel_semantic_channel(
        &graph,
        &query_vector,
        &strategies,
        max_steps,
        strategies.len(),
    );

    let response = semantic::channeling_result_to_vis(&req.query, &result, &graph);
    (StatusCode::OK, Json(serde_json::json!(response))).into_response()
}

/// GET /api/v1/semantic/stats — Network graph statistics
async fn handle_stats(State(state): State<SemanticApiState>) -> impl IntoResponse {
    let graph = state.graph.read().await;
    let plugins = state.plugins.read().await;
    Json(serde_json::json!({
        "tag_count": graph.tag_count(),
        "edge_count": graph.edge_count(),
        "binding_count": graph.binding_count(),
        "plugins_registered": plugins.list().len(),
        "status": "live"
    }))
}

/// GET /api/v1/semantic/health — Health check
async fn handle_health(State(state): State<SemanticApiState>) -> impl IntoResponse {
    let graph = state.graph.read().await;
    let plugins = state.plugins.read().await;
    let plugin_list = plugins.list();
    Json(serde_json::json!({
        "status": "ok",
        "engine": "semantic_channeling_v1",
        "graph_tags": graph.tag_count(),
        "graph_edges": graph.edge_count(),
        "mode": "live",
        "plugins": plugin_list.len(),
        "features": {
            "plugin_api": true,
            "neural_compression_learning": true,
            "custom_embeddings": true,
            "unified_search": true
        }
    }))
}

// ═══════════════════════════════════════════════════════════════
// UNIFIED MULTI-SOURCE SEARCH
// ═══════════════════════════════════════════════════════════════

/// POST /api/v1/semantic/unified — Search all sources (network + plugins)
async fn handle_unified_search(
    State(state): State<SemanticApiState>,
    Json(req): Json<SemanticSearchRequest>,
) -> impl IntoResponse {
    if req.query.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Query cannot be empty"})),
        )
            .into_response();
    }

    let plugins = state.plugins.read().await;
    match semantic_plugin::search_all_sources(&state.graph, &plugins, &req).await {
        Ok(response) => (StatusCode::OK, Json(serde_json::json!(response))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Unified search failed: {}", e)})),
        )
            .into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════
// PLUGIN CRUD HANDLERS
// ═══════════════════════════════════════════════════════════════

/// POST /api/v1/semantic/plugins — Register a new plugin
async fn handle_register_plugin(
    State(state): State<SemanticApiState>,
    Json(req): Json<RegisterPluginRequest>,
) -> impl IntoResponse {
    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Plugin name cannot be empty"})),
        )
            .into_response();
    }

    let mut plugins = state.plugins.write().await;
    match plugins.register(req) {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": hex::encode(id),
                "status": "registered"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/v1/semantic/plugins — List all registered plugins
async fn handle_list_plugins(State(state): State<SemanticApiState>) -> impl IntoResponse {
    let plugins = state.plugins.read().await;
    let mut list = plugins.list();

    // Fill in graph stats (requires reading each plugin's graph)
    for info in &mut list {
        if let Some(plugin) = plugins.find_by_hex(&info.id) {
            let graph = plugin.graph.read().await;
            info.graph_tags = graph.tag_count();
            info.graph_edges = graph.edge_count();
            info.graph_bindings = graph.binding_count();
        }
    }

    Json(serde_json::json!({
        "plugins": list,
        "count": list.len()
    }))
}

/// DELETE /api/v1/semantic/plugins/:id — Remove a plugin
async fn handle_remove_plugin(
    State(state): State<SemanticApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut plugins = state.plugins.write().await;

    // Parse ID
    let plugin_id = if let Ok(bytes) = hex::decode(&id) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid plugin ID"})),
            )
                .into_response();
        }
    } else {
        // Try name-based
        *blake3::hash(format!("semantic-plugin:{}", id.to_lowercase()).as_bytes()).as_bytes()
    };

    match plugins.remove(&plugin_id) {
        Some(name) => (
            StatusCode::OK,
            Json(serde_json::json!({"removed": name})),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Plugin not found"})),
        )
            .into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════
// PLUGIN DATA OPERATIONS
// ═══════════════════════════════════════════════════════════════

/// POST /api/v1/semantic/plugins/:id/ingest — Ingest data items
async fn handle_plugin_ingest(
    State(state): State<SemanticApiState>,
    Path(id): Path<String>,
    Json(req): Json<IngestRequest>,
) -> impl IntoResponse {
    if req.items.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "No items to ingest"})),
        )
            .into_response();
    }

    let mut plugins = state.plugins.write().await;
    let plugin = match plugins.find_by_hex_mut(&id) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Plugin not found"})),
            )
                .into_response();
        }
    };

    match semantic_plugin::ingest_items(plugin, req.items).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!(result))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Ingest failed: {}", e)})),
        )
            .into_response(),
    }
}

/// POST /api/v1/semantic/plugins/:id/search — Search a plugin's graph
async fn handle_plugin_search(
    State(state): State<SemanticApiState>,
    Path(id): Path<String>,
    Json(req): Json<SemanticSearchRequest>,
) -> impl IntoResponse {
    if req.query.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Query cannot be empty"})),
        )
            .into_response();
    }

    let plugins = state.plugins.read().await;
    let plugin = match plugins.find_by_hex(&id) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Plugin not found"})),
            )
                .into_response();
        }
    };

    match semantic_plugin::search_plugin(plugin, &req).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!(result))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Search failed: {}", e)})),
        )
            .into_response(),
    }
}

/// GET /api/v1/semantic/plugins/:id/stats — Plugin graph statistics
async fn handle_plugin_stats(
    State(state): State<SemanticApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let plugins = state.plugins.read().await;
    let plugin = match plugins.find_by_hex(&id) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Plugin not found"})),
            )
                .into_response();
        }
    };

    let graph = plugin.graph.read().await;
    (StatusCode::OK, Json(serde_json::json!({
        "plugin": plugin.name,
        "tag_count": graph.tag_count(),
        "edge_count": graph.edge_count(),
        "binding_count": graph.binding_count(),
        "item_count": plugin.item_count,
        "compression_signatures": plugin.compression_signatures.len(),
        "categories": plugin.categories,
        "compression_learning": plugin.compression_learning,
        "status": "live"
    }))).into_response()
}
