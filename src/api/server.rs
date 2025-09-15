//! ZHTP Orchestrator API Server
//! 
//! HTTP API server that coordinates Level 2 components (protocols, blockchain, network)
//! and provides orchestrated endpoints for Web4 functionality

use crate::api::{ApiConfig, ApiEndpoints, handlers::*};
use anyhow::{Result, Context};
use axum::{
    routing::{get, post},
    Router, Json, extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{info, warn, error};

/// Start the ZHTP orchestrator API server
pub async fn start_api_server(config: ApiConfig) -> Result<()> {
    let port = config.port.unwrap_or(9333);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    
    info!("🚀 Starting ZHTP Orchestrator API server on {}", addr);
    
    let app = create_app(config).await?;
    
    let listener = TcpListener::bind(addr)
        .await
        .context("Failed to bind API server")?;
        
    info!("✅ ZHTP Orchestrator API server listening on {}", addr);
    
    axum::serve(listener, app)
        .await
        .context("API server failed")?;
        
    Ok(())
}

/// Create the Axum application with all routes
async fn create_app(config: ApiConfig) -> Result<Router> {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);
    
    let app = Router::new()
        // Root endpoints
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        
        // API v1 routes - Level 1 Orchestrator endpoints
        .route("/api/v1/status", get(orchestrator_status))
        .route("/api/v1/info", get(orchestrator_info))
        
        // Node management (orchestrated)
        .route("/api/v1/node/start", post(node_start))
        .route("/api/v1/node/stop", post(node_stop))
        .route("/api/v1/node/status", get(node_status))
        .route("/api/v1/node/restart", post(node_restart))
        
        // Wallet operations (orchestrated via protocols)
        .route("/api/v1/wallet/create", post(wallet_create))
        .route("/api/v1/wallet/balance/:address", get(wallet_balance))
        .route("/api/v1/wallet/transfer", post(wallet_transfer))
        .route("/api/v1/wallet/history/:address", get(wallet_history))
        .route("/api/v1/wallet/list", get(wallet_list))
        
        // DAO operations (orchestrated via protocols)
        .route("/api/v1/dao/info", get(dao_info))
        .route("/api/v1/dao/propose", post(dao_propose))
        .route("/api/v1/dao/vote", post(dao_vote))
        .route("/api/v1/dao/ubi/claim", post(dao_ubi_claim))
        
        // Identity operations (orchestrated via protocols)
        .route("/api/v1/identity/create", post(identity_create))
        .route("/api/v1/identity/verify", post(identity_verify))
        .route("/api/v1/identity/list", get(identity_list))
        
        // Network operations (orchestrated via network)
        .route("/api/v1/network/status", get(network_status))
        .route("/api/v1/network/peers", get(network_peers))
        .route("/api/v1/network/test", post(network_test))
        
        // Blockchain operations (orchestrated via blockchain)
        .route("/api/v1/blockchain/status", get(blockchain_status))
        .route("/api/v1/blockchain/transaction", post(blockchain_transaction))
        .route("/api/v1/blockchain/stats", get(blockchain_stats))
        
        // System monitoring
        .route("/api/v1/monitor/system", get(monitor_system))
        .route("/api/v1/monitor/health", get(monitor_health))
        .route("/api/v1/monitor/performance", get(monitor_performance))
        .route("/api/v1/monitor/logs", get(monitor_logs))
        
        // Component management
        .route("/api/v1/component/start", post(component_start))
        .route("/api/v1/component/stop", post(component_stop))
        .route("/api/v1/component/status", post(component_status))
        .route("/api/v1/component/list", get(component_list))
        
        // Server management
        .route("/api/v1/server/start", post(server_start))
        .route("/api/v1/server/stop", post(server_stop))
        .route("/api/v1/server/restart", post(server_restart))
        .route("/api/v1/server/status", get(server_status))
        .route("/api/v1/server/config", get(server_config))
        
        .layer(
            ServiceBuilder::new()
                .layer(cors)
                .into_inner(),
        );
    
    info!("🔧 Configured ZHTP Orchestrator API routes");
    Ok(app)
}

// Root handlers
async fn root_handler() -> impl IntoResponse {
    Json(json!({
        "service": "ZHTP Orchestrator",
        "version": env!("CARGO_PKG_VERSION"),
        "level": "Level 1 - Orchestrator",
        "coordinates": ["protocols", "blockchain", "network"],
        "api_version": "v1",
        "status": "operational"
    }))
}

async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "orchestrator": "operational",
        "components_status": "checking..."
    }))
}

async fn status_handler() -> impl IntoResponse {
    Json(json!({
        "orchestrator_status": "running",
        "level": "Level 1",
        "components": {
            "protocols": "coordinating",
            "blockchain": "coordinating", 
            "network": "coordinating"
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// Orchestrator-specific endpoints
async fn orchestrator_status() -> impl IntoResponse {
    info!("📊 Orchestrator status requested");
    
    Json(json!({
        "orchestrator": {
            "status": "operational",
            "level": "Level 1",
            "coordinates": ["protocols", "blockchain", "network"],
            "uptime": "running",
            "version": env!("CARGO_PKG_VERSION")
        },
        "components": {
            "protocols": "active",
            "blockchain": "active", 
            "network": "active",
            "consensus": "coordinated",
            "storage": "coordinated",
            "economy": "coordinated"
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn orchestrator_info() -> impl IntoResponse {
    Json(json!({
        "name": "ZHTP Orchestrator",
        "description": "Level 1 orchestrator coordinating Level 2 components",
        "version": env!("CARGO_PKG_VERSION"),
        "architecture": {
            "level": 1,
            "type": "orchestrator",
            "coordinates": ["protocols", "blockchain", "network"],
            "manages": ["consensus", "storage", "economy", "proofs", "identity", "crypto"]
        },
        "capabilities": [
            "component_coordination",
            "service_orchestration", 
            "level_2_management",
            "user_interface_provision",
            "system_monitoring"
        ]
    }))
}

// Placeholder handlers that will coordinate with Level 2 components
// These would make HTTP calls to lib-protocols, lib-blockchain, lib-network servers

macro_rules! orchestrate_endpoint {
    ($name:ident, $component:expr, $endpoint:expr) => {
        async fn $name() -> impl IntoResponse {
            info!("🎯 Orchestrating {} via {}", $endpoint, $component);
            
            // This would make actual HTTP calls to Level 2 components
            // For now, return orchestration response
            Json(json!({
                "orchestrated": true,
                "component": $component,
                "endpoint": $endpoint,
                "status": "coordinated",
                "message": format!("Orchestrated {} operation via {}", $endpoint, $component),
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
    };
}

macro_rules! orchestrate_endpoint_with_body {
    ($name:ident, $component:expr, $endpoint:expr) => {
        async fn $name(Json(payload): Json<Value>) -> impl IntoResponse {
            info!("🎯 Orchestrating {} via {} with payload", $endpoint, $component);
            
            // This would make actual HTTP calls to Level 2 components
            // For now, return orchestration response
            Json(json!({
                "orchestrated": true,
                "component": $component,
                "endpoint": $endpoint,
                "payload_received": payload,
                "status": "coordinated",
                "message": format!("Orchestrated {} operation via {}", $endpoint, $component),
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
    };
}

// Node management
orchestrate_endpoint_with_body!(node_start, "orchestrator", "node/start");
orchestrate_endpoint_with_body!(node_stop, "orchestrator", "node/stop");
orchestrate_endpoint!(node_status, "orchestrator", "node/status");
orchestrate_endpoint_with_body!(node_restart, "orchestrator", "node/restart");

// Wallet operations (coordinated via lib-protocols)
orchestrate_endpoint_with_body!(wallet_create, "protocols", "wallet/create");
orchestrate_endpoint_with_body!(wallet_transfer, "protocols", "wallet/transfer");
orchestrate_endpoint!(wallet_list, "protocols", "wallet/list");

async fn wallet_balance(Path(address): Path<String>) -> impl IntoResponse {
    info!("🎯 Orchestrating wallet balance for {} via protocols", address);
    
    Json(json!({
        "orchestrated": true,
        "component": "protocols",
        "endpoint": "wallet/balance",
        "address": address,
        "status": "coordinated",
        "message": format!("Orchestrated wallet balance for {}", address),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn wallet_history(Path(address): Path<String>) -> impl IntoResponse {
    info!("🎯 Orchestrating wallet history for {} via protocols", address);
    
    Json(json!({
        "orchestrated": true,
        "component": "protocols",
        "endpoint": "wallet/history", 
        "address": address,
        "status": "coordinated",
        "message": format!("Orchestrated wallet history for {}", address),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// DAO operations (coordinated via lib-protocols)
orchestrate_endpoint!(dao_info, "protocols", "dao/info");
orchestrate_endpoint_with_body!(dao_propose, "protocols", "dao/propose");
orchestrate_endpoint_with_body!(dao_vote, "protocols", "dao/vote");
orchestrate_endpoint_with_body!(dao_ubi_claim, "protocols", "dao/ubi/claim");

// Identity operations (coordinated via lib-protocols)  
orchestrate_endpoint_with_body!(identity_create, "protocols", "identity/create");
orchestrate_endpoint_with_body!(identity_verify, "protocols", "identity/verify");
orchestrate_endpoint!(identity_list, "protocols", "identity/list");

// Network operations (coordinated via lib-network)
orchestrate_endpoint!(network_status, "network", "status");
orchestrate_endpoint!(network_peers, "network", "peers");
orchestrate_endpoint_with_body!(network_test, "network", "test");

// Blockchain operations (coordinated via lib-blockchain)
orchestrate_endpoint!(blockchain_status, "blockchain", "status");
orchestrate_endpoint_with_body!(blockchain_transaction, "blockchain", "transaction");
orchestrate_endpoint!(blockchain_stats, "blockchain", "stats");

// System monitoring
orchestrate_endpoint!(monitor_system, "orchestrator", "monitor/system");
orchestrate_endpoint!(monitor_health, "orchestrator", "monitor/health");
orchestrate_endpoint!(monitor_performance, "orchestrator", "monitor/performance");
orchestrate_endpoint!(monitor_logs, "orchestrator", "monitor/logs");

// Component management
orchestrate_endpoint_with_body!(component_start, "orchestrator", "component/start");
orchestrate_endpoint_with_body!(component_stop, "orchestrator", "component/stop");
orchestrate_endpoint_with_body!(component_status, "orchestrator", "component/status");
orchestrate_endpoint!(component_list, "orchestrator", "component/list");

// Server management
orchestrate_endpoint_with_body!(server_start, "orchestrator", "server/start");
orchestrate_endpoint_with_body!(server_stop, "orchestrator", "server/stop");
orchestrate_endpoint_with_body!(server_restart, "orchestrator", "server/restart");
orchestrate_endpoint!(server_status, "orchestrator", "server/status");
orchestrate_endpoint!(server_config, "orchestrator", "server/config");
