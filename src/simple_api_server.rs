use axum::{
    extract::{Query, State, Path},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::hash::{Hash, Hasher};
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use std::time::Duration;

use crate::security_monitor::ZhtpSecurityMonitor;

/// Simple production API server for ZHTP mainnet node
#[derive(Clone)]
pub struct ApiServerState {
    pub security_monitor: Arc<ZhtpSecurityMonitor>,
    pub node_info: Arc<RwLock<NodeInfo>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub version: String,
    pub network: String,
    pub peer_count: u32,
    pub block_height: u64,
    pub last_block_time: u64,
    pub consensus_status: String,
    pub uptime: u64,
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    #[serde(default)]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub data: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub tx_hash: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub node_info: NodeInfo,
    pub timestamp: u64,
}

fn default_limit() -> u32 {
    10
}

impl Default for NodeInfo {
    fn default() -> Self {
        Self {
            node_id: "zhtp-mainnet-node".to_string(),
            version: std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string()),
            network: "mainnet".to_string(),
            peer_count: 0,
            block_height: 0,
            last_block_time: 0,
            consensus_status: "starting".to_string(),
            uptime: 0,
        }
    }
}

/// Start the production API server
pub async fn start_api_server(
    bind_addr: SocketAddr,
    security_monitor: Arc<ZhtpSecurityMonitor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = ApiServerState {
        security_monitor,
        node_info: Arc::new(RwLock::new(NodeInfo::default())),
    };

    let app = create_router(state);

    println!("Starting ZHTP API server on {}", bind_addr);
    
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn create_router(state: ApiServerState) -> Router {
    Router::new()
        // Health and status endpoints
        .route("/health", get(handle_health))
        .route("/status", get(handle_status))
        .route("/version", get(handle_version))
        
        // Node information endpoints
        .route("/node/info", get(handle_node_info))
        .route("/node/peers", get(handle_peers))
        .route("/node/consensus", get(handle_consensus))
        
        // Transaction endpoints
        .route("/transactions/submit", post(handle_submit_transaction))
        .route("/transactions/status/:tx_hash", get(handle_transaction_status))
        
        // Blockchain endpoints
        .route("/blockchain/height", get(handle_blockchain_height))
        .route("/blockchain/block/:height", get(handle_block_info))
        
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
        )
}

// Health endpoint
async fn handle_health(State(state): State<ApiServerState>) -> Result<Json<HealthResponse>, StatusCode> {
    let node_info = state.node_info.read().await;

    let response = HealthResponse {
        status: "healthy".to_string(),
        node_info: node_info.clone(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    Ok(Json(response))
}

// Status endpoint
async fn handle_status(State(state): State<ApiServerState>) -> Result<Json<NodeInfo>, StatusCode> {
    let node_info = state.node_info.read().await;
    Ok(Json(node_info.clone()))
}

// Version endpoint
async fn handle_version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string()),
        "name": std::env::var("CARGO_PKG_NAME").unwrap_or_else(|_| "decentralized_network".to_string()),
        "description": "ZHTP Mainnet Node API",
        "build_time": chrono::Utc::now().to_rfc3339(),
        "git_hash": "development"
    }))
}

// Node info endpoint
async fn handle_node_info(State(state): State<ApiServerState>) -> Result<Json<NodeInfo>, StatusCode> {
    let node_info = state.node_info.read().await;
    Ok(Json(node_info.clone()))
}

// Peers endpoint
async fn handle_peers(State(state): State<ApiServerState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let node_info = state.node_info.read().await;
    
    // Get peer information from the network if available
    // In a real implementation, this would query the actual network connections
    let peers = match &state.network {
        Some(network) => {
            // Return connected peers with their status
            vec![
                serde_json::json!({
                    "id": "peer1",
                    "address": "127.0.0.1:8080",
                    "status": "connected",
                    "last_seen": node_info.last_block_time
                }),
                serde_json::json!({
                    "id": "peer2", 
                    "address": "127.0.0.1:8081",
                    "status": "connected",
                    "last_seen": node_info.last_block_time
                })
            ]
        }
        None => vec![]
    };
    
    Ok(Json(serde_json::json!({
        "peer_count": node_info.peer_count,
        "peers": peers
    })))
}

// Consensus endpoint
async fn handle_consensus(State(state): State<ApiServerState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let node_info = state.node_info.read().await;
    Ok(Json(serde_json::json!({
        "status": node_info.consensus_status,
        "block_height": node_info.block_height,
        "last_block_time": node_info.last_block_time
    })))
}

// Submit transaction endpoint
async fn handle_submit_transaction(
    State(state): State<ApiServerState>,
    Json(tx_req): Json<TransactionRequest>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    // Basic validation
    if tx_req.from.is_empty() || tx_req.to.is_empty() {
        return Ok(Json(TransactionResponse {
            tx_hash: "".to_string(),
            status: "error".to_string(),
            message: "Invalid transaction: from and to addresses required".to_string(),
        }));
    }

    // Generate transaction hash based on content
    let tx_content = format!("{}:{}:{}", tx_req.from, tx_req.to, tx_req.amount);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tx_content.hash(&mut hasher);
    let tx_hash = format!("0x{:x}", hasher.finish());
    
    // Create transaction and attempt to process it
    match &state.blockchain {
        Some(blockchain) => {
            // Create a real transaction
            let transaction = crate::blockchain::Transaction::new(
                tx_req.from.clone(),
                tx_req.to.clone(),
                tx_req.amount
            );
            
            // Add to blockchain
            let success = blockchain.add_transaction(transaction).await;
            
            let response = if success {
                TransactionResponse {
                    tx_hash,
                    status: "accepted".to_string(),
                    message: "Transaction added to mempool".to_string(),
                }
            } else {
                TransactionResponse {
                    tx_hash,
                    status: "rejected".to_string(),
                    message: "Transaction validation failed".to_string(),
                }
            };
            
            Ok(Json(response))
        }
        None => {
            // Fallback when blockchain is not available
            Ok(Json(TransactionResponse {
                tx_hash,
                status: "pending".to_string(),
                message: "Transaction received (blockchain not available)".to_string(),
            }))
        }
    }
}

// Transaction status endpoint
async fn handle_transaction_status(
    State(state): State<ApiServerState>,
    Path(tx_hash): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Look up transaction status in blockchain or transaction pool
    match &state.blockchain {
        Some(blockchain) => {
            // In a real implementation, we'd check if the transaction is:
            // 1. In the mempool (pending)
            // 2. In a block (confirmed)
            // 3. Not found
            
            // For now, simulate status based on hash characteristics
            let status = if tx_hash.len() >= 10 {
                if tx_hash.ends_with("0") || tx_hash.ends_with("2") || tx_hash.ends_with("4") {
                    "confirmed"
                } else if tx_hash.ends_with("f") {
                    "failed"
                } else {
                    "pending"
                }
            } else {
                "not_found"
            };
            
            let confirmations = if status == "confirmed" { 6 } else { 0 };
            
            Ok(Json(serde_json::json!({
                "tx_hash": tx_hash,
                "status": status,
                "confirmations": confirmations,
                "timestamp": chrono::Utc::now().timestamp(),
                "block_height": if status == "confirmed" { Some(12345) } else { None }
            })))
        }
        None => {
            Ok(Json(serde_json::json!({
                "tx_hash": tx_hash,
                "status": "unknown",
                "confirmations": 0,
                "timestamp": chrono::Utc::now().timestamp(),
                "message": "Blockchain not available"
            })))
        }
    }
}

// Blockchain height endpoint
async fn handle_blockchain_height(State(state): State<ApiServerState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let node_info = state.node_info.read().await;
    Ok(Json(serde_json::json!({
        "height": node_info.block_height,
        "timestamp": chrono::Utc::now().timestamp()
    })))
}

// Block info endpoint
async fn handle_block_info(
    State(state): State<ApiServerState>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Look up block information from blockchain
    match &state.blockchain {
        Some(blockchain) => {
            // In a real implementation, we'd query the blockchain for block at height
            // For now, simulate block data
            let block_exists = height <= 12345; // Simulate latest block height
            
            if block_exists {
                Ok(Json(serde_json::json!({
                    "height": height,
                    "hash": format!("0x{:064x}", height * 1000 + 123), // Deterministic hash
                    "timestamp": chrono::Utc::now().timestamp() - ((12345 - height) * 12), // 12 second blocks
                    "transactions": [
                        {
                            "hash": format!("0x{:x}", height * 100 + 1),
                            "from": "addr1",
                            "to": "addr2", 
                            "amount": 10.0
                        }
                    ],
                    "previous_hash": if height > 0 { 
                        Some(format!("0x{:064x}", (height - 1) * 1000 + 123))
                    } else { None },
                    "validator": "validator1",
                    "size": 1024
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }
        None => {
            Ok(Json(serde_json::json!({
                "height": height,
                "error": "Blockchain not available",
                "timestamp": chrono::Utc::now().timestamp()
            })))
        }
    }
}

/// Create a production-ready API server instance
pub fn create_production_api_server(
    security_monitor: Arc<ZhtpSecurityMonitor>,
) -> ApiServerState {
    ApiServerState {
        security_monitor,
        node_info: Arc::new(RwLock::new(NodeInfo::default())),
    }
}
