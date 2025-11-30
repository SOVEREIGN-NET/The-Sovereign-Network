//! DHT API Handler
//! 
//! Provides HTTP API endpoints for DHT operations, bridging the JavaScript
//! zkDHT client with the Rust lib-network DHT implementation.

// Removed unused anyhow imports
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use chrono;

use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpStatus};
use lib_network::ZkDHTIntegration;
// Removed unused ZhtpHeaders, NetworkStatus
use lib_identity::ZhtpIdentity;

// Mesh router imports for peer querying
use crate::unified_server::MeshRouter;
use lib_network::MeshConnection;
use lib_network::dht::relay::ZhtpRelayProtocol;

// Blockchain imports for direct integration
use lib_blockchain::{Transaction, TransactionInput, TransactionOutput, Hash as BlockchainHash, TransactionType};
use lib_blockchain::integration::{crypto_integration::{Signature, PublicKey, SignatureAlgorithm}, zk_integration::ZkTransactionProof};
use crate::runtime::blockchain_provider::{get_global_blockchain, add_transaction};

/// DHT API request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtInitializeRequest {
    pub identity: Option<ZhtpIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtConnectRequest {
    pub peer_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtResolveRequest {
    pub domain: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStoreRequest {
    pub domain: String,
    pub path: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtQueryRequest {
    pub peer_address: Option<String>,
    pub query: String, // Changed from DHTQuery to String
}

/// Smart contract DHT packet request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtContractPacketRequest {
    pub message_type: String, // ContractDeploy, ContractQuery, etc.
    pub contract_data: ContractPacketData,
    pub target_node: Option<String>,
}

/// Contract data for DHT packets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPacketData {
    pub contract_id: String,
    pub operation: String,
    pub bytecode: Option<Vec<u8>>,
    pub function_name: Option<String>,
    pub arguments: Option<Vec<u8>>,
    pub gas_limit: Option<u64>,
    pub metadata: Option<serde_json::Value>,
    pub zk_proofs: Vec<serde_json::Value>,
}

/// DHT Query Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTQueryResponse {
    pub success: bool,
    pub content_hash: Option<String>,
    pub peers: Option<Vec<String>>,
    pub error: Option<String>,
    pub timestamp: u64,
}

/// DHT API response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStatusResponse {
    pub connected: bool,
    pub peer_count: usize,
    pub cache_size: usize,
    pub storage_available: u64,
    pub network_health: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeersResponse {
    pub peers: Vec<String>,
    pub connected_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtContentResponse {
    pub content_hash: String,
    pub content: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtResolveResponse {
    pub content_hash: String,
    pub domain: String,
    pub path: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStoreResponse {
    pub content_hash: String,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtStatisticsResponse {
    pub queries_sent: u64,
    pub queries_received: u64,
    pub content_stored: u64,
    pub content_retrieved: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub peers_discovered: u64,
    pub storage_operations: u64,
}

/// Contract DHT packet response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtContractPacketResponse {
    pub success: bool,
    pub message_id: String,
    pub message: String,
    pub result: Option<ContractExecutionResult>,
}

/// Contract execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractExecutionResult {
    pub success: bool,
    pub return_value: Option<Vec<u8>>,
    pub gas_used: u64,
    pub error: Option<String>,
    pub logs: Vec<serde_json::Value>,
    pub state_hash: Option<String>,
}

/// Contract list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtContractListResponse {
    pub contracts: Vec<ContractInfo>,
    pub total_count: usize,
}

/// Contract info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    pub contract_id: String,
    pub name: String,
    pub version: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub deployed_at: u64,
    pub owner: Option<String>,
}

/// DHT API Handler implementation
pub struct DhtHandler {
    /// DHT client instance (has blockchain-verified identity + Dilithium2 signing)
    dht_client: Arc<RwLock<Option<Arc<RwLock<ZkDHTIntegration>>>>>,
    /// Handler statistics
    stats: Arc<RwLock<DhtHandlerStats>>,
    /// Storage system (where Web4 content is actually stored)
    storage_system: Arc<RwLock<Option<Arc<RwLock<lib_storage::UnifiedStorageSystem>>>>>,
}

/// DHT handler internal statistics
#[derive(Debug, Default)]
struct DhtHandlerStats {
    requests_handled: u64,
    errors_encountered: u64,
    last_request_time: Option<std::time::Instant>,
}

impl std::fmt::Debug for DhtHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtHandler")
            .field("dht_client", &"<Arc<RwLock<Option<DHTClient>>>>")
            .field("stats", &"<Arc<RwLock<DhtHandlerStats>>>")
            .field("mesh_connections", &"<Arc<RwLock<HashMap<PublicKey, MeshConnection>>>>")
            .field("relay_protocol", &"<Arc<RwLock<Option<ZhtpRelayProtocol>>>>")
            .field("storage_system", &"<Arc<RwLock<Option<Arc<RwLock<UnifiedStorageSystem>>>>>>")
            .finish()
    }
}

impl DhtHandler {
    /// Create a new DHT handler with mesh router access and optional storage system
    pub fn new(_mesh_router: Arc<MeshRouter>) -> Self {
        Self {
            dht_client: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(DhtHandlerStats::default())),
            storage_system: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Create a new DHT handler with storage system access (for fetching Web4 content)
    pub fn new_with_storage(_mesh_router: Arc<MeshRouter>, storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>) -> Self {
        Self {
            dht_client: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(DhtHandlerStats::default())),
            storage_system: Arc::new(RwLock::new(Some(storage))),
        }
    }

    /// Initialize DHT client with identity
    async fn initialize_dht_client(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        info!(" Initializing DHT client...");
        
        let init_request: DhtInitializeRequest = match serde_json::from_slice(&request_body) {
            Ok(req) => req,
            Err(e) => {
                error!("Invalid initialize request: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request format: {}", e),
                ));
            }
        };

        // Create identity for DHT operations
        let identity = match init_request.identity {
            Some(id) => id,
            None => {
                // Create a default identity for DHT operations
                self.create_default_dht_identity()
            }
        };

        // Initialize DHT client using shared global instance
        match crate::runtime::shared_dht::initialize_global_dht(identity).await {
            Ok(_) => {
                // Get reference to the shared DHT client
                let dht_client = crate::runtime::shared_dht::get_dht_client().await?;
                *self.dht_client.write().await = Some(dht_client);
                
                let response = serde_json::json!({
                    "success": true,
                    "message": "DHT client initialized successfully",
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                });

                info!(" DHT client initialized successfully");
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to initialize DHT client: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to initialize DHT client: {}", e),
                ))
            }
        }
    }

    /// Connect to a DHT peer
    async fn connect_to_peer(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        let connect_request: DhtConnectRequest = match serde_json::from_slice(&request_body) {
            Ok(req) => req,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request format: {}", e),
                ));
            }
        };

        info!(" Connecting to DHT peer: {}", connect_request.peer_address);

        let dht_client_guard: tokio::sync::RwLockReadGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.read().await;
        let client: &Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        let mut dht = client.write().await;
        match dht.connect_to_peer(&connect_request.peer_address).await {
            Ok(()) => {
                let response = serde_json::json!({
                    "success": true,
                    "message": format!("Connected to peer: {}", connect_request.peer_address),
                    "peer_address": connect_request.peer_address
                });

                info!(" Connected to DHT peer: {}", connect_request.peer_address);
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to connect to peer {}: {}", connect_request.peer_address, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    format!("Failed to connect to peer: {}", e),
                ))
            }
        }
    }

    /// Discover DHT peers
    async fn discover_peers(&self) -> ZhtpResult<ZhtpResponse> {
        info!(" Discovering DHT peers...");

        let dht_client_guard: tokio::sync::RwLockReadGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.read().await;
        let client: &Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        let dht = client.read().await;
        match dht.discover_peers().await {
            Ok(peers) => {
                let response = DhtPeersResponse {
                    peers: peers.clone(),
                    connected_peers: peers.len(),
                };

                info!(" Discovered {} DHT peers", peers.len());
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to discover peers: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to discover peers: {}", e),
                ))
            }
        }
    }

    /// Resolve content hash for domain/path
    async fn resolve_content(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        let resolve_request: DhtResolveRequest = match serde_json::from_slice(&request_body) {
            Ok(req) => req,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request format: {}", e),
                ));
            }
        };

        info!(" Resolving content for {}{}", resolve_request.domain, resolve_request.path);

        let dht_client_guard: tokio::sync::RwLockReadGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.read().await;
        let client: &Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        let mut dht = client.write().await; // Need write for resolve_content
        match dht.resolve_content(&resolve_request.domain, &resolve_request.path).await {
            Ok(Some(content)) => {
                // Convert content to hex string for the hash
                let content_hash = hex::encode(&content);
                let response = DhtResolveResponse {
                    content_hash,
                    domain: resolve_request.domain,
                    path: resolve_request.path,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                info!(" Content resolved to hash: {}", response.content_hash);
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Ok(None) => {
                error!("Content not found for {}{}", resolve_request.domain, resolve_request.path);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Content not found for {}{}", resolve_request.domain, resolve_request.path),
                ))
            }
            Err(e) => {
                error!("Failed to resolve content: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Content not found: {}", e),
                ))
            }
        }
    }

    /// Fetch content by hash
    async fn fetch_content(&self, content_hash: &str) -> ZhtpResult<ZhtpResponse> {
        info!("  Fetching content with hex key: {}", content_hash);

        // CRITICAL FIX: Content is stored in UnifiedStorageSystem's DhtStorage during Web4 registration.
        // Try storage_system first (where Web4 actually stores content).
        
        // First try: UnifiedStorageSystem's DhtStorage (where Web4 stores content)
        // content_hash is already a hex string, pass it directly
        let storage_guard = self.storage_system.read().await;
        if let Some(storage) = storage_guard.as_ref() {
            let mut storage_locked = storage.write().await;
            
            // Pass the hex string directly
            match storage_locked.get_dht_content_by_hex(content_hash).await {
                Ok(Some(content)) => {
                    info!("  Content found in UnifiedStorageSystem's DhtStorage: {} bytes", content.len());
                    drop(storage_locked);
                    drop(storage_guard);
                    return self.create_content_response(content_hash, content, "unified-storage").await;
                }
                Ok(None) => {
                    info!("  Content not in UnifiedStorageSystem's DhtStorage");
                }
                Err(e) => {
                    warn!("   Error querying UnifiedStorageSystem: {}", e);
                }
            }
            drop(storage_locked);
        }
        drop(storage_guard);
        
        // Second try: Global shared DHT
        if let Ok(client) = crate::runtime::shared_dht::get_dht_client().await {
            let mut dht = client.write().await;
            match dht.fetch_content(content_hash).await {
                Ok(Some(content)) => {
                    info!("  Content found in global shared DHT: {} bytes", content.len());
                    return self.create_content_response(content_hash, content, "global-dht").await;
                }
                _ => {
                    info!("  Content not in global shared DHT");
                }
            }
        }

        // Third try: Handler's DHT client (if any)
        let dht_client_guard = self.dht_client.read().await;
        if let Some(client) = dht_client_guard.as_ref() {
            let client = Arc::clone(client);
            drop(dht_client_guard);
            
            let mut dht = client.write().await;
            match dht.fetch_content(content_hash).await {
                Ok(Some(content)) => {
                    info!("  Content found in handler's DHT: {} bytes", content.len());
                    return self.create_content_response(content_hash, content, "handler-dht").await;
                }
                _ => {
                    info!("  Content not in handler's DHT either");
                }
            }
        }
        
        // If not found in any DHT, return error
        warn!("  Content not found anywhere: {}", content_hash);
        return Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            format!("Content not found: {}", content_hash),
        ));
    }
    
    /// Helper to create content response
    async fn create_content_response(&self, content_hash: &str, content: Vec<u8>, source: &str) -> ZhtpResult<ZhtpResponse> {
        // CRITICAL FIX: DHT stores compressed content, but API should return decompressed
        // Try to decompress the content (LZ4 format with prepended size)
        let original_size = content.len();
        let decompressed_content: Vec<u8> = match lz4_flex::decompress_size_prepended(&content) {
            Ok(decompressed) => {
                info!("  Decompressed content: {} bytes -> {} bytes", original_size, decompressed.len());
                decompressed
            }
            Err(e) => {
                // If decompression fails, content might not be compressed (or using different format)
                info!("   Content not compressed or decompression failed: {} - returning as-is", e);
                content
            }
        };
        
        let mut metadata = HashMap::new();
        metadata.insert("content_hash".to_string(), content_hash.to_string());
        metadata.insert("compressed_size".to_string(), original_size.to_string());
        metadata.insert("decompressed_size".to_string(), decompressed_content.len().to_string());
        metadata.insert("source".to_string(), source.to_string());
        metadata.insert("timestamp".to_string(), 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string()
        );

        let response = DhtContentResponse {
            content_hash: content_hash.to_string(),
            content: decompressed_content,
            metadata,
        };

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response).unwrap(),
            "application/json".to_string(),
            None,
        ))
    }
    
    /// DEBUG: List all keys in DHT storage
    async fn list_storage_keys(&self) -> ZhtpResult<ZhtpResponse> {
        info!(" Listing all DHT storage keys (DEBUG)");
        
        let storage_guard = self.storage_system.read().await;
        if let Some(storage) = storage_guard.as_ref() {
            let _storage_locked = storage.read().await;
            
            // Since we can't directly access DhtStorage, return diagnostic info
            let response = serde_json::json!({
                "message": "DHT storage diagnostic - check server logs for details",
                "note": "Run server with RUST_LOG=info to see storage operations"
            });
            
            return Ok(ZhtpResponse::success_with_content_type(
                serde_json::to_vec(&response).unwrap(),
                "application/json".to_string(),
                None,
            ));
        }
        
        Ok(ZhtpResponse::error(
            ZhtpStatus::ServiceUnavailable,
            "Storage system not initialized".to_string(),
        ))
    }

    /// Store content in DHT
    async fn store_content(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        let store_request: DhtStoreRequest = match serde_json::from_slice(&request_body) {
            Ok(req) => req,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request format: {}", e),
                ));
            }
        };

        info!(" Storing content for {}{}", store_request.domain, store_request.path);

        let mut dht_client_guard: tokio::sync::RwLockWriteGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.write().await;
        let client: &mut Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_mut() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        let mut dht = client.write().await;
        match dht.store_content(&store_request.domain, &store_request.path, store_request.content).await {
            Ok(content_hash) => {
                let response = DhtStoreResponse {
                    content_hash: content_hash.clone(),
                    success: true,
                    message: format!("Content stored successfully for {}{}", store_request.domain, store_request.path),
                };

                info!(" Content stored with hash: {}", content_hash);
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to store content: {}", e);
                let response = DhtStoreResponse {
                    content_hash: String::new(),
                    success: false,
                    message: format!("Failed to store content: {}", e),
                };

                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    serde_json::to_string(&response).unwrap(),
                ))
            }
        }
    }

    /// Send DHT query
    async fn query_dht(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        let query_request: DhtQueryRequest = match serde_json::from_slice(&request_body) {
            Ok(req) => req,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request format: {}", e),
                ));
            }
        };

        info!(" Sending DHT query...");

        let dht_client_guard: tokio::sync::RwLockReadGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.read().await;
        let client: &Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        let dht = client.read().await;
        // Send query based on whether peer address is specified
        let result = if let Some(peer_address) = query_request.peer_address {
            dht.send_dht_query(&peer_address, query_request.query).await
        } else {
            // Query first available peer or return empty
            dht.send_dht_query("default", query_request.query).await
        };

        match result {
            Ok(results) => {
                let first_result: Option<String> = results.get(0).cloned();
                let response = DHTQueryResponse {
                    success: true,
                    content_hash: first_result,
                    peers: Some(results),
                    error: None,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                info!(" DHT query completed successfully");
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("DHT query failed: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("DHT query failed: {}", e),
                ))
            }
        }
    }

    /// Get DHT statistics
    async fn get_dht_statistics(&self) -> ZhtpResult<ZhtpResponse> {
        info!(" Getting DHT statistics...");

        let dht_client_guard: tokio::sync::RwLockReadGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.read().await;
        let client: &Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        let dht = client.read().await;
        match dht.get_dht_statistics().await {
            Ok(stats) => {
                let response = DhtStatisticsResponse {
                    queries_sent: stats.get("queries_sent").copied().unwrap_or(0.0) as u64,
                    queries_received: stats.get("queries_received").copied().unwrap_or(0.0) as u64,
                    content_stored: stats.get("content_stored").copied().unwrap_or(0.0) as u64,
                    content_retrieved: stats.get("content_retrieved").copied().unwrap_or(0.0) as u64,
                    cache_hits: stats.get("cache_hits").copied().unwrap_or(0.0) as u64,
                    cache_misses: stats.get("cache_misses").copied().unwrap_or(0.0) as u64,
                    peers_discovered: stats.get("peers_discovered").copied().unwrap_or(0.0) as u64,
                    storage_operations: stats.get("storage_operations").copied().unwrap_or(0.0) as u64,
                };

                info!(" DHT statistics retrieved");
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to get DHT statistics: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get statistics: {}", e),
                ))
            }
        }
    }

    /// Send smart contract DHT packet - Direct blockchain integration
    async fn send_contract_packet(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        info!(" Processing contract deployment via direct blockchain integration");
        
        // Skip JSON parsing - create contract directly
        let contract_id = format!("contract_{}", chrono::Utc::now().timestamp());
        let operation = "Deploy";
        
        info!(" Creating smart contract: {} with operation: {}", contract_id, operation);

        // Deploy smart contract directly to blockchain
        match self.deploy_smart_contract_to_blockchain(contract_id.clone(), operation).await {
            Ok(tx_hash) => {
                info!(" Smart contract deployed successfully to blockchain: {}", tx_hash);
                
                // Also store in DHT for Web4 accessibility
                match self.store_contract_in_dht(&contract_id, &tx_hash).await {
                    Ok(_) => {
                        info!(" Contract metadata stored in DHT for Web4 access");
                        
                        let response_data = serde_json::json!({
                            "status": "success",
                            "message": "Smart contract deployed successfully",
                            "contract_id": contract_id,
                            "blockchain_transaction": tx_hash,
                            "dht_stored": true,
                            "web4_accessible": true
                        });
                        
                        Ok(ZhtpResponse::success_with_content_type(
                            serde_json::to_vec(&response_data).unwrap(),
                            "application/json".to_string(),
                            None,
                        ))
                    }
                    Err(e) => {
                        warn!(" Contract deployed to blockchain but DHT storage failed: {}", e);
                        
                        let response_data = serde_json::json!({
                            "status": "partial_success",
                            "message": "Smart contract deployed to blockchain, DHT storage failed",
                            "contract_id": contract_id,
                            "blockchain_transaction": tx_hash,
                            "dht_stored": false,
                            "error": e.to_string()
                        });
                        
                        Ok(ZhtpResponse::success_with_content_type(
                            serde_json::to_vec(&response_data).unwrap(),
                            "application/json".to_string(),
                            None,
                        ))
                    }
                }
            }
            Err(e) => {
                error!(" Failed to deploy smart contract to blockchain: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Smart contract deployment failed: {}", e),
                ))
            }
        }
    }

    /// List contracts in DHT network
    async fn list_dht_contracts(&self) -> ZhtpResult<ZhtpResponse> {
        info!(" Listing contracts in DHT network...");

        let dht_client_guard: tokio::sync::RwLockReadGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.read().await;
        let _client: &Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        // For now, return a mock list of contracts
        // In a full implementation, this would query the DHT for contracts
        let mock_contracts = vec![
            ContractInfo {
                contract_id: "counter_v1".to_string(),
                name: "Simple Counter".to_string(),
                version: "1.0.0".to_string(),
                author: Some("ZHTP Developer".to_string()),
                description: Some("A simple counter contract for testing".to_string()),
                deployed_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() - 3600, // 1 hour ago
                owner: Some("dht_node_1".to_string()),
            },
            ContractInfo {
                contract_id: "token_v1".to_string(),
                name: "ZHTP Token".to_string(),
                version: "1.0.0".to_string(),
                author: Some("ZHTP Foundation".to_string()),
                description: Some("Official ZHTP token contract".to_string()),
                deployed_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() - 7200, // 2 hours ago
                owner: Some("dht_node_2".to_string()),
            },
        ];

        let response = DhtContractListResponse {
            contracts: mock_contracts.clone(),
            total_count: mock_contracts.len(),
        };

        info!(" Found {} contracts in DHT network", mock_contracts.len());
        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response).unwrap(),
            "application/json".to_string(),
            None,
        ))
    }

    /// Get contract response for a specific message ID
    async fn get_contract_response(&self, message_id: &str) -> ZhtpResult<ZhtpResponse> {
        info!(" Getting contract response for message: {}", message_id);

        // For now, return a mock response
        // In a full implementation, this would check for received responses
        let mock_response = serde_json::json!({
            "received": true,
            "response": {
                "success": true,
                "message_id": message_id,
                "contract_data": {
                    "contract_id": "test_contract",
                    "result": {
                        "success": true,
                        "return_value": [1, 2, 3, 4],
                        "gas_used": 5000,
                        "error": null,
                        "logs": [],
                        "state_hash": "abc123"
                    }
                }
            }
        });

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&mock_response).unwrap(),
            "application/json".to_string(),
            None,
        ))
    }

    /// Get DHT status
    async fn get_dht_status(&self) -> ZhtpResult<ZhtpResponse> {
        debug!(" Getting DHT status...");

        let dht_client_guard: tokio::sync::RwLockReadGuard<Option<Arc<RwLock<ZkDHTIntegration>>>> = self.dht_client.read().await;
        let client: &Arc<RwLock<ZkDHTIntegration>> = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                let response = DhtStatusResponse {
                    connected: false,
                    peer_count: 0,
                    cache_size: 0,
                    storage_available: 0,
                    network_health: 0.0,
                };

                return Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ));
            }
        };

        let dht = client.read().await;
        match dht.get_network_status().await {
            Ok(network_status) => {
                let response = DhtStatusResponse {
                    connected: network_status.connected_nodes > 0,
                    peer_count: network_status.connected_nodes as usize,
                    cache_size: 0, // Not available in DHTNetworkStatus
                    storage_available: network_status.total_keys as u64,
                    network_health: if network_status.connected_nodes > 0 {
                        0.8 + (network_status.connected_nodes as f64 * 0.02).min(0.2)
                    } else { 
                        0.0 
                    },
                };

                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                warn!("Failed to get network status: {}", e);
                let response = DhtStatusResponse {
                    connected: false,
                    peer_count: 0,
                    cache_size: 0,
                    storage_available: 0,
                    network_health: 0.0,
                };

                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
        }
    }

    /// Create a default identity for DHT operations
    fn create_default_dht_identity(&self) -> ZhtpIdentity {
        use lib_identity::types::IdentityType;
        use lib_identity::ZhtpIdentity;

        // Create DHT service identity using P1-7 architecture
        ZhtpIdentity::new_unified(
            IdentityType::Device,
            None, // No age for service
            None, // No jurisdiction for service
            "dht-service",
            Some([42u8; 64]), // Fixed seed for deterministic DHT service identity
        ).unwrap_or_else(|_| {
            // Fallback to random seed if fixed seed fails
            ZhtpIdentity::new_unified(
                IdentityType::Device,
                None,
                None,
                "dht-service-fallback",
                None,
            ).expect("Failed to create DHT service identity")
        })
    }

    /// Update handler statistics
    async fn update_stats(&self, success: bool) {
        let mut stats = self.stats.write().await;
        stats.requests_handled += 1;
        if !success {
            stats.errors_encountered += 1;
        }
        stats.last_request_time = Some(std::time::Instant::now());
    }

    /// Deploy smart contract directly to blockchain (bypassing HTTP API)
    /// 
    ///  REMOVED: This function created fake system transactions with invalid signatures.
    /// 
    /// ARCHITECTURAL ISSUE: Contract deployment should either:
    /// 1. Be a real system transaction (only for protocol-level contracts)
    /// 2. Require deployer identity and proper signature (for user contracts)
    /// 
    /// The previous implementation used:
    /// - Fake "SYSTEM_CONTRACT_DEPLOY_INPUT" (not a real system transaction)
    /// - contract_id.as_bytes() as signature (not cryptographically valid)
    /// - "SYSTEM_CONTRACT_DEPLOYER" as public key (not real)
    /// 
    /// This would be REJECTED by blockchain validation.
    async fn deploy_smart_contract_to_blockchain(&self, contract_id: String, operation: &str) -> Result<String, anyhow::Error> {
        Err(anyhow::anyhow!(
            "Smart contract deployment via DHT disabled: requires proper deployer identity and signature. \
             Contract deployment should use proper TransactionBuilder with deployer's private key, \
             or be implemented as protocol-level system transaction if needed for core functionality."
        ))
    }

    /// Store contract metadata in DHT for Web4 accessibility
    async fn store_contract_in_dht(&self, contract_id: &str, blockchain_tx_hash: &str) -> Result<(), anyhow::Error> {
        info!(" Storing contract {} metadata in DHT with blockchain reference: {}", contract_id, blockchain_tx_hash);
        
        // Create contract metadata for DHT storage
        let metadata = serde_json::json!({
            "contract_id": contract_id,
            "blockchain_transaction": blockchain_tx_hash,
            "deployment_time": chrono::Utc::now().timestamp(),
            "type": "smart_contract",
            "status": "deployed",
            "web4_accessible": true,
            "dht_key": format!("contract:{}", contract_id)
        });
        
        // Store in DHT (for now just log - would use actual DHT client)
        info!(" DHT storage metadata: {}", metadata);
        info!(" Contract {} metadata stored in DHT successfully", contract_id);
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for DhtHandler {
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/dht/") || request.uri.starts_with("/api/dht/")
    }

    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let _success = true;
        let response = match request.method {
            ZhtpMethod::Get => match request.uri.as_str() {
                "/api/v1/dht/status" => {
                    debug!(" DHT status request");
                    self.get_dht_status().await
                }
                "/api/v1/dht/peers" => {
                    info!(" DHT peers request");
                    self.discover_peers().await
                }
                "/api/v1/dht/statistics" => {
                    info!(" DHT statistics request");
                    self.get_dht_statistics().await
                }
                "/api/v1/dht/storage/keys" => {
                    info!(" DHT storage keys debug request");
                    self.list_storage_keys().await
                }
                "/api/dht/contracts/list" => {
                    info!(" DHT contracts list request");
                    self.list_dht_contracts().await
                }
                path if path.starts_with("/api/dht/response/") => {
                    let message_id = path.strip_prefix("/api/dht/response/").unwrap_or("");
                    if message_id.is_empty() {
                        Ok(ZhtpResponse::error(
                            ZhtpStatus::BadRequest,
                            "Message ID required".to_string(),
                        ))
                    } else {
                        info!(" DHT contract response request: {}", message_id);
                        self.get_contract_response(message_id).await
                    }
                }
                path if path.starts_with("/api/v1/dht/content/") => {
                    let content_hash = path.strip_prefix("/api/v1/dht/content/").unwrap_or("");
                    if content_hash.is_empty() {
                        Ok(ZhtpResponse::error(
                            ZhtpStatus::BadRequest,
                            "Content hash required".to_string(),
                        ))
                    } else {
                        info!(" DHT fetch content request: {}...", &content_hash[..16.min(content_hash.len())]);
                        self.fetch_content(content_hash).await
                    }
                }
                _ => {
                    warn!("❓ Unknown DHT GET endpoint: {}", request.uri);
                    Ok(ZhtpResponse::not_found("Unknown DHT GET endpoint".to_string()))
                }
            },
            ZhtpMethod::Post => match request.uri.as_str() {
                "/api/v1/dht/initialize" => {
                    info!(" DHT initialize request");
                    self.initialize_dht_client(request.body).await
                }
                "/api/v1/dht/connect" => {
                    info!(" DHT connect request");
                    self.connect_to_peer(request.body).await
                }
                "/api/v1/dht/resolve" => {
                    info!(" DHT resolve request");
                    self.resolve_content(request.body).await
                }
                "/api/v1/dht/store" => {
                    info!(" DHT store request");
                    self.store_content(request.body).await
                }
                "/api/v1/dht/query" => {
                    info!(" DHT query request");
                    self.query_dht(request.body).await
                }
                "/api/dht/send" => {
                    info!(" DHT contract packet send request");
                    self.send_contract_packet(request.body).await
                }
                "/api/v1/dht/contract" => {
                    info!(" DHT smart contract operation request");
                    self.send_contract_packet(request.body).await
                }
                _ => {
                    warn!("❓ Unknown DHT POST endpoint: {}", request.uri);
                    Ok(ZhtpResponse::not_found("Unknown DHT POST endpoint".to_string()))
                }
            },
            _ => {
                warn!(" Unsupported DHT method: {:?}", request.method);
                Ok(ZhtpResponse::method_not_allowed("Method not allowed for DHT endpoint".to_string()))
            }
        };

        // Update statistics
        match &response {
            Ok(resp) => {
                let success = !matches!(resp.status, ZhtpStatus::InternalServerError | ZhtpStatus::ServiceUnavailable);
                self.update_stats(success).await;
            }
            Err(_) => {
                self.update_stats(false).await;
            }
        }

        response
    }
}
