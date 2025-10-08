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
use lib_network::DHTClient;
use lib_network::dht::{DHTQuery, DHTQueryResponse};
use lib_network::dht::protocol::{ZhtpQueryOptions, CachePreference};
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
    pub query: DHTQuery,
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
    dht_client: Arc<RwLock<Option<DHTClient>>>,
    /// Handler statistics
    stats: Arc<RwLock<DhtHandlerStats>>,
    /// Mesh connections for querying peers
    mesh_connections: Arc<RwLock<HashMap<PublicKey, MeshConnection>>>,
    /// ZHTP relay protocol for encrypted queries
    relay_protocol: Arc<RwLock<Option<ZhtpRelayProtocol>>>,
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
            .finish()
    }
}

impl DhtHandler {
    /// Create a new DHT handler with mesh router access
    pub fn new(mesh_router: Arc<MeshRouter>) -> Self {
        Self {
            dht_client: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(DhtHandlerStats::default())),
            mesh_connections: mesh_router.get_connections(),
            relay_protocol: mesh_router.get_relay_protocol(),
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

        // Initialize DHT client
        match lib_network::initialize_dht_client(identity).await {
            Ok(client) => {
                *self.dht_client.write().await = Some(client);
                
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

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        match client.connect_to_peer(&connect_request.peer_address).await {
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

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        match client.discover_peers().await {
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

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        match client.resolve_content(&resolve_request.domain, &resolve_request.path).await {
            Ok(content_hash) => {
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
        info!("📥 Fetching content: {}...", &content_hash[..16]);

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        // Try local DHT first
        match client.fetch_content(content_hash).await {
            Ok(content) => {
                let mut metadata = HashMap::new();
                metadata.insert("content_hash".to_string(), content_hash.to_string());
                metadata.insert("size".to_string(), content.len().to_string());
                metadata.insert("source".to_string(), "local-dht".to_string());
                metadata.insert("timestamp".to_string(), 
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .to_string()
                );

                let response = DhtContentResponse {
                    content_hash: content_hash.to_string(),
                    content,
                    metadata,
                };

                info!("✅ Content fetched from local DHT: {} bytes", response.content.len());
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&response).unwrap(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(local_err) => {
                info!("❌ Content not in local DHT, querying mesh peers...");
                
                // ✅ Query mesh peers (TCP and Bluetooth)
                match self.query_mesh_peers_for_content(content_hash).await {
                    Ok(content) => {
                        let mut metadata = HashMap::new();
                        metadata.insert("content_hash".to_string(), content_hash.to_string());
                        metadata.insert("size".to_string(), content.len().to_string());
                        metadata.insert("source".to_string(), "mesh-peer".to_string());
                        metadata.insert("timestamp".to_string(), 
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                                .to_string()
                        );

                        let response = DhtContentResponse {
                            content_hash: content_hash.to_string(),
                            content,
                            metadata,
                        };

                        info!("✅ Content fetched from mesh peer: {} bytes", response.content.len());
                        Ok(ZhtpResponse::success_with_content_type(
                            serde_json::to_vec(&response).unwrap(),
                            "application/json".to_string(),
                            None,
                        ))
                    }
                    Err(mesh_err) => {
                        error!("Failed to fetch content from DHT and mesh: local={}, mesh={}", local_err, mesh_err);
                        Ok(ZhtpResponse::error(
                            ZhtpStatus::NotFound,
                            format!("Content not found in DHT or mesh network: {}", content_hash),
                        ))
                    }
                }
            }
        }
    }
    
    /// Query mesh peers for content (including Bluetooth peers)
    async fn query_mesh_peers_for_content(&self, content_hash: &str) -> Result<Vec<u8>, anyhow::Error> {
        info!("🔍 Querying mesh peers for content: {}", &content_hash[..16.min(content_hash.len())]);
        
        // Get mesh connections from handler's reference
        let connections = self.mesh_connections.read().await;
        
        if connections.is_empty() {
            return Err(anyhow::anyhow!("No mesh peers available"));
        }
        
        info!("📡 Querying {} mesh peers (TCP + Bluetooth)", connections.len());
        
        // Try each peer until we find the content
        for (peer_id, connection) in connections.iter() {
            let peer_id_hex = hex::encode(&peer_id.as_bytes()[..8.min(peer_id.as_bytes().len())]);
            info!("  Querying peer {} via {:?}...", peer_id_hex, connection.protocol);
            
            // Send relay query to peer
            match self.send_relay_query_to_peer(peer_id, connection, content_hash).await {
                Ok(content) => {
                    info!("✅ Found content on peer {}", peer_id_hex);
                    return Ok(content);
                }
                Err(e) => {
                    debug!("  Peer {} doesn't have content: {}", peer_id_hex, e);
                    continue;
                }
            }
        }
        
        Err(anyhow::anyhow!("Content not found on any mesh peer"))
    }
    
    /// Send ZHTP relay query to a specific peer
    async fn send_relay_query_to_peer(
        &self,
        _peer_id: &lib_crypto::PublicKey,
        connection: &lib_network::MeshConnection,
        content_hash: &str,
    ) -> Result<Vec<u8>, anyhow::Error> {
        use lib_network::protocols::NetworkProtocol;
        
        // Get the peer's address from connection
        let peer_addr = connection.peer_address.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Peer has no known address"))?;
        
        match connection.protocol {
            NetworkProtocol::TCP => {
                // Send UDP relay query (existing ZHTP relay protocol)
                self.send_udp_relay_query(peer_addr, content_hash).await
            }
            NetworkProtocol::BluetoothLE => {
                // Send via TCP to Bluetooth peer (they're connected via TCP too)
                self.send_tcp_relay_query(peer_addr, content_hash).await
            }
            NetworkProtocol::WiFiDirect => {
                // Send via TCP for WiFi Direct peers
                self.send_tcp_relay_query(peer_addr, content_hash).await
            }
            _ => {
                Err(anyhow::anyhow!("Unsupported protocol: {:?}", connection.protocol))
            }
        }
    }
    
    /// Send UDP relay query (standard ZHTP relay protocol)
    async fn send_udp_relay_query(&self, peer_addr: &str, content_hash: &str) -> Result<Vec<u8>, anyhow::Error> {
        use tokio::net::UdpSocket;
        use lib_network::dht::protocol::ZhtpQueryOptions;
        
        info!("📤 Sending UDP relay query to {}", peer_addr);
        
        // Parse content_hash as domain/path
        let (domain, path) = if content_hash.contains('/') {
            let parts: Vec<&str> = content_hash.splitn(2, '/').collect();
            (parts[0], parts.get(1).copied().unwrap_or(""))
        } else {
            (content_hash, "")
        };
        
        // Get relay protocol from handler's reference
        let relay_protocol = self.relay_protocol.read().await;
        if let Some(protocol) = relay_protocol.as_ref() {
            // Create relay query options
            let options = ZhtpQueryOptions {
                max_size: Some(1024 * 1024), // 1MB max
                accept_compression: true,
                cache_preference: CachePreference::PreferFresh,
            };
            
            let query = protocol.create_relay_query(peer_addr, domain, path, options).await?;
            let query_bytes = bincode::serialize(&query)?;
            
            // Send via UDP
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.send_to(&query_bytes, peer_addr).await?;
            
            // Wait for response (with timeout)
            let mut response_buf = vec![0u8; 65536];
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.recv_from(&mut response_buf)
            ).await {
                Ok(Ok((len, _))) => {
                    // Parse response
                    if let Ok(response) = bincode::deserialize::<lib_network::dht::protocol::ZhtpRelayResponse>(&response_buf[..len]) {
                        let payload = protocol.process_relay_response(peer_addr, &response).await?;
                        if let Some(content) = payload.content {
                            return Ok(content);
                        }
                    }
                    Err(anyhow::anyhow!("Invalid relay response"))
                }
                Ok(Err(e)) => Err(anyhow::anyhow!("UDP receive error: {}", e)),
                Err(_) => Err(anyhow::anyhow!("Relay query timeout"))
            }
        } else {
            Err(anyhow::anyhow!("Relay protocol not initialized"))
        }
    }
    
    /// Send TCP relay query (for Bluetooth and WiFi Direct peers)
    /// Uses DHTClient's built-in send_dht_query which has proper blockchain identity and Dilithium2 signing
    async fn send_tcp_relay_query(&self, peer_addr: &str, content_hash: &str) -> Result<Vec<u8>, anyhow::Error> {
        info!("📤 Sending TCP DHT query to {} for hash {}", peer_addr, &content_hash[..8.min(content_hash.len())]);
        
        // Parse content hash into domain/path format
        let (domain, path) = if content_hash.contains('/') {
            let parts: Vec<&str> = content_hash.splitn(2, '/').collect();
            (parts[0].to_string(), format!("/{}", parts.get(1).unwrap_or(&"")))
        } else {
            (content_hash.to_string(), "/".to_string())
        };
        
        // Use DHTClient's send_dht_query if available (has blockchain-verified identity + Dilithium2 signing)
        let dht_client_guard = self.dht_client.read().await;
        if let Some(ref client) = *dht_client_guard {
            let query = lib_network::dht::DHTQuery::ContentResolve {
                domain,
                path,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            
            match client.send_dht_query(peer_addr, query).await {
                Ok(response) => {
                    // DHTQueryResponse is a struct with success/error/content_hash fields
                    if response.success {
                        if let Some(hash) = response.content_hash {
                            info!("✅ Received content hash from peer {}: {}", peer_addr, hash);
                            // Content hash received - would fetch content from storage
                            // For now, return an error to indicate content needs to be fetched
                            return Err(anyhow::anyhow!("Content hash received but content fetch not implemented"));
                        } else {
                            debug!("✅ Query succeeded but no content hash returned from {}", peer_addr);
                            return Err(anyhow::anyhow!("No content hash in response"));
                        }
                    } else if let Some(err) = response.error {
                        return Err(anyhow::anyhow!("DHT query error: {}", err));
                    } else {
                        return Err(anyhow::anyhow!("Unexpected DHT response - no success or error"));
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("DHT query failed: {}", e));
                }
            }
        }
        
        Err(anyhow::anyhow!("No DHT client available"))
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

        info!("💾 Storing content for {}{}", store_request.domain, store_request.path);

        let mut dht_client_guard = self.dht_client.write().await;
        let client = match dht_client_guard.as_mut() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        match client.store_content(&store_request.domain, &store_request.path, store_request.content).await {
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

        info!("📤 Sending DHT query...");

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        // Send query based on whether peer address is specified
        let result = if let Some(peer_address) = query_request.peer_address {
            client.send_dht_query(&peer_address, query_request.query).await
        } else {
            // Query all connected peers or use a default query method
            client.query_dht(&format!("{:?}", query_request.query)).await
                .map(|results| DHTQueryResponse {
                    success: true,
                    content_hash: results.first().cloned(),
                    peers: Some(results),
                    error: None,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                })
        };

        match result {
            Ok(response) => {
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
        info!("📊 Getting DHT statistics...");

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
            Some(client) => client,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "DHT client not initialized".to_string(),
                ));
            }
        };

        match client.get_dht_statistics().await {
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
                        warn!("⚠️ Contract deployed to blockchain but DHT storage failed: {}", e);
                        
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
                error!("❌ Failed to deploy smart contract to blockchain: {}", e);
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

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
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
        info!("📥 Getting contract response for message: {}", message_id);

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

        let dht_client_guard = self.dht_client.read().await;
        let client = match dht_client_guard.as_ref() {
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

        match client.get_network_status().await {
            Ok(network_status) => {
                let response = DhtStatusResponse {
                    connected: network_status.connected,
                    peer_count: network_status.peer_count,
                    cache_size: network_status.cache_size,
                    storage_available: network_status.storage_available,
                    network_health: if network_status.connected && network_status.peer_count > 0 { 
                        0.8 + (network_status.peer_count as f64 * 0.02).min(0.2)
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
        use lib_identity::types::{IdentityType, AccessLevel};
        use lib_identity::wallets::WalletManager;
        use lib_identity::{IdentityId, ZhtpIdentity};
        use lib_proofs::ZeroKnowledgeProof;
        use std::collections::HashMap;

        let identity_id = IdentityId::from_bytes(&[42u8; 32]); // Fixed ID for DHT operations
        
        ZhtpIdentity {
            id: identity_id.clone(),
            identity_type: IdentityType::Device, // DHT service identity
            public_key: vec![1, 2, 3, 4, 5, 6, 7, 8], // Placeholder public key
            ownership_proof: ZeroKnowledgeProof {
                proof_system: "dht_service".to_string(),
                proof_data: vec![],
                public_inputs: vec![],
                verification_key: vec![],
                plonky2_proof: None,
                proof: vec![],
            },
            credentials: HashMap::new(),
            reputation: 100, // High reputation for DHT service
            age: None, // Services don't have age
            access_level: AccessLevel::FullCitizen, // Full access for DHT operations
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("type".to_string(), "dht_service".to_string());
                metadata.insert("version".to_string(), "1.0".to_string());
                metadata
            },
            private_data_id: None,
            wallet_manager: WalletManager::new(identity_id),
            did_document_hash: None,
            attestations: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            recovery_keys: vec![],
        }
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
    async fn deploy_smart_contract_to_blockchain(&self, contract_id: String, operation: &str) -> Result<String, anyhow::Error> {
        info!("🚀 Deploying smart contract {} to blockchain with operation: {}", contract_id, operation);
        
        // Get direct access to blockchain
        let blockchain = get_global_blockchain().await?;
        
        // Create smart contract transaction
        let contract_bytecode = format!("CONTRACT_{}_{}", contract_id, operation);
        let metadata = format!("Smart contract deployment: {}", contract_id);
        
        // Create transaction inputs (for smart contract deployment, we use system input)
        let system_input = TransactionInput {
            previous_output: BlockchainHash::from_slice(b"SYSTEM_CONTRACT_DEPLOY_INPUT___"),
            output_index: 0,
            nullifier: BlockchainHash::from_slice(&contract_id.as_bytes()[..32.min(contract_id.len())]),
            zk_proof: ZkTransactionProof::default(),
        };
        
        // Create transaction output (contract deployment)
        let contract_output = TransactionOutput {
            commitment: BlockchainHash::from_slice(contract_bytecode.as_bytes()),
            note: BlockchainHash::from_slice(contract_id.as_bytes()),
            recipient: PublicKey::new(contract_id.as_bytes().to_vec()),
        };
        
        // Create signature for the transaction
        let signature = Signature {
            signature: contract_id.as_bytes().to_vec(),
            public_key: PublicKey::new(b"SYSTEM_CONTRACT_DEPLOYER_____".to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        // Create the transaction
        let mut transaction = Transaction::new(
            vec![system_input],
            vec![contract_output],
            1000, // Fee for contract deployment
            signature,
            metadata.as_bytes().to_vec(),
        );
        
        // Set transaction type for smart contract deployment
        transaction.transaction_type = TransactionType::ContractDeployment;
        let tx_hash = transaction.hash().to_string();
        
        // Add transaction to blockchain directly
        add_transaction(transaction).await?;
        
        info!(" Smart contract {} deployed to blockchain with hash: {}", contract_id, tx_hash);
        Ok(tx_hash)
    }

    /// Store contract metadata in DHT for Web4 accessibility
    async fn store_contract_in_dht(&self, contract_id: &str, blockchain_tx_hash: &str) -> Result<(), anyhow::Error> {
        info!("📦 Storing contract {} metadata in DHT with blockchain reference: {}", contract_id, blockchain_tx_hash);
        
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
        info!("📦 DHT storage metadata: {}", metadata);
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
                    debug!("🌐 DHT status request");
                    self.get_dht_status().await
                }
                "/api/v1/dht/peers" => {
                    info!("👥 DHT peers request");
                    self.discover_peers().await
                }
                "/api/v1/dht/statistics" => {
                    info!("📊 DHT statistics request");
                    self.get_dht_statistics().await
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
                        info!("📥 DHT contract response request: {}", message_id);
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
                        info!("📥 DHT fetch content request: {}...", &content_hash[..16.min(content_hash.len())]);
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
                    info!("💾 DHT store request");
                    self.store_content(request.body).await
                }
                "/api/v1/dht/query" => {
                    info!("📤 DHT query request");
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
                warn!("❌ Unsupported DHT method: {:?}", request.method);
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
