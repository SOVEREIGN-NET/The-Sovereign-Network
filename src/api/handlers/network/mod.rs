//! Network API handlers for ZHTP
//! 
//! Provides endpoints for network management, peer operations, and network statistics.
//! Built on lib-network functions and runtime orchestrator capabilities.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
// Removed unused tokio::sync::RwLock, anyhow::Result, serde_json::json
use tracing::{info, warn, error};

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

use crate::runtime::RuntimeOrchestrator;

// Request/Response structures for network operations

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkPeersResponse {
    pub status: String,
    pub peer_count: usize,
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub peer_type: String,
    pub status: String,
    pub connection_time: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkStatsResponse {
    pub status: String,
    pub mesh_status: MeshStatusInfo,
    pub traffic_stats: TrafficStats,
    pub peer_distribution: PeerDistribution,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MeshStatusInfo {
    pub internet_connected: bool,
    pub mesh_connected: bool,
    pub connectivity_percentage: f64,
    pub coverage: f64,
    pub stability: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerDistribution {
    pub active_peers: u32,
    pub local_peers: u32,
    pub regional_peers: u32,
    pub global_peers: u32,
    pub relay_peers: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddPeerRequest {
    pub peer_address: String,
    pub peer_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddPeerResponse {
    pub status: String,
    pub peer_id: String,
    pub message: String,
    pub connected: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovePeerResponse {
    pub status: String,
    pub peer_id: String,
    pub message: String,
    pub removed: bool,
}

/// Network handler implementation
pub struct NetworkHandler {
    runtime: Arc<RuntimeOrchestrator>,
}

impl NetworkHandler {
    pub fn new(runtime: Arc<RuntimeOrchestrator>) -> Self {
        Self { runtime }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for NetworkHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("Network handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Get, "/api/v1/blockchain/network/peers") => {
                self.handle_get_network_peers(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/network/stats") => {
                self.handle_get_network_stats(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/network/peer/add") => {
                self.handle_add_network_peer(request).await
            }
            (ZhtpMethod::Delete, path) if path.starts_with("/api/v1/blockchain/network/peer/") => {
                self.handle_remove_network_peer(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Network endpoint not found".to_string(),
                ))
            }
        };
        
        match response {
            Ok(mut resp) => {
                resp.headers.set("X-Handler", "Network".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                error!("Network handler error: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Network error: {}", e),
                ))
            }
        }
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/blockchain/network/")
    }
    
    fn priority(&self) -> u32 {
        85 // Lower priority than blockchain, higher than storage
    }
}

impl NetworkHandler {
    /// Get list of connected peers
    /// GET /api/v1/blockchain/network/peers
    async fn handle_get_network_peers(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting network peers");

        match self.runtime.get_connected_peers().await {
            Ok(peer_list) => {
                let peers: Vec<PeerInfo> = peer_list.into_iter().enumerate().map(|(i, peer_name)| {
                    let peer_type = if peer_name.starts_with("local-") {
                        "local"
                    } else if peer_name.starts_with("regional-") {
                        "regional"
                    } else if peer_name.starts_with("global-") {
                        "global"
                    } else if peer_name.starts_with("relay-") {
                        "relay"
                    } else {
                        "unknown"
                    };

                    PeerInfo {
                        peer_id: format!("peer_{}", i + 1),
                        peer_type: peer_type.to_string(),
                        status: if peer_name == "No peers connected" || peer_name == "Network status unavailable" {
                            "disconnected"
                        } else {
                            "connected"
                        }.to_string(),
                        connection_time: if peer_name != "No peers connected" && peer_name != "Network status unavailable" {
                            Some(std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs())
                        } else {
                            None
                        },
                    }
                }).collect();

                let response = NetworkPeersResponse {
                    status: "success".to_string(),
                    peer_count: peers.len(),
                    peers,
                };

                info!("API: Retrieved {} network peers", response.peer_count);
                
                let json_response = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to get network peers: {}", e);
                
                let error_response = NetworkPeersResponse {
                    status: "error".to_string(),
                    peer_count: 0,
                    peers: vec![],
                };
                
                let json_response = serde_json::to_vec(&error_response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
        }
    }

    /// Get network statistics
    /// GET /api/v1/blockchain/network/stats
    async fn handle_get_network_stats(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting network statistics");

        // Get mesh status from lib-network
        let mesh_status = match lib_network::get_mesh_status().await {
            Ok(status) => status,
            Err(e) => {
                warn!("API: Failed to get mesh status: {}", e);
                lib_network::types::MeshStatus::default()
            }
        };

        // Get network statistics from lib-network
        let network_stats = match lib_network::get_network_statistics().await {
            Ok(stats) => stats,
            Err(e) => {
                warn!("API: Failed to get network statistics: {}", e);
                lib_network::types::NetworkStatistics {
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    peer_count: 0,
                    connection_count: 0,
                }
            }
        };

        let response = NetworkStatsResponse {
            status: "success".to_string(),
            mesh_status: MeshStatusInfo {
                internet_connected: mesh_status.internet_connected,
                mesh_connected: mesh_status.mesh_connected,
                connectivity_percentage: mesh_status.connectivity_percentage,
                coverage: mesh_status.coverage,
                stability: mesh_status.stability,
            },
            traffic_stats: TrafficStats {
                bytes_sent: network_stats.bytes_sent,
                bytes_received: network_stats.bytes_received,
                packets_sent: network_stats.packets_sent,
                packets_received: network_stats.packets_received,
                connection_count: network_stats.connection_count,
            },
            peer_distribution: PeerDistribution {
                active_peers: mesh_status.active_peers,
                local_peers: mesh_status.local_peers,
                regional_peers: mesh_status.regional_peers,
                global_peers: mesh_status.global_peers,
                relay_peers: mesh_status.relay_peers,
            },
        };

        info!("API: Retrieved network statistics - {} active peers, {:.1}% connectivity", 
              response.peer_distribution.active_peers,
              response.mesh_status.connectivity_percentage);
        
        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
        
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Add a new peer to the network
    /// POST /api/v1/blockchain/network/peer/add
    async fn handle_add_network_peer(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Adding network peer");

        // Parse request body
        let add_request: AddPeerRequest = if request.body.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Request body is required".to_string(),
            ));
        } else {
            serde_json::from_slice(&request.body)
                .map_err(|e| anyhow::anyhow!("Invalid JSON in request body: {}", e))?
        };

        // Validate peer address format
        if add_request.peer_address.is_empty() {
            warn!("API: Empty peer address provided");
            let error_response = AddPeerResponse {
                status: "error".to_string(),
                peer_id: "".to_string(),
                message: "Peer address cannot be empty".to_string(),
                connected: false,
            };

            let json_response = serde_json::to_vec(&error_response)
                .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
            
            return Ok(ZhtpResponse::success_with_content_type(
                json_response,
                "application/json".to_string(),
                None,
            ));
        }

        // Generate peer ID based on address
        let peer_id = format!("peer_{}", 
            std::collections::hash_map::DefaultHasher::new()
                .using(&add_request.peer_address)
                .finish());

        match self.runtime.connect_to_peer(&add_request.peer_address).await {
            Ok(()) => {
                let response = AddPeerResponse {
                    status: "success".to_string(),
                    peer_id: peer_id.clone(),
                    message: format!("Successfully initiated connection to peer {}", add_request.peer_address),
                    connected: true,
                };

                info!("API: Successfully added peer {} ({})", peer_id, add_request.peer_address);
                
                let json_response = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to add peer {}: {}", add_request.peer_address, e);
                
                let response = AddPeerResponse {
                    status: "error".to_string(),
                    peer_id: peer_id,
                    message: format!("Failed to connect to peer: {}", e),
                    connected: false,
                };
                
                let json_response = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
        }
    }

    /// Remove a peer from the network
    /// DELETE /api/v1/blockchain/network/peer/{peer_id}
    async fn handle_remove_network_peer(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract peer_id from URL path
        let peer_id = match request.uri.strip_prefix("/api/v1/blockchain/network/peer/") {
            Some(id_str) => id_str.to_string(),
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid peer removal URL format".to_string(),
                ));
            }
        };

        info!("🔌 API: Removing network peer: {}", peer_id);

        // For demonstration, we'll use the peer_id as the address
        // In a real implementation, you'd maintain a mapping of peer_id -> address
        let peer_address = format!("peer-address-{}", peer_id);

        match self.runtime.disconnect_from_peer(&peer_address).await {
            Ok(()) => {
                let response = RemovePeerResponse {
                    status: "success".to_string(),
                    peer_id: peer_id.clone(),
                    message: format!("Successfully initiated disconnection from peer {}", peer_id),
                    removed: true,
                };

                info!("API: Successfully removed peer {}", peer_id);
                
                let json_response = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to remove peer {}: {}", peer_id, e);
                
                let response = RemovePeerResponse {
                    status: "error".to_string(),
                    peer_id: peer_id.clone(),
                    message: format!("Failed to disconnect from peer: {}", e),
                    removed: false,
                };
                
                let json_response = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
        }
    }
}

// Helper trait for hash generation (using std::hash)
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

trait HashExtension {
    fn using<T: Hash>(self, value: &T) -> Self;
}

impl HashExtension for DefaultHasher {
    fn using<T: Hash>(mut self, value: &T) -> Self {
        value.hash(&mut self);
        self
    }
}