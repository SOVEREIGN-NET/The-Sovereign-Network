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
pub struct GasInfoResponse {
    pub status: String,
    pub gas_price: u64,
    pub estimated_cost: u64,
    pub base_fee: u64,
    pub priority_fee: u64,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncMetricsResponse {
    pub status: String,
    pub blocks_sent: u64,
    pub blocks_received: u64,
    pub transactions_sent: u64,
    pub transactions_received: u64,
    pub blocks_relayed: u64,
    pub transactions_relayed: u64,
    pub blocks_rejected: u64,
    pub transactions_rejected: u64,
    pub sync_efficiency: f64,
    pub relay_ratio: f64,
}

// Phase 4: Advanced monitoring response structures

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetricsResponse {
    pub status: String,
    pub avg_block_propagation_ms: f64,
    pub avg_tx_propagation_ms: f64,
    pub p95_block_latency_ms: u64,
    pub p95_tx_latency_ms: u64,
    pub min_block_latency_ms: u64,
    pub max_block_latency_ms: u64,
    pub min_tx_latency_ms: u64,
    pub max_tx_latency_ms: u64,
    pub bytes_sent_per_sec: f64,
    pub bytes_received_per_sec: f64,
    pub peak_bandwidth_usage_bps: u64,
    pub duplicate_block_ratio: f64,
    pub duplicate_tx_ratio: f64,
    pub validation_success_rate: f64,
    pub relay_efficiency: f64,
    pub measurement_duration_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertsResponse {
    pub status: String,
    pub total_alerts: usize,
    pub unacknowledged_count: usize,
    pub alerts: Vec<AlertInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertInfo {
    pub id: String,
    pub level: String,
    pub category: String,
    pub message: String,
    pub timestamp: u64,
    pub acknowledged: bool,
    pub peer_id: Option<String>,
    pub metric_value: Option<f64>,
    pub threshold_value: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcknowledgeAlertRequest {
    pub alert_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcknowledgeAlertResponse {
    pub status: String,
    pub acknowledged: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertThresholdsResponse {
    pub status: String,
    pub max_block_latency_ms: u64,
    pub max_tx_latency_ms: u64,
    pub max_bandwidth_mbps: f64,
    pub min_validation_success_rate: f64,
    pub max_duplicate_ratio: f64,
    pub min_peer_score: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateThresholdsRequest {
    pub max_block_latency_ms: Option<u64>,
    pub max_tx_latency_ms: Option<u64>,
    pub max_bandwidth_mbps: Option<f64>,
    pub min_validation_success_rate: Option<f64>,
    pub max_duplicate_ratio: Option<f64>,
    pub min_peer_score: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsHistoryResponse {
    pub status: String,
    pub interval_secs: u64,
    pub snapshots: Vec<HistorySnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HistorySnapshot {
    pub timestamp: u64,
    pub blocks_received: u64,
    pub txs_received: u64,
    pub blocks_rejected: u64,
    pub txs_rejected: u64,
    pub avg_latency_ms: f64,
    pub bandwidth_bps: u64,
    pub active_peers: usize,
    pub banned_peers: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerPerformanceResponse {
    pub status: String,
    pub total_peers: usize,
    pub peers: Vec<PeerPerformanceInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerPerformanceInfo {
    pub peer_id: String,
    pub reputation_score: i32,
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub txs_accepted: u64,
    pub txs_rejected: u64,
    pub violations: u32,
    pub acceptance_rate: f64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub status: String, // "active", "warning", "banned"
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
            // Gas pricing endpoint (Issue #10)
            (ZhtpMethod::Get, "/api/v1/network/gas") => {
                self.handle_get_gas_info(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/network/peers") => {
                self.handle_get_network_peers(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/network/stats") => {
                self.handle_get_network_stats(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/sync/metrics") => {
                self.handle_get_sync_metrics(request).await
            }
            // Phase 4: Advanced monitoring endpoints
            (ZhtpMethod::Get, "/api/v1/blockchain/sync/performance") => {
                self.handle_get_performance_metrics(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/sync/alerts") => {
                self.handle_get_alerts(request).await
            }
            (ZhtpMethod::Post, "/api/v1/blockchain/sync/alerts/acknowledge") => {
                self.handle_acknowledge_alert(request).await
            }
            (ZhtpMethod::Delete, "/api/v1/blockchain/sync/alerts/acknowledged") => {
                self.handle_clear_acknowledged_alerts(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/sync/alerts/thresholds") => {
                self.handle_get_alert_thresholds(request).await
            }
            (ZhtpMethod::Put, "/api/v1/blockchain/sync/alerts/thresholds") => {
                self.handle_update_alert_thresholds(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/sync/history") => {
                self.handle_get_metrics_history(request).await
            }
            (ZhtpMethod::Get, "/api/v1/blockchain/sync/peers") => {
                self.handle_get_peer_performance(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/blockchain/sync/peers/") => {
                self.handle_get_specific_peer_performance(request).await
            }
            // Existing endpoints
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
        request.uri.starts_with("/api/v1/blockchain/network/") ||
        request.uri.starts_with("/api/v1/blockchain/sync/") ||
        request.uri.starts_with("/api/v1/network/")
    }
    
    fn priority(&self) -> u32 {
        85 // Lower priority than blockchain, higher than storage
    }
}

impl NetworkHandler {
    /// Get gas pricing information
    /// GET /api/v1/network/gas (Issue #10)
    async fn handle_get_gas_info(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting gas pricing information");

        // For now, return static gas pricing information
        // TODO: Integrate with actual gas price calculation from economic model
        let base_fee = 100; // Base fee in smallest unit
        let priority_fee = 50; // Priority fee for faster processing
        let gas_price = base_fee + priority_fee;
        let estimated_cost = gas_price * 21000; // Estimate for standard transaction

        let response = GasInfoResponse {
            status: "success".to_string(),
            gas_price,
            estimated_cost,
            base_fee,
            priority_fee,
        };

        info!("API: Gas info - price: {}, estimated cost: {}", gas_price, estimated_cost);

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

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

    /// Get blockchain sync metrics
    /// GET /api/v1/blockchain/sync/metrics
    async fn handle_get_sync_metrics(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting blockchain sync metrics");

        // Get metrics from global mesh router provider
        match crate::runtime::mesh_router_provider::get_broadcast_metrics().await {
            Ok(metrics) => {
                // Calculate efficiency and relay ratios
                let total_received = metrics.blocks_received + metrics.transactions_received;
                let total_relayed = metrics.blocks_relayed + metrics.transactions_relayed;
                let total_rejected = metrics.blocks_rejected + metrics.transactions_rejected;
                
                let sync_efficiency = if total_received > 0 {
                    ((total_received - total_rejected) as f64 / total_received as f64) * 100.0
                } else {
                    100.0
                };
                
                let relay_ratio = if total_received > 0 {
                    (total_relayed as f64 / total_received as f64) * 100.0
                } else {
                    0.0
                };

                let response = SyncMetricsResponse {
                    status: "success".to_string(),
                    blocks_sent: metrics.blocks_sent,
                    blocks_received: metrics.blocks_received,
                    transactions_sent: metrics.transactions_sent,
                    transactions_received: metrics.transactions_received,
                    blocks_relayed: metrics.blocks_relayed,
                    transactions_relayed: metrics.transactions_relayed,
                    blocks_rejected: metrics.blocks_rejected,
                    transactions_rejected: metrics.transactions_rejected,
                    sync_efficiency,
                    relay_ratio,
                };

                info!("API: Sync metrics - {} blocks sent, {} received, {:.1}% efficiency", 
                      response.blocks_sent, response.blocks_received, response.sync_efficiency);
                
                let json_response = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to get mesh router metrics: {}", e);
                
                // Return zero metrics on error
                let response = SyncMetricsResponse {
                    status: "error".to_string(),
                    blocks_sent: 0,
                    blocks_received: 0,
                    transactions_sent: 0,
                    transactions_received: 0,
                    blocks_relayed: 0,
                    transactions_relayed: 0,
                    blocks_rejected: 0,
                    transactions_rejected: 0,
                    sync_efficiency: 0.0,
                    relay_ratio: 0.0,
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

        info!(" API: Removing network peer: {}", peer_id);

        // For demonstration, we'll use the peer_id as the address
        // In a implementation, you'd maintain a mapping of peer_id -> address
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

    // ==================== Phase 4: Advanced Monitoring Handler Methods ====================

    /// Get detailed performance metrics
    /// GET /api/v1/blockchain/sync/performance
    async fn handle_get_performance_metrics(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting sync performance metrics");
        
        match crate::runtime::mesh_router_provider::get_performance_metrics().await {
            Ok(metrics) => {
                let response = PerformanceMetricsResponse {
                    status: "success".to_string(),
                    avg_block_propagation_ms: metrics.avg_block_propagation_ms,
                    avg_tx_propagation_ms: metrics.avg_tx_propagation_ms,
                    p95_block_latency_ms: metrics.p95_block_latency_ms,
                    p95_tx_latency_ms: metrics.p95_tx_latency_ms,
                    min_block_latency_ms: metrics.min_block_latency_ms,
                    max_block_latency_ms: metrics.max_block_latency_ms,
                    min_tx_latency_ms: metrics.min_tx_latency_ms,
                    max_tx_latency_ms: metrics.max_tx_latency_ms,
                    bytes_sent_per_sec: metrics.bytes_sent_per_sec,
                    bytes_received_per_sec: metrics.bytes_received_per_sec,
                    peak_bandwidth_usage_bps: metrics.peak_bandwidth_usage_bps,
                    duplicate_block_ratio: metrics.duplicate_block_ratio,
                    duplicate_tx_ratio: metrics.duplicate_tx_ratio,
                    validation_success_rate: metrics.validation_success_rate,
                    relay_efficiency: metrics.relay_efficiency,
                    measurement_duration_secs: metrics.measurement_duration_secs,
                };
                
                info!("API: Performance metrics - {:.2}ms avg block latency, {:.1}% validation success", 
                      response.avg_block_propagation_ms, response.validation_success_rate);
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to get performance metrics: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get performance metrics: {}", e),
                ))
            }
        }
    }

    /// Get active alerts
    /// GET /api/v1/blockchain/sync/alerts
    async fn handle_get_alerts(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting active alerts");
        
        match crate::runtime::mesh_router_provider::get_active_alerts().await {
            Ok(alerts) => {
                let unacknowledged_count = alerts.iter().filter(|a| !a.acknowledged).count();
                
                let alert_infos: Vec<AlertInfo> = alerts.iter().map(|alert| {
                    let level_str = match alert.level {
                        crate::unified_server::AlertLevel::Info => "info",
                        crate::unified_server::AlertLevel::Warning => "warning",
                        crate::unified_server::AlertLevel::Critical => "critical",
                    };
                    
                    AlertInfo {
                        id: alert.id.clone(),
                        level: level_str.to_string(),
                        category: alert.category.clone(),
                        message: alert.message.clone(),
                        timestamp: alert.timestamp,
                        acknowledged: alert.acknowledged,
                        peer_id: alert.peer_id.clone(),
                        metric_value: alert.metric_value,
                        threshold_value: alert.threshold_value,
                    }
                }).collect();
                
                let response = AlertsResponse {
                    status: "success".to_string(),
                    total_alerts: alerts.len(),
                    unacknowledged_count,
                    alerts: alert_infos,
                };
                
                info!("API: Retrieved {} alerts ({} unacknowledged)", response.total_alerts, unacknowledged_count);
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to get alerts: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get alerts: {}", e),
                ))
            }
        }
    }

    /// Acknowledge an alert
    /// POST /api/v1/blockchain/sync/alerts/acknowledge
    async fn handle_acknowledge_alert(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Acknowledging alert");
        
        // Parse request body
        let ack_request: AcknowledgeAlertRequest = if request.body.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Request body with alert_id is required".to_string(),
            ));
        } else {
            serde_json::from_slice(&request.body)
                .map_err(|e| anyhow::anyhow!("Invalid JSON in request body: {}", e))?
        };
        
        match crate::runtime::mesh_router_provider::acknowledge_alert(&ack_request.alert_id).await {
            Ok(acknowledged) => {
                let response = AcknowledgeAlertResponse {
                    status: if acknowledged { "success" } else { "not_found" }.to_string(),
                    acknowledged,
                    message: if acknowledged {
                        format!("Alert {} acknowledged", ack_request.alert_id)
                    } else {
                        format!("Alert {} not found", ack_request.alert_id)
                    },
                };
                
                info!("API: Alert {} acknowledgment: {}", ack_request.alert_id, acknowledged);
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to acknowledge alert: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to acknowledge alert: {}", e),
                ))
            }
        }
    }

    /// Clear acknowledged alerts
    /// DELETE /api/v1/blockchain/sync/alerts/acknowledged
    async fn handle_clear_acknowledged_alerts(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Clearing acknowledged alerts");
        
        match crate::runtime::mesh_router_provider::clear_acknowledged_alerts().await {
            Ok(()) => {
                let response = serde_json::json!({
                    "status": "success",
                    "message": "Acknowledged alerts cleared"
                });
                
                info!("API: Successfully cleared acknowledged alerts");
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to clear acknowledged alerts: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to clear acknowledged alerts: {}", e),
                ))
            }
        }
    }

    /// Get alert thresholds configuration
    /// GET /api/v1/blockchain/sync/alerts/thresholds
    async fn handle_get_alert_thresholds(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting alert thresholds");
        
        match crate::runtime::mesh_router_provider::get_alert_thresholds().await {
            Ok(thresholds) => {
                let response = AlertThresholdsResponse {
                    status: "success".to_string(),
                    max_block_latency_ms: thresholds.max_block_latency_ms,
                    max_tx_latency_ms: thresholds.max_tx_latency_ms,
                    max_bandwidth_mbps: thresholds.max_bandwidth_mbps,
                    min_validation_success_rate: thresholds.min_validation_success_rate,
                    max_duplicate_ratio: thresholds.max_duplicate_ratio,
                    min_peer_score: thresholds.min_peer_score,
                };
                
                info!("API: Retrieved alert thresholds");
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to get alert thresholds: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get alert thresholds: {}", e),
                ))
            }
        }
    }

    /// Update alert thresholds configuration
    /// PUT /api/v1/blockchain/sync/alerts/thresholds
    async fn handle_update_alert_thresholds(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Updating alert thresholds");
        
        // Parse request body
        let update_request: UpdateThresholdsRequest = if request.body.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Request body with threshold values is required".to_string(),
            ));
        } else {
            serde_json::from_slice(&request.body)
                .map_err(|e| anyhow::anyhow!("Invalid JSON in request body: {}", e))?
        };
        
        // Get current thresholds first
        match crate::runtime::mesh_router_provider::get_alert_thresholds().await {
            Ok(mut thresholds) => {
                // Update only the provided fields
                if let Some(val) = update_request.max_block_latency_ms {
                    thresholds.max_block_latency_ms = val;
                }
                if let Some(val) = update_request.max_tx_latency_ms {
                    thresholds.max_tx_latency_ms = val;
                }
                if let Some(val) = update_request.max_bandwidth_mbps {
                    thresholds.max_bandwidth_mbps = val;
                }
                if let Some(val) = update_request.min_validation_success_rate {
                    thresholds.min_validation_success_rate = val;
                }
                if let Some(val) = update_request.max_duplicate_ratio {
                    thresholds.max_duplicate_ratio = val;
                }
                if let Some(val) = update_request.min_peer_score {
                    thresholds.min_peer_score = val;
                }
                
                // Apply the updated thresholds
                match crate::runtime::mesh_router_provider::update_alert_thresholds(thresholds.clone()).await {
                    Ok(()) => {
                        let response = AlertThresholdsResponse {
                            status: "success".to_string(),
                            max_block_latency_ms: thresholds.max_block_latency_ms,
                            max_tx_latency_ms: thresholds.max_tx_latency_ms,
                            max_bandwidth_mbps: thresholds.max_bandwidth_mbps,
                            min_validation_success_rate: thresholds.min_validation_success_rate,
                            max_duplicate_ratio: thresholds.max_duplicate_ratio,
                            min_peer_score: thresholds.min_peer_score,
                        };
                        
                        info!("API: Successfully updated alert thresholds");
                        
                        let json = serde_json::to_vec(&response)
                            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                        
                        Ok(ZhtpResponse::success_with_content_type(
                            json,
                            "application/json".to_string(),
                            None,
                        ))
                    }
                    Err(e) => {
                        error!("API: Failed to update alert thresholds: {}", e);
                        Ok(ZhtpResponse::error(
                            ZhtpStatus::InternalServerError,
                            format!("Failed to update alert thresholds: {}", e),
                        ))
                    }
                }
            }
            Err(e) => {
                error!("API: Failed to get current thresholds: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get current thresholds: {}", e),
                ))
            }
        }
    }

    /// Get metrics history
    /// GET /api/v1/blockchain/sync/history?last_n=100
    async fn handle_get_metrics_history(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting metrics history");
        
        // Parse query parameter for last_n
        let last_n = request.uri
            .split('?')
            .nth(1)
            .and_then(|query| {
                query.split('&')
                    .find(|param| param.starts_with("last_n="))
                    .and_then(|param| param.strip_prefix("last_n="))
                    .and_then(|val| val.parse::<usize>().ok())
            });
        
        match crate::runtime::mesh_router_provider::get_metrics_history(last_n).await {
            Ok(snapshots) => {
                let history_snapshots: Vec<HistorySnapshot> = snapshots.iter().map(|s| {
                    HistorySnapshot {
                        timestamp: s.timestamp,
                        blocks_received: s.blocks_received,
                        txs_received: s.txs_received,
                        blocks_rejected: s.blocks_rejected,
                        txs_rejected: s.txs_rejected,
                        avg_latency_ms: s.avg_latency_ms,
                        bandwidth_bps: s.bandwidth_bps,
                        active_peers: s.active_peers,
                        banned_peers: s.banned_peers,
                    }
                }).collect();
                
                let response = MetricsHistoryResponse {
                    status: "success".to_string(),
                    interval_secs: 60, // Hard-coded from MetricsHistory::new(720, 60)
                    snapshots: history_snapshots,
                };
                
                info!("API: Retrieved {} metrics snapshots", response.snapshots.len());
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to get metrics history: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get metrics history: {}", e),
                ))
            }
        }
    }

    /// Get all peer performance statistics
    /// GET /api/v1/blockchain/sync/peers
    async fn handle_get_peer_performance(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting peer performance statistics");
        
        match crate::runtime::mesh_router_provider::list_peer_performance().await {
            Ok(peer_stats) => {
                let peer_infos: Vec<PeerPerformanceInfo> = peer_stats.iter().map(|stats| {
                    let status = if stats.violations > 10 {
                        "banned"
                    } else if stats.reputation_score < 0 {
                        "warning"
                    } else {
                        "active"
                    };
                    
                    PeerPerformanceInfo {
                        peer_id: stats.peer_id.clone(),
                        reputation_score: stats.reputation_score,
                        blocks_accepted: stats.blocks_accepted,
                        blocks_rejected: stats.blocks_rejected,
                        txs_accepted: stats.txs_accepted,
                        txs_rejected: stats.txs_rejected,
                        violations: stats.violations,
                        acceptance_rate: stats.acceptance_rate,
                        first_seen: stats.first_seen,
                        last_seen: stats.last_seen,
                        status: status.to_string(),
                    }
                }).collect();
                
                let response = PeerPerformanceResponse {
                    status: "success".to_string(),
                    total_peers: peer_infos.len(),
                    peers: peer_infos,
                };
                
                info!("API: Retrieved performance stats for {} peers", response.total_peers);
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("API: Failed to get peer performance: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get peer performance: {}", e),
                ))
            }
        }
    }

    /// Get specific peer performance statistics
    /// GET /api/v1/blockchain/sync/peers/{peer_id}
    async fn handle_get_specific_peer_performance(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract peer_id from URL path
        let peer_id = match request.uri.strip_prefix("/api/v1/blockchain/sync/peers/") {
            Some(id_str) => {
                // Remove query parameters if present
                id_str.split('?').next().unwrap_or(id_str).to_string()
            }
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid peer performance URL format".to_string(),
                ));
            }
        };
        
        info!("API: Getting performance statistics for peer: {}", peer_id);
        
        match crate::runtime::mesh_router_provider::get_peer_performance(&peer_id).await {
            Ok(Some(stats)) => {
                let status = if stats.violations > 10 {
                    "banned"
                } else if stats.reputation_score < 0 {
                    "warning"
                } else {
                    "active"
                };
                
                let peer_info = PeerPerformanceInfo {
                    peer_id: stats.peer_id.clone(),
                    reputation_score: stats.reputation_score,
                    blocks_accepted: stats.blocks_accepted,
                    blocks_rejected: stats.blocks_rejected,
                    txs_accepted: stats.txs_accepted,
                    txs_rejected: stats.txs_rejected,
                    violations: stats.violations,
                    acceptance_rate: stats.acceptance_rate,
                    first_seen: stats.first_seen,
                    last_seen: stats.last_seen,
                    status: status.to_string(),
                };
                
                let response = serde_json::json!({
                    "status": "success",
                    "peer": peer_info
                });
                
                info!("API: Retrieved performance stats for peer {}", peer_id);
                
                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
                
                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Ok(None) => {
                warn!("API: Peer {} not found", peer_id);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Peer {} not found", peer_id),
                ))
            }
            Err(e) => {
                error!("API: Failed to get peer performance for {}: {}", peer_id, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get peer performance: {}", e),
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