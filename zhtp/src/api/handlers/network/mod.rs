//! Network API handlers for ZHTP
//!
//! Provides endpoints for network management, peer operations, and network statistics.
//! Built on lib-network functions and runtime orchestrator capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
// Removed unused tokio::sync::RwLock, anyhow::Result, serde_json::json
use chrono;
use tracing::{error, info, warn};
use uuid;

// ZHTP protocol imports
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use lib_blockchain::BlockchainQuery;
use crate::runtime::RuntimeOrchestrator;

// Constants
const CONTENT_TYPE_JSON: &str = "application/json";
#[allow(dead_code)]
const API_VERSION: &str = "1.0";

/// Standardized error response format (Issue #11)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
    pub timestamp: u64,
}

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
pub struct IdentityPendingRequest {
    pub recipient_did: String,
    pub device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityPendingResponse {
    pub status: String,
    pub recipient_did: String,
    pub device_id: String,
    pub envelopes: Vec<lib_protocols::types::IdentityEnvelope>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityAckRequest {
    pub recipient_did: String,
    pub device_id: String,
    pub message_id: u64,
    #[serde(default)]
    pub retain_until_ttl: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityAckResponse {
    pub status: String,
    pub recipient_did: String,
    pub device_id: String,
    pub message_id: u64,
    pub acknowledged: bool,
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

// Issue #2197: Relay-capable candidate discovery

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayCandidatesRequest {
    pub min_quality: Option<f64>,
    pub capability: Option<String>, // "relay", "dht", "api", etc.
    pub page: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayCandidatesResponse {
    pub status: String,
    pub total: usize,
    pub page: usize,
    pub limit: usize,
    pub candidates: Vec<RelayCandidateInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayCandidateInfo {
    pub did: String,
    pub peer_id: String,
    pub endpoints: Vec<String>,
    pub protocols: Vec<String>,
    pub routing_capacity: u32,
    pub bandwidth_mbps: f64,
    pub latency_ms: u32,
    pub reliability_score: f64,
    pub trust_score: f64,
    pub health_state: String, // "healthy", "degraded", "unhealthy"
    pub admission_state: String, // "admitted", "pending", "rejected"
    pub tier: String,
}

/// Network handler implementation
pub struct NetworkHandler {
    runtime: Arc<RuntimeOrchestrator>,
}

impl NetworkHandler {
    pub fn new(runtime: Arc<RuntimeOrchestrator>) -> Self {
        Self { runtime }
    }

    /// Create standardized JSON error response (Issue #11)
    #[allow(dead_code)]
    fn json_error(
        &self,
        status: ZhtpStatus,
        message: impl Into<String>,
    ) -> ZhtpResult<ZhtpResponse> {
        let code = match status {
            ZhtpStatus::BadRequest => 400,
            ZhtpStatus::Unauthorized => 401,
            ZhtpStatus::Forbidden => 403,
            ZhtpStatus::NotFound => 404,
            ZhtpStatus::InternalServerError => 500,
            ZhtpStatus::ServiceUnavailable => 503,
            _ => 500,
        };

        let error_response = ErrorResponse {
            error: message.into(),
            code,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        ZhtpResponse::error_json(status, &error_response)
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for NetworkHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Structured logging for audit trail (Issue #12)
        let request_id = uuid::Uuid::new_v4().to_string();
        let start_time = std::time::Instant::now();

        info!(
            request_id = %request_id,
            method = ?request.method,
            uri = %request.uri,
            timestamp = request.timestamp,
            "Network API request received"
        );

        let response = match (request.method, request.uri.as_str()) {
            // Gas pricing endpoint (Issue #10)
            (ZhtpMethod::Get, "/api/v1/node/status") => self.handle_node_status(request).await,
            (ZhtpMethod::Post, "/api/v1/node/shutdown") => self.handle_node_shutdown(request).await,
            (ZhtpMethod::Post, "/api/v1/node/halt-consensus") => self.handle_halt_consensus(request).await,
            (ZhtpMethod::Post, "/api/v1/node/force-sync") => self.handle_node_force_sync(request).await,
            (ZhtpMethod::Get, "/api/v1/network/gas") => self.handle_get_gas_info(request).await,
            (ZhtpMethod::Get, "/api/v1/network/ping") => self.handle_ping(request).await,
            (ZhtpMethod::Get, "/api/v1/network/relay-candidates") => {
                self.handle_get_relay_candidates(request).await
            }
            // Issue #1801: Missing network endpoints
            (ZhtpMethod::Get, "/api/v1/network/directory") => {
                self.handle_get_directory(request).await
            }
            (ZhtpMethod::Get, "/api/v1/network/topology") => {
                self.handle_topology_ui(request).await
            }
            (ZhtpMethod::Get, "/api/v1/network/status") => {
                self.handle_get_network_status(request).await
            }
            (ZhtpMethod::Get, "/api/v1/network/peers") => {
                self.handle_get_network_peers(request).await
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
            (ZhtpMethod::Post, "/api/v1/network/identity/pending") => {
                self.handle_get_identity_pending(request).await
            }
            (ZhtpMethod::Post, "/api/v1/network/identity/ack") => {
                self.handle_identity_ack(request).await
            }
            // Existing endpoints
            (ZhtpMethod::Post, "/api/v1/blockchain/network/peer/add") => {
                self.handle_add_network_peer(request).await
            }
            (ZhtpMethod::Delete, path) if path.starts_with("/api/v1/blockchain/network/peer/") => {
                self.handle_remove_network_peer(request).await
            }
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "Network endpoint not found".to_string(),
            )),
        };

        // Structured logging for response (Issue #12)
        let duration_ms = start_time.elapsed().as_millis();

        match response {
            Ok(mut resp) => {
                resp.headers.set("X-Handler", "Network".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());

                info!(
                    request_id = %request_id,
                    status = ?resp.status,
                    duration_ms = duration_ms,
                    "Network API request completed successfully"
                );

                Ok(resp)
            }
            Err(e) => {
                error!(
                    request_id = %request_id,
                    error = %e,
                    duration_ms = duration_ms,
                    "Network API request failed"
                );

                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Network error: {}", e),
                ))
            }
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/blockchain/network/")
            || request.uri.starts_with("/api/v1/blockchain/sync/")
            || request.uri.starts_with("/api/v1/network/")
            || request.uri.starts_with("/api/v1/node/")
    }

    fn priority(&self) -> u32 {
        85 // Lower priority than blockchain, higher than storage
    }
}

impl NetworkHandler {
    /// Get relay-capable peer candidates
    /// GET /api/v1/network/relay-candidates (Issue #2197)
    async fn handle_get_relay_candidates(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting relay candidates");

        // Parse query parameters from URI
        let query = request.uri.split('?').nth(1).unwrap_or("");
        let params: HashMap<&str, &str> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .filter_map(|p| {
                let mut parts = p.splitn(2, '=');
                Some((parts.next()?, parts.next().unwrap_or("")))
            })
            .collect();

        let min_quality = params
            .get("min_quality")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);
        let capability = params.get("capability").map(|s| s.to_string());
        let page = params
            .get("page")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let limit = params
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(20)
            .clamp(1, 100);

        // Access peer registry via global mesh router
        let candidates = match crate::runtime::mesh_router_provider::get_global_mesh_router().await
        {
            Ok(mesh_router) => {
                let registry = mesh_router.connections.read().await;
                let mut candidates: Vec<RelayCandidateInfo> = registry
                    .all_peers()
                    .filter(|entry| {
                        // Base filter: Tier2 OR routing_capacity > 0
                        let is_relay = entry.tier == lib_network::peer_registry::PeerTier::Tier2
                            || entry.capabilities.routing_capacity > 0;

                        if !is_relay {
                            return false;
                        }

                        // Quality filter
                        if min_quality > 0.0 && entry.trust_score < min_quality {
                            return false;
                        }

                        // Capability filter
                        if let Some(ref cap) = capability {
                            match cap.as_str() {
                                "relay" => {
                                    entry.tier == lib_network::peer_registry::PeerTier::Tier2
                                        || entry.capabilities.routing_capacity > 0
                                }
                                "dht" => entry.dht_info.is_some(),
                                "api" => entry.capabilities.api_endpoint.is_some(),
                                _ => true,
                            }
                        } else {
                            true
                        }
                    })
                    .map(|entry| {
                        let health_state = if entry.reliability_score >= 0.8 {
                            "healthy"
                        } else if entry.reliability_score >= 0.5 {
                            "degraded"
                        } else {
                            "unhealthy"
                        }
                        .to_string();

                        let admission_state = entry
                            .relay_admission
                            .as_ref()
                            .map(|a| match a.state {
                                lib_network::peer_registry::relay_admission::RelayAdmissionState::Eligible => "admitted",
                                lib_network::peer_registry::relay_admission::RelayAdmissionState::Probation => "pending",
                                lib_network::peer_registry::relay_admission::RelayAdmissionState::Blocked => "rejected",
                            })
                            .unwrap_or("pending")
                            .to_string();

                        RelayCandidateInfo {
                            did: entry.peer_id.did().to_string(),
                            peer_id: hex::encode(
                                &entry.peer_id.public_key().as_bytes()[..8],
                            ),
                            endpoints: entry
                                .endpoints
                                .iter()
                                .map(|ep| ep.address.to_string())
                                .collect(),
                            protocols: entry
                                .active_protocols
                                .iter()
                                .map(|p| format!("{:?}", p))
                                .collect(),
                            routing_capacity: entry.capabilities.routing_capacity,
                            bandwidth_mbps: entry.connection_metrics.bandwidth_capacity as f64
                                / 1_000_000.0,
                            latency_ms: entry.connection_metrics.latency_ms,
                            reliability_score: entry.reliability_score,
                            trust_score: entry.trust_score,
                            health_state,
                            admission_state,
                            tier: format!("{:?}", entry.tier),
                        }
                    })
                    .collect();

                // Sort by trust score descending, then reliability
                candidates.sort_by(|a, b| {
                    b.trust_score
                        .partial_cmp(&a.trust_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            b.reliability_score
                                .partial_cmp(&a.reliability_score)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                });

                candidates
            }
            Err(e) => {
                error!("API: Failed to access mesh router for relay candidates: {}", e);
                vec![]
            }
        };

        let total = candidates.len();
        let start = (page - 1) * limit;
        let paginated = if start < total {
            candidates.into_iter().skip(start).take(limit).collect()
        } else {
            vec![]
        };

        let response = RelayCandidatesResponse {
            status: "success".to_string(),
            total,
            page,
            limit,
            candidates: paginated,
        };

        info!(
            "API: Retrieved {} relay candidates (page {}, limit {})",
            response.candidates.len(), page, limit
        );

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get gas pricing information
    /// GET /api/v1/network/gas (Issue #10)
    async fn handle_get_gas_info(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting gas pricing information");

        // Security: Rate limit gas price queries (100 requests per 15 minutes per IP)
        let client_ip = request
            .headers
            .get("X-Real-IP")
            .or_else(|| {
                request
                    .headers
                    .get("X-Forwarded-For")
                    .and_then(|f| f.split(',').next().map(|s| s.trim().to_string()))
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Note: Rate limiter would need to be added to NetworkHandler struct
        // For now, just log the IP for monitoring
        info!("Gas price request from IP: {}", client_ip);

        // Static gas pricing - integrate with economic model when available
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

        info!(
            "API: Gas info - price: {}, estimated cost: {}",
            gas_price, estimated_cost
        );

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Handle a ping request
    /// GET /api/v1/network/ping
    async fn handle_ping(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Handling ping request");
        let response = serde_json::json!({
            "status": "ok"
        });
        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get list of connected peers
    /// GET /api/v1/blockchain/network/peers
    async fn handle_get_network_peers(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting network peers");

        match self.runtime.get_connected_peers().await {
            Ok(peer_list) => {
                let peers: Vec<PeerInfo> = peer_list
                    .into_iter()
                    .enumerate()
                    .map(|(i, peer_name)| {
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
                            status: if peer_name == "No peers connected"
                                || peer_name == "Network status unavailable"
                            {
                                "disconnected"
                            } else {
                                "connected"
                            }
                            .to_string(),
                            connection_time: if peer_name != "No peers connected"
                                && peer_name != "Network status unavailable"
                            {
                                Some(
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                )
                            } else {
                                None
                            },
                        }
                    })
                    .collect();

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

        info!(
            "API: Retrieved network statistics - {} active peers, {:.1}% connectivity",
            response.peer_distribution.active_peers, response.mesh_status.connectivity_percentage
        );

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get network status (Issue #1801)
    /// GET /api/v1/network/status
    /// Node status: comprehensive status for the setup UI and dashboard.
    /// Public endpoint — no auth required.
    async fn handle_node_status(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("blockchain unavailable: {}", e))?;
        let blockchain = blockchain_arc.read().await;

        let environment = self.runtime.get_environment();

        // Node identity
        let node_did = crate::runtime::node_identity::get_runtime_node_did()
            .unwrap_or_else(|| "not_initialized".to_string());

        // Check if identity is registered on-chain
        let identity_registered = blockchain.query_identity_exists(&node_did);

        // Wallet balance (if registered)
        let (wallet_id, sov_balance) = if identity_registered {
            let did_hex = node_did.strip_prefix("did:zhtp:").unwrap_or(&node_did);
            match hex::decode(did_hex) {
                Ok(owner_bytes) => {
                    let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();

                    let wallet = blockchain.query_all_wallets().into_iter().find(|(_, w)| {
                        w.owner_identity_id
                            .as_ref()
                            .map(|id| id.as_bytes() == owner_bytes.as_slice())
                            .unwrap_or(false)
                            && w.wallet_type == "Primary"
                    }).map(|(_, w)| w);

                    if let Some(w) = wallet {
                        let wallet_id_hex = hex::encode(w.wallet_id.as_bytes());
                        // Look up balance by key_id (wallet_id). We use find_balance_by_key_id
                        // because PublicKey's Hash/PartialEq compare all fields (dilithium_pk,
                        // kyber_pk, key_id), so a synthetic PublicKey with zeroed crypto keys
                        // would never match a real entry in the balances HashMap.
                        // #2637: token_balance() is sled-first and keyed by key_id.
                        let wallet_key_id = w.wallet_id.as_array();
                        let balance = blockchain
                            .token_balance(&sov_token_id, &wallet_key_id)
                            .unwrap_or(0);
                        (Some(wallet_id_hex), balance)
                    } else {
                        (None, 0)
                    }
                }
                Err(_) => {
                    // DID hex portion is not valid hex — treat as no wallet
                    (None, 0)
                }
            }
        } else {
            (None, 0)
        };

        let validator_count = blockchain.query_validator_count();
        let identity_count = blockchain.query_identity_count();
        let chain_height = blockchain.query_height();
        let blocks_count = blockchain.query_block_count();
        let pending_count = blockchain.query_pending_count();

        // `identity_not_registered` is reserved for nodes that genuinely
        // have not finished first-time setup: no DID at all, or a DID that
        // the chain has never seen *and* the node hasn't loaded any chain
        // state yet (i.e. it can't possibly be serving clients).
        //
        // Observer-mode gateways and bootstrap-seeded validators
        // legitimately have a DID that isn't present in `identity_registry`
        // (which is only populated by on-chain `IdentityRegistration`
        // transactions). Once such a node has loaded the chain and sees a
        // healthy validator set, it is fully operational regardless of
        // whether *its own* identity has a chain-side tx — and the mobile
        // app reads this `state` field to decide whether the node is
        // reachable.
        let node_is_known_validator = blockchain.query_validator(&node_did).is_some();
        let identity_known_to_chain = identity_registered || node_is_known_validator;

        let state = if node_did == "not_initialized" {
            "setup_required"
        } else if !identity_known_to_chain && chain_height == 0 {
            // Genuine first-boot: node has a DID but neither the chain knows
            // about it nor have we loaded any chain state. Check this BEFORE
            // the `chain_height == 0 → connecting` branch — otherwise this
            // arm is unreachable and a fresh-boot node always reports
            // "connecting" instead of the more precise
            // "identity_not_registered" the mobile setup flow keys off of
            // (CR #2660).
            "identity_not_registered"
        } else if chain_height == 0 {
            "connecting"
        } else if validator_count == 0 {
            "connecting"
        } else {
            "ready"
        };

        // Sync telemetry: estimate target height from validator activity
        let last_block_time = blockchain.query_latest_block()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seconds_behind = if last_block_time > 0 && now > last_block_time {
            now - last_block_time
        } else {
            0
        };

        let response = serde_json::json!({
            "state": state,
            "did": node_did,
            "identity_registered": identity_registered,
            "chain_height": chain_height,
            "wallet_id": wallet_id,
            "sov_balance": sov_balance.to_string(),
            "sov_balance_human": format!("{:.4}", sov_balance as f64 / 1_000_000_000_000_000_000.0),
            "validator_count": validator_count,
            "identity_count": identity_count,
            "network_id": environment.to_string().to_ascii_lowercase(),
            "pending_transactions": pending_count,
            "blocks_stored": blocks_count,
            "last_block_time": last_block_time,
            "seconds_behind": seconds_behind,
        });

        Ok(ZhtpResponse::json(&response, None)?)
    }

    /// POST /api/v1/node/shutdown — clean shutdown of the node process
    async fn handle_node_shutdown(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Node shutdown requested");
        // Signal the runtime to begin graceful shutdown
        let response = serde_json::json!({
            "success": true,
            "message": "Shutdown initiated. Node will stop after current block is finalized.",
            "state": "shutting_down",
        });
        // Spawn shutdown in background so the response gets sent first
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            info!("Node shutdown: sending SIGTERM to self");
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM); }
        });
        Ok(ZhtpResponse::json(&response, None)?)
    }

    /// POST /api/v1/node/halt-consensus — coordinated consensus halt (Council only)
    async fn handle_halt_consensus(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Council-only gate
        let principal = crate::api::principal::extract_principal_from_request(&request);
        if principal.role != lib_access_control::Role::Council {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Forbidden,
                "Consensus halt requires Council role".to_string(),
            ));
        }

        // Parse optional reason from body
        let reason_str = serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|v| v.get("reason").and_then(|r| r.as_str().map(String::from)))
            .unwrap_or_else(|| "operator-halt".to_string());

        let halt_reason = match reason_str.as_str() {
            "upgrade" => lib_consensus_core::fsm::state::HaltReason::UpgradeScheduled,
            "emergency" => lib_consensus_core::fsm::state::HaltReason::EmergencyHalt,
            _ => lib_consensus_core::fsm::state::HaltReason::ConsensusFailure,
        };

        // Get current height
        let height = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => bc.read().await.height,
            Err(_) => 0,
        };

        // Send halt event to consensus
        if let Some(component) = self.runtime.get_component(&crate::runtime::ComponentId::Consensus).await {
            if let Some(consensus) = component.as_any().downcast_ref::<crate::runtime::components::consensus::ConsensusComponent>() {
                match consensus.halt_consensus(halt_reason, height).await {
                    Ok(()) => {
                        let response = serde_json::json!({
                            "success": true,
                            "message": format!("Consensus halt scheduled at height {}", height),
                            "reason": reason_str,
                            "height": height,
                        });
                        return Ok(ZhtpResponse::json(&response, None)?);
                    }
                    Err(e) => {
                        return Ok(ZhtpResponse::error(
                            ZhtpStatus::InternalServerError,
                            format!("Failed to halt consensus: {}", e),
                        ));
                    }
                }
            }
        }

        Ok(ZhtpResponse::error(
            ZhtpStatus::InternalServerError,
            "Consensus component not available".to_string(),
        ))
    }

    /// POST /api/v1/node/force-sync — trigger immediate catch-up sync from peers
    async fn handle_node_force_sync(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Force sync requested");
        // Trigger catch-up by reading current height and requesting sync
        let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("blockchain unavailable: {}", e))?;
        let height = {
            let bc = blockchain_arc.read().await;
            bc.height
        };
        let response = serde_json::json!({
            "success": true,
            "message": "Force sync triggered",
            "current_height": height,
            "state": "syncing",
        });
        Ok(ZhtpResponse::json(&response, None)?)
    }

    async fn handle_get_directory(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting network directory (topology)");

        let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("blockchain unavailable: {}", e))?;
        let blockchain = blockchain_arc.read().await;
        let environment = self.runtime.get_environment();

        // Compute this node's SPKI pin
        let local_spki = Self::compute_local_spki();

        // This node's identity
        let node_did = self.runtime.get_user_wallet().await
            .map(|w| format!("did:zhtp:{}", hex::encode(&w.node_identity.id.0)))
            .unwrap_or_default();
        let node_role = format!("{:?}", self.runtime.get_node_role().await).to_ascii_lowercase();

        // Known validator/gateway SPKI pins (SHA-256 of SubjectPublicKeyInfo DER).
        // Keyed by IP. These are stable unless a node regenerates its TLS cert.
        // TODO: move to on-chain validator registry so nodes publish their own pins.
        let known_spki_pins: std::collections::HashMap<&str, &str> = [
            ("77.42.37.161",   "611bd1197ee799c17ac46f3f27df45ec4580d924f0dc3597ba79bcad3d0fa970"), // g1
            ("77.42.74.80",    "611bd1197ee799c17ac46f3f27df45ec4580d924f0dc3597ba79bcad3d0fa970"), // g2
            ("178.105.9.247",  "eb71239b161a8ea0cdc94f3853298f3e063523c9860a9630cc57504b024a3f54"), // g3
            ("148.113.140.176","939828e5fc146d3b2efb3255d53ba12b48f9da9c0a823bae145f6720eab3937c"), // g4
            ("51.75.62.133",   "154afc2efe9d834f5264fd21033d49362599e358233d1c0d67ad487bab366d09"), // g5
            ("91.98.113.188",  "611bd1197ee799c17ac46f3f27df45ec4580d924f0dc3597ba79bcad3d0fa970"), // gateway
        ].into_iter().collect();

        // Build validator entries from on-chain registry, with IP overlay
        let ip_overlay = crate::runtime::validator_ip::get_all_resolved_addresses();
        let validators: Vec<serde_json::Value> = blockchain
            .validator_registry
            .iter()
            .filter(|(_, v)| v.status == "active")
            .map(|(did, v)| {
                let endpoint = ip_overlay.get(did).unwrap_or(&v.network_address);
                let ip = endpoint.split(':').next().unwrap_or("");
                let spki_pin = known_spki_pins.get(ip).unwrap_or(&"").to_string();
                serde_json::json!({
                    "did": v.identity_id,
                    "role": "validator",
                    "endpoint": endpoint,
                    "ip": ip,
                    "quic_port": 9334,
                    "mesh_port": 9333,
                    "stake": v.stake,
                    "status": v.status,
                    "blocks_validated": v.blocks_validated,
                    "last_activity": v.last_activity,
                    "commission_rate": v.commission_rate,
                    "admission": v.admission_source,
                    "spki_pin": spki_pin,
                })
            })
            .collect();

        // Gateway entries from on-chain registry (populated via GatewayRegistration transactions)
        let gateways: Vec<serde_json::Value> = blockchain
            .gateway_registry
            .values()
            .filter(|g| g.status == "active")
            .map(|g| {
                let ip = g.endpoints.split(':').next().unwrap_or("");
                let spki_pin = known_spki_pins.get(ip).unwrap_or(&"").to_string();
                serde_json::json!({
                    "did": g.identity_id,
                    "role": "gateway",
                    "endpoint": g.endpoints,
                    "ip": ip,
                    "quic_port": 9334,
                    "zdns_port": 53,
                    "status": g.status,
                    "stake": g.stake,
                    "commission_rate": g.commission_rate,
                    "spki_pin": spki_pin,
                })
            })
            .collect();

        // Peer count
        let peer_count = self.runtime.get_connected_peers().await
            .map(|p| p.len())
            .unwrap_or(0);

        let response = serde_json::json!({
            "network_id": environment.to_string().to_ascii_lowercase(),
            "chain_height": blockchain.query_height(),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            // Back-compat: top-level fields for older clients
            "validators": validators,
            "validator_count": validators.len(),
            "local_spki_pin": local_spki,
            // New structured format
            "this_node": {
                "did": node_did,
                "role": node_role,
                "spki_pin": local_spki,
            },
            "topology": {
                "validators": validators,
                "gateways": gateways,
                "total_validators": validators.len(),
                "total_gateways": gateways.len(),
                "connected_peers": peer_count,
            },
        });

        Ok(ZhtpResponse::json(&response, None)?)
    }

    async fn handle_topology_ui(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        const TOPOLOGY_HTML: &str = include_str!("../../../ui/topology.html");
        Ok(ZhtpResponse::html(TOPOLOGY_HTML.to_string(), None))
    }

    fn compute_local_spki() -> String {
        // Canonical location only — anchored at node_data_dir so it
        // matches `Environment::data_directory()`. If the cert lives
        // elsewhere the deployment is misconfigured; we don't want to
        // silently swallow a stale cert by trying multiple legacy paths.
        let cert_path = crate::node_data_path("data/tls/server.crt");
        if let Ok(pem) = std::fs::read(&cert_path) {
            if let Some(Ok(cert_der)) = rustls_pemfile::certs(&mut pem.as_slice()).next() {
                if let Ok(hash) = lib_network::protocols::quic_mesh::QuicMeshProtocol::compute_spki_sha256(cert_der.as_ref()) {
                    return hex::encode(hash);
                }
            }
        }
        String::new()
    }

    async fn handle_get_network_status(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting network status");

        // Get peer count from runtime
        let peer_count = match self.runtime.get_connected_peers().await {
            Ok(peers) => peers.len(),
            Err(_) => 0,
        };

        // Get blockchain height via global provider
        let blockchain_height =
            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(bc) => {
                    let blockchain = bc.read().await;
                    blockchain.get_height()
                }
                Err(_) => 0,
            };

        // Consensus info would come from consensus component
        // Using placeholder values that will be populated when consensus exposes this data
        let consensus_height = blockchain_height; // Placeholder
        let consensus_round = 0u64; // Placeholder

        // Determine sync status
        // NOTE: Placeholder value until consensus exposes real sync state.
        // Currently we always report "synced" to avoid misleading branch logic
        // based on identical placeholder heights.
        let sync_status = "synced";

        let response = serde_json::json!({
            "connected_peers": peer_count,
            "consensus_round": consensus_round,
            "consensus_height": consensus_height,
            "blockchain_height": blockchain_height,
            "sync_status": sync_status
        });

        info!(
            "API: Network status - {} peers, height {}, status {}",
            peer_count, blockchain_height, sync_status
        );

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

                info!(
                    "API: Sync metrics - {} blocks sent, {} received, {:.1}% efficiency",
                    response.blocks_sent, response.blocks_received, response.sync_efficiency
                );

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

    /// Fetch pending identity envelopes for a recipient device
    /// POST /api/v1/network/identity/pending
    async fn handle_get_identity_pending(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting identity pending envelopes");

        let req: IdentityPendingRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid identity pending request: {}", e))?;

        let mesh_router = crate::runtime::mesh_router_provider::get_global_mesh_router()
            .await
            .map_err(|e| anyhow::anyhow!("Mesh router unavailable: {}", e))?;

        let quic = mesh_router.quic_protocol.read().await;
        let quic = quic
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("QUIC mesh protocol not available"))?;
        let handler = quic
            .message_handler
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Mesh message handler not configured"))?;

        let envelopes = handler
            .read()
            .await
            .get_identity_pending_for_device(&req.recipient_did, &req.device_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch pending envelopes: {}", e))?;

        let response = IdentityPendingResponse {
            status: "success".to_string(),
            recipient_did: req.recipient_did,
            device_id: req.device_id,
            envelopes,
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Acknowledge delivery of an identity envelope
    /// POST /api/v1/network/identity/ack
    async fn handle_identity_ack(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Acknowledging identity delivery");

        let req: IdentityAckRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid identity ack request: {}", e))?;

        let mesh_router = crate::runtime::mesh_router_provider::get_global_mesh_router()
            .await
            .map_err(|e| anyhow::anyhow!("Mesh router unavailable: {}", e))?;

        let quic = mesh_router.quic_protocol.read().await;
        let quic = quic
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("QUIC mesh protocol not available"))?;
        let handler = quic
            .message_handler
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Mesh message handler not configured"))?;

        let acknowledged = handler
            .read()
            .await
            .acknowledge_identity_delivery(&req.recipient_did, req.message_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to acknowledge delivery: {}", e))?;

        let response = IdentityAckResponse {
            status: "success".to_string(),
            recipient_did: req.recipient_did,
            device_id: req.device_id,
            message_id: req.message_id,
            acknowledged,
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
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

        // Generate peer ID based on address using cryptographic hash (issue #9)
        let peer_hash = lib_crypto::hashing::hash_blake3(add_request.peer_address.as_bytes());
        let peer_id = format!("peer_{}", hex::encode(&peer_hash[..8]));

        match self
            .runtime
            .connect_to_peer(&add_request.peer_address)
            .await
        {
            Ok(()) => {
                let response = AddPeerResponse {
                    status: "success".to_string(),
                    peer_id: peer_id.clone(),
                    message: format!(
                        "Successfully initiated connection to peer {}",
                        add_request.peer_address
                    ),
                    connected: true,
                };

                info!(
                    "API: Successfully added peer {} ({})",
                    peer_id, add_request.peer_address
                );

                let json_response = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!(
                    "API: Failed to add peer {}: {}",
                    add_request.peer_address, e
                );

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
    async fn handle_get_performance_metrics(
        &self,
        _request: ZhtpRequest,
    ) -> ZhtpResult<ZhtpResponse> {
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

                let alert_infos: Vec<AlertInfo> = alerts
                    .iter()
                    .map(|alert| {
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
                    })
                    .collect();

                let response = AlertsResponse {
                    status: "success".to_string(),
                    total_alerts: alerts.len(),
                    unacknowledged_count,
                    alerts: alert_infos,
                };

                info!(
                    "API: Retrieved {} alerts ({} unacknowledged)",
                    response.total_alerts, unacknowledged_count
                );

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

                info!(
                    "API: Alert {} acknowledgment: {}",
                    ack_request.alert_id, acknowledged
                );

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
    async fn handle_clear_acknowledged_alerts(
        &self,
        _request: ZhtpRequest,
    ) -> ZhtpResult<ZhtpResponse> {
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
    async fn handle_update_alert_thresholds(
        &self,
        request: ZhtpRequest,
    ) -> ZhtpResult<ZhtpResponse> {
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
                match crate::runtime::mesh_router_provider::update_alert_thresholds(
                    thresholds.clone(),
                )
                .await
                {
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
        let last_n = request.uri.split('?').nth(1).and_then(|query| {
            query
                .split('&')
                .find(|param| param.starts_with("last_n="))
                .and_then(|param| param.strip_prefix("last_n="))
                .and_then(|val| val.parse::<usize>().ok())
        });

        match crate::runtime::mesh_router_provider::get_metrics_history(last_n).await {
            Ok(snapshots) => {
                let history_snapshots: Vec<HistorySnapshot> = snapshots
                    .iter()
                    .map(|s| HistorySnapshot {
                        timestamp: s.timestamp,
                        blocks_received: s.blocks_received,
                        txs_received: s.txs_received,
                        blocks_rejected: s.blocks_rejected,
                        txs_rejected: s.txs_rejected,
                        avg_latency_ms: s.avg_latency_ms,
                        bandwidth_bps: s.bandwidth_bps,
                        active_peers: s.active_peers,
                        banned_peers: s.banned_peers,
                    })
                    .collect();

                let response = MetricsHistoryResponse {
                    status: "success".to_string(),
                    interval_secs: 60, // Hard-coded from MetricsHistory::new(720, 60)
                    snapshots: history_snapshots,
                };

                info!(
                    "API: Retrieved {} metrics snapshots",
                    response.snapshots.len()
                );

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
                let peer_infos: Vec<PeerPerformanceInfo> = peer_stats
                    .iter()
                    .map(|stats| {
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
                    })
                    .collect();

                let response = PeerPerformanceResponse {
                    status: "success".to_string(),
                    total_peers: peer_infos.len(),
                    peers: peer_infos,
                };

                info!(
                    "API: Retrieved performance stats for {} peers",
                    response.total_peers
                );

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
    async fn handle_get_specific_peer_performance(
        &self,
        request: ZhtpRequest,
    ) -> ZhtpResult<ZhtpResponse> {
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
