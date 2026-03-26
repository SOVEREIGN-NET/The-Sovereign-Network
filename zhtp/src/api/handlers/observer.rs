//! Observer API handlers for ZHTP
//!
//! Provides endpoints for consensus observer metrics and network health summaries.
//! Issue #1788: Expose observer metrics via API endpoints

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};

use crate::runtime::{ComponentHealth as RuntimeComponentHealth, ComponentId, ComponentStatus, RuntimeOrchestrator};

/// Per-height metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct HeightMetricsResponse {
    pub status: String,
    pub height: u64,
    pub round_count: u32,
    pub commit_latency_ms: Option<u64>,
    pub classification: String,
    pub phases: Vec<PhaseMetric>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhaseMetric {
    pub phase_type: String,
    pub duration_ms: u64,
    pub completed: bool,
}

/// Network health summary response
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkHealthResponse {
    pub status: String,
    pub stall_rate: f64,
    pub average_rounds_per_height: f64,
    pub partition_indicators: PartitionIndicators,
    pub validator_anomaly_scores: Vec<ValidatorAnomalyScore>,
    pub recent_heights: Vec<HeightSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartitionIndicators {
    pub potential_partition_detected: bool,
    pub stalled_heights: Vec<u64>,
    pub divergent_heights: Vec<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorAnomalyScore {
    pub validator_id: String,
    pub anomaly_score: f64,
    pub violations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeightSummary {
    pub height: u64,
    pub rounds: u32,
    pub classification: String,
    pub timestamp: u64,
}

/// Surprisal score response for anomaly detection
#[derive(Debug, Serialize, Deserialize)]
pub struct SurprisalScoreResponse {
    pub status: String,
    pub height: u64,
    pub surprisal_score: f64,
    pub baseline_score: f64,
    pub deviation_factor: f64,
    pub classification: String,
}

/// Observer operational status response
#[derive(Debug, Serialize, Deserialize)]
pub struct ObserverStatusResponse {
    pub status: String,
    pub node_role: String,
    pub lifecycle_state: String,
    pub blockchain_component: String,
    pub network_component: String,
    pub local_height: u64,
    pub connected_peers: u32,
    pub mesh_connected: bool,
    pub mesh_connectivity_percent: f64,
    pub can_mine: bool,
    pub can_validate: bool,
    pub stores_full_blockchain: bool,
}

/// Observer sync response
#[derive(Debug, Serialize, Deserialize)]
pub struct ObserverSyncResponse {
    pub status: String,
    pub sync_state: String,
    pub local_height: u64,
    pub connected_peers: u32,
    pub mesh_connected: bool,
    pub mesh_connectivity_percent: f64,
}

/// Observer network health response
#[derive(Debug, Serialize, Deserialize)]
pub struct ObserverNetworkHealthResponse {
    pub status: String,
    pub health_classification: String,
    pub lifecycle_state: String,
    pub blockchain_component: String,
    pub network_component: String,
    pub local_height: u64,
    pub mesh_connected: bool,
    pub internet_connected: bool,
    pub connectivity_percentage: f64,
    pub relay_connectivity: f64,
    pub active_peers: u32,
    pub local_peers: u32,
    pub regional_peers: u32,
    pub global_peers: u32,
    pub relay_peers: u32,
    pub churn_rate: f64,
    pub coverage: f64,
    pub redundancy: f64,
    pub stability: f64,
}

/// Observer lifecycle response
#[derive(Debug, Serialize, Deserialize)]
pub struct ObserverLifecycleResponse {
    pub status: String,
    pub lifecycle_state: String,
    pub node_role: String,
    pub blockchain_component: String,
    pub network_component: String,
    pub local_height: u64,
    pub connected_peers: u32,
    pub mesh_connected: bool,
}

/// Observer handler implementation
pub struct ObserverHandler {
    _runtime: Arc<RuntimeOrchestrator>,
}

impl ObserverHandler {
    pub fn new(_runtime: Arc<RuntimeOrchestrator>) -> Self {
        Self { _runtime }
    }

}

#[async_trait::async_trait]
impl ZhtpRequestHandler for ObserverHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let start_time = std::time::Instant::now();

        info!(
            method = ?request.method,
            uri = %request.uri,
            "Observer API request received"
        );

        // Normalize URI: strip trailing slashes and query strings for consistent matching
        let normalized_uri = request.uri.trim_end_matches('/');
        let normalized_uri = if normalized_uri.is_empty() {
            "/"
        } else {
            normalized_uri
        };
        let match_uri = normalized_uri.split('?').next().unwrap_or(normalized_uri);

        let response = match (request.method, match_uri) {
            (ZhtpMethod::Get, "/api/v1/observer/status") => {
                self.handle_get_observer_status(request).await
            }
            (ZhtpMethod::Get, "/api/v1/observer/lifecycle/current") => {
                self.handle_get_observer_lifecycle(request).await
            }
            (ZhtpMethod::Get, "/api/v1/observer/sync/current") => {
                self.handle_get_observer_sync(request).await
            }
            // Issue #1788: Per-height metrics endpoint
            (ZhtpMethod::Get, "/api/v1/observer/height/current") => {
                self.handle_get_current_height_metrics(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/observer/height/") => {
                self.handle_get_height_metrics(request).await
            }
            // Issue #1788: Network health summary endpoint
            (ZhtpMethod::Get, "/api/v1/observer/network/health") => {
                self.handle_get_network_health(request).await
            }
            // Issue #1788: Surprisal score endpoint
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/observer/surprisal/") => {
                self.handle_get_surprisal_score(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Observer endpoint not found".to_string(),
                ))
            }
        };

        let duration_ms = start_time.elapsed().as_millis();

        match &response {
            Ok(resp) => {
                info!(
                    status = ?resp.status,
                    duration_ms = duration_ms,
                    "Observer API request completed"
                );
            }
            Err(e) => {
                error!(
                    error = %e,
                    duration_ms = duration_ms,
                    "Observer API request failed"
                );
            }
        }

        response
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/observer/")
    }

    fn priority(&self) -> u32 {
        75 // Priority for observer API handler
    }
}

impl ObserverHandler {
    fn component_status_label(health: Option<&RuntimeComponentHealth>) -> String {
        match health.map(|info| &info.status) {
            Some(ComponentStatus::Stopped) => "stopped",
            Some(ComponentStatus::Starting) => "starting",
            Some(ComponentStatus::Running) => "running",
            Some(ComponentStatus::Stopping) => "stopping",
            Some(ComponentStatus::Registered) => "registered",
            Some(ComponentStatus::Failed) => "failed",
            Some(ComponentStatus::Error(_)) => "error",
            None => "unknown",
        }
        .to_string()
    }

    fn classify_observer_lifecycle(
        blockchain_status: &str,
        network_status: &str,
        local_height: u64,
        connected_peers: u32,
        mesh_connected: bool,
    ) -> &'static str {
        if matches!(blockchain_status, "error" | "failed")
            || matches!(network_status, "error" | "failed")
        {
            return "degraded";
        }

        if blockchain_status == "starting" || blockchain_status == "registered" {
            return "starting";
        }

        if local_height == 0 && connected_peers == 0 {
            return "discovering";
        }

        if local_height == 0 && connected_peers > 0 {
            return "bootstrapping";
        }

        if local_height > 0 && connected_peers == 0 {
            return "degraded";
        }

        if local_height > 0 && mesh_connected {
            return "serving";
        }

        if local_height > 0 {
            return "caught_up";
        }

        "starting"
    }

    fn classify_sync_state(
        local_height: u64,
        connected_peers: u32,
        mesh_connected: bool,
        blockchain_status: &str,
    ) -> &'static str {
        if matches!(blockchain_status, "error" | "failed") {
            return "degraded";
        }

        if local_height == 0 && connected_peers == 0 {
            return "waiting_for_peers";
        }

        if local_height == 0 && connected_peers > 0 {
            return "bootstrapping";
        }

        if local_height > 0 && connected_peers == 0 {
            return "peer_unavailable";
        }

        if local_height > 0 && mesh_connected {
            return "connected";
        }

        if local_height > 0 {
            return "recovering";
        }

        "starting"
    }

    async fn observer_runtime_snapshot(
        &self,
    ) -> anyhow::Result<(
        crate::runtime::NodeRole,
        String,
        String,
        u64,
        u32,
        bool,
        f64,
    )> {
        let node_role = self._runtime.get_node_role().await;
        let detailed_health = self._runtime.get_detailed_health().await?;

        let blockchain_status =
            Self::component_status_label(detailed_health.get(&ComponentId::Blockchain));
        let network_status =
            Self::component_status_label(detailed_health.get(&ComponentId::Network));

        let local_height = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => blockchain_arc.read().await.height,
            Err(_) => 0,
        };

        let mesh_status = lib_network::get_mesh_status().await.ok();
        let connected_peers = mesh_status.as_ref().map(|status| status.active_peers).unwrap_or(0);
        let mesh_connected = mesh_status
            .as_ref()
            .map(|status| status.mesh_connected)
            .unwrap_or(false);
        let mesh_connectivity_percent = mesh_status
            .as_ref()
            .map(|status| status.connectivity_percentage)
            .unwrap_or(0.0);

        Ok((
            node_role,
            blockchain_status,
            network_status,
            local_height,
            connected_peers,
            mesh_connected,
            mesh_connectivity_percent,
        ))
    }

    fn classify_network_health(
        blockchain_status: &str,
        network_status: &str,
        mesh_connected: bool,
        active_peers: u32,
        connectivity_percentage: f64,
    ) -> &'static str {
        if matches!(blockchain_status, "error" | "failed")
            || matches!(network_status, "error" | "failed")
        {
            return "degraded";
        }

        if !mesh_connected || active_peers == 0 {
            return "warning";
        }

        if connectivity_percentage >= 80.0 {
            return "healthy";
        }

        "warning"
    }

    /// Get observer operational status.
    /// GET /api/v1/observer/status
    async fn handle_get_observer_status(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting observer operational status");

        let (
            node_role,
            blockchain_status,
            network_status,
            local_height,
            connected_peers,
            mesh_connected,
            mesh_connectivity_percent,
        ) = self.observer_runtime_snapshot().await?;

        let lifecycle_state = Self::classify_observer_lifecycle(
            &blockchain_status,
            &network_status,
            local_height,
            connected_peers,
            mesh_connected,
        );

        let response = ObserverStatusResponse {
            status: "success".to_string(),
            node_role: format!("{:?}", node_role),
            lifecycle_state: lifecycle_state.to_string(),
            blockchain_component: blockchain_status,
            network_component: network_status,
            local_height,
            connected_peers,
            mesh_connected,
            mesh_connectivity_percent,
            can_mine: node_role.can_mine(),
            can_validate: node_role.can_validate(),
            stores_full_blockchain: node_role.stores_full_blockchain(),
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get observer sync status.
    /// GET /api/v1/observer/sync/current
    async fn handle_get_observer_sync(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting observer sync status");

        let (
            _node_role,
            blockchain_status,
            _network_status,
            local_height,
            connected_peers,
            mesh_connected,
            mesh_connectivity_percent,
        ) = self.observer_runtime_snapshot().await?;

        let response = ObserverSyncResponse {
            status: "success".to_string(),
            sync_state: Self::classify_sync_state(
                local_height,
                connected_peers,
                mesh_connected,
                &blockchain_status,
            )
            .to_string(),
            local_height,
            connected_peers,
            mesh_connected,
            mesh_connectivity_percent,
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get observer lifecycle status.
    /// GET /api/v1/observer/lifecycle/current
    async fn handle_get_observer_lifecycle(
        &self,
        _request: ZhtpRequest,
    ) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting observer lifecycle state");

        let (
            node_role,
            blockchain_status,
            network_status,
            local_height,
            connected_peers,
            mesh_connected,
            _mesh_connectivity_percent,
        ) = self.observer_runtime_snapshot().await?;

        let response = ObserverLifecycleResponse {
            status: "success".to_string(),
            lifecycle_state: Self::classify_observer_lifecycle(
                &blockchain_status,
                &network_status,
                local_height,
                connected_peers,
                mesh_connected,
            )
            .to_string(),
            node_role: format!("{:?}", node_role),
            blockchain_component: blockchain_status,
            network_component: network_status,
            local_height,
            connected_peers,
            mesh_connected,
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get metrics for current height
    /// GET /api/v1/observer/height/current (Issue #1788)
    async fn handle_get_current_height_metrics(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting current height metrics");

        // TODO: Wire to actual ObserverService from lib-consensus
        // The observer service exists in lib-consensus but is not yet integrated
        // into the zhtp runtime. Once integrated, this should query:
        // - observer_service.get_height_analysis(current_height)
        // - observer_service.get_recent_analyses(window_size)
        //
        // For now, return 501 Not Implemented to avoid misleading synthetic data.
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Observer metrics not yet available - pending integration with consensus observer service".to_string(),
        ))
    }

    /// Get metrics for specific height
    /// GET /api/v1/observer/height/{height} (Issue #1788)
    async fn handle_get_height_metrics(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting specific height metrics");

        // Extract height from URL for validation (even though we return 501)
        let height_str = request.uri.strip_prefix("/api/v1/observer/height/")
            .unwrap_or("");
        
        if height_str.parse::<u64>().is_err() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid height parameter".to_string(),
            ));
        }

        // TODO: Wire to actual ObserverService from lib-consensus
        // Once integrated, query: observer_service.get_height_analysis(height)
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Observer metrics not yet available - pending integration with consensus observer service".to_string(),
        ))
    }

    /// Get network health summary
    /// GET /api/v1/observer/network/health (Issue #1788)
    async fn handle_get_network_health(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting network health summary");

        let (
            _node_role,
            blockchain_status,
            network_status,
            local_height,
            connected_peers,
            mesh_connected,
            _mesh_connectivity_percent,
        ) = self.observer_runtime_snapshot().await?;

        let lifecycle_state = Self::classify_observer_lifecycle(
            &blockchain_status,
            &network_status,
            local_height,
            connected_peers,
            mesh_connected,
        );

        let mesh_status = lib_network::get_mesh_status().await.unwrap_or_default();

        let response = ObserverNetworkHealthResponse {
            status: "success".to_string(),
            health_classification: Self::classify_network_health(
                &blockchain_status,
                &network_status,
                mesh_status.mesh_connected,
                mesh_status.active_peers,
                mesh_status.connectivity_percentage,
            )
            .to_string(),
            lifecycle_state: lifecycle_state.to_string(),
            blockchain_component: blockchain_status,
            network_component: network_status,
            local_height,
            mesh_connected: mesh_status.mesh_connected,
            internet_connected: mesh_status.internet_connected,
            connectivity_percentage: mesh_status.connectivity_percentage,
            relay_connectivity: mesh_status.relay_connectivity,
            active_peers: mesh_status.active_peers,
            local_peers: mesh_status.local_peers,
            regional_peers: mesh_status.regional_peers,
            global_peers: mesh_status.global_peers,
            relay_peers: mesh_status.relay_peers,
            churn_rate: mesh_status.churn_rate,
            coverage: mesh_status.coverage,
            redundancy: mesh_status.redundancy,
            stability: mesh_status.stability,
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get surprisal score for anomaly detection
    /// GET /api/v1/observer/surprisal/{height} (Issue #1788)
    async fn handle_get_surprisal_score(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting surprisal score");

        // Extract height from URL for validation (even though we return 501)
        let height_str = request.uri.strip_prefix("/api/v1/observer/surprisal/")
            .unwrap_or("");
        
        if height_str.parse::<u64>().is_err() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid height parameter".to_string(),
            ));
        }

        // TODO: Wire to actual ObserverService from lib-consensus
        // The surprisal engine exists in lib-consensus::observer::surprisal_engine
        // Once integrated, this would query: observer_service.get_height_analysis(height)
        // and return the surprisal_stats field from the HeightAnalysis.
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Observer surprisal score not yet available - pending integration with consensus observer service".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_status_response_schema_round_trip() {
        let original = ObserverStatusResponse {
            status: "success".to_string(),
            node_role: "Observer".to_string(),
            lifecycle_state: "serving".to_string(),
            blockchain_component: "running".to_string(),
            network_component: "running".to_string(),
            local_height: 42,
            connected_peers: 3,
            mesh_connected: true,
            mesh_connectivity_percent: 87.5,
            can_mine: false,
            can_validate: false,
            stores_full_blockchain: true,
        };

        let json = serde_json::to_string(&original).expect("must serialise");
        let decoded: ObserverStatusResponse = serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(decoded.lifecycle_state, "serving");
        assert_eq!(decoded.local_height, 42);
        assert_eq!(decoded.connected_peers, 3);
        assert!(decoded.mesh_connected);
        assert!(decoded.stores_full_blockchain);
    }

    #[test]
    fn observer_sync_response_schema_round_trip() {
        let original = ObserverSyncResponse {
            status: "success".to_string(),
            sync_state: "bootstrapping".to_string(),
            local_height: 0,
            connected_peers: 2,
            mesh_connected: true,
            mesh_connectivity_percent: 55.0,
        };

        let json = serde_json::to_string(&original).expect("must serialise");
        let decoded: ObserverSyncResponse = serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(decoded.sync_state, "bootstrapping");
        assert_eq!(decoded.local_height, 0);
        assert_eq!(decoded.connected_peers, 2);
        assert!(decoded.mesh_connected);
    }

    #[test]
    fn observer_network_health_response_schema_round_trip() {
        let original = ObserverNetworkHealthResponse {
            status: "success".to_string(),
            health_classification: "healthy".to_string(),
            lifecycle_state: "serving".to_string(),
            blockchain_component: "running".to_string(),
            network_component: "running".to_string(),
            local_height: 42,
            mesh_connected: true,
            internet_connected: true,
            connectivity_percentage: 88.0,
            relay_connectivity: 75.0,
            active_peers: 5,
            local_peers: 2,
            regional_peers: 1,
            global_peers: 1,
            relay_peers: 1,
            churn_rate: 0.5,
            coverage: 90.0,
            redundancy: 80.0,
            stability: 95.0,
        };

        let json = serde_json::to_string(&original).expect("must serialise");
        let decoded: ObserverNetworkHealthResponse =
            serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(decoded.health_classification, "healthy");
        assert_eq!(decoded.active_peers, 5);
        assert_eq!(decoded.local_height, 42);
        assert!(decoded.mesh_connected);
        assert!(decoded.internet_connected);
    }

    #[test]
    fn observer_lifecycle_response_schema_round_trip() {
        let original = ObserverLifecycleResponse {
            status: "success".to_string(),
            lifecycle_state: "bootstrapping".to_string(),
            node_role: "Observer".to_string(),
            blockchain_component: "running".to_string(),
            network_component: "running".to_string(),
            local_height: 0,
            connected_peers: 2,
            mesh_connected: true,
        };

        let json = serde_json::to_string(&original).expect("must serialise");
        let decoded: ObserverLifecycleResponse =
            serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(decoded.lifecycle_state, "bootstrapping");
        assert_eq!(decoded.node_role, "Observer");
        assert_eq!(decoded.connected_peers, 2);
        assert!(decoded.mesh_connected);
    }

    #[test]
    fn observer_lifecycle_classification_prefers_discovering_before_bootstrapping() {
        assert_eq!(
            ObserverHandler::classify_observer_lifecycle("running", "running", 0, 0, false),
            "discovering"
        );
        assert_eq!(
            ObserverHandler::classify_observer_lifecycle("running", "running", 0, 2, true),
            "bootstrapping"
        );
    }

    #[test]
    fn observer_sync_classification_reports_peer_loss_after_local_sync() {
        assert_eq!(
            ObserverHandler::classify_sync_state(12, 0, false, "running"),
            "peer_unavailable"
        );
        assert_eq!(
            ObserverHandler::classify_sync_state(12, 3, true, "running"),
            "connected"
        );
    }

    #[test]
    fn observer_network_health_classification_degrades_for_component_errors() {
        assert_eq!(
            ObserverHandler::classify_network_health("error", "running", true, 4, 90.0),
            "degraded"
        );
        assert_eq!(
            ObserverHandler::classify_network_health("running", "running", true, 4, 90.0),
            "healthy"
        );
        assert_eq!(
            ObserverHandler::classify_network_health("running", "running", false, 0, 0.0),
            "warning"
        );
    }
}
