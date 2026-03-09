//! Observer API handlers for ZHTP
//!
//! Provides endpoints for consensus observer metrics and network health summaries.
//! Issue #1788: Expose observer metrics via API endpoints

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

use crate::runtime::RuntimeOrchestrator;

const CONTENT_TYPE_JSON: &str = "application/json";

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

/// Observer handler implementation
pub struct ObserverHandler {
    _runtime: Arc<RuntimeOrchestrator>,
}

impl ObserverHandler {
    pub fn new(_runtime: Arc<RuntimeOrchestrator>) -> Self {
        Self { _runtime }
    }

    /// Calculate classification based on round count and patterns
    fn classify_height(round_count: u32, has_stall: bool, has_fault: bool) -> &'static str {
        match (round_count, has_stall, has_fault) {
            (0, _, _) => "unknown",
            (1, false, false) => "healthy",
            (1, true, _) => "delayed",
            (2..=3, _, false) => "recovering",
            (2..=3, _, true) => "degraded",
            (4.., _, _) => "divergence",
            _ => "unknown",
        }
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
        75 // Lower priority than core blockchain, higher than monitoring
    }
}

impl ObserverHandler {
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

        // TODO: Wire to actual ObserverService from lib-consensus
        // Once integrated, query: observer_service.get_network_health(window_size)
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Observer network health not yet available - pending integration with consensus observer service".to_string(),
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

    // Helper methods

    /// Classification logic for consensus heights.
    /// 
    /// This defines the API contract for height classifications:
    /// - `healthy`: 1 round, no stalls
    /// - `delayed`: 1 round with stall
    /// - `recovering`: 2-3 rounds, no fault
    /// - `degraded`: 2-3 rounds with fault
    /// - `divergence`: 4+ rounds
    ///
    /// TODO: When wiring to real ObserverService, this logic should come from
    /// lib_consensus::observer::height_scoring::compute_height_score()
    fn classify_height(round_count: u32, has_stall: bool, has_fault: bool) -> &'static str {
        match (round_count, has_stall, has_fault) {
            (1, false, _) => "healthy",
            (1, true, _) => "delayed",
            (2..=3, _, false) => "recovering",
            (2..=3, _, true) => "degraded",
            (4.., _, _) => "divergence",
            _ => "unknown",
        }
    }
}
