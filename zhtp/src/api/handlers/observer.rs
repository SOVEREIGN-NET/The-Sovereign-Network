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

        let response = match (request.method, request.uri.as_str()) {
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

        // Get current blockchain height
        let current_height = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => {
                let blockchain = bc.read().await;
                blockchain.get_height()
            }
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::ServiceUnavailable,
                    "Blockchain not available".to_string(),
                ));
            }
        };

        // Build metrics for current height (placeholder implementation)
        // In full implementation, this would query the observer service
        let metrics = self.build_height_metrics(current_height).await;

        let json_response = serde_json::to_vec(&metrics)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get metrics for specific height
    /// GET /api/v1/observer/height/{height} (Issue #1788)
    async fn handle_get_height_metrics(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting specific height metrics");

        // Extract height from URL
        let height_str = request.uri.strip_prefix("/api/v1/observer/height/")
            .unwrap_or("");
        
        let height: u64 = match height_str.parse() {
            Ok(h) => h,
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid height parameter".to_string(),
                ));
            }
        };

        // Build metrics for specified height
        let metrics = self.build_height_metrics(height).await;

        let json_response = serde_json::to_vec(&metrics)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get network health summary
    /// GET /api/v1/observer/network/health (Issue #1788)
    async fn handle_get_network_health(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting network health summary");

        // Get recent heights for analysis
        let current_height = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(bc) => {
                let blockchain = bc.read().await;
                blockchain.get_height()
            }
            Err(_) => 0,
        };

        // Analyze recent heights (placeholder implementation)
        let recent_heights = self.analyze_recent_heights(current_height).await;

        // Calculate aggregate metrics
        let total_rounds: u32 = recent_heights.iter().map(|h| h.rounds).sum();
        let avg_rounds = if !recent_heights.is_empty() {
            total_rounds as f64 / recent_heights.len() as f64
        } else {
            0.0
        };

        let stalled_count = recent_heights.iter()
            .filter(|h| h.classification == "delayed" || h.classification == "degraded")
            .count();
        let stall_rate = if !recent_heights.is_empty() {
            stalled_count as f64 / recent_heights.len() as f64
        } else {
            0.0
        };

        let stalled_heights: Vec<u64> = recent_heights.iter()
            .filter(|h| h.classification == "delayed" || h.classification == "degraded")
            .map(|h| h.height)
            .collect();

        let divergent_heights: Vec<u64> = recent_heights.iter()
            .filter(|h| h.classification == "divergence")
            .map(|h| h.height)
            .collect();

        let response = NetworkHealthResponse {
            status: "success".to_string(),
            stall_rate,
            average_rounds_per_height: avg_rounds,
            partition_indicators: PartitionIndicators {
                potential_partition_detected: stall_rate > 0.3, // >30% stalls indicates potential partition
                stalled_heights,
                divergent_heights,
            },
            validator_anomaly_scores: vec![], // Placeholder - would come from slashing/oracle
            recent_heights,
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

        // Extract height from URL
        let height_str = request.uri.strip_prefix("/api/v1/observer/surprisal/")
            .unwrap_or("");
        
        let height: u64 = match height_str.parse() {
            Ok(h) => h,
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid height parameter".to_string(),
                ));
            }
        };

        // Calculate surprisal score (placeholder implementation)
        // In full implementation, this would use the surprisal engine
        let baseline_score = 1.0; // Baseline expected rounds
        let actual_rounds = self.get_round_count_for_height(height).await;
        let surprisal_score = if actual_rounds > 1 {
            (actual_rounds as f64).ln() // Simple log-based surprisal
        } else {
            0.0
        };
        let deviation_factor = surprisal_score / baseline_score;

        let classification = if deviation_factor < 0.5 {
            "normal"
        } else if deviation_factor < 1.0 {
            "elevated"
        } else if deviation_factor < 2.0 {
            "high"
        } else {
            "critical"
        };

        let response = SurprisalScoreResponse {
            status: "success".to_string(),
            height,
            surprisal_score,
            baseline_score,
            deviation_factor,
            classification: classification.to_string(),
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    // Helper methods

    /// Build height metrics (placeholder - would query observer service in full implementation)
    async fn build_height_metrics(&self, height: u64) -> HeightMetricsResponse {
        // Placeholder: simulate metrics based on height
        // In full implementation, this would query the observer service
        let round_count = self.get_round_count_for_height(height).await;
        let has_stall = round_count > 1;
        let has_fault = round_count > 3;
        let classification = Self::classify_height(round_count, has_stall, has_fault);

        // Build phase metrics (placeholder)
        let phases = if round_count == 1 {
            vec![
                PhaseMetric { phase_type: "Propose".to_string(), duration_ms: 100, completed: true },
                PhaseMetric { phase_type: "PreVote".to_string(), duration_ms: 150, completed: true },
                PhaseMetric { phase_type: "PreCommit".to_string(), duration_ms: 100, completed: true },
            ]
        } else {
            vec![
                PhaseMetric { phase_type: "Propose".to_string(), duration_ms: 5000, completed: false },
                PhaseMetric { phase_type: "NewRound".to_string(), duration_ms: 100, completed: true },
            ]
        };

        HeightMetricsResponse {
            status: "success".to_string(),
            height,
            round_count,
            commit_latency_ms: if classification == "healthy" { Some(350) } else { None },
            classification: classification.to_string(),
            phases,
        }
    }

    /// Get round count for a height (placeholder)
    async fn get_round_count_for_height(&self, height: u64) -> u32 {
        // Placeholder: derive from height for deterministic testing
        // In full implementation, this would query consensus state
        match height % 10 {
            0 => 1,  // Healthy
            1 => 1,  // Healthy
            2 => 2,  // Recovering
            3 => 1,  // Healthy
            4 => 3,  // Degraded
            5 => 1,  // Healthy
            6 => 5,  // Divergence
            7 => 1,  // Healthy
            8 => 2,  // Recovering
            _ => 1,  // Healthy
        }
    }

    /// Analyze recent heights for network health
    async fn analyze_recent_heights(&self, current_height: u64) -> Vec<HeightSummary> {
        let window_size = 20.min(current_height as usize + 1);
        let start_height = current_height.saturating_sub(window_size as u64 - 1);

        let mut results = Vec::with_capacity(window_size);
        for h in start_height..=current_height {
            let round_count = self.get_round_count_for_height(h).await;
            let has_stall = round_count > 1;
            let has_fault = round_count > 3;
            results.push(HeightSummary {
                height: h,
                rounds: round_count,
                classification: Self::classify_height(round_count, has_stall, has_fault).to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
        }
        results
    }
}
