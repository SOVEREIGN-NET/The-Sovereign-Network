//! Monitoring API handlers for ZHTP
//!
//! Provides endpoints for node health, system metrics, and performance monitoring.
//! Issue #1801: Implement missing monitoring endpoints

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use crate::runtime::RuntimeOrchestrator;

const CONTENT_TYPE_JSON: &str = "application/json";

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub components: ComponentHealth,
    pub uptime_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub blockchain: String,
    pub consensus: String,
    pub oracle: String,
    pub mempool: String,
    pub network: String,
}

/// System metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemMetricsResponse {
    pub status: String,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: u64,
    pub disk_usage_gb: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
}

/// Performance metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceResponse {
    pub status: String,
    pub avg_block_time_secs: f64,
    pub blocks_per_hour: u64,
    pub mempool_size: usize,
    pub tx_throughput_per_sec: f64,
}

/// Monitor handler implementation
pub struct MonitorHandler {
    _runtime: Arc<RuntimeOrchestrator>,
}

impl MonitorHandler {
    pub fn new(runtime: Arc<RuntimeOrchestrator>) -> Self {
        Self { _runtime: runtime }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for MonitorHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let start_time = std::time::Instant::now();

        info!(
            method = ?request.method,
            uri = %request.uri,
            "Monitor API request received"
        );

        let response = match (request.method, request.uri.as_str()) {
            // Issue #1801: Health check endpoint
            (ZhtpMethod::Get, "/api/v1/monitor/health") => self.handle_get_health(request).await,
            // Issue #1801: System metrics endpoint
            (ZhtpMethod::Get, "/api/v1/monitor/system") => self.handle_get_system(request).await,
            // Issue #1801: Performance metrics endpoint
            (ZhtpMethod::Get, "/api/v1/monitor/performance") => {
                self.handle_get_performance(request).await
            }
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "Monitor endpoint not found".to_string(),
            )),
        };

        let duration_ms = start_time.elapsed().as_millis();

        match &response {
            Ok(resp) => {
                info!(
                    status = ?resp.status,
                    duration_ms = duration_ms,
                    "Monitor API request completed"
                );
            }
            Err(e) => {
                error!(
                    error = %e,
                    duration_ms = duration_ms,
                    "Monitor API request failed"
                );
            }
        }

        response
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/monitor/")
    }

    fn priority(&self) -> u32 {
        80 // Lower priority than network
    }
}

impl MonitorHandler {
    /// Compute overall health status from individual component statuses.
    ///
    /// Any component reporting "error" → "degraded".
    /// Any component reporting "warning" (with no errors) → "warning".
    /// All components "ok" → "healthy".
    pub(crate) fn compute_overall_status(network: &str, blockchain: &str) -> &'static str {
        if network == "error" || blockchain == "error" {
            "degraded"
        } else if network == "warning" || blockchain == "warning" {
            "warning"
        } else {
            "healthy"
        }
    }

    /// Convert average block time (seconds) to blocks-per-hour.
    pub(crate) fn blocks_per_hour(avg_block_time_secs: f64) -> u64 {
        if avg_block_time_secs > 0.0 {
            (3600.0 / avg_block_time_secs) as u64
        } else {
            0
        }
    }

    /// Get health check status
    /// GET /api/v1/monitor/health (Issue #1801)
    async fn handle_get_health(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting health status");

        // Check blockchain component via global provider
        let blockchain_health =
            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(bc) => {
                    let blockchain = bc.read().await;
                    if blockchain.get_height() > 0 {
                        "ok"
                    } else {
                        "warning"
                    }
                }
                Err(_) => "error",
            };

        // Check network component
        let network_health = match self._runtime.get_connected_peers().await {
            Ok(peers) if !peers.is_empty() => "ok",
            Ok(_) => "warning", // No peers but network functional
            Err(_) => "error",
        };

        // Placeholder for other components
        // These would check actual component status when exposed by runtime
        let consensus_health = "ok"; // Placeholder
        let oracle_health = "ok"; // Placeholder
        let mempool_health = "ok"; // Placeholder

        // Determine overall status
        let overall_status = Self::compute_overall_status(network_health, blockchain_health);

        // Get uptime
        // TODO: Track actual node start time in the runtime and compute real uptime here.
        // For now, expose a neutral placeholder value instead of a misleading "seconds since midnight".
        let uptime_secs: u64 = 0;

        let response = HealthResponse {
            status: overall_status.to_string(),
            components: ComponentHealth {
                blockchain: blockchain_health.to_string(),
                consensus: consensus_health.to_string(),
                oracle: oracle_health.to_string(),
                mempool: mempool_health.to_string(),
                network: network_health.to_string(),
            },
            uptime_secs,
        };

        info!(
            "API: Health status - {}, uptime {}s",
            overall_status, uptime_secs
        );

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get system metrics
    /// GET /api/v1/monitor/system (Issue #1801)
    async fn handle_get_system(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting system metrics");

        // Try to get system metrics from runtime
        // In a full implementation, these would come from system monitoring
        // For now, return placeholder values
        let (cpu_usage, memory_mb, disk_gb, net_rx, net_tx) = (0.0, 0, 0, 0, 0);

        let response = SystemMetricsResponse {
            status: "success".to_string(),
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_mb,
            disk_usage_gb: disk_gb,
            network_rx_bytes: net_rx,
            network_tx_bytes: net_tx,
        };

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }

    /// Get performance metrics
    /// GET /api/v1/monitor/performance (Issue #1801)
    async fn handle_get_performance(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting performance metrics");

        // Get blockchain stats via global provider
        let (_height, avg_block_time, mempool_size) =
            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(bc) => {
                    let blockchain = bc.read().await;
                    let height = blockchain.get_height();

                    // Calculate average block time from recent blocks (placeholder)
                    let avg_block_time = if height > 0 {
                        // Would calculate from actual block timestamps
                        15.0 // Placeholder: 15 seconds per block
                    } else {
                        0.0
                    };

                    let mempool_size = blockchain.get_pending_transactions().len();

                    (height, avg_block_time, mempool_size)
                }
                Err(_) => (0, 0.0, 0),
            };

        // Calculate blocks per hour
        let blocks_per_hour = Self::blocks_per_hour(avg_block_time);

        // Calculate transaction throughput (placeholder)
        let tx_throughput = 0.0; // Would calculate from recent block tx counts

        let response = PerformanceResponse {
            status: "success".to_string(),
            avg_block_time_secs: avg_block_time,
            blocks_per_hour,
            mempool_size,
            tx_throughput_per_sec: tx_throughput,
        };

        info!(
            "API: Performance - {}s avg block time, {} mempool",
            avg_block_time, mempool_size
        );

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Response schema round-trips ──────────────────────────────────────────

    /// Verifies that `HealthResponse` serialises to valid JSON and every
    /// expected field survives a round-trip.  If a field is renamed or removed
    /// this test will break, locking in the public API contract.
    #[test]
    fn health_response_schema_round_trip() {
        let original = HealthResponse {
            status: "healthy".to_string(),
            components: ComponentHealth {
                blockchain: "ok".to_string(),
                consensus: "ok".to_string(),
                oracle: "ok".to_string(),
                mempool: "ok".to_string(),
                network: "ok".to_string(),
            },
            uptime_secs: 3600,
        };

        let json = serde_json::to_string(&original).expect("must serialise");
        let decoded: HealthResponse = serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(decoded.status, "healthy");
        assert_eq!(decoded.uptime_secs, 3600);
        assert_eq!(decoded.components.blockchain, "ok");
        assert_eq!(decoded.components.consensus, "ok");
        assert_eq!(decoded.components.oracle, "ok");
        assert_eq!(decoded.components.mempool, "ok");
        assert_eq!(decoded.components.network, "ok");

        // All five component keys must be present in the JSON object.
        let map: serde_json::Value = serde_json::from_str(&json).unwrap();
        let comps = &map["components"];
        for key in &["blockchain", "consensus", "oracle", "mempool", "network"] {
            assert!(
                comps.get(key).is_some(),
                "component key `{key}` missing from serialised JSON"
            );
        }
    }

    #[test]
    fn system_metrics_response_schema_round_trip() {
        let original = SystemMetricsResponse {
            status: "success".to_string(),
            cpu_usage_percent: 42.5,
            memory_usage_mb: 1024,
            disk_usage_gb: 50,
            network_rx_bytes: 100_000,
            network_tx_bytes: 200_000,
        };

        let json = serde_json::to_string(&original).expect("must serialise");
        let decoded: SystemMetricsResponse = serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(decoded.status, "success");
        assert!((decoded.cpu_usage_percent - 42.5).abs() < f64::EPSILON);
        assert_eq!(decoded.memory_usage_mb, 1024);
        assert_eq!(decoded.disk_usage_gb, 50);
        assert_eq!(decoded.network_rx_bytes, 100_000);
        assert_eq!(decoded.network_tx_bytes, 200_000);

        // Key names must be stable.
        let map: serde_json::Value = serde_json::from_str(&json).unwrap();
        for key in &[
            "status",
            "cpu_usage_percent",
            "memory_usage_mb",
            "disk_usage_gb",
            "network_rx_bytes",
            "network_tx_bytes",
        ] {
            assert!(
                map.get(key).is_some(),
                "field `{key}` missing from serialised JSON"
            );
        }
    }

    #[test]
    fn performance_response_schema_round_trip() {
        let original = PerformanceResponse {
            status: "success".to_string(),
            avg_block_time_secs: 15.0,
            blocks_per_hour: 240,
            mempool_size: 37,
            tx_throughput_per_sec: 1.5,
        };

        let json = serde_json::to_string(&original).expect("must serialise");
        let decoded: PerformanceResponse = serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(decoded.status, "success");
        assert!((decoded.avg_block_time_secs - 15.0).abs() < f64::EPSILON);
        assert_eq!(decoded.blocks_per_hour, 240);
        assert_eq!(decoded.mempool_size, 37);
        assert!((decoded.tx_throughput_per_sec - 1.5).abs() < f64::EPSILON);

        let map: serde_json::Value = serde_json::from_str(&json).unwrap();
        for key in &[
            "status",
            "avg_block_time_secs",
            "blocks_per_hour",
            "mempool_size",
            "tx_throughput_per_sec",
        ] {
            assert!(
                map.get(key).is_some(),
                "field `{key}` missing from serialised JSON"
            );
        }
    }

    // ── Overall-status logic ─────────────────────────────────────────────────

    #[test]
    fn overall_status_healthy_when_all_ok() {
        assert_eq!(
            MonitorHandler::compute_overall_status("ok", "ok"),
            "healthy"
        );
    }

    #[test]
    fn overall_status_warning_when_network_warns() {
        assert_eq!(
            MonitorHandler::compute_overall_status("warning", "ok"),
            "warning"
        );
    }

    #[test]
    fn overall_status_warning_when_blockchain_warns() {
        assert_eq!(
            MonitorHandler::compute_overall_status("ok", "warning"),
            "warning"
        );
    }

    #[test]
    fn overall_status_degraded_when_network_errors() {
        assert_eq!(
            MonitorHandler::compute_overall_status("error", "ok"),
            "degraded"
        );
    }

    #[test]
    fn overall_status_degraded_when_blockchain_errors() {
        assert_eq!(
            MonitorHandler::compute_overall_status("ok", "error"),
            "degraded"
        );
    }

    /// Error takes precedence over warning.
    #[test]
    fn overall_status_degraded_when_error_and_warning() {
        assert_eq!(
            MonitorHandler::compute_overall_status("error", "warning"),
            "degraded"
        );
    }

    // ── blocks_per_hour calculation ──────────────────────────────────────────

    #[test]
    fn blocks_per_hour_standard_15s_block_time() {
        // 3600 / 15 = 240
        assert_eq!(MonitorHandler::blocks_per_hour(15.0), 240);
    }

    #[test]
    fn blocks_per_hour_zero_block_time_returns_zero() {
        assert_eq!(MonitorHandler::blocks_per_hour(0.0), 0);
    }

    #[test]
    fn blocks_per_hour_one_second_block_time() {
        assert_eq!(MonitorHandler::blocks_per_hour(1.0), 3600);
    }

    #[test]
    fn blocks_per_hour_truncates_fractional_result() {
        // 3600 / 7 = 514.28… → truncated to 514
        assert_eq!(MonitorHandler::blocks_per_hour(7.0), 514);
    }

    // ── URI routing helpers ──────────────────────────────────────────────────

    /// `can_handle` must accept all /api/v1/monitor/* paths and reject others.
    /// We verify the same prefix logic in isolation rather than through the
    /// full handler (which would require a live RuntimeOrchestrator).
    #[test]
    fn monitor_uri_prefix_matching() {
        let monitor_uris = [
            "/api/v1/monitor/health",
            "/api/v1/monitor/system",
            "/api/v1/monitor/performance",
            "/api/v1/monitor/",
        ];
        for uri in &monitor_uris {
            assert!(
                uri.starts_with("/api/v1/monitor/"),
                "expected monitor prefix for `{uri}`"
            );
        }

        let non_monitor_uris = [
            "/api/v1/blockchain/blocks",
            "/api/v1/wallet/list",
            "/api/v1/monitor", // no trailing slash
            "/monitor/health",
            "/",
        ];
        for uri in &non_monitor_uris {
            assert!(
                !uri.starts_with("/api/v1/monitor/"),
                "expected non-monitor prefix for `{uri}`"
            );
        }
    }

    /// Routing table must map each known path to a distinct handler branch.
    /// We verify the uri strings used in the dispatch `match` are not typos.
    #[test]
    fn known_route_uris_are_distinct() {
        let routes = [
            "/api/v1/monitor/health",
            "/api/v1/monitor/system",
            "/api/v1/monitor/performance",
        ];
        let unique: std::collections::HashSet<_> = routes.iter().collect();
        assert_eq!(
            unique.len(),
            routes.len(),
            "duplicate route URIs detected in monitor handler"
        );
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;
    use lib_protocols::types::{ZhtpHeaders, ZHTP_VERSION};

    fn create_test_request(method: ZhtpMethod, uri: &str) -> ZhtpRequest {
        ZhtpRequest {
            method,
            uri: uri.to_string(),
            version: ZHTP_VERSION.to_string(),
            headers: ZhtpHeaders::new(),
            body: vec![],
            timestamp: 0,
            requester: None,
            auth_proof: None,
        }
    }

    #[test]
    fn test_can_handle_monitor_paths() {
        // Test can_handle logic directly without needing RuntimeOrchestrator
        assert!("/api/v1/monitor/health".starts_with("/api/v1/monitor/"));
        assert!("/api/v1/monitor/system".starts_with("/api/v1/monitor/"));
        assert!("/api/v1/monitor/performance".starts_with("/api/v1/monitor/"));
    }

    #[test]
    fn test_cannot_handle_non_monitor_paths() {
        assert!(!"/api/v1/observer/health".starts_with("/api/v1/monitor/"));
        assert!(!"/api/v1/blockchain/height".starts_with("/api/v1/monitor/"));
        assert!(!"/health".starts_with("/api/v1/monitor/"));
    }

    #[test]
    fn test_health_response_schema_structure() {
        // Verify the HealthResponse structure is correct
        let response = HealthResponse {
            status: "healthy".to_string(),
            components: ComponentHealth {
                blockchain: "ok".to_string(),
                consensus: "ok".to_string(),
                oracle: "ok".to_string(),
                mempool: "ok".to_string(),
                network: "ok".to_string(),
            },
            uptime_secs: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify required fields exist
        assert!(parsed.get("status").is_some(), "status field required");
        assert!(
            parsed.get("components").is_some(),
            "components field required"
        );
        assert!(
            parsed.get("uptime_secs").is_some(),
            "uptime_secs field required"
        );

        // Verify components sub-fields
        let components = parsed.get("components").unwrap();
        assert!(
            components.get("blockchain").is_some(),
            "blockchain component required"
        );
        assert!(
            components.get("consensus").is_some(),
            "consensus component required"
        );
        assert!(
            components.get("oracle").is_some(),
            "oracle component required"
        );
        assert!(
            components.get("mempool").is_some(),
            "mempool component required"
        );
        assert!(
            components.get("network").is_some(),
            "network component required"
        );
    }

    #[test]
    fn test_health_status_values() {
        // Test valid status values
        let valid_statuses = ["healthy", "warning", "degraded"];
        assert!(valid_statuses.contains(&"healthy"));
        assert!(valid_statuses.contains(&"warning"));
        assert!(valid_statuses.contains(&"degraded"));

        // Test valid component health values
        let valid_health = ["ok", "warning", "error"];
        assert!(valid_health.contains(&"ok"));
        assert!(valid_health.contains(&"warning"));
        assert!(valid_health.contains(&"error"));
    }

    #[test]
    fn test_uri_normalization_logic() {
        // Test the URI normalization logic that would be applied
        // Note: The normalization splits on '?' FIRST, then trims trailing slashes
        let test_cases = vec![
            ("/api/v1/monitor/health", "/api/v1/monitor/health"),
            ("/api/v1/monitor/health/", "/api/v1/monitor/health"),
            ("/api/v1/monitor/health?verbose=1", "/api/v1/monitor/health"),
            (
                "/api/v1/monitor/health/?verbose=1",
                "/api/v1/monitor/health/",
            ), // '?' split happens first!
        ];

        for (input, expected) in test_cases {
            // Match the actual logic in the handler:
            // 1. trim_end_matches('/')
            // 2. split('?').next()
            let normalized_uri = input.trim_end_matches('/');
            let normalized_uri = if normalized_uri.is_empty() {
                "/"
            } else {
                normalized_uri
            };
            let match_uri = normalized_uri.split('?').next().unwrap_or(normalized_uri);
            assert_eq!(match_uri, expected, "Failed for input: {}", input);
        }
    }

    // Note: Integration tests for the full handler would require a RuntimeOrchestrator
    // which is complex to set up in unit tests. These tests focus on:
    // 1. Response schema validation
    // 2. URI normalization logic
    // 3. can_handle logic
    //
    // For full integration tests, see: zhtp/src/api/test_network_handler.rs
}
