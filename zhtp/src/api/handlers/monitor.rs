//! Monitoring API handlers for ZHTP
//!
//! Provides endpoints for node health, system metrics, and performance monitoring.
//! Issue #1801: Implement missing monitoring endpoints

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tracing::{info, error};

use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

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
    pub fn new(_runtime: Arc<RuntimeOrchestrator>) -> Self {
        Self { _runtime }
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
            (ZhtpMethod::Get, "/api/v1/monitor/health") => {
                self.handle_get_health(request).await
            }
            // Issue #1801: System metrics endpoint
            (ZhtpMethod::Get, "/api/v1/monitor/system") => {
                self.handle_get_system(request).await
            }
            // Issue #1801: Performance metrics endpoint
            (ZhtpMethod::Get, "/api/v1/monitor/performance") => {
                self.handle_get_performance(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Monitor endpoint not found".to_string(),
                ))
            }
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
    /// Get health check status
    /// GET /api/v1/monitor/health (Issue #1801)
    async fn handle_get_health(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("API: Getting health status");

        // Check blockchain component via global provider
        let blockchain_health = match crate::runtime::blockchain_provider::get_global_blockchain().await {
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
        let overall_status = if network_health == "error" || blockchain_health == "error" {
            "degraded"
        } else {
            "healthy"
        };

        // Get uptime (placeholder - would track actual node start time)
        let uptime_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() % 86400; // Placeholder: use seconds since midnight

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

        info!("API: Health status - {}, uptime {}s", overall_status, uptime_secs);

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
        let blocks_per_hour = if avg_block_time > 0.0 {
            (3600.0 / avg_block_time) as u64
        } else {
            0
        };

        // Calculate transaction throughput (placeholder)
        let tx_throughput = 0.0; // Would calculate from recent block tx counts

        let response = PerformanceResponse {
            status: "success".to_string(),
            avg_block_time_secs: avg_block_time,
            blocks_per_hour,
            mempool_size,
            tx_throughput_per_sec: tx_throughput,
        };

        info!("API: Performance - {}s avg block time, {} mempool", 
              avg_block_time, mempool_size);

        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            CONTENT_TYPE_JSON.to_string(),
            None,
        ))
    }
}
