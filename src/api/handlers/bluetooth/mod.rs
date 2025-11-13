//! Bluetooth API handlers for ZHTP
//!
//! Provides endpoints for Bluetooth status monitoring and management.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tracing::info;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

use crate::unified_server::{BluetoothRouter, BluetoothClassicRouter};

/// Response structure for Bluetooth status
#[derive(Debug, Serialize, Deserialize)]
pub struct BluetoothStatusResponse {
    pub status: String,
    pub bluetooth_le: BluetoothProtocolStatus,
    pub bluetooth_classic: BluetoothProtocolStatus,
    pub timestamp: u64,
}

/// Status information for a Bluetooth protocol
#[derive(Debug, Serialize, Deserialize)]
pub struct BluetoothProtocolStatus {
    pub status: String,
    pub description: String,
}

/// Bluetooth API handler
pub struct BluetoothHandler {
    bluetooth_le_router: Arc<BluetoothRouter>,
    bluetooth_classic_router: Arc<BluetoothClassicRouter>,
}

impl BluetoothHandler {
    /// Create a new Bluetooth handler
    pub fn new(bluetooth_le_router: Arc<BluetoothRouter>, bluetooth_classic_router: Arc<BluetoothClassicRouter>) -> Self {
        Self {
            bluetooth_le_router,
            bluetooth_classic_router,
        }
    }

    /// Handle GET /api/v1/bluetooth/status
    async fn handle_get_bluetooth_status(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("Bluetooth status requested");

        // Get current status of both Bluetooth protocols
        let bluetooth_le_status = self.bluetooth_le_router.get_status().await;
        let bluetooth_classic_status = self.bluetooth_classic_router.get_status().await;

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build response with descriptive messages
        let response = BluetoothStatusResponse {
            status: "success".to_string(),
            bluetooth_le: BluetoothProtocolStatus {
                status: bluetooth_le_status.clone(),
                description: get_status_description(&bluetooth_le_status),
            },
            bluetooth_classic: BluetoothProtocolStatus {
                status: bluetooth_classic_status.clone(),
                description: get_status_description(&bluetooth_classic_status),
            },
            timestamp,
        };

        // Serialize to JSON bytes
        let json_response = serde_json::to_vec(&response)
            .map_err(|e| anyhow::anyhow!("Failed to serialize response: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
}

/// Get human-readable description for status
fn get_status_description(status: &str) -> String {
    match status {
        "NOT_STARTED" => "Initialization has not started yet".to_string(),
        "INITIALIZING" => "Currently initializing Bluetooth protocol".to_string(),
        "ACTIVE" => "Bluetooth protocol is active and ready".to_string(),
        "FAILED" => "Bluetooth initialization failed".to_string(),
        "TIMEOUT" => "Bluetooth initialization timed out after 60 seconds".to_string(),
        _ => format!("Unknown status: {}", status),
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for BluetoothHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("Bluetooth handler: {} {}", request.method, request.uri);

        match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Get, "/api/v1/bluetooth/status") => {
                self.handle_get_bluetooth_status(request).await
            }
            _ => {
                // Endpoint not found
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Endpoint not found: {} {}", request.method, request.uri),
                ))
            }
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/bluetooth/")
    }

    fn priority(&self) -> u32 {
        90  // Same priority as other handlers
    }
}
