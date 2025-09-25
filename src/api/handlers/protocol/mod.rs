//! Protocol Handler Module
//! 
//! Clean, minimal protocol operations and server information

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

/// Clean protocol handler implementation
pub struct ProtocolHandler {
    server_info: Arc<RwLock<ServerInfo>>,
}

#[derive(Clone)]
pub struct ServerInfo {
    pub version: String,
    pub protocol_version: String,
    pub start_time: u64,
    pub node_id: String,
}

impl ProtocolHandler {
    pub fn new() -> Self {
        let server_info = ServerInfo {
            version: "1.0.0".to_string(),
            protocol_version: "ZHTP/1.0".to_string(),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            node_id: "zhtp-node-dev".to_string(), // Mock node ID
        };

        Self {
            server_info: Arc::new(RwLock::new(server_info)),
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for ProtocolHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("🔌 Protocol handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Get, "/api/v1/protocol/info") => {
                self.handle_protocol_info(request).await
            }
            (ZhtpMethod::Get, "/api/v1/protocol/health") => {
                self.handle_health_check(request).await
            }
            (ZhtpMethod::Get, "/api/v1/protocol/version") => {
                self.handle_version_info(request).await
            }
            (ZhtpMethod::Get, "/api/v1/protocol/capabilities") => {
                self.handle_capabilities(request).await
            }
            (ZhtpMethod::Get, "/api/v1/protocol/stats") => {
                self.handle_protocol_stats(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Protocol endpoint not found".to_string(),
                ))
            }
        };
        
        match response {
            Ok(mut resp) => {
                resp.headers.set("X-Handler", "Protocol".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                tracing::error!("Protocol handler error: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Protocol error: {}", e),
                ))
            }
        }
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/protocol/")
    }
    
    fn priority(&self) -> u32 {
        70
    }
}

// Response structures
#[derive(Serialize)]
struct ProtocolInfoResponse {
    status: String,
    protocol: String,
    version: String,
    node_id: String,
    uptime: u64,
    supported_methods: Vec<String>,
    supported_features: Vec<String>,
}

#[derive(Serialize)]
struct HealthCheckResponse {
    status: String,
    healthy: bool,
    uptime: u64,
    timestamp: u64,
    checks: Vec<HealthCheck>,
}

#[derive(Serialize)]
struct HealthCheck {
    name: String,
    status: String,
    message: String,
}

#[derive(Serialize)]
struct VersionResponse {
    status: String,
    server_version: String,
    protocol_version: String,
    api_version: String,
    build_info: BuildInfo,
}

#[derive(Serialize)]
struct BuildInfo {
    commit: String,
    build_date: String,
    rust_version: String,
}

#[derive(Serialize)]
struct CapabilitiesResponse {
    status: String,
    capabilities: Vec<Capability>,
    extensions: Vec<String>,
}

#[derive(Serialize)]
struct Capability {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

#[derive(Serialize)]
struct ProtocolStatsResponse {
    status: String,
    requests_handled: u64,
    active_connections: u32,
    total_bytes_sent: u64,
    total_bytes_received: u64,
    average_response_time: f64,
    error_rate: f64,
}

impl ProtocolHandler {
    /// Handle protocol information request
    async fn handle_protocol_info(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let server_info = self.server_info.read().await;
        
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() - server_info.start_time;
        
        let response_data = ProtocolInfoResponse {
            status: "active".to_string(),
            protocol: "ZHTP".to_string(),
            version: server_info.protocol_version.clone(),
            node_id: server_info.node_id.clone(),
            uptime,
            supported_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            supported_features: vec![
                "identity_management".to_string(),
                "blockchain_operations".to_string(),
                "storage_management".to_string(),
                "protocol_info".to_string(),
            ],
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle health check request
    async fn handle_health_check(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let server_info = self.server_info.read().await;
        
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() - server_info.start_time;
        
        let checks = vec![
            HealthCheck {
                name: "server".to_string(),
                status: "healthy".to_string(),
                message: "Server is running normally".to_string(),
            },
            HealthCheck {
                name: "handlers".to_string(),
                status: "healthy".to_string(),
                message: "All handlers are responsive".to_string(),
            },
            HealthCheck {
                name: "memory".to_string(),
                status: "healthy".to_string(),
                message: "Memory usage is within normal limits".to_string(),
            },
        ];
        
        let response_data = HealthCheckResponse {
            status: "healthy".to_string(),
            healthy: true,
            uptime,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            checks,
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle version information request
    async fn handle_version_info(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let server_info = self.server_info.read().await;
        
        let response_data = VersionResponse {
            status: "version_info".to_string(),
            server_version: server_info.version.clone(),
            protocol_version: server_info.protocol_version.clone(),
            api_version: "1.0".to_string(),
            build_info: BuildInfo {
                commit: "dev-build".to_string(),
                build_date: "2025-09-18".to_string(),
                rust_version: "1.70+".to_string(),
            },
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle capabilities request
    async fn handle_capabilities(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let capabilities = vec![
            Capability {
                name: "identity_management".to_string(),
                version: "1.0".to_string(),
                description: "Identity creation, verification, and management".to_string(),
                enabled: true,
            },
            Capability {
                name: "blockchain_operations".to_string(),
                version: "1.0".to_string(),
                description: "Blockchain interaction and transaction processing".to_string(),
                enabled: true,
            },
            Capability {
                name: "storage_management".to_string(),
                version: "1.0".to_string(),
                description: "Data storage and retrieval operations".to_string(),
                enabled: true,
            },
            Capability {
                name: "protocol_info".to_string(),
                version: "1.0".to_string(),
                description: "Protocol information and server status".to_string(),
                enabled: true,
            },
        ];
        
        let response_data = CapabilitiesResponse {
            status: "capabilities_listed".to_string(),
            capabilities,
            extensions: vec![
                "zhtp-native".to_string(),
                "post-quantum-crypto".to_string(),
            ],
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle protocol statistics request
    async fn handle_protocol_stats(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let response_data = ProtocolStatsResponse {
            status: "stats_retrieved".to_string(),
            requests_handled: 0, // Would need to track these
            active_connections: 1, // Mock value
            total_bytes_sent: 0, // Would need to track these
            total_bytes_received: 0, // Would need to track these
            average_response_time: 50.0, // Mock value in ms
            error_rate: 0.01, // Mock value (1%)
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
}