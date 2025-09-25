//! Storage Handler Module
//! 
//! Clean, minimal storage operations using lib-storage patterns

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use lib_identity::types::IdentityId;

// Storage imports - using UnifiedStorageSystem
use lib_storage::UnifiedStorageSystem;

/// Clean storage handler implementation
pub struct StorageHandler {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
}

impl StorageHandler {
    pub fn new(storage: Arc<RwLock<UnifiedStorageSystem>>) -> Self {
        Self { storage }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for StorageHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("💾 Storage handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Get, "/api/v1/storage/status") => {
                self.handle_storage_status(request).await
            }
            (ZhtpMethod::Post, "/api/v1/storage/put") => {
                self.handle_put_data(request).await
            }
            (ZhtpMethod::Post, "/api/v1/storage/get") => {
                self.handle_get_data(request).await
            }
            (ZhtpMethod::Delete, "/api/v1/storage/delete") => {
                self.handle_delete_data(request).await
            }
            (ZhtpMethod::Get, "/api/v1/storage/stats") => {
                self.handle_storage_stats(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Storage endpoint not found".to_string(),
                ))
            }
        };
        
        match response {
            Ok(mut resp) => {
                resp.headers.set("X-Handler", "Storage".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                tracing::error!("Storage handler error: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Storage error: {}", e),
                ))
            }
        }
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/storage/")
    }
    
    fn priority(&self) -> u32 {
        80
    }
}

// Request/Response structures
#[derive(Deserialize)]
struct PutDataRequest {
    key: String,
    value: String,
    ttl: Option<u64>,
}

#[derive(Deserialize)]
struct GetDataRequest {
    key: String,
}

#[derive(Deserialize)]
struct DeleteDataRequest {
    key: String,
}

#[derive(Serialize)]
struct StorageStatusResponse {
    status: String,
    provider: String,
    available_space: u64,
    used_space: u64,
    total_keys: u64,
    uptime: u64,
}

#[derive(Serialize)]
struct PutDataResponse {
    status: String,
    message: String,
    key: String,
    size: usize,
}

#[derive(Serialize)]
struct GetDataResponse {
    status: String,
    key: String,
    value: String,
    size: usize,
    created_at: Option<u64>,
}

#[derive(Serialize)]
struct DeleteDataResponse {
    status: String,
    message: String,
    key: String,
}

#[derive(Serialize)]
struct StorageStatsResponse {
    status: String,
    total_keys: u64,
    total_size: u64,
    average_key_size: f64,
    read_operations: u64,
    write_operations: u64,
    delete_operations: u64,
}

impl StorageHandler {
    /// Handle storage status request
    async fn handle_storage_status(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let response_data = StorageStatusResponse {
            status: "active".to_string(),
            provider: "lib-storage".to_string(),
            available_space: 1024 * 1024 * 1024, // 1GB mock
            used_space: 1024 * 1024, // 1MB mock
            total_keys: 100, // Mock value
            uptime: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None::<IdentityId>,
        ))
    }
    
    /// Handle data storage request
    async fn handle_put_data(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: PutDataRequest = serde_json::from_slice(&request.body)?;
        
        // Mock successful storage operation
        let response_data = PutDataResponse {
            status: "stored".to_string(),
            message: "Data stored successfully".to_string(),
            key: req_data.key,
            size: req_data.value.len(),
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None::<IdentityId>,
        ))
    }
    
    /// Handle data retrieval request
    async fn handle_get_data(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: GetDataRequest = serde_json::from_slice(&request.body)?;
        
        // Mock data retrieval
        let response_data = GetDataResponse {
            status: "found".to_string(),
            key: req_data.key.clone(),
            value: format!("mock_value_for_{}", req_data.key),
            size: 100, // Mock size
            created_at: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None::<IdentityId>,
        ))
    }
    
    /// Handle data deletion request
    async fn handle_delete_data(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: DeleteDataRequest = serde_json::from_slice(&request.body)?;
        
        // Mock successful deletion
        let response_data = DeleteDataResponse {
            status: "deleted".to_string(),
            message: "Data deleted successfully".to_string(),
            key: req_data.key,
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None::<IdentityId>,
        ))
    }
    
    /// Handle storage statistics request
    async fn handle_storage_stats(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let response_data = StorageStatsResponse {
            status: "stats_retrieved".to_string(),
            total_keys: 100, // Mock value
            total_size: 1024 * 1024, // Mock 1MB
            average_key_size: 1024.0, // Mock value
            read_operations: 50,  // Mock values
            write_operations: 30, // Mock values
            delete_operations: 10, // Mock values
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None::<IdentityId>,
        ))
    }
}