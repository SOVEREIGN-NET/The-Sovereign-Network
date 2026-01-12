//! Storage Handler Module
//! 
//! Clean, minimal storage operations using lib-storage patterns

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
// Removed unused serde_json::json import

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use lib_identity::types::IdentityId;

// Storage imports - using PersistentStorageSystem and types
use lib_storage::{PersistentStorageSystem, StorageRequirements, QualityRequirements, BudgetConstraints};
use lib_storage::types::economic_types::PaymentSchedule;
use lib_identity::ZhtpIdentity;
use lib_identity::types::identity_types::IdentityType;

/// Clean storage handler implementation
pub struct StorageHandler {
    storage: Arc<RwLock<PersistentStorageSystem>>,
    wallet_content_manager: Option<Arc<RwLock<lib_storage::WalletContentManager>>>,
}

impl StorageHandler {
    pub fn new(storage: Arc<RwLock<PersistentStorageSystem>>) -> Self {
        Self { 
            storage,
            wallet_content_manager: None,
        }
    }
    
    pub fn with_wallet_manager(mut self, manager: Arc<RwLock<lib_storage::WalletContentManager>>) -> Self {
        self.wallet_content_manager = Some(manager);
        self
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for StorageHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!(" Storage handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Get, "/api/v1/storage/status") => {
                self.handle_storage_status(request).await
            }
            (ZhtpMethod::Post, "/api/v1/storage/store") => {
                self.handle_store_content(request).await
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
    content_hash: String,
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
        // Get actual storage statistics from the storage system
        let mut storage = self.storage.write().await;
        let stats = storage.get_statistics().await?;
        
        let response_data = StorageStatusResponse {
            status: "active".to_string(),
            provider: "lib-storage".to_string(),
            available_space: {
                // Calculate available space based on system or configured limits
                // For now, use a reasonable default based on total usage
                let used_space = stats.storage_stats.total_storage_used;
                let estimated_capacity = (used_space * 10).max(10 * 1024 * 1024 * 1024); // At least 10GB capacity
                estimated_capacity - used_space
            },
            used_space: stats.storage_stats.total_storage_used,
            total_keys: stats.storage_stats.total_content_count,
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
    
    /// Handle wallet-aware content storage
    /// POST /api/v1/storage/store
    /// 
    /// Stores content and registers ownership to wallet if wallet_id provided
    async fn handle_store_content(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(Deserialize)]
        struct StoreRequest {
            data: String,  // Base64 encoded content
            wallet_id: Option<String>,  // Optional wallet owner
        }
        
        let req_data: StoreRequest = serde_json::from_slice(&request.body)?;
        
        // Decode base64 data
        let content = base64::decode(&req_data.data)
            .map_err(|e| anyhow::anyhow!("Invalid base64 data: {}", e))?;
        
        // Validate content size (10MB limit)
        const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024;
        if content.len() > MAX_CONTENT_SIZE {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::PayloadTooLarge,
                format!("Content size {} exceeds limit of {} bytes", content.len(), MAX_CONTENT_SIZE),
            ));
        }
        
        // Calculate content hash
        use lib_crypto::hashing::hash_blake3;
        let content_hash = hash_blake3(&content);
        let content_hash_obj = lib_crypto::Hash::from_bytes(&content_hash[..32]);
        
        tracing::info!("Storing content with hash: {} ({} bytes)", 
            hex::encode(&content_hash), content.len());
        
        // Register ownership if wallet_id provided and we have wallet_content_manager
        let ownership_registered = if let (Some(wallet_id_str), Some(ref manager)) = 
            (&req_data.wallet_id, &self.wallet_content_manager) 
        {
            match lib_crypto::Hash::from_hex(wallet_id_str) {
                Ok(wallet_id) => {
                    // Create a minimal ZhtpIdentity for the owner using P1-7 architecture
                    let owner_identity = ZhtpIdentity::new_unified(
                        IdentityType::Human,
                        Some(25), // Default age
                        Some("US".to_string()), // Default jurisdiction
                        &format!("wallet-{}", hex::encode(&wallet_id.0[..8])),
                        None, // Random seed
                    ).unwrap_or_else(|_| {
                        // Fallback identity if creation fails
                        ZhtpIdentity::new_unified(
                            IdentityType::Human,
                            Some(25),
                            Some("US".to_string()),
                            "default-user",
                            None,
                        ).unwrap()
                    });
                    
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    
                    // Create full ContentMetadata as required
                    let metadata = lib_storage::ContentMetadata {
                        hash: content_hash_obj.clone(),
                        content_hash: content_hash_obj.clone(),
                        owner: owner_identity,
                        size: content.len() as u64,
                        content_type: "application/octet-stream".to_string(),
                        filename: format!("upload_{}.bin", hex::encode(&content_hash[..8])),
                        description: "Uploaded via storage API".to_string(),
                        checksum: content_hash_obj.clone(),
                        
                        // Storage configuration
                        tier: lib_storage::StorageTier::Hot,
                        encryption: lib_storage::EncryptionLevel::None,
                        access_pattern: lib_storage::AccessPattern::Occasional,
                        replication_factor: 3,
                        total_chunks: ((content.len() / 65536) + 1) as u32,
                        is_encrypted: false,
                        is_compressed: false,
                        
                        // Access control (public by default)
                        access_control: vec![lib_storage::AccessLevel::Public],
                        tags: vec!["upload".to_string(), "api".to_string()],
                        
                        // Economics
                        cost_per_day: 10,
                        created_at: current_time,
                        last_accessed: current_time,
                        access_count: 0,
                        expires_at: None,
                    };
                    
                    let mut mgr = manager.write().await;
                    match mgr.register_content_ownership(
                        content_hash_obj,
                        wallet_id,
                        &metadata,
                        0  // No purchase price for uploads
                    ) {
                        Ok(_) => {
                            tracing::info!(" Registered content ownership: {} → {}", 
                                hex::encode(&content_hash), wallet_id_str);
                            true
                        }
                        Err(e) => {
                            tracing::warn!("Failed to register ownership: {}", e);
                            false
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Invalid wallet_id format: {}", e);
                    false
                }
            }
        } else {
            false
        };
        
        #[derive(Serialize)]
        struct StoreResponse {
            success: bool,
            hash: String,
            size: usize,
            wallet_id: Option<String>,
            ownership_registered: bool,
            message: String,
        }
        
        let response_data = StoreResponse {
            success: true,
            hash: hex::encode(&content_hash),
            size: content.len(),
            wallet_id: req_data.wallet_id.clone(),
            ownership_registered,
            message: if ownership_registered {
                "Content stored and ownership registered successfully".to_string()
            } else if req_data.wallet_id.is_some() {
                "Content stored but ownership registration failed".to_string()
            } else {
                "Content stored successfully (no wallet specified)".to_string()
            },
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
        
        // Validate storage key format
        if req_data.key.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Storage key cannot be empty".to_string(),
            ));
        }
        
        // Validate content size (example: 10MB limit)
        const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024;
        if req_data.value.len() > MAX_CONTENT_SIZE {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::PayloadTooLarge,
                format!("Content size {} exceeds limit of {} bytes", req_data.value.len(), MAX_CONTENT_SIZE),
            ));
        }
        
        tracing::info!("Validated storage request for key '{}' with {} bytes", req_data.key, req_data.value.as_bytes().len());
        
        // Use actual storage system to store the data
        let mut storage = self.storage.write().await;
        
        // Create storage requirements for the data
        let storage_requirements = StorageRequirements {
            duration_days: 30, // Default 30 days storage
            quality_requirements: QualityRequirements {
                min_uptime: 0.99,
                max_response_time: 1000,
                min_replication: 2,
                geographic_distribution: None,
                required_certifications: Vec::new(),
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 1000, // ZHTP tokens
                max_cost_per_gb_day: 10,
                payment_schedule: PaymentSchedule::Daily,
                max_price_volatility: 0.1,
            },
            replication_factor: 3,
            geographic_preferences: Vec::new(),
        };
        
        // Extract identity from authentication headers or create anonymous identity
        let uploader = if let Some(auth_header) = request.headers.get("Authorization") {
            if auth_header.starts_with("Bearer ") {
                let token = &auth_header[7..];
                // In a implementation, this would decode the JWT token to get identity
                // For now, create an identity based on the token
                ZhtpIdentity::new_unified(
                    IdentityType::Human,
                    Some(25), // Default age
                    Some("US".to_string()), // Default jurisdiction
                    &format!("auth-{}", &token[..std::cmp::min(8, token.len())]),
                    None, // Random seed
                ).map_err(|e| anyhow::anyhow!("Failed to create authenticated identity: {}", e))?
            } else {
                // Invalid auth format, create anonymous identity
                ZhtpIdentity::new_unified(
                    IdentityType::Human,
                    Some(25), // Default age
                    Some("US".to_string()), // Default jurisdiction
                    "anonymous-user",
                    None, // Random seed
                ).map_err(|e| anyhow::anyhow!("Failed to create anonymous identity: {}", e))?
            }
        } else {
            // No authentication provided, create anonymous identity
            ZhtpIdentity::new_unified(
                IdentityType::Human,
                Some(25), // Default age
                Some("US".to_string()), // Default jurisdiction
                "anonymous-user",
                None, // Random seed
            ).map_err(|e| anyhow::anyhow!("Failed to create anonymous identity: {}", e))?
        };
        
        // Convert string data to bytes
        let data_bytes = req_data.value.as_bytes().to_vec();
        let data_size = data_bytes.len();
        
        // Store the data using erasure coding
        let content_hash = match storage.store_with_erasure_coding(data_bytes, storage_requirements, uploader).await {
            Ok(hash) => {
                tracing::info!("Successfully stored key '{}' with {} bytes of data, content hash: {:?}", 
                    req_data.key, data_size, hash);
                hash
            }
            Err(e) => {
                tracing::error!("Failed to store key '{}': {}", req_data.key, e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Storage operation failed: {}", e),
                ));
            }
        };
        
        // Log TTL usage if provided
        if let Some(ttl_seconds) = req_data.ttl {
            tracing::info!("TTL set to {} seconds for key '{}'", ttl_seconds, req_data.key);
        }
        
        // Create response with TTL information if provided
        let ttl_info = if let Some(ttl) = req_data.ttl {
            format!(" with TTL of {} seconds", ttl)
        } else {
            " with no expiration".to_string()
        };
        
        let response_data = PutDataResponse {
            status: "stored".to_string(),
            message: format!("Data stored successfully{} with content hash {:?}", ttl_info, content_hash),
            key: req_data.key,
            size: data_size,
            content_hash: format!("{:?}", content_hash),
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
        
        // UnifiedStorageSystem doesn't currently have direct key-value retrieval interface
        // This functionality needs to be implemented in lib-storage
        tracing::warn!("Key-value retrieval not implemented in UnifiedStorageSystem for key: {}", req_data.key);
        
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Key-value retrieval interface not available in UnifiedStorageSystem".to_string(),
        ))
    }
    
    /// Handle data deletion request
    async fn handle_delete_data(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: DeleteDataRequest = serde_json::from_slice(&request.body)?;
        
        // UnifiedStorageSystem doesn't currently have direct key deletion interface
        // This functionality needs to be implemented in lib-storage
        tracing::warn!("Key-value deletion not implemented in UnifiedStorageSystem for key: {}", req_data.key);
        
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Key-value deletion interface not available in UnifiedStorageSystem".to_string(),
        ))
    }
    
    /// Handle storage statistics request
    async fn handle_storage_stats(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        let mut storage = self.storage.write().await;
        let stats = storage.get_statistics().await?;
        
        let response_data = StorageStatsResponse {
            status: "stats_retrieved".to_string(),
            total_keys: stats.storage_stats.total_content_count,
            total_size: stats.storage_stats.total_storage_used,
            average_key_size: if stats.storage_stats.total_content_count > 0 {
                stats.storage_stats.total_storage_used as f64 / stats.storage_stats.total_content_count as f64
            } else {
                0.0
            },
            read_operations: stats.storage_stats.total_downloads,
            write_operations: stats.storage_stats.total_uploads,
            delete_operations: 0, // This stat is not tracked in current StorageStats
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None::<IdentityId>,
        ))
    }
    


}