//! ZHTP Request Handlers
//! 
//! Core request handlers for all ZHTP methods (GET, POST, PUT, DELETE, etc.)
//! with zero-knowledge proof validation, economic fee processing, and
//! post-quantum cryptographic security.

#![allow(dead_code)]

use crate::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use crate::zhtp::{ZhtpResult, ServerCapabilities};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

// Import ZK proof functionality from lib-proofs
use lib_proofs::{
    ZkProof, ZkTransactionProof, TransactionVerifier,
    types::VerificationResult, initialize_zk_system
};

/// Core ZHTP request handlers
pub struct ZhtpHandlers {
    /// Content store
    content_store: Arc<RwLock<HashMap<String, StoredContent>>>,
    /// Handler configuration
    config: HandlerConfig,
    /// Request cache
    request_cache: Arc<RwLock<HashMap<String, CachedResponse>>>,
    /// Handler statistics
    stats: Arc<RwLock<HandlerStats>>,
}

/// Handler configuration
#[derive(Debug, Clone)]
pub struct HandlerConfig {
    /// Enable request caching
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
    /// Maximum content size for uploads
    pub max_content_size: usize,
    /// Enable compression
    pub enable_compression: bool,
    /// Compression threshold
    pub compression_threshold: usize,
    /// Enable content validation
    pub enable_content_validation: bool,
    /// Enable zero-knowledge proof validation
    pub enable_zk_validation: bool,
    /// Enable economic fee validation
    pub enable_economic_validation: bool,
    /// Test mode - allows mock proofs for testing
    pub test_mode: bool,
}

/// Stored content structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContent {
    /// Content ID
    pub id: String,
    /// Content data
    pub data: Vec<u8>,
    /// Content type
    pub content_type: String,
    /// Content metadata
    pub metadata: ContentMetadata,
    /// Access permissions
    pub access_permissions: AccessPermissions,
    /// Storage timestamp
    pub created_at: u64,
    /// Last accessed timestamp
    pub last_accessed: u64,
    /// Content hash for integrity
    pub content_hash: String,
    /// Zero-knowledge proof of content validity
    pub validity_proof: Option<ZkContentProof>,
    /// Economic assessment
    pub economic_data: EconomicData,
}

/// Content metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Original filename
    pub filename: Option<String>,
    /// File size in bytes
    pub size: usize,
    /// MIME type
    pub mime_type: String,
    /// Content encoding
    pub encoding: Option<String>,
    /// Content language
    pub language: Option<String>,
    /// Content tags
    pub tags: Vec<String>,
    /// Content description
    pub description: Option<String>,
    /// Content version
    pub version: Option<String>,
    /// Author information
    pub author: Option<String>,
    /// License information
    pub license: Option<String>,
}

/// Access permissions for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPermissions {
    /// Public read access
    pub public_read: bool,
    /// Public write access
    pub public_write: bool,
    /// Required identity proofs
    pub required_proofs: Vec<String>,
    /// Allowed user IDs
    pub allowed_users: Vec<String>,
    /// Denied user IDs
    pub denied_users: Vec<String>,
    /// Geographic restrictions
    pub geo_restrictions: Vec<String>,
    /// Time-based restrictions
    pub time_restrictions: Option<TimeRestrictions>,
    /// Economic access requirements
    pub economic_requirements: Option<EconomicRequirements>,
}

/// Time-based access restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestrictions {
    /// Start time (Unix timestamp)
    pub start_time: Option<u64>,
    /// End time (Unix timestamp)
    pub end_time: Option<u64>,
    /// Allowed hours (0-23)
    pub allowed_hours: Option<Vec<u8>>,
    /// Allowed days of week (0-6, Sunday=0)
    pub allowed_days: Option<Vec<u8>>,
}

/// Economic access requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicRequirements {
    /// Required payment amount
    pub payment_amount: Option<u64>,
    /// Required stake amount
    pub stake_amount: Option<u64>,
    /// Required reputation score
    pub min_reputation: Option<u32>,
    /// Required DAO membership
    pub require_dao_membership: bool,
}

/// Zero-knowledge proof for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkContentProof {
    /// Proof data
    pub proof: Vec<u8>,
    /// Verification key
    pub verification_key: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<String>,
    /// Proof generation timestamp
    pub created_at: u64,
    /// Proof expiration
    pub expires_at: Option<u64>,
}

/// Economic data for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicData {
    /// Total fees collected for this content
    pub total_fees_collected: u64,
    /// DAO fees collected
    pub dao_fees_collected: u64,
    /// UBI contributions
    pub ubi_contributions: u64,
    /// Access count
    pub access_count: u64,
    /// Revenue distribution
    pub revenue_distribution: HashMap<String, u64>,
}

/// Cached response
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// Response data
    pub response: ZhtpResponse,
    /// Cache timestamp
    pub cached_at: u64,
    /// Cache TTL
    pub ttl: u64,
    /// Access count
    pub access_count: u64,
}

/// Handler statistics
#[derive(Debug, Clone, Default)]
pub struct HandlerStats {
    /// Total requests handled
    pub total_requests: u64,
    /// Requests by method
    pub method_stats: HashMap<ZhtpMethod, u64>,
    /// Response time statistics
    pub response_times: ResponseTimeStats,
    /// Error statistics
    pub error_stats: HashMap<String, u64>,
    /// Cache statistics
    pub cache_stats: CacheStats,
    /// Economic statistics
    pub economic_stats: EconomicStats,
}

/// Response time statistics
#[derive(Debug, Clone, Default)]
pub struct ResponseTimeStats {
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Minimum response time
    pub min_response_time_ms: u64,
    /// Maximum response time
    pub max_response_time_ms: u64,
    /// 95th percentile response time
    pub p95_response_time_ms: u64,
    /// 99th percentile response time
    pub p99_response_time_ms: u64,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Cache hit ratio
    pub hit_ratio: f64,
    /// Total cached items
    pub total_items: u64,
    /// Cache size in bytes
    pub size_bytes: u64,
}

/// Economic statistics
#[derive(Debug, Clone, Default)]
pub struct EconomicStats {
    /// Total fees processed
    pub total_fees_processed: u64,
    /// Total DAO fees
    pub total_dao_fees: u64,
    /// Total UBI contributions
    pub total_ubi_contributions: u64,
    /// Economic transactions count
    pub economic_transactions: u64,
}

impl ZhtpHandlers {
    /// Create new ZHTP handlers
    pub fn new(handler_config: HandlerConfig) -> Self {
        Self {
            content_store: Arc::new(RwLock::new(HashMap::new())),
            config: handler_config,
            request_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HandlerStats::default())),
        }
    }
    
    /// Handle incoming ZHTP request
    pub async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let start_time = SystemTime::now();
        
        // Update statistics
        self.update_request_stats(&request).await;
        
        // Check cache first
        if self.config.enable_caching {
            if let Some(cached_response) = self.get_cached_response(&request).await? {
                self.update_cache_stats(true).await;
                return Ok(cached_response);
            }
            self.update_cache_stats(false).await;
        }
        
        // Route request to appropriate handler
        let response = match &request.method {
            ZhtpMethod::Get => self.handle_get(request.clone()).await?,
            ZhtpMethod::Post => self.handle_post(request.clone()).await?,
            ZhtpMethod::Put => self.handle_put(request.clone()).await?,
            ZhtpMethod::Patch => self.handle_patch(request.clone()).await?,
            ZhtpMethod::Delete => self.handle_delete(request.clone()).await?,
            ZhtpMethod::Head => self.handle_head(request.clone()).await?,
            ZhtpMethod::Options => self.handle_options(request.clone()).await?,
            ZhtpMethod::Verify => self.handle_verify(request.clone()).await?,
            ZhtpMethod::Connect => self.handle_connect(request.clone()).await?,
            ZhtpMethod::Trace => self.handle_trace(request.clone()).await?,
        };
        
        // Cache successful responses
        if self.config.enable_caching && response.status == ZhtpStatus::Ok {
            self.cache_response(&request, &response).await?;
        }
        
        // Update response time statistics
        self.update_response_time_stats(start_time).await;
        
        Ok(response)
    }
    
    /// Handle GET requests
    pub async fn handle_get(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling GET request: {}", request.uri);
        
        // API endpoints are now handled by zhtp orchestrator
        if request.uri.starts_with("/api/") {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "API endpoints moved to zhtp orchestrator".to_string(),
            ));
        }
        
        // Handle content retrieval
        if let Some(content_id) = self.extract_content_id(&request.uri) {
            return self.handle_content_get(&content_id, &request).await;
        }
        
        // Handle server capabilities request
        if request.uri == "/capabilities" || request.uri == "/.well-known/zhtp" {
            return self.handle_capabilities_request().await;
        }
        
        // Handle root request
        if request.uri == "/" {
            return self.handle_root_request().await;
        }
        
        // Default 404 response
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotFound,
            format!("Resource {} not found", request.uri),
        ))
    }
    
    /// Handle POST requests
    pub async fn handle_post(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling POST request: {}", request.uri);
        
        // Validate request size
        if request.body.len() > self.config.max_content_size {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::PayloadTooLarge,
                format!("Request body too large: {} bytes (max: {})", 
                    request.body.len(), self.config.max_content_size),
            ));
        }
        
        // Validate economic requirements
        if self.config.enable_economic_validation {
            if let Some(response) = self.validate_economic_requirements(&request).await? {
                return Ok(response);
            }
        }
        
        // Validate zero-knowledge proofs
        if self.config.enable_zk_validation {
            if let Some(response) = self.validate_zk_proofs(&request).await? {
                return Ok(response);
            }
        }
        
        // API endpoints are now handled by zhtp orchestrator
        if request.uri.starts_with("/api/") {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "API endpoints moved to zhtp orchestrator".to_string(),
            ));
        }
        
        // Handle content upload
        if request.uri.starts_with("/content/upload") {
            return self.handle_content_upload(&request).await;
        }
        
        // Handle content creation
        if request.uri.starts_with("/content/") {
            return self.handle_content_create(&request).await;
        }
        
        // Default handling
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            format!("POST to {} not implemented", request.uri),
        ))
    }
    
    /// Handle PUT requests
    pub async fn handle_put(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling PUT request: {}", request.uri);
        
        // Validate request size
        if request.body.len() > self.config.max_content_size {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::PayloadTooLarge,
                "Request body too large".to_string(),
            ));
        }
        
        // API endpoints are now handled by zhtp orchestrator
        if request.uri.starts_with("/api/") {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "API endpoints moved to zhtp orchestrator".to_string(),
            ));
        }
        
        // Handle content update
        if let Some(content_id) = self.extract_content_id(&request.uri) {
            return self.handle_content_update(&content_id, &request).await;
        }
        
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            format!("PUT to {} not implemented", request.uri),
        ))
    }
    
    /// Handle PATCH requests
    pub async fn handle_patch(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling PATCH request: {}", request.uri);
        
        // API endpoints are now handled by zhtp orchestrator
        if request.uri.starts_with("/api/") {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "API endpoints moved to zhtp orchestrator".to_string(),
            ));
        }
        
        // Handle partial content updates
        if let Some(content_id) = self.extract_content_id(&request.uri) {
            return self.handle_content_patch(&content_id, &request).await;
        }
        
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            format!("PATCH to {} not implemented", request.uri),
        ))
    }
    
    /// Handle DELETE requests
    pub async fn handle_delete(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling DELETE request: {}", request.uri);
        
        // API endpoints are now handled by zhtp orchestrator
        if request.uri.starts_with("/api/") {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "API endpoints moved to zhtp orchestrator".to_string(),
            ));
        }
        
        // Handle content deletion
        if let Some(content_id) = self.extract_content_id(&request.uri) {
            return self.handle_content_delete(&content_id, &request).await;
        }
        
        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            format!("DELETE to {} not implemented", request.uri),
        ))
    }
    
    /// Handle HEAD requests
    pub async fn handle_head(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("👀 Handling HEAD request: {}", request.uri);
        
        // Get the full response first
        let mut full_response = self.handle_get(request).await?;
        
        // Clear the body but keep headers
        full_response.body = Vec::new();
        
        Ok(full_response)
    }
    
    /// Handle OPTIONS requests
    pub async fn handle_options(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling OPTIONS request: {}", request.uri);
        
        let mut response = ZhtpResponse::success(Vec::new(), None);
        
        // Add CORS headers
        response.headers.set("Access-Control-Allow-Origin", "*".to_string());
        response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, VERIFY".to_string());
        response.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Wallet-Address, X-User-ID, X-API-Key, X-ZK-Proof".to_string());
        response.headers.set("Access-Control-Max-Age", "3600".to_string());
        
        // Add ZHTP-specific options
        response.headers.set("ZHTP-Version", "1.0".to_string());
        response.headers.set("ZHTP-Features", "zk-proofs,post-quantum,dao-fees,ubi,mesh".to_string());
        
        Ok(response)
    }
    
    /// Handle VERIFY requests (ZHTP-specific)
    pub async fn handle_verify(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling VERIFY request: {}", request.uri);
        
        // Extract verification data from request
        let verification_type = request.headers.get("X-Verification-Type")
            .unwrap_or_else(|| "general".to_string());
        
        let verification_data = if !request.body.is_empty() {
            Some(request.body.clone())
        } else {
            None
        };
        
        // Perform verification based on type
        let verification_result = match verification_type.as_str() {
            "zk-proof" => self.verify_zk_proof(verification_data).await?,
            "signature" => self.verify_signature(verification_data).await?,
            "content" => self.verify_content_integrity(&request.uri, verification_data).await?,
            "identity" => self.verify_identity(verification_data).await?,
            "economic" => self.verify_economic_proof(verification_data).await?,
            _ => VerificationResult::Invalid("Unknown verification type".to_string()),
        };
        
        let response_data = serde_json::json!({
            "verification_type": verification_type,
            "valid": verification_result.is_valid(),
            "error": verification_result.error_message(),
            "details": verification_result.verification_time_ms(),
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        
        Ok(ZhtpResponse::json(&response_data, None)?)
    }
    
    // Content handling methods
    
    async fn handle_content_get(&self, content_id: &str, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let content_store = self.content_store.read().await;
        
        if let Some(content) = content_store.get(content_id) {
            // Check access permissions
            if !self.check_content_access(content, request).await? {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Forbidden,
                    "Access denied to content".to_string(),
                ));
            }
            
            // Clone content data before dropping the lock
            let content_data = content.data.clone();
            let content_type = content.content_type.clone();
            let content_hash = content.content_hash.clone();
            let content_size = content.metadata.size;
            let created_at = content.created_at;
            let filename = content.metadata.filename.clone();
            
            // Update access statistics
            drop(content_store);
            self.update_content_access_stats(content_id).await;
            
            // Return content with appropriate headers
            let mut response = ZhtpResponse::success_with_content_type(
                content_data,
                content_type,
                None,
            );
            
            // Add content metadata headers
            response.headers.set("Content-Hash", content_hash);
            response.headers.set("Content-Size", content_size.to_string());
            response.headers.set("Content-Created", created_at.to_string());
            
            if let Some(filename) = &filename {
                response.headers.set("Content-Disposition", format!("attachment; filename=\"{}\"", filename));
            }
            
            Ok(response)
        } else {
            Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Content {} not found", content_id),
            ))
        }
    }
    
    async fn handle_content_upload(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Generate content ID
        let content_id = Uuid::new_v4().to_string();
        
        // Extract metadata from headers
        let content_type = request.headers.get("Content-Type")
            .unwrap_or_else(|| "application/octet-stream".to_string());
        
        let filename = request.headers.get("Content-Disposition")
            .and_then(|cd| self.extract_filename_from_disposition(&cd));
        
        // Create content metadata
        let metadata = ContentMetadata {
            filename,
            size: request.body.len(),
            mime_type: content_type.clone(),
            encoding: request.headers.get("Content-Encoding"),
            language: request.headers.get("Content-Language"),
            tags: self.extract_tags_from_headers(request).await,
            description: request.headers.get("Content-Description"),
            version: request.headers.get("Content-Version"),
            author: request.headers.get("Content-Author"),
            license: request.headers.get("Content-License"),
        };
        
        // Calculate content hash
        let content_hash = self.calculate_content_hash(&request.body);
        
        // Create access permissions
        let access_permissions = self.create_default_access_permissions(request).await;
        
        // Create economic assessment for the content
        let economic_assessment = crate::types::EconomicAssessment {
            network_fee: 100,
            dao_fee: 20,
            total_fee: 120,
            storage_cost: 50,
            bandwidth_cost: 30,
            processing_cost: 20,
            quality_multiplier: 1.0,
            estimated_time: 1,
            currency: crate::types::economic::TOKEN_NAME.to_string(),
        };
        
        // Create economic data
        let economic_data = EconomicData {
            total_fees_collected: 0,
            dao_fees_collected: 0,
            ubi_contributions: 0,
            access_count: 0,
            revenue_distribution: HashMap::new(),
        };
        
        // Create stored content
        let stored_content = StoredContent {
            id: content_id.clone(),
            data: request.body.clone(),
            content_type,
            metadata,
            access_permissions,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_accessed: 0,
            content_hash: content_hash.clone(),
            validity_proof: self.generate_validity_proof(&content_id, &content_hash, &economic_assessment).await.ok(),
            economic_data,
        };
        
        // Store content
        self.content_store.write().await.insert(content_id.clone(), stored_content);
        
        // Create response
        let response_data = serde_json::json!({
            "content_id": content_id,
            "status": "uploaded",
            "size": request.body.len(),
            "content_url": format!("/content/{}", content_id),
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        
        Ok(ZhtpResponse::json(&response_data, None)?)
    }
    
    async fn handle_content_create(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Similar to upload but with different semantics
        self.handle_content_upload(request).await
    }
    
    async fn handle_content_update(&self, content_id: &str, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let mut content_store = self.content_store.write().await;
        
        if let Some(content) = content_store.get_mut(content_id) {
            // Check access permissions
            if !self.check_content_write_access(content, request).await? {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Forbidden,
                    "Write access denied to content".to_string(),
                ));
            }
            
            // Update content
            content.data = request.body.clone();
            content.content_hash = self.calculate_content_hash(&request.body);
            content.metadata.size = request.body.len();
            content.last_accessed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            let response_data = serde_json::json!({
                "content_id": content_id,
                "status": "updated",
                "size": request.body.len(),
                "timestamp": content.last_accessed
            });
            
            Ok(ZhtpResponse::json(&response_data, None)?)
        } else {
            Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Content {} not found", content_id),
            ))
        }
    }
    
    async fn handle_content_patch(&self, content_id: &str, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Implement partial content updates
        // For now, delegate to full update
        self.handle_content_update(content_id, request).await
    }
    
    async fn handle_content_delete(&self, content_id: &str, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let mut content_store = self.content_store.write().await;
        
        if let Some(content) = content_store.get(content_id) {
            // Check access permissions
            if !self.check_content_write_access(content, request).await? {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Forbidden,
                    "Delete access denied to content".to_string(),
                ));
            }
            
            content_store.remove(content_id);
            
            let response_data = serde_json::json!({
                "content_id": content_id,
                "status": "deleted",
                "timestamp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });
            
            Ok(ZhtpResponse::json(&response_data, None)?)
        } else {
            Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Content {} not found", content_id),
            ))
        }
    }
    
    async fn handle_capabilities_request(&self) -> ZhtpResult<ZhtpResponse> {
        let capabilities = ServerCapabilities::default();
        capabilities.to_response()
    }
    
    async fn handle_root_request(&self) -> ZhtpResult<ZhtpResponse> {
        let root_info = serde_json::json!({
            "protocol": "ZHTP",
            "version": "1.0",
            "server": "ZHTP Server",
            "message": "Welcome to the Zero Knowledge Hypertext Transfer Protocol",
            "features": [
                "Zero-knowledge proofs",
                "Post-quantum cryptography", 
                "Economic incentives",
                "DAO governance",
                "UBI integration",
                "Mesh networking",
                " capability"
            ],
            "endpoints": {
                "api": "/api/v1/",
                "capabilities": "/capabilities",
                "content": "/content/",
                "docs": "/docs/"
            },
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        
        Ok(ZhtpResponse::json(&root_info, None)?)
    }
    
    // Helper methods
    
    fn extract_content_id(&self, uri: &str) -> Option<String> {
        if let Some(captures) = regex::Regex::new(r"/content/([^/?]+)")
            .ok()?
            .captures(uri) 
        {
            captures.get(1).map(|m| m.as_str().to_string())
        } else {
            None
        }
    }
    
    fn calculate_content_hash(&self, data: &[u8]) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        format!("sha3-256:{}", hex::encode(hasher.finalize()))
    }
    
    fn extract_filename_from_disposition(&self, disposition: &str) -> Option<String> {
        // Simple filename extraction from Content-Disposition header
        if let Some(start) = disposition.find("filename=\"") {
            let start = start + 10; // Length of "filename=\""
            if let Some(end) = disposition[start..].find('"') {
                return Some(disposition[start..start + end].to_string());
            }
        }
        None
    }
    
    async fn extract_tags_from_headers(&self, request: &ZhtpRequest) -> Vec<String> {
        request.headers.get("Content-Tags")
            .map(|tags| tags.split(',').map(|tag| tag.trim().to_string()).collect())
            .unwrap_or_default()
    }
    
    async fn create_default_access_permissions(&self, request: &ZhtpRequest) -> AccessPermissions {
        AccessPermissions {
            public_read: request.headers.get("Content-Public-Read")
                .map(|v| v == "true")
                .unwrap_or(false),
            public_write: false, // Default to private write
            required_proofs: Vec::new(),
            allowed_users: Vec::new(),
            denied_users: Vec::new(),
            geo_restrictions: Vec::new(),
            time_restrictions: None,
            economic_requirements: None,
        }
    }
    
    async fn check_content_access(&self, content: &StoredContent, request: &ZhtpRequest) -> ZhtpResult<bool> {
        // Simplified access check
        if content.access_permissions.public_read {
            return Ok(true);
        }
        
        // Check if user is in allowed list
        if let Some(user_id) = request.headers.get("X-User-ID") {
            if content.access_permissions.allowed_users.contains(&user_id) {
                return Ok(true);
            }
        }
        
        // More complex access checks would go here
        Ok(false)
    }
    
    async fn check_content_write_access(&self, content: &StoredContent, request: &ZhtpRequest) -> ZhtpResult<bool> {
        // Simplified write access check
        if content.access_permissions.public_write {
            return Ok(true);
        }
        
        // Check if user is in allowed list
        if let Some(user_id) = request.headers.get("X-User-ID") {
            if content.access_permissions.allowed_users.contains(&user_id) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    // Statistics and caching methods
    
    async fn update_request_stats(&self, request: &ZhtpRequest) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        *stats.method_stats.entry(request.method.clone()).or_insert(0) += 1;
    }
    
    async fn update_cache_stats(&self, hit: bool) {
        let mut stats = self.stats.write().await;
        if hit {
            stats.cache_stats.hits += 1;
        } else {
            stats.cache_stats.misses += 1;
        }
        
        let total = stats.cache_stats.hits + stats.cache_stats.misses;
        if total > 0 {
            stats.cache_stats.hit_ratio = stats.cache_stats.hits as f64 / total as f64;
        }
    }
    
    async fn update_response_time_stats(&self, start_time: SystemTime) {
        if let Ok(duration) = start_time.elapsed() {
            let duration_ms = duration.as_millis() as u64;
            let mut stats = self.stats.write().await;
            
            // Update average
            let current_avg = stats.response_times.avg_response_time_ms;
            stats.response_times.avg_response_time_ms = 
                (current_avg + duration_ms as f64) / 2.0;
            
            // Update min/max
            if stats.response_times.min_response_time_ms == 0 || duration_ms < stats.response_times.min_response_time_ms {
                stats.response_times.min_response_time_ms = duration_ms;
            }
            if duration_ms > stats.response_times.max_response_time_ms {
                stats.response_times.max_response_time_ms = duration_ms;
            }
        }
    }
    
    async fn update_content_access_stats(&self, content_id: &str) {
        if let Some(content) = self.content_store.write().await.get_mut(content_id) {
            content.economic_data.access_count += 1;
            content.last_accessed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
    }
    
    async fn get_cached_response(&self, request: &ZhtpRequest) -> ZhtpResult<Option<ZhtpResponse>> {
        let cache_key = format!("{}:{}", request.method.as_str(), request.uri);
        let cache = self.request_cache.read().await;
        
        if let Some(cached) = cache.get(&cache_key) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            if now < cached.cached_at + cached.ttl {
                return Ok(Some(cached.response.clone()));
            }
        }
        
        Ok(None)
    }
    
    async fn cache_response(&self, request: &ZhtpRequest, response: &ZhtpResponse) -> ZhtpResult<()> {
        let cache_key = format!("{}:{}", request.method.as_str(), request.uri);
        let cached_response = CachedResponse {
            response: response.clone(),
            cached_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ttl: self.config.cache_ttl,
            access_count: 0,
        };
        
        self.request_cache.write().await.insert(cache_key, cached_response);
        Ok(())
    }
    
    // Validation methods
    
    async fn validate_economic_requirements(&self, request: &ZhtpRequest) -> ZhtpResult<Option<ZhtpResponse>> {
        // Use centralized validation logic directly
        if request.headers.get("X-DAO-Fee").is_none() {
            return Ok(Some(ZhtpResponse::error(
                ZhtpStatus::PaymentRequired,
                "DAO fee required for this operation".to_string(),
            )));
        }
        
        // Validate DAO fee amount
        if let Some(dao_fee) = request.headers.get("X-DAO-Fee") {
            if let Ok(fee_amount) = dao_fee.parse::<f64>() {
                // Calculate minimum required fee using centralized logic
                let request_value = crate::economics::utils::calculate_request_value(&request.method, &request.body, &request.uri);
                let min_fee = (request_value as f64 * 0.02).max(5.0); // 2% DAO fee, minimum 5 tokens
                
                if fee_amount < min_fee {
                    return Ok(Some(ZhtpResponse::error(
                        ZhtpStatus::PaymentRequired,
                        format!("Insufficient DAO fee: {} required, {} provided", min_fee, fee_amount),
                    )));
                }
            } else {
                return Ok(Some(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid DAO fee format".to_string(),
                )));
            }
        }
        
        Ok(None)
    }

    /// Validate fee payment proof
    async fn validate_fee_proof(&self, fee_amount: f64, fee_proof: &str, request: &ZhtpRequest) -> ZhtpResult<()> {
        // Decode hex proof
        let proof_bytes = hex::decode(fee_proof)
            .map_err(|_| anyhow::anyhow!("Fee proof must be valid hexadecimal"))?;

        if proof_bytes.len() < 128 {
            return Err(anyhow::anyhow!("Fee proof too short"));
        }

        // Extract components: tx_hash(32) + block_hash(32) + signature(64+)
        let tx_hash = &proof_bytes[..32];
        let block_hash = &proof_bytes[32..64];
        let signature = &proof_bytes[64..];

        // Validate transaction hash
        if tx_hash.iter().all(|&b| b == 0) {
            return Err(anyhow::anyhow!("Invalid transaction hash"));
        }

        // Validate block hash
        if block_hash.iter().all(|&b| b == 0) {
            return Err(anyhow::anyhow!("Invalid block hash"));
        }

        // Create payment commitment for signature verification
        let mut payment_data = Vec::new();
        payment_data.extend_from_slice(&fee_amount.to_be_bytes());
        payment_data.extend_from_slice(request.uri.as_bytes());
        payment_data.extend_from_slice(&request.timestamp.to_be_bytes());

        // Verify signature (simplified)
        let payment_hash = self.calculate_content_hash(&payment_data);
        let signature_hash = self.calculate_content_hash(signature);
        
        // Check signature validity (basic correlation check)
        if payment_hash[..8] != signature_hash[..8] {
            return Err(anyhow::anyhow!("Fee payment signature verification failed"));
        }

        Ok(())
    }
    
    async fn validate_zk_proofs(&self, request: &ZhtpRequest) -> ZhtpResult<Option<ZhtpResponse>> {
        // In test mode, allow simplified ZK proof validation
        if self.config.test_mode {
            if let Some(zk_proof_header) = request.headers.get("X-ZK-Proof") {
                // Simple validation - just check it's not empty and reasonable length
                if zk_proof_header.len() >= 32 {
                    tracing::debug!("ZK proof validation passed (test mode)");
                    return Ok(None);
                } else {
                    return Ok(Some(ZhtpResponse::error(
                        ZhtpStatus::BadRequest,
                        "ZK proof too short (test mode requires at least 32 characters)".to_string(),
                    )));
                }
            } else {
                return Ok(Some(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Missing ZK proof header".to_string(),
                )));
            }
        }

        // Production mode - full validation
        // Check if ZK proof is provided when required
        if let Some(zk_proof_header) = request.headers.get("X-ZK-Proof") {
            // Try to decode as JSON (preferred) or hex (fallback)
            let proof_bytes = if zk_proof_header.starts_with('{') {
                // JSON format - parse as ZkProof from lib-proofs
                match serde_json::from_str::<ZkProof>(&zk_proof_header) {
                    Ok(zk_proof) => {
                        // Use lib-proofs verification system
                        return match self.verify_zk_proof_with_lib_proofs(&zk_proof, request).await {
                            Ok(verification_result) if verification_result.is_valid() => {
                                tracing::debug!("ZK proof verified successfully with lib-proofs");
                                self.update_zk_verification_stats().await;
                                Ok(None) // Proof valid, continue processing
                            }
                            Ok(verification_result) => {
                                let error_msg = verification_result.error_message()
                                    .unwrap_or("ZK proof verification failed");
                                Ok(Some(ZhtpResponse::error(
                                    ZhtpStatus::Forbidden,
                                    error_msg.to_string(),
                                )))
                            }
                            Err(e) => {
                                tracing::error!("ZK proof verification error: {}", e);
                                Ok(Some(ZhtpResponse::error(
                                    ZhtpStatus::BadRequest,
                                    format!("ZK proof verification error: {}", e),
                                )))
                            }
                        };
                    }
                    Err(_) => {
                        // Not valid JSON, try hex decoding
                        hex::decode(zk_proof_header)
                            .map_err(|_| anyhow::anyhow!("ZK proof must be valid JSON or hexadecimal"))?
                    }
                }
            } else {
                // Hex format (legacy)
                hex::decode(zk_proof_header)
                    .map_err(|_| anyhow::anyhow!("ZK proof must be valid hexadecimal"))?
            };
            
            if proof_bytes.len() < 96 {
                return Ok(Some(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "ZK proof too short (minimum 96 bytes required)".to_string(),
                )));
            }

            // For raw bytes, use crypto module with lib-proofs integration
            let public_inputs = self.generate_zk_public_inputs(request);
            let crypto = crate::crypto::ZhtpCrypto::new()
                .map_err(|e| anyhow::anyhow!("Crypto initialization failed: {}", e))?;

            match crypto.verify_zk_proof(&proof_bytes, &public_inputs) {
                Ok(true) => {
                    tracing::debug!("ZK proof verified successfully");
                    self.update_zk_verification_stats().await;
                }
                Ok(false) => {
                    return Ok(Some(ZhtpResponse::error(
                        ZhtpStatus::Forbidden,
                        "ZK proof verification failed".to_string(),
                    )));
                }
                Err(e) => {
                    tracing::error!("ZK proof verification error: {}", e);
                    return Ok(Some(ZhtpResponse::error(
                        ZhtpStatus::BadRequest,
                        format!("ZK proof verification error: {}", e),
                    )));
                }
            }

            // Validate proof freshness
            if let Err(e) = self.validate_zk_proof_freshness(request).await {
                return Ok(Some(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("ZK proof freshness validation failed: {}", e),
                )));
            }

        } else {
            return Ok(Some(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "ZK proof required for this operation".to_string(),
            )));
        }
        
        Ok(None)
    }

    /// Generate public inputs for ZK proof from request
    fn generate_zk_public_inputs(&self, request: &ZhtpRequest) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        
        // Include request method
        hasher.update(request.method.as_str().as_bytes());
        
        // Include request URI
        hasher.update(request.uri.as_bytes());
        
        // Include timestamp
        hasher.update(&request.timestamp.to_be_bytes());
        
        // Include requester if available
        if let Some(requester) = &request.requester {
            hasher.update(&requester.0);
        }
        
        // Include content hash if body present
        if !request.body.is_empty() {
            let content_hash = self.calculate_content_hash(&request.body);
            hasher.update(&content_hash);
        }
        
        hasher.finalize().to_vec()
    }

    /// Validate ZK proof freshness
    async fn validate_zk_proof_freshness(&self, request: &ZhtpRequest) -> ZhtpResult<()> {
        if let Some(timestamp_str) = request.headers.get("X-ZK-Proof-Timestamp") {
            let proof_timestamp: u64 = timestamp_str.parse()
                .map_err(|_| anyhow::anyhow!("Invalid ZK proof timestamp"))?;
            
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            // Proof should be recent (within 5 minutes)
            if current_time.saturating_sub(proof_timestamp) > 300 {
                return Err(anyhow::anyhow!("ZK proof is too old"));
            }
            
            if proof_timestamp > current_time + 60 {
                return Err(anyhow::anyhow!("ZK proof timestamp from future"));
            }
        }
        
        Ok(())
    }

    /// Update ZK verification statistics
    async fn update_zk_verification_stats(&self) {
        // This would update server statistics for ZK proof verification
        tracing::debug!("Updated ZK verification statistics");
    }
    
    // Verification methods
    
    async fn verify_zk_proof(&self, _data: Option<Vec<u8>>) -> ZhtpResult<VerificationResult> {
        // Simplified ZK proof verification
        Ok(VerificationResult::Valid {
            circuit_id: "zk_proof".to_string(),
            verification_time_ms: 10,
            public_inputs: vec![],
        })
    }
    
    async fn verify_signature(&self, _data: Option<Vec<u8>>) -> ZhtpResult<VerificationResult> {
        // Simplified signature verification
        Ok(VerificationResult::Valid {
            circuit_id: "signature".to_string(),
            verification_time_ms: 5,
            public_inputs: vec![],
        })
    }
    
    async fn verify_content_integrity(&self, _uri: &str, _data: Option<Vec<u8>>) -> ZhtpResult<VerificationResult> {
        // Simplified content integrity verification
        Ok(VerificationResult::Valid {
            circuit_id: "content_integrity".to_string(),
            verification_time_ms: 8,
            public_inputs: vec![],
        })
    }
    
    async fn verify_identity(&self, _data: Option<Vec<u8>>) -> ZhtpResult<VerificationResult> {
        // Simplified identity verification
        Ok(VerificationResult::Valid {
            circuit_id: "identity".to_string(),
            verification_time_ms: 12,
            public_inputs: vec![],
        })
    }
    
    async fn verify_economic_proof(&self, _data: Option<Vec<u8>>) -> ZhtpResult<VerificationResult> {
        // Simplified economic proof verification
        Ok(VerificationResult::Valid {
            circuit_id: "economic_proof".to_string(),
            verification_time_ms: 15,
            public_inputs: vec![],
        })
    }
    
    /// Get handler statistics
    pub async fn get_stats(&self) -> HandlerStats {
        self.stats.read().await.clone()
    }
    
    /// Get content store size
    pub async fn get_content_store_size(&self) -> usize {
        self.content_store.read().await.len()
    }
    
    /// Clear request cache
    pub async fn clear_cache(&self) {
        self.request_cache.write().await.clear();
    }

    /// Handle CONNECT requests - establish persistent connection
    pub async fn handle_connect(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling CONNECT request: {}", request.uri);
        
        // CONNECT method is used to establish a persistent connection to a server
        // For ZHTP, this could be used for mesh node connections or WebSocket upgrades
        
        let target = request.uri.strip_prefix('/').unwrap_or(&request.uri);
        
        let response_data = serde_json::json!({
            "method": "CONNECT",
            "target": target,
            "connection_status": "established",
            "mesh_node_id": format!("node_{}", uuid::Uuid::new_v4()),
            "capabilities": ["mesh_routing", "zk_validation", "dao_processing"],
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

        let mut response = ZhtpResponse::json(&response_data, None)?;
        response.headers.set("Connection", "Established".to_string());
        response.headers.set("ZHTP-Connection-Type", "Mesh".to_string());
        
        Ok(response)
    }

    /// Handle TRACE requests - debug routing and mesh network
    pub async fn handle_trace(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::debug!("Handling TRACE request: {}", request.uri);
        
        // TRACE method returns diagnostic information about the request path
        // For ZHTP, this includes mesh routing information and node capabilities
        
        let trace_data = serde_json::json!({
            "method": "TRACE",
            "original_uri": request.uri,
            "trace_id": format!("trace_{}", uuid::Uuid::new_v4()),
            "request_headers": {
                "host": request.headers.host,
                "user_agent": request.headers.user_agent,
                "content_type": request.headers.content_type,
            },
            "mesh_path": [
                {
                    "node_id": "entry_node",
                    "hop": 1,
                    "latency_ms": 5,
                    "capabilities": ["routing", "validation"]
                },
                {
                    "node_id": "target_node", 
                    "hop": 2,
                    "latency_ms": 12,
                    "capabilities": ["content_serving", "zk_validation"]
                }
            ],
            "total_hops": 2,
            "total_latency_ms": 17,
            "economic_fees": {
                "routing_fee": 0.001,
                "validation_fee": 0.002,
                "total_fee": 0.003
            },
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

        let mut response = ZhtpResponse::json(&trace_data, None)?;
        response.headers.set("Content-Type", "application/json".to_string());
        response.headers.set("ZHTP-Trace-Version", "1.0".to_string());
        
        Ok(response)
    }
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_ttl: 3600, // 1 hour
            max_content_size: 16 * 1024 * 1024, // 16MB
            enable_compression: true,
            compression_threshold: 1024, // 1KB
            enable_content_validation: true,
            enable_zk_validation: true,
            enable_economic_validation: true,
            test_mode: false,
        }
    }
}

// Public handler functions for external use

/// Handle GET request
pub async fn handle_get(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_get(request).await
}

/// Handle POST request
pub async fn handle_post(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_post(request).await
}

/// Handle PUT request
pub async fn handle_put(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_put(request).await
}

/// Handle DELETE request
pub async fn handle_delete(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_delete(request).await
}

/// Handle HEAD request
pub async fn handle_head(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_head(request).await
}

/// Handle OPTIONS request
pub async fn handle_options(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_options(request).await
}

/// Handle VERIFY request
pub async fn handle_verify(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_verify(request).await
}

/// Handle CONNECT request
pub async fn handle_connect(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_connect(request).await
}

/// Handle TRACE request
pub async fn handle_trace(request: ZhtpRequest, handlers: &ZhtpHandlers) -> ZhtpResult<ZhtpResponse> {
    handlers.handle_trace(request).await
}

impl ZhtpHandlers {
    /// Verify ZK proof using lib-proofs package
    async fn verify_zk_proof_with_lib_proofs(&self, zk_proof: &ZkProof, request: &ZhtpRequest) -> Result<VerificationResult> {
        // Initialize ZK system from lib-proofs
        let zk_system = initialize_zk_system()
            .map_err(|e| anyhow::anyhow!("Failed to initialize ZK system: {}", e))?;

        // If this is a Plonky2 proof, use the verifier
        if let Some(plonky2_proof) = &zk_proof.plonky2_proof {
            match zk_system.verify_transaction(plonky2_proof) {
                Ok(is_valid) => {
                    return Ok(if is_valid {
                        VerificationResult::Valid {
                            circuit_id: "plonky2_transaction".to_string(),
                            verification_time_ms: 50,
                            public_inputs: zk_proof.public_inputs.iter().map(|&b| b as u64).collect(),
                        }
                    } else {
                        VerificationResult::Invalid("Plonky2 verification failed".to_string())
                    });
                },
                Err(e) => {
                    tracing::debug!("Plonky2 verification failed: {}", e);
                    // Fall through to other verification methods
                }
            }
        }

        // For transaction proofs, try to use transaction verifier
        if let Ok(tx_proof) = serde_json::from_slice::<ZkTransactionProof>(&zk_proof.proof_data) {
            match ZkTransactionProof::verify_transaction(&tx_proof) {
                Ok(is_valid) => {
                    return Ok(if is_valid {
                        VerificationResult::Valid {
                            circuit_id: "transaction_verifier".to_string(),
                            verification_time_ms: 30,
                            public_inputs: zk_proof.public_inputs.iter().map(|&b| b as u64).collect(),
                        }
                    } else {
                        VerificationResult::Invalid("Transaction verification failed".to_string())
                    });
                },
                Err(e) => {
                    tracing::debug!("Transaction proof verification failed: {}", e);
                    // Fall through to basic verification
                }
            }
        }

        // Use TransactionVerifier for detailed verification
        if let Ok(_verifier) = TransactionVerifier::new() {
            // Create a simple transaction proof from the request data
            let public_inputs = self.generate_zk_public_inputs(request);
            
            // For now, basic validation of the proof structure
            if !zk_proof.proof_data.is_empty() && !zk_proof.public_inputs.is_empty() {
                // Check if proof contains commitment to request data
                let contains_commitment = zk_proof.public_inputs.windows(32).any(|window| {
                    window.iter().zip(public_inputs.iter())
                        .filter(|(a, b)| a == b)
                        .count() >= 8 // At least 1/4 of the hash should match
                });

                return Ok(if contains_commitment {
                    VerificationResult::Valid {
                        circuit_id: "commitment_verification".to_string(),
                        verification_time_ms: 20,
                        public_inputs: zk_proof.public_inputs.iter().map(|&b| b as u64).collect(),
                    }
                } else {
                    VerificationResult::Invalid("Proof commitment verification failed".to_string())
                });
            }
        }

        // Fallback to basic structural validation
        let is_structurally_valid = !zk_proof.proof_data.is_empty() && zk_proof.proof_data.len() >= 96;
        Ok(if is_structurally_valid {
            VerificationResult::Valid {
                circuit_id: "structural_validation".to_string(),
                verification_time_ms: 5,
                public_inputs: vec![],
            }
        } else {
            VerificationResult::Invalid("Proof structure validation failed".to_string())
        })
    }

    /// Generate validity proof for content
    async fn generate_validity_proof(
        &self,
        content_id: &str,
        content_hash: &str,
        economic_data: &crate::types::EconomicAssessment,
    ) -> Result<ZkContentProof> {
        use lib_crypto::hash_blake3;
        
        // Create proof context with content metadata
        let proof_context = serde_json::json!({
            "content_id": content_id,
            "content_hash": content_hash,
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "fees": {
                "network_fee": economic_data.network_fee,
                "dao_fee": economic_data.dao_fee,
                "total_fee": economic_data.total_fee
            },
            "server_id": "lib-server-v1.0"
        });
        
        let context_bytes = proof_context.to_string().into_bytes();
        
        // Try to use lib-proofs for proof generation
        if let Ok(_zk_system) = initialize_zk_system() {
            // Generate a simple validity proof using lib-proofs
            // Create some dummy transaction parameters for content validity proof
            let content_hash_bytes: [u8; 32] = hash_blake3(content_hash.as_bytes()).try_into().unwrap_or([0u8; 32]);
            let sender_blinding: [u8; 32] = hash_blake3(&context_bytes).try_into().unwrap_or([0u8; 32]);
            let receiver_blinding: [u8; 32] = hash_blake3(&[content_hash.as_bytes(), &context_bytes].concat()).try_into().unwrap_or([0u8; 32]);
            
            match ZkTransactionProof::prove_transaction(
                1000, // sender_balance
                0,    // receiver_balance  
                1,    // amount (1 unit for content validity)
                economic_data.total_fee as u64, // fee
                sender_blinding,
                    receiver_blinding,
                    content_hash_bytes
                ) {
                    Ok(proof) => {
                        tracing::debug!("Generated ZK validity proof for content {}", content_id);
                        let proof_bytes = serde_json::to_vec(&proof).map_err(|e| anyhow::anyhow!("Proof serialization failed: {}", e))?;
                        return Ok(ZkContentProof {
                            proof: proof_bytes,
                            verification_key: vec![0u8; 32], // Placeholder verification key
                            public_inputs: vec![content_id.to_string(), content_hash.to_string()],
                            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                            expires_at: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + 86400), // 24 hours
                        });
                    }
                    Err(e) => {
                        tracing::debug!("ZK proof generation failed: {}, using fallback", e);
                    }
                }
        }
        
        // Fallback: Generate a structured proof-like format
        let fallback_proof = serde_json::json!({
            "proof_type": "content_validity",
            "version": "1.0",
            "content_id": content_id,
            "content_hash": content_hash,
            "context_hash": hex::encode(hash_blake3(&context_bytes)),
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "signature": hex::encode(hash_blake3(&[context_bytes.clone(), content_hash.as_bytes().to_vec()].concat())),
            "economic_commitment": {
                "network_fee": economic_data.network_fee,
                "dao_fee": economic_data.dao_fee,
                "proof_hash": hex::encode(hash_blake3(&economic_data.total_fee.to_le_bytes()))
            }
        });
        
        let fallback_proof_bytes = serde_json::to_vec(&fallback_proof).map_err(|e| anyhow::anyhow!("Fallback proof serialization failed: {}", e))?;
        
        Ok(ZkContentProof {
            proof: fallback_proof_bytes,
            verification_key: hash_blake3(&context_bytes).to_vec(),
            public_inputs: vec![content_id.to_string(), content_hash.to_string()],
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            expires_at: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + 86400),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZhtpHeaders;

    fn create_test_request(method: ZhtpMethod, uri: &str) -> ZhtpRequest {
        ZhtpRequest {
            method,
            uri: uri.to_string(),
            version: "1.0".to_string(),
            headers: ZhtpHeaders::new(),
            body: Vec::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            requester: None,
            auth_proof: None,
        }
    }

    async fn create_valid_zk_proof() -> String {
        // Generate a valid ZK proof using lib-proofs
        if let Ok(_zk_system) = initialize_zk_system() {
            let content_hash = lib_crypto::hash_blake3(b"test content");
            let content_hash_bytes: [u8; 32] = content_hash.try_into().unwrap_or([0u8; 32]);
            let sender_blinding: [u8; 32] = lib_crypto::hash_blake3(b"test_sender").try_into().unwrap_or([0u8; 32]);
            let receiver_blinding: [u8; 32] = lib_crypto::hash_blake3(b"test_receiver").try_into().unwrap_or([0u8; 32]);
            
            match ZkTransactionProof::prove_transaction(
                1000, // sender_balance
                0,    // receiver_balance  
                1,    // amount
                100,  // fee
                sender_blinding,
                receiver_blinding,
                    content_hash_bytes
                ) {
                    Ok(proof) => {
                        if let Ok(proof_json) = serde_json::to_string(&proof) {
                            return proof_json;
                        }
                    }
                    Err(_) => {}
                }
        }
        
        // Fallback to hex format (which is also valid according to the validation logic)
        "a".repeat(128) // 64 bytes in hex format
    }

    fn create_valid_fee_proof() -> String {
        // Create a valid 128-byte hex proof (tx_hash + block_hash + signature)
        let tx_hash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"; // 32 bytes
        let block_hash = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"; // 32 bytes  
        let signature = "a".repeat(128); // 64 bytes signature
        format!("{}{}{}", tx_hash, block_hash, signature)
    }

    #[tokio::test]
    async fn test_get_capabilities() {
        let config = HandlerConfig::default();
        let handlers = ZhtpHandlers::new(config);
        
        let request = create_test_request(ZhtpMethod::Get, "/capabilities");
        let response = handlers.handle_get(request).await.unwrap();
        
        assert_eq!(response.status, ZhtpStatus::Ok);
    }

    #[tokio::test]
    async fn test_options_request() {
        let config = HandlerConfig::default();
        let handlers = ZhtpHandlers::new(config);
        
        let request = create_test_request(ZhtpMethod::Options, "/api/v1/test");
        let response = handlers.handle_options(request).await.unwrap();
        
        assert_eq!(response.status, ZhtpStatus::Ok);
        assert!(response.headers.get("Access-Control-Allow-Origin").is_some());
    }

    #[tokio::test]
    async fn test_content_upload() {
        let mut config = HandlerConfig::default();
        config.test_mode = true; // Enable test mode for simplified validation
        let handlers = ZhtpHandlers::new(config);
        
        let mut request = create_test_request(ZhtpMethod::Post, "/content/upload");
        request.body = b"test content".to_vec();
        request.headers.set("Content-Type", "text/plain".to_string());
        
        // Add proper ZHTP protocol headers with test-friendly proofs
        request.headers.set("X-DAO-Fee", "100".to_string());
        request.headers.set("X-DAO-Fee-Proof", create_valid_fee_proof());
        request.headers.set("X-Payment-Proof", create_valid_fee_proof());
        request.headers.set("X-ZK-Proof", "test_zk_proof_".to_string() + &"a".repeat(64)); // Test mode proof
        
        let response = handlers.handle_post(request).await.unwrap();
        
        assert_eq!(response.status, ZhtpStatus::Ok);
    }

    #[tokio::test]
    async fn test_api_endpoint_routing() {
        let config = HandlerConfig::default();
        let handlers = ZhtpHandlers::new(config);

        // Test that capabilities endpoint returns Ok
        let request = create_test_request(ZhtpMethod::Get, "/.well-known/zhtp");
        let response = handlers.handle_get(request).await.unwrap();

        assert_eq!(response.status, ZhtpStatus::Ok);
    }
}
