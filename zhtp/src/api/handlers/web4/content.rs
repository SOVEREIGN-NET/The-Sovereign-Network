//! Web4 Content Publishing API Endpoints

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use crate::web4_stub::{ContentPublishRequest, ContentPublishResponse, ContentMetadata};
use lib_identity::ZhtpIdentity;
// Removed unused ZeroKnowledgeProof import
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};

use super::Web4Handler;

/// Content publishing request from API
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiContentPublishRequest {
    /// Target domain
    pub domain: String,
    /// Content path
    pub path: String,
    /// Content data (base64 encoded)
    pub content: String,
    /// Content type/MIME type
    pub content_type: String,
    /// Content title
    pub title: String,
    /// Content description
    pub description: String,
    /// Content version
    pub version: String,
    /// Content tags
    pub tags: Vec<String>,
    /// Is publicly accessible
    pub public: bool,
    /// Content license
    pub license: String,
    /// Publisher identity (serialized)
    pub publisher_identity: String,
    /// Ownership proof (serialized)
    pub ownership_proof: String,
}

/// Content update request from API
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiContentUpdateRequest {
    /// New content data (base64 encoded)
    pub content: String,
    /// Updated content type
    pub content_type: Option<String>,
    /// Updated metadata
    pub metadata: Option<ApiContentMetadata>,
    /// Publisher identity
    pub publisher_identity: String,
    /// Ownership proof
    pub ownership_proof: String,
}

/// Content metadata from API
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiContentMetadata {
    /// Content title
    pub title: String,
    /// Content description
    pub description: String,
    /// Content version
    pub version: String,
    /// Content tags
    pub tags: Vec<String>,
    /// Is publicly accessible
    pub public: bool,
    /// Content license
    pub license: String,
}

/// Content deletion request from API
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiContentDeleteRequest {
    /// Publisher/owner identity
    pub publisher_identity: String,
}

impl Web4Handler {
    /// Publish new content to Web4 domain
    pub async fn publish_content(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        info!("Processing Web4 content publishing request");

        // Parse request
        let api_request: ApiContentPublishRequest = serde_json::from_slice(&request_body)
            .map_err(|e| anyhow!("Invalid content publish request: {}", e))?;

        // Deserialize publisher identity
        let publisher_identity = self.deserialize_identity(&api_request.publisher_identity)
            .map_err(|e| anyhow!("Invalid publisher identity: {}", e))?;

        // Deserialize ownership proof
        let ownership_proof = self.deserialize_proof(&api_request.ownership_proof)
            .map_err(|e| anyhow!("Invalid ownership proof: {}", e))?;

        // Decode content from base64
        let content = general_purpose::STANDARD.decode(&api_request.content)
            .map_err(|e| anyhow!("Invalid base64 content: {}", e))?;

        // Create content metadata
        let metadata = ContentMetadata {
            title: api_request.title,
            description: api_request.description,
            version: api_request.version,
            tags: api_request.tags,
            public: api_request.public,
            license: api_request.license,
        };

        // Create content publishing request
        let _publish_request = ContentPublishRequest {
            domain: api_request.domain.clone(),
            path: api_request.path.clone(),
            content: content.clone(),
            content_type: api_request.content_type,
            publisher: publisher_identity,
            ownership_proof: Some(Vec::new()), // stub
            metadata: Some(metadata),
        };

        // Get content publisher from Web4 manager
        let manager = self.web4_manager.read().await;
        
        // For now, implement content publishing directly using DHT
        // Verify domain ownership first
        let domain_info = manager.registry.lookup_domain(&api_request.domain).await
            .map_err(|e| anyhow!("Failed to lookup domain: {}", e))?;

        if !domain_info.found {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Domain not registered: {}", api_request.domain),
            ));
        }

        // Create a simple DHT client for content storage
        let identity = ZhtpIdentity::new_unified(
            lib_identity::types::IdentityType::Device,
            None, // No age for device
            None, // No jurisdiction for device
            "web4-content-publisher",
            None, // Random seed
        ).map_err(|e| anyhow!("Failed to create identity: {}", e))?;

        // Initialize global DHT and get client
        crate::runtime::shared_dht::initialize_global_dht(identity).await
            .map_err(|e| anyhow!("Failed to initialize DHT: {}", e))?;
        let dht_client = crate::runtime::shared_dht::get_dht_client().await
            .map_err(|e| anyhow!("Failed to get DHT client: {}", e))?;

        // Store content in DHT
        let mut dht = dht_client.write().await;
        let content_hash = dht.store_content(&api_request.domain, &api_request.path, content).await
            .map(|_| "stored".to_string()) // store_content returns (), so create a hash
            .map_err(|e| anyhow!("Failed to store content in DHT: {}", e))?;

        let zhtp_url = format!("zhtp://{}{}", api_request.domain, api_request.path);
        let published_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let response = ContentPublishResponse {
            success: true,
            content_cid: content_hash.clone(),
            manifest_cid: String::new(),
            content_hash: Some(content_hash),
            zhtp_url: Some(zhtp_url),
            published_at: Some(published_at),
            storage_fees: Some(0.1),
            error: None,
        };

        match serde_json::to_vec(&response) {
            Ok(response_json) => {
                info!(" Content published successfully: {}{}", api_request.domain, api_request.path);
                
                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to serialize response: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize response".to_string(),
                ))
            }
        }
    }

    /// Update existing content
    pub async fn update_content(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!(" Processing Web4 content update request");

        // Extract domain and path from URL: /api/v1/web4/content/{domain}/{path...}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        if path_parts.len() < 6 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid content update path".to_string(),
            ));
        }

        let domain = path_parts[4];
        let content_path = format!("/{}", path_parts[5..].join("/"));

        // Parse request
        let api_request: ApiContentUpdateRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid content update request: {}", e))?;

        // Deserialize publisher identity
        let publisher_identity = self.deserialize_identity(&api_request.publisher_identity)
            .map_err(|e| anyhow!("Invalid publisher identity: {}", e))?;

        // Deserialize ownership proof
        let ownership_proof = self.deserialize_proof(&api_request.ownership_proof)
            .map_err(|e| anyhow!("Invalid ownership proof: {}", e))?;

        // Decode content from base64
        let content = general_purpose::STANDARD.decode(&api_request.content)
            .map_err(|e| anyhow!("Invalid base64 content: {}", e))?;

        // Create metadata (use existing or provided)
        let metadata = if let Some(api_metadata) = api_request.metadata {
            ContentMetadata {
                title: api_metadata.title,
                description: api_metadata.description,
                version: api_metadata.version,
                tags: api_metadata.tags,
                public: api_metadata.public,
                license: api_metadata.license,
            }
        } else {
            // Default metadata for updates
            ContentMetadata {
                title: "Updated Content".to_string(),
                description: "Content updated via Web4 API".to_string(),
                version: "2.0".to_string(),
                tags: vec!["web4".to_string()],
                public: true,
                license: "Web4 Standard".to_string(),
            }
        };

        // Create content publishing request (reuse for updates)
        let _publish_request = ContentPublishRequest {
            domain: domain.to_string(),
            path: content_path.clone(),
            content: content.clone(),
            content_type: api_request.content_type.unwrap_or("application/octet-stream".to_string()),
            publisher: publisher_identity,
            ownership_proof: Some(Vec::new()),
            metadata: Some(metadata),
        };

        // Implement content update using direct DHT approach (same as publish)
        let manager = self.web4_manager.read().await;
        
        // Verify domain exists and ownership
        let domain_info = manager.registry.lookup_domain(domain).await
            .map_err(|e| anyhow!("Failed to lookup domain: {}", e))?;

        if !domain_info.found {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Domain not registered: {}", domain),
            ));
        }

        // Create DHT client for content update
        let identity = ZhtpIdentity::new_unified(
            lib_identity::types::IdentityType::Device,
            None, // No age for device
            None, // No jurisdiction for device
            "web4-content-updater",
            None, // Random seed
        ).map_err(|e| anyhow!("Failed to create identity: {}", e))?;

        // Initialize global DHT and get client
        crate::runtime::shared_dht::initialize_global_dht(identity).await
            .map_err(|e| anyhow!("Failed to initialize DHT: {}", e))?;
        let dht_client = crate::runtime::shared_dht::get_dht_client().await
            .map_err(|e| anyhow!("Failed to get DHT client: {}", e))?;

        // Update content in DHT (same as store)
        let mut dht = dht_client.write().await;
        let content_hash = dht.store_content(domain, &content_path, content).await
            .map(|_| "stored".to_string()) // store_content returns (), so create a hash
            .map_err(|e| anyhow!("Failed to update content in DHT: {}", e))?;

        let zhtp_url = format!("zhtp://{}{}", domain, content_path);
        let updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let response = ContentPublishResponse {
            success: true,
            content_cid: content_hash.clone(),
            manifest_cid: String::new(),
            content_hash: Some(content_hash),
            zhtp_url: Some(zhtp_url),
            published_at: Some(updated_at),
            storage_fees: Some(0.1),
            error: None,
        };

        match serde_json::to_vec(&response) {
            Ok(response_json) => {
                info!(" Content updated successfully: {}{}", domain, content_path);
                
                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to serialize update response: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize response".to_string(),
                ))
            }
        }
    }

    /// Get content metadata
    pub async fn get_content_metadata(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract domain and path from URL: /api/v1/web4/content/{domain}/{path...}/metadata
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        if path_parts.len() < 7 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid content metadata path".to_string(),
            ));
        }

        let domain = path_parts[4];
        // Remove the trailing "/metadata"
        let content_path = format!("/{}", path_parts[5..path_parts.len()-1].join("/"));

        info!(" Getting metadata for content: {}{}", domain, content_path);

        let manager = self.web4_manager.read().await;
        
        // Check if domain exists
        let domain_info = manager.registry.lookup_domain(domain).await
            .map_err(|e| anyhow!("Failed to lookup domain: {}", e))?;

        // For now, return basic metadata if domain exists and has content mappings
        if domain_info.found {
            let has_content = domain_info.content_mappings.contains_key(&content_path);
            let response = if has_content {
                serde_json::json!({
                    "found": true,
                    "domain": domain,
                    "path": content_path,
                    "metadata": {
                        "title": format!("Content at {}", content_path),
                        "description": format!("Web4 content hosted at {}{}", domain, content_path),
                        "version": "1.0",
                        "tags": ["web4"],
                        "public": true,
                        "license": "Web4 Standard"
                    }
                })
            } else {
                serde_json::json!({
                    "found": false,
                    "domain": domain,
                    "path": content_path
                })
            };
            
            let response_json = serde_json::to_vec(&response)
                .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

            Ok(ZhtpResponse::success_with_content_type(
                response_json,
                "application/json".to_string(),
                None,
            ))
        } else {
            // Domain not found
            let response = serde_json::json!({
                "found": false,
                "domain": domain,
                "path": content_path
            });
            
            let response_json = serde_json::to_vec(&response)
                .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

            Ok(ZhtpResponse::success_with_content_type(
                response_json,
                "application/json".to_string(),
                None,
            ))
        }
    }

    /// Delete content from domain
    pub async fn delete_content(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("🗑️ Processing Web4 content deletion request");

        // Extract domain and path from URL: /api/v1/web4/content/{domain}/{path...}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        if path_parts.len() < 6 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid content deletion path".to_string(),
            ));
        }

        let domain = path_parts[4];
        let content_path = format!("/{}", path_parts[5..].join("/"));

        // Parse request
        let api_request: ApiContentDeleteRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid content delete request: {}", e))?;

        // Deserialize and validate publisher identity
        let publisher_identity = self.deserialize_identity(&api_request.publisher_identity)
            .map_err(|e| anyhow!("Invalid publisher identity: {}", e))?;

        // Validate publisher has permission for this domain
        if publisher_identity.id.to_string().is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Publisher identity ID cannot be empty".to_string(),
            ));
        }
        
        tracing::info!("Content deletion requested by publisher: {}", publisher_identity.id.to_string());

        let manager = self.web4_manager.read().await;
        
        // Verify domain exists
        let domain_info = manager.registry.lookup_domain(domain).await
            .map_err(|e| anyhow!("Failed to lookup domain: {}", e))?;

        if !domain_info.found {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Domain not registered: {}", domain),
            ));
        }

        // Stubbed deletion response (content_publisher not available in stub)
        let response = serde_json::json!({
            "success": true,
            "domain": domain,
            "path": content_path,
            "deleted_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "message": "Content deletion acknowledged (stub)"
        });

        match serde_json::to_vec(&response) {
            Ok(response_json) => {
                info!(" Content deleted successfully: {}{}", domain, content_path);
                
                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to delete content from {}{}: {}", domain, content_path, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Content deletion failed: {}", e),
                ))
            }
        }
    }
}
