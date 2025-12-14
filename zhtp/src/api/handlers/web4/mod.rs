//! Web4 API Handlers
//!
//! Web4 domain registration and content publishing endpoints that integrate
//! with the existing ZHTP server infrastructure.
//!
//! # Content Serving
//!
//! The `GET /api/v1/web4/content/{domain}/{path}` endpoint serves Web4 content
//! using the `Web4ContentService`. This is the canonical API for content retrieval.
//!
//! # Gateway Handler
//!
//! The `Web4GatewayHandler` provides Host-based routing for Web4 domains.
//! It intercepts requests like `myapp.zhtp.localhost` and routes them to
//! the appropriate Web4 content.

pub mod domains;
pub mod content;
pub mod gateway;
pub mod chunked_upload;

pub use domains::*;
pub use content::*;
pub use gateway::*;
pub use chunked_upload::{ChunkedUploadManager, UploadLimits, UploadStats, handle_chunked_upload};

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::zhtp::ZhtpRequestHandler;
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_network::{Web4Manager, Web4ContentService};
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use chrono;
use uuid;

/// Standardized error response format (Issue #11)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
    pub timestamp: u64,
}

/// Web4 API handler that integrates with existing ZHTP server
pub struct Web4Handler {
    /// Web4 system manager
    web4_manager: Arc<RwLock<Web4Manager>>,
    /// Content service for serving Web4 content
    content_service: Arc<Web4ContentService>,
    /// Wallet-content ownership manager
    wallet_content_manager: Arc<RwLock<lib_storage::WalletContentManager>>,
    /// Identity manager for owner DID lookups
    identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
    /// Blockchain for UTXO transaction creation
    blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
    /// Chunked upload manager for large files
    chunked_upload_manager: Arc<ChunkedUploadManager>,
}

impl Web4Handler {
    /// Create new Web4 API handler with existing storage system and identity manager
    pub async fn new(
        storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
        blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
    ) -> ZhtpResult<Self> {
        info!("Initializing Web4 API handler with existing storage system");

        let web4_manager = lib_network::initialize_web4_system_with_storage(storage).await
            .map_err(|e| anyhow::anyhow!("Failed to initialize Web4 system: {}", e))?;

        // Create content service using the registry from the manager
        let content_service = Web4ContentService::new(Arc::clone(&web4_manager.registry));

        info!("Web4 API handler initialized successfully");

        // Initialize wallet-content manager for ownership tracking
        let wallet_content_manager = lib_storage::WalletContentManager::new();

        Ok(Self {
            web4_manager: Arc::new(RwLock::new(web4_manager)),
            content_service: Arc::new(content_service),
            wallet_content_manager: Arc::new(RwLock::new(wallet_content_manager)),
            identity_manager,
            blockchain,
            chunked_upload_manager: Arc::new(ChunkedUploadManager::new()),
        })
    }

    /// Create new Web4 API handler with existing domain registry (avoids creating duplicate)
    /// This is the preferred constructor when a DomainRegistry already exists
    pub async fn new_with_registry(
        domain_registry: Arc<lib_network::DomainRegistry>,
        storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
        blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
    ) -> ZhtpResult<Self> {
        info!("Initializing Web4 API handler with existing domain registry");

        // Create Web4Manager using existing registry
        let web4_manager = lib_network::Web4Manager::new_with_registry(
            domain_registry.clone(),
            storage.clone()
        ).await.map_err(|e| anyhow::anyhow!("Failed to create Web4Manager: {}", e))?;

        // Create content service using the shared registry
        let content_service = Web4ContentService::new(domain_registry);

        info!("Web4 API handler initialized with shared domain registry");

        // Initialize wallet-content manager for ownership tracking
        let wallet_content_manager = lib_storage::WalletContentManager::new();

        Ok(Self {
            web4_manager: Arc::new(RwLock::new(web4_manager)),
            content_service: Arc::new(content_service),
            wallet_content_manager: Arc::new(RwLock::new(wallet_content_manager)),
            identity_manager,
            blockchain,
            chunked_upload_manager: Arc::new(ChunkedUploadManager::new()),
        })
    }

    /// Get reference to the Web4Manager for sharing with other handlers
    pub fn get_web4_manager(&self) -> Arc<RwLock<Web4Manager>> {
        Arc::clone(&self.web4_manager)
    }

    /// Create standardized JSON error response (Issue #11)
    fn json_error(&self, status: ZhtpStatus, message: impl Into<String>) -> ZhtpResult<ZhtpResponse> {
        let code = match status {
            ZhtpStatus::BadRequest => 400,
            ZhtpStatus::Unauthorized => 401,
            ZhtpStatus::Forbidden => 403,
            ZhtpStatus::NotFound => 404,
            ZhtpStatus::InternalServerError => 500,
            ZhtpStatus::ServiceUnavailable => 503,
            _ => 500,
        };

        let error_response = ErrorResponse {
            error: message.into(),
            code,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        ZhtpResponse::error_json(status, &error_response)
    }

    /// Get Web4 system statistics
    async fn get_web4_statistics(&self) -> ZhtpResult<ZhtpResponse> {
        let manager = self.web4_manager.read().await;

        match manager.registry.get_statistics().await {
            Ok(stats) => {
                let stats_json = serde_json::to_vec(&stats)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize statistics: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    stats_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to get Web4 statistics: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to retrieve Web4 statistics".to_string(),
                ))
            }
        }
    }

    /// Load Web4 resource content (Issue #9)
    /// POST /api/v1/web4/load
    async fn load_web4_resource(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct LoadRequest {
            url: String,
        }

        let load_req: LoadRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        info!("Loading Web4 resource: {}", load_req.url);

        // Parse URL to extract domain and path
        // Expected format: web4://domain.zhtp/path or just domain.zhtp/path
        let (domain, path) = if let Some(stripped) = load_req.url.strip_prefix("web4://") {
            let parts: Vec<&str> = stripped.splitn(2, '/').collect();
            (parts[0].to_string(), parts.get(1).map(|s| s.to_string()))
        } else {
            let parts: Vec<&str> = load_req.url.splitn(2, '/').collect();
            (parts[0].to_string(), parts.get(1).map(|s| s.to_string()))
        };

        let manager = self.web4_manager.read().await;

        // Resolve domain to get contract ID
        match manager.registry.lookup_domain(&domain).await {
            Ok(lookup) if lookup.found => {
                if let Some(record) = lookup.record {
                    // Return contract/content information
                    // Note: Web4 domains don't have direct contract associations yet
                    let response = serde_json::json!({
                        "status": "success",
                        "domain": domain,
                        "owner": record.owner,
                        "path": path,
                        "content_available": !record.content_mappings.is_empty(),
                        "note": "Contract association not yet implemented"
                    });

                    let json = serde_json::to_vec(&response)
                        .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

                    Ok(ZhtpResponse::success_with_content_type(
                        json,
                        "application/json".to_string(),
                        None,
                    ))
                } else {
                    Ok(ZhtpResponse::error(
                        ZhtpStatus::NotFound,
                        format!("Domain record incomplete: {}", domain),
                    ))
                }
            }
            Ok(_) => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Domain not found: {}", domain),
                ))
            }
            Err(e) => {
                error!("Failed to resolve domain {}: {}", domain, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to resolve domain: {}", e),
                ))
            }
        }
    }

    /// Resolve Web4 domain to DApp (Issue #9)
    /// GET /api/v1/web4/resolve/{domain}
    async fn resolve_web4_domain(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let domain = request.uri
            .strip_prefix("/api/v1/web4/resolve/")
            .ok_or_else(|| anyhow::anyhow!("Invalid resolve URL"))?;

        info!("Resolving Web4 domain: {}", domain);

        let manager = self.web4_manager.read().await;

        match manager.registry.lookup_domain(domain).await {
            Ok(lookup) if lookup.found => {
                if let Some(record) = lookup.record {
                    // Note: Web4 domains don't have direct contract associations yet
                    let response = serde_json::json!({
                        "status": "success",
                        "domain": domain,
                        "owner": record.owner,
                        "registered_at": record.registered_at,
                        "expires_at": record.expires_at,
                        "note": "Contract association not yet implemented"
                    });

                    let json = serde_json::to_vec(&response)
                        .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

                    Ok(ZhtpResponse::success_with_content_type(
                        json,
                        "application/json".to_string(),
                        None,
                    ))
                } else {
                    Ok(ZhtpResponse::error(
                        ZhtpStatus::NotFound,
                        format!("Domain record incomplete: {}", domain),
                    ))
                }
            }
            Ok(_) => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Domain not found: {}", domain),
                ))
            }
            Err(e) => {
                error!("Failed to resolve domain {}: {}", domain, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to resolve domain: {}", e),
                ))
            }
        }
    }

    /// Serve Web4 content
    /// GET /api/v1/web4/content/{domain}/{path...}
    ///
    /// This is the canonical content serving endpoint. It uses Web4ContentService
    /// which handles:
    /// - Path normalization (security-critical)
    /// - SPA routing policy
    /// - MIME type resolution
    /// - Cache header generation
    async fn serve_content(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Parse domain and path from URL
        // URL format: /api/v1/web4/content/{domain}/{path...}
        let content_path = request.uri
            .strip_prefix("/api/v1/web4/content/")
            .ok_or_else(|| anyhow::anyhow!("Invalid content URL"))?;

        // Split into domain and path
        let (domain, path) = match content_path.find('/') {
            Some(idx) => {
                let (d, p) = content_path.split_at(idx);
                (d.to_string(), p.to_string()) // path includes leading /
            }
            None => {
                // No path specified, serve root
                (content_path.to_string(), "/".to_string())
            }
        };

        debug!(
            domain = %domain,
            path = %path,
            "Serving Web4 content"
        );

        // Use content service to serve the content
        match self.content_service.serve(&domain, &path).await {
            Ok(result) => {
                info!(
                    domain = %domain,
                    path = %path,
                    mime_type = %result.mime_type,
                    cache_control = %result.cache_control,
                    is_fallback = result.is_fallback,
                    content_length = result.content.len(),
                    "Content served successfully"
                );

                // Build response with headers
                let mut response = ZhtpResponse::success_with_content_type(
                    result.content,
                    result.mime_type,
                    None,
                )
                .with_cache_control(result.cache_control);

                // Add ETag if present
                if let Some(etag) = result.etag {
                    response = response.with_etag(etag);
                }

                // Add any custom headers from the result
                for (key, value) in result.headers {
                    response = response.with_custom_header(key, value);
                }

                // Add fallback indicator header (useful for debugging SPA routing)
                if result.is_fallback {
                    response = response.with_custom_header(
                        "X-Web4-Fallback".to_string(),
                        "true".to_string(),
                    );
                }

                Ok(response)
            }
            Err(e) => {
                warn!(
                    domain = %domain,
                    path = %path,
                    error = %e,
                    "Content not found"
                );

                self.json_error(ZhtpStatus::NotFound, format!("Content not found: {}", e))
            }
        }
    }

    /// Upload a blob (small file, direct upload)
    /// POST /api/v1/web4/content/blob
    async fn upload_blob(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let content_type = request.headers.content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());

        debug!(
            content_type = %content_type,
            size = request.body.len(),
            "Uploading blob"
        );

        // Generate content ID from hash
        let content_hash = lib_crypto::hash_blake3(&request.body);
        let content_id = format!("bafk{}", hex::encode(&content_hash[..16]));

        // TODO: Store blob in persistent storage
        // For now, just return the CID
        // In production, this should store in blob storage

        let response = serde_json::json!({
            "content_id": content_id,
            "size": request.body.len(),
            "content_type": content_type,
        });

        info!(
            content_id = %content_id,
            size = request.body.len(),
            "Blob uploaded"
        );

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ))
    }

    /// Upload a manifest
    /// POST /api/v1/web4/content/manifest
    async fn upload_manifest(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Parse manifest JSON
        let manifest: serde_json::Value = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid manifest JSON: {}", e))?;

        debug!(
            domain = manifest.get("domain").and_then(|v| v.as_str()).unwrap_or("unknown"),
            files = manifest.get("files").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
            "Uploading manifest"
        );

        // Generate manifest CID from hash
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_hash = lib_crypto::hash_blake3(&manifest_bytes);
        let manifest_cid = format!("bafk{}", hex::encode(&manifest_hash[..16]));

        // TODO: Store manifest in persistent storage
        // In production, this should store the manifest and validate it

        let response = serde_json::json!({
            "manifest_cid": manifest_cid,
            "domain": manifest.get("domain"),
            "files_count": manifest.get("files").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
        });

        info!(
            manifest_cid = %manifest_cid,
            "Manifest uploaded"
        );

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ))
    }
}

/// Implement ZHTP request handler trait to integrate with existing server
#[async_trait::async_trait]
impl ZhtpRequestHandler for Web4Handler {
    /// Handle ZHTP requests for Web4 endpoints
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Structured logging for audit trail (Issue #12)
        let request_id = uuid::Uuid::new_v4().to_string();
        let start_time = std::time::Instant::now();

        info!(
            request_id = %request_id,
            method = ?request.method,
            uri = %request.uri,
            timestamp = request.timestamp,
            "Web4 API request received"
        );

        let path = &request.uri;
        let response = match path.as_str() {
            // Issue #9: Web4 resource loading and domain resolution
            "/api/v1/web4/load" if request.method == lib_protocols::ZhtpMethod::Post => {
                self.load_web4_resource(request).await
            }
            path if path.starts_with("/api/v1/web4/resolve/") => {
                self.resolve_web4_domain(request).await
            }

            // Domain versioning endpoints (must come before general domain endpoints)
            "/api/v1/web4/domains/resolve" if request.method == lib_protocols::ZhtpMethod::Post => {
                self.resolve_domain_manifest(request).await
            }
            "/api/v1/web4/domains/update" if request.method == lib_protocols::ZhtpMethod::Post => {
                self.update_domain_version(request).await
            }
            path if path.starts_with("/api/v1/web4/domains/status/") && request.method == lib_protocols::ZhtpMethod::Get => {
                self.get_domain_status(request).await
            }
            path if path.starts_with("/api/v1/web4/domains/history/") && request.method == lib_protocols::ZhtpMethod::Get => {
                self.get_domain_history(request).await
            }
            path if path.starts_with("/api/v1/web4/domains/") && path.ends_with("/rollback") && request.method == lib_protocols::ZhtpMethod::Post => {
                self.rollback_domain(request).await
            }

            // Domain management endpoints
            path if path.starts_with("/api/v1/web4/domains/register") => {
                self.register_domain_simple(request.body).await
            }
            path if path.starts_with("/api/v1/web4/domains/") && request.method == lib_protocols::ZhtpMethod::Get => {
                self.get_domain(request).await
            }
            path if path.starts_with("/api/v1/web4/domains/") && path.ends_with("/transfer") => {
                self.transfer_domain(request).await
            }
            path if path.starts_with("/api/v1/web4/domains/") && path.ends_with("/release") => {
                self.release_domain(request).await
            }

            // Chunked upload endpoints (must be before general content endpoints)
            path if path.starts_with("/api/v1/web4/content/upload/") => {
                // Extract owner DID from request headers or use placeholder
                // In production, this should come from the authenticated principal via VerifiedPrincipal
                let owner_did = request.headers.get("x-owner-did")
                    .unwrap_or_else(|| "anonymous".to_string());
                handle_chunked_upload(request, &self.chunked_upload_manager, &owner_did).await
            }

            // Content publishing endpoints
            path if path == "/api/v1/web4/content/publish" => {
                self.publish_content(request.body).await
            }
            // Blob upload endpoint (for direct/small files)
            path if path == "/api/v1/web4/content/blob" && request.method == lib_protocols::ZhtpMethod::Post => {
                self.upload_blob(request).await
            }
            // Manifest upload endpoint
            path if path == "/api/v1/web4/content/manifest" && request.method == lib_protocols::ZhtpMethod::Post => {
                self.upload_manifest(request).await
            }
            path if path.starts_with("/api/v1/web4/content/") && request.method == lib_protocols::ZhtpMethod::Put => {
                self.update_content(request).await
            }
            path if path.starts_with("/api/v1/web4/content/") && path.ends_with("/metadata") => {
                self.get_content_metadata(request).await
            }
            path if path.starts_with("/api/v1/web4/content/") && request.method == lib_protocols::ZhtpMethod::Delete => {
                self.delete_content(request).await
            }
            // Content serving endpoint (GET) - uses Web4ContentService
            path if path.starts_with("/api/v1/web4/content/") && request.method == lib_protocols::ZhtpMethod::Get => {
                self.serve_content(request).await
            }

            // Statistics endpoint
            "/api/v1/web4/statistics" => {
                self.get_web4_statistics().await
            }

            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Web4 endpoint not found: {}", path),
            )),
        };

        // Structured logging for response (Issue #12)
        let duration_ms = start_time.elapsed().as_millis();

        match &response {
            Ok(resp) => {
                info!(
                    request_id = %request_id,
                    status = ?resp.status,
                    duration_ms = duration_ms,
                    "Web4 API request completed"
                );
            }
            Err(e) => {
                error!(
                    request_id = %request_id,
                    error = %e,
                    duration_ms = duration_ms,
                    "Web4 API request failed"
                );
            }
        }

        response
    }

    /// Check if this handler can process the request
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/web4/")
    }

    /// Get handler priority (higher than default)
    fn priority(&self) -> u32 {
        200 // Higher priority for Web4 endpoints
    }
}