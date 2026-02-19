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
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use lib_network::web4::{DomainRegistry, ContentPublisher, NameResolver, Web4ContentService};
use tracing::{info, warn, error, debug};
use crate::pouw::validation::{ReceiptValidator, ValidatedReceipt};
use crate::pouw::types::ProofType;
use serde::{Serialize, Deserialize};
use chrono;
use uuid;
use hex;

/// Standardized error response format (Issue #11)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
    pub timestamp: u64,
}

/// Web4 API handler that integrates with existing ZHTP server
pub struct Web4Handler {
    /// Domain registry for managing Web4 domains
    domain_registry: Arc<DomainRegistry>,
    /// Read-only name resolver
    name_resolver: Arc<NameResolver>,
    /// Content publisher for publishing content
    content_publisher: Arc<ContentPublisher>,
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
    /// Optional POUW validator for emitting Web4 receipts on successful serves/resolves
    pouw_validator: Option<Arc<RwLock<ReceiptValidator>>>,
    /// DID of this node (for receipt attribution)
    node_did: Option<String>,
}

impl Web4Handler {
    /// Create new Web4 API handler with existing domain registry and content publisher
    /// This is the preferred constructor when a DomainRegistry already exists
    pub async fn new_with_registry(
        domain_registry: Arc<DomainRegistry>,
        content_publisher: Arc<ContentPublisher>,
        identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
        blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
    ) -> ZhtpResult<Self> {
        info!("Initializing Web4 API handler with existing domain registry");

        // Create content service using the shared registry
        let content_service = Web4ContentService::new(domain_registry.clone());
        let name_resolver = Arc::new(NameResolver::new(domain_registry.clone()));

        info!("Web4 API handler initialized with shared domain registry");

        // Initialize wallet-content manager for ownership tracking
        let wallet_content_manager = lib_storage::WalletContentManager::new();

        Ok(Self {
            domain_registry,
            name_resolver,
            content_publisher,
            content_service: Arc::new(content_service),
            wallet_content_manager: Arc::new(RwLock::new(wallet_content_manager)),
            identity_manager,
            blockchain,
            chunked_upload_manager: Arc::new(ChunkedUploadManager::new()),
            pouw_validator: None,
            node_did: None,
        })
    }

    /// Get reference to the domain registry
    pub fn get_domain_registry(&self) -> Arc<DomainRegistry> {
        Arc::clone(&self.domain_registry)
    }

    /// Attach a POUW validator for emitting Web4 receipts on successful serves/resolves
    pub fn with_pouw_validator(
        mut self,
        pouw_validator: Arc<RwLock<ReceiptValidator>>,
        node_did: String,
    ) -> Self {
        self.pouw_validator = Some(pouw_validator);
        self.node_did = Some(node_did);
        self
    }

    /// Emit a Web4ContentServed receipt (server-side, fire-and-forget)
    async fn emit_content_served(&self, domain: &str, bytes: u64) {
        let Some(v) = &self.pouw_validator else { return };
        let node_did = self.node_did.as_deref().unwrap_or("did:zhtp:node");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut nonce = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let receipt = ValidatedReceipt {
            receipt_nonce: nonce,
            client_did: node_did.to_string(),
            task_id: vec![0u8; 16],
            proof_type: ProofType::Web4ContentServed,
            bytes_verified: bytes,
            validated_at: now,
            challenge_nonce: vec![0u8; 16],
            manifest_cid: None,
            domain: Some(domain.to_string()),
            route_hops: None,
            served_from_cache: Some(true),
        };
        v.read().await.emit_direct(receipt).await;
    }

    /// Emit a Web4ManifestRoute receipt (server-side, fire-and-forget)
    async fn emit_manifest_route(&self, domain: &str, bytes: u64) {
        let Some(v) = &self.pouw_validator else { return };
        let node_did = self.node_did.as_deref().unwrap_or("did:zhtp:node");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut nonce = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let receipt = ValidatedReceipt {
            receipt_nonce: nonce,
            client_did: node_did.to_string(),
            task_id: vec![0u8; 16],
            proof_type: ProofType::Web4ManifestRoute,
            bytes_verified: bytes,
            validated_at: now,
            challenge_nonce: vec![0u8; 16],
            manifest_cid: None,
            domain: Some(domain.to_string()),
            route_hops: Some(1),
            served_from_cache: None,
        };
        v.read().await.emit_direct(receipt).await;
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

        match self.domain_registry.get_statistics().await {
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

        // Resolve domain via read-only view model
        match self.name_resolver.resolve(&domain).await {
            Ok(record) => {
                let owner = hex::encode(&record.owner.0[..16]);
                let content_available = !record.content_mappings.is_empty();
                // Return contract/content information
                // Note: Web4 domains don't have direct contract associations yet
                let response = serde_json::json!({
                    "status": "success",
                    "domain": domain,
                    "owner": owner,
                    "path": path,
                    "content_available": content_available,
                    "note": "Contract association not yet implemented"
                });

                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to resolve domain {}: {}", domain, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Domain not found: {}", domain),
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

        match self.name_resolver.resolve(domain).await {
            Ok(record) => {
                let owner = hex::encode(&record.owner.0[..16]);
                let registered_at = record.registered_at;
                let expires_at = record.expires_at;
                // Note: Web4 domains don't have direct contract associations yet
                let response = serde_json::json!({
                    "status": "success",
                    "domain": domain,
                    "owner": owner,
                    "registered_at": registered_at,
                    "expires_at": expires_at,
                    "note": "Contract association not yet implemented"
                });

                let json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))?;

                // Emit Web4ManifestRoute receipt for successful domain resolution
                self.emit_manifest_route(domain, json.len() as u64).await;

                Ok(ZhtpResponse::success_with_content_type(
                    json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to resolve domain {}: {}", domain, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Domain not found: {}", domain),
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

                // Emit Web4ContentServed receipt for successful content serve
                self.emit_content_served(&domain, result.content.len() as u64).await;

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

    /// Upload or fetch a blob
    /// POST /api/v1/web4/content/blob
    /// Upload: raw bytes in body
    /// Fetch: body is {"cid": "bafk..."}
    async fn handle_blob(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Check if this is a fetch request (body is JSON with "cid" field)
        if let Ok(fetch_req) = serde_json::from_slice::<serde_json::Value>(&request.body) {
            if let Some(cid) = fetch_req.get("cid").and_then(|v| v.as_str()) {
                // This is a FETCH request - retrieve blob by CID
                return self.fetch_content_by_cid(cid).await;
            }
        }

        // This is an UPLOAD request - store the blob
        let content_type = request.headers.content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string());

        debug!(
            content_type = %content_type,
            size = request.body.len(),
            "Uploading blob"
        );

        // Store blob in content-addressed storage
        let content_id = self.domain_registry.store_content_by_cid(request.body.clone()).await
            .map_err(|e| anyhow::anyhow!("Failed to store blob: {}", e))?;

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

    /// Upload or fetch a manifest
    /// POST /api/v1/web4/content/manifest
    /// Upload: body is the manifest JSON
    /// Fetch: body is {"cid": "bafk..."}
    async fn handle_manifest(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Check if this is a fetch request (body contains {"cid": "..."})
        if let Ok(fetch_req) = serde_json::from_slice::<serde_json::Value>(&request.body) {
            if let Some(cid) = fetch_req.get("cid").and_then(|v| v.as_str()) {
                // This is a FETCH request - retrieve manifest by CID
                return self.fetch_content_by_cid(cid).await;
            }
        }

        // This is an UPLOAD request - store the manifest
        let manifest: serde_json::Value = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid manifest JSON: {}", e))?;

        let files_count = manifest.get("files")
            .and_then(|v| {
                // Handle both array (Vec<FileEntry>) and object (HashMap<String, ManifestFile>) formats
                if let Some(arr) = v.as_array() {
                    Some(arr.len())
                } else if let Some(obj) = v.as_object() {
                    Some(obj.len())
                } else {
                    None
                }
            })
            .unwrap_or(0);

        debug!(
            domain = manifest.get("domain").and_then(|v| v.as_str()).unwrap_or("unknown"),
            files = files_count,
            "Uploading manifest"
        );

        // Store manifest in content-addressed storage
        let manifest_cid = self.domain_registry.store_content_by_cid(request.body.clone()).await
            .map_err(|e| anyhow::anyhow!("Failed to store manifest: {}", e))?;

        let response = serde_json::json!({
            "manifest_cid": manifest_cid,
            "domain": manifest.get("domain"),
            "files_count": files_count,
        });

        info!(
            manifest_cid = %manifest_cid,
            files_count = files_count,
            "Manifest uploaded and stored"
        );

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ))
    }

    /// Fetch content by CID
    /// GET /api/v1/web4/cid/{cid} or POST with {"cid": "..."}
    async fn fetch_content_by_cid(&self, cid: &str) -> ZhtpResult<ZhtpResponse> {
        info!("Fetching content by CID: {}", cid);

        let content = self.domain_registry.get_content_by_cid(cid).await
            .map_err(|e| anyhow::anyhow!("Failed to retrieve content: {}", e))?;

        match content {
            Some(data) => {
                info!("Content found for CID {}: {} bytes", cid, data.len());
                // Return raw content (could be manifest JSON or blob bytes)
                Ok(ZhtpResponse::success_with_content_type(
                    data,
                    "application/octet-stream".to_string(),
                    None,
                ))
            }
            None => {
                warn!("Content not found for CID: {}", cid);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Content not found: {}", cid),
                ))
            }
        }
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
            "/api/v1/web4/domains/admin/migrate-domains" if request.method == lib_protocols::ZhtpMethod::Post => {
                self.migrate_domains(request).await
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
            path if path.starts_with("/api/v1/web4/domains?") && request.method == lib_protocols::ZhtpMethod::Get => {
                self.list_domains(request).await
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
            // Blob upload/fetch endpoint
            path if path == "/api/v1/web4/content/blob" && request.method == lib_protocols::ZhtpMethod::Post => {
                self.handle_blob(request).await
            }
            // Manifest upload/fetch endpoint
            path if path == "/api/v1/web4/content/manifest" && request.method == lib_protocols::ZhtpMethod::Post => {
                self.handle_manifest(request).await
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
