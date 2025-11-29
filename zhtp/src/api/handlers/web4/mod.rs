//! Web4 API Handlers
//! 
//! Web4 domain registration and content publishing endpoints that integrate
//! with the existing ZHTP server infrastructure

pub mod domains;
pub mod content;

pub use domains::*;
pub use content::*;

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use lib_protocols::zhtp::ZhtpRequestHandler;
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_network::Web4Manager;
use tracing::{info, error};

/// Web4 API handler that integrates with existing ZHTP server
pub struct Web4Handler {
    /// Web4 system manager
    web4_manager: Arc<RwLock<Web4Manager>>,
    /// Wallet-content ownership manager
    wallet_content_manager: Arc<RwLock<lib_storage::WalletContentManager>>,
    /// Identity manager for owner DID lookups
    identity_manager: Arc<RwLock<lib_identity::IdentityManager>>,
    /// Blockchain for UTXO transaction creation
    blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
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
        
        info!(" Web4 API handler initialized successfully");
        
        // Initialize wallet-content manager for ownership tracking
        let wallet_content_manager = lib_storage::WalletContentManager::new();
        
        Ok(Self {
            web4_manager: Arc::new(RwLock::new(web4_manager)),
            wallet_content_manager: Arc::new(RwLock::new(wallet_content_manager)),
            identity_manager,
            blockchain,
        })
    }

    /// Get reference to the Web4Manager for sharing with other handlers
    pub fn get_web4_manager(&self) -> Arc<RwLock<Web4Manager>> {
        Arc::clone(&self.web4_manager)
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
}

/// Implement ZHTP request handler trait to integrate with existing server
#[async_trait::async_trait]
impl ZhtpRequestHandler for Web4Handler {
    /// Handle ZHTP requests for Web4 endpoints
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = &request.uri;
        info!("Handling Web4 request: {} {}", request.method as u8, path);
        
        match path.as_str() {
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
            
            // Content publishing endpoints
            path if path == "/api/v1/web4/content/publish" => {
                self.publish_content(request.body).await
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
            
            // Statistics endpoint
            "/api/v1/web4/statistics" => {
                self.get_web4_statistics().await
            }
            
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Web4 endpoint not found: {}", path),
            )),
        }
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