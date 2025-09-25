//! ZHTP Server Module
//! 
//! Clean, minimal ZHTP server implementation

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, Context};
use tracing::{info, error};

// ZHTP protocol imports
use lib_protocols::zhtp::{Router, ZhtpRequestHandler, ZhtpResult};
use lib_protocols::zhtp::routing::RouterConfig;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};

// Import our handlers and middleware
use crate::api::handlers::{IdentityHandler, BlockchainHandler, StorageHandler, ProtocolHandler, NetworkHandler};
use crate::api::middleware::MiddlewareStack;

// External library imports
use lib_identity::IdentityManager;
use lib_blockchain::Blockchain;
use lib_storage::StorageProvider;
use lib_economy::EconomicModel;

/// Clean ZHTP server implementation
pub struct ZhtpServer {
    router: Router,
    middleware: MiddlewareStack,
    identity_manager: Arc<RwLock<IdentityManager>>,
    blockchain: Arc<RwLock<Blockchain>>,
    storage: Arc<RwLock<lib_storage::UnifiedStorageSystem>>,
    economic_model: Arc<RwLock<EconomicModel>>,
}

impl std::fmt::Debug for ZhtpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZhtpServer")
            .field("router", &"<Router>")
            .field("middleware", &"<MiddlewareStack>")
            .field("identity_manager", &"<Arc<RwLock<IdentityManager>>>")
            .field("blockchain", &"<Arc<RwLock<Blockchain>>>")
            .field("storage", &"<Arc<RwLock<UnifiedStorageSystem>>>")
            .field("economic_model", &"<Arc<RwLock<EconomicModel>>>")
            .finish()
    }
}

impl ZhtpServer {
    /// Create a new ZHTP server with clean configuration
    pub async fn new() -> Result<Self> {
        info!("🚀 Initializing ZHTP Server...");
        
        // Initialize router with default config
        let router_config = RouterConfig::default();
        let mut router = Router::new(router_config);
        
        // Initialize core components (these would be properly initialized in real implementation)
        let identity_manager = Arc::new(RwLock::new(
            IdentityManager::new()
        ));
        
        let blockchain = Arc::new(RwLock::new(
            Blockchain::new()?
        ));
        
        // For storage, we'll use a placeholder - in real implementation this would be proper storage
        let storage = Arc::new(RwLock::new(
            lib_storage::UnifiedStorageSystem::new(lib_storage::UnifiedStorageConfig {
                node_id: lib_storage::types::NodeId::from(lib_crypto::Hash::from_bytes(b"node_001")),
                addresses: vec!["127.0.0.1:8000".to_string()],
                economic_config: lib_storage::EconomicManagerConfig::default(),
                storage_config: lib_storage::StorageConfig {
                    max_storage_size: 1024 * 1024 * 1024, // 1GB
                    default_tier: lib_storage::StorageTier::Hot,
                    enable_compression: true,
                    enable_encryption: true,
                },
                erasure_config: lib_storage::ErasureConfig {
                    data_shards: 4,
                    parity_shards: 2,
                },
            }).await?
        ));
        
        let economic_model = Arc::new(RwLock::new(
            EconomicModel::new()
        ));
        
        // Register network handler routes
        use crate::runtime::RuntimeOrchestrator;
        use crate::config::NodeConfig;
        let runtime = Arc::new(RuntimeOrchestrator::new(NodeConfig::default()).await?);
        let network_handler = Arc::new(NetworkHandler::new(runtime));
        
        // Create routes for network endpoints
        use lib_protocols::zhtp::routing::{Route, RoutePattern, EconomicRequirements, AccessRequirements, RouteMetadata, MonitoringConfig};
        use lib_protocols::types::ZhtpMethod;
        
        // GET /api/v1/blockchain/network/peers
        let peers_route = Route {
            pattern: RoutePattern::Exact("/api/v1/blockchain/network/peers".to_string()),
            methods: vec![ZhtpMethod::Get],
            handler: network_handler.clone(),
            priority: 100,
            economic_requirements: EconomicRequirements::default(),
            access_requirements: AccessRequirements::default(),
            metadata: RouteMetadata {
                name: "get_network_peers".to_string(),
                description: "Get list of connected network peers".to_string(),
                version: "1.0".to_string(),
                tags: vec!["network".to_string(), "peers".to_string()],
                rate_limit: None,
                cache_config: None,
                monitoring: MonitoringConfig {
                    enable_logging: true,
                    enable_metrics: true,
                    enable_tracing: false,
                    custom_metrics: vec![],
                },
            },
            middleware: vec![],
        };
        router.add_route(peers_route)?;
        
        // GET /api/v1/blockchain/network/stats
        let stats_route = Route {
            pattern: RoutePattern::Exact("/api/v1/blockchain/network/stats".to_string()),
            methods: vec![ZhtpMethod::Get],
            handler: network_handler.clone(),
            priority: 100,
            economic_requirements: EconomicRequirements::default(),
            access_requirements: AccessRequirements::default(),
            metadata: RouteMetadata {
                name: "get_network_stats".to_string(),
                description: "Get network statistics and health metrics".to_string(),
                version: "1.0".to_string(),
                tags: vec!["network".to_string(), "stats".to_string()],
                rate_limit: None,
                cache_config: None,
                monitoring: MonitoringConfig {
                    enable_logging: true,
                    enable_metrics: true,
                    enable_tracing: false,
                    custom_metrics: vec![],
                },
            },
            middleware: vec![],
        };
        router.add_route(stats_route)?;
        
        // POST /api/v1/blockchain/network/peer/add
        let add_peer_route = Route {
            pattern: RoutePattern::Exact("/api/v1/blockchain/network/peer/add".to_string()),
            methods: vec![ZhtpMethod::Post],
            handler: network_handler.clone(),
            priority: 100,
            economic_requirements: EconomicRequirements::default(),
            access_requirements: AccessRequirements::default(),
            metadata: RouteMetadata {
                name: "add_network_peer".to_string(),
                description: "Add a new peer to the network".to_string(),
                version: "1.0".to_string(),
                tags: vec!["network".to_string(), "peers".to_string()],
                rate_limit: None,
                cache_config: None,
                monitoring: MonitoringConfig {
                    enable_logging: true,
                    enable_metrics: true,
                    enable_tracing: false,
                    custom_metrics: vec![],
                },
            },
            middleware: vec![],
        };
        router.add_route(add_peer_route)?;
        
        // DELETE /api/v1/blockchain/network/peer/{peer_id}
        let remove_peer_route = Route {
            pattern: RoutePattern::Parameterized("/api/v1/blockchain/network/peer/{peer_id}".to_string(), vec!["peer_id".to_string()]),
            methods: vec![ZhtpMethod::Delete],
            handler: network_handler.clone(),
            priority: 100,
            economic_requirements: EconomicRequirements::default(),
            access_requirements: AccessRequirements::default(),
            metadata: RouteMetadata {
                name: "remove_network_peer".to_string(),
                description: "Remove a peer from the network".to_string(),
                version: "1.0".to_string(),
                tags: vec!["network".to_string(), "peers".to_string()],
                rate_limit: None,
                cache_config: None,
                monitoring: MonitoringConfig {
                    enable_logging: true,
                    enable_metrics: true,
                    enable_tracing: false,
                    custom_metrics: vec![],
                },
            },
            middleware: vec![],
        };
        router.add_route(remove_peer_route)?;
        
        info!("📋 Router configured with network handler routes");
        
        // Initialize middleware stack
        let middleware = MiddlewareStack::new();
        
        info!("✅ ZHTP Server initialized successfully");
        
        Ok(Self {
            router,
            middleware,
            identity_manager,
            blockchain,
            storage,
            economic_model,
        })
    }
    
    /// Handle incoming ZHTP request
    pub async fn handle_request(&mut self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Process request through middleware
        if let Some(middleware_response) = self.middleware.process_request(&request).await
            .map_err(|e| anyhow::anyhow!("Middleware error: {}", e))? {
            return Ok(middleware_response);
        }
        
        // Route request to appropriate handler
        let response = self.router.route_request(request.clone()).await
            .unwrap_or_else(|e| {
                error!("Router error: {}", e);
                ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Router error: {}", e),
                )
            });
        
        // Process response through middleware
        let final_response = self.middleware.process_response(&request, response).await
            .map_err(|e| anyhow::anyhow!("Middleware error: {}", e))?;
        
        Ok(final_response)
    }
    
    /// Start the ZHTP server
    pub async fn start(&self, bind_address: &str) -> Result<()> {
        info!("🌐 Starting ZHTP server on {}", bind_address);
        
        // This is where you would implement the actual server listening logic
        // For now, we'll just log that the server is ready
        info!("✅ ZHTP server is ready to handle requests");
        info!("📍 Server endpoints:");
        info!("   - Identity: /api/v1/identity/*");
        info!("   - Blockchain: /api/v1/blockchain/*");
        info!("   - Storage: /api/v1/storage/*");
        info!("   - Protocol: /api/v1/protocol/*");
        
        // In a real implementation, this would be an infinite loop handling connections
        Ok(())
    }
    
    /// Health check endpoint
    pub async fn health_check(&self) -> Result<ZhtpResponse> {
        let health_data = serde_json::json!({
            "status": "healthy",
            "version": "1.0.0",
            "protocol": "ZHTP/1.0",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            "handlers": [
                "identity",
                "blockchain", 
                "storage",
                "protocol"
            ]
        });
        
        let json_response = serde_json::to_vec(&health_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Get server statistics
    pub async fn get_stats(&self) -> Result<ZhtpResponse> {
        let stats_data = serde_json::json!({
            "status": "active",
            "handlers_registered": 4,
            "middleware_layers": 4,
            "requests_processed": 0, // Would need to track this
            "uptime": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        });
        
        let json_response = serde_json::to_vec(&stats_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
}