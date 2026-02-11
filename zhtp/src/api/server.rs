//! ZHTP Server Module
//! 
//! Clean, minimal ZHTP server implementation

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, Context};
use tracing::{info, error};

// ZHTP protocol imports
use lib_protocols::zhtp::{Router, ZhtpResult};
// Removed unused Context, ZhtpRequestHandler
use lib_protocols::zhtp::routing::RouterConfig;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};

// Import our handlers and middleware
use crate::api::handlers::{NetworkHandler, PouwHandler};
// Removed unused IdentityHandler, BlockchainHandler, StorageHandler, ProtocolHandler
use crate::api::middleware::MiddlewareStack;

// External library imports
use lib_identity::IdentityManager;
use lib_blockchain::Blockchain;
// Removed unused StorageProvider
use lib_economy::EconomicModel;

/// Clean ZHTP server implementation
pub struct ZhtpServer {
    router: Router,
    middleware: MiddlewareStack,
    identity_manager: Arc<RwLock<IdentityManager>>,
    blockchain: Arc<RwLock<Blockchain>>,
    storage: Arc<RwLock<lib_storage::PersistentStorageSystem>>,
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
        info!(" Initializing ZHTP Server...");
        
        // Initialize router with default config
        let router_config = RouterConfig::default();
        let mut router = Router::new(router_config);
        
        // Initialize core components (these would be properly initialized in implementation)
        let identity_manager = Arc::new(RwLock::new(
            IdentityManager::new()
        ));
        
        let blockchain = Arc::new(RwLock::new(
            Blockchain::new()?
        ));
        
        // IMPORTANT: Use global storage - never open sled database directly here
        // Storage is initialized once by StorageComponent during runtime bootstrap
        let storage = crate::runtime::storage_provider::get_global_storage().await
            .map_err(|e| anyhow::anyhow!(
                "FATAL: Cannot create ApiServer - global storage not initialized. \
                Storage must be initialized by StorageComponent before ApiServer. Error: {}", e
            ))?;
        
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
        
        // ====================================================================
        // Register PoUW (Proof-of-Useful-Work) Handler Routes
        // ====================================================================
        
        // Initialize ChallengeGenerator with node's signing keys
        // NOTE: In production, these keys should come from the node's keystore
        let node_private_key = [0u8; 32]; // Placeholder - replace with actual key
        let node_id = [0u8; 32]; // Placeholder - replace with actual key
        let challenge_generator = Arc::new(crate::pouw::ChallengeGenerator::new(
            node_private_key,
            node_id,
        ));
        let pouw_handler = Arc::new(PouwHandler::new(challenge_generator.clone()));
        
        // GET /pouw/challenge - Generate challenge tokens (wildcard to catch query params)
        let pouw_challenge_route = Route {
            pattern: RoutePattern::Exact("/pouw/challenge".to_string()),
            methods: vec![ZhtpMethod::Get],
            handler: pouw_handler.clone(),
            priority: 100,
            economic_requirements: EconomicRequirements::default(),
            access_requirements: AccessRequirements::default(),
            metadata: RouteMetadata {
                name: "get_pouw_challenge".to_string(),
                description: "Generate a new PoUW challenge token".to_string(),
                version: "1.0".to_string(),
                tags: vec!["pouw".to_string(), "challenge".to_string()],
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
        router.add_route(pouw_challenge_route)?;
        
        // GET /pouw/health - Health check endpoint
        let pouw_health_route = Route {
            pattern: RoutePattern::Exact("/pouw/health".to_string()),
            methods: vec![ZhtpMethod::Get],
            handler: pouw_handler.clone(),
            priority: 100,
            economic_requirements: EconomicRequirements::default(),
            access_requirements: AccessRequirements::default(),
            metadata: RouteMetadata {
                name: "get_pouw_health".to_string(),
                description: "Get PoUW service health status".to_string(),
                version: "1.0".to_string(),
                tags: vec!["pouw".to_string(), "health".to_string()],
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
        router.add_route(pouw_health_route)?;
        
        info!("Router configured with PoUW handler routes");
        
        info!("Router configured with network handler routes");
        
        // Initialize middleware stack
        let middleware = MiddlewareStack::new();
        
        info!("ZHTP Server initialized successfully");
        
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
            .context("Middleware error")? {
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
            .context("Middleware error")?;
        
        Ok(final_response)
    }
    
    /// Start the ZHTP server
    pub async fn start(&self, bind_address: &str) -> Result<()> {
        info!("Starting ZHTP server on {}", bind_address);
        
        // This is where you would implement the actual server listening logic
        // For now, we'll just log that the server is ready
        info!("ZHTP server is ready to handle requests");
        info!(" Server endpoints:");
        info!("   - Identity: /api/v1/identity/*");
        info!("   - Blockchain: /api/v1/blockchain/*");
        info!("   - Storage: /api/v1/storage/*");
        info!("   - Protocol: /api/v1/protocol/*");
        
        // In a implementation, this would be an infinite loop handling connections
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
        // Use all server fields to gather comprehensive stats
        let identity_count = {
            let _identity_manager = self.identity_manager.read().await;
            // Use placeholder since identities field is private
            0usize
        };
        
        let blockchain_stats = {
            let blockchain = self.blockchain.read().await;
            let block_count = blockchain.blocks.len();
            let transaction_count = blockchain.blocks.iter()
                .map(|block| block.transactions.len())
                .sum::<usize>();
            (block_count, transaction_count)
        };
        
        let storage_stats = {
            let mut storage = self.storage.write().await;
            match storage.get_statistics().await {
                Ok(stats) => (stats.storage_stats.total_storage_used, stats.storage_stats.total_content_count),
                Err(_) => (0, 0) // Default values on error
            }
        };
        
        let economic_stats = {
            let economic_model = self.economic_model.read().await;
            // Use available public fields from EconomicModel
            let total_supply = economic_model.max_supply;
            let circulating_supply = economic_model.current_supply;
            (total_supply, circulating_supply)
        };
        
        let stats_data = serde_json::json!({
            "status": "active",
            "handlers_registered": 4,
            "middleware_layers": 4,
            "requests_processed": 0, // Would need to track this
            "uptime": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            "identity_stats": {
                "total_identities": identity_count
            },
            "blockchain_stats": {
                "block_count": blockchain_stats.0,
                "transaction_count": blockchain_stats.1
            },
            "storage_stats": {
                "total_storage_used": storage_stats.0,
                "total_content_count": storage_stats.1
            },
            "economic_stats": {
                "total_supply": economic_stats.0,
                "circulating_supply": economic_stats.1
            }
        });
        
        let json_response = serde_json::to_vec(&stats_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Get identity manager status
    pub async fn get_identity_status(&self) -> Result<ZhtpResponse> {
        let identity_manager = self.identity_manager.read().await;
        let identity_count = identity_manager.list_identities().len();
        
        let status_data = serde_json::json!({
            "status": "active",
            "total_identities": identity_count,
            "identity_manager_ready": true
        });
        
        let json_response = serde_json::to_vec(&status_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Get blockchain status
    pub async fn get_blockchain_status(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        
        let status_data = serde_json::json!({
            "status": "active",
            "height": blockchain.get_height(),
            "pending_transactions": blockchain.get_pending_transactions().len(),
            "total_identities": blockchain.get_all_identities().len(),
            "blockchain_ready": true
        });
        
        let json_response = serde_json::to_vec(&status_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Get storage system status
    pub async fn get_storage_status(&self) -> Result<ZhtpResponse> {
        let (total_used, total_count) = {
            let mut storage = self.storage.write().await;
            match storage.get_statistics().await {
                Ok(stats) => (stats.storage_stats.total_storage_used, stats.storage_stats.total_content_count),
                Err(_) => (0, 0)
            }
        };
        
        let status_data = serde_json::json!({
            "status": "active",
            "total_storage_used": total_used,
            "total_content_count": total_count,
            "storage_ready": true
        });
        
        let json_response = serde_json::to_vec(&status_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Get economic model status
    pub async fn get_economic_status(&self) -> Result<ZhtpResponse> {
        let economic_model = self.economic_model.read().await;
        
        let status_data = serde_json::json!({
            "status": "active",
            "base_routing_rate": economic_model.base_routing_rate,
            "quality_multiplier": economic_model.quality_multiplier,
            "current_supply": economic_model.current_supply,
            "max_supply": economic_model.max_supply,
            "economic_model_ready": true
        });
        
        let json_response = serde_json::to_vec(&status_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
}