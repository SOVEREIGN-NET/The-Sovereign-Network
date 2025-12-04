//! API Handler Registration Module
//!
//! Extracted from unified_server.rs (lines 6218-6315)
//! 
//! Registers all HTTP API handlers with the router:
//! - Blockchain operations
//! - Identity and wallet management
//! - Storage operations
//! - DHT operations
//! - Web4 domains and DNS
//! - Marketplace
//! - Validator management
//! - Protocol management

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_blockchain::Blockchain;
use lib_storage::UnifiedStorageSystem;
use lib_identity::IdentityManager;
use lib_economy::EconomicModel;

use crate::api::handlers::{
    BlockchainHandler,
    IdentityHandler,
    StorageHandler,
    WalletHandler,
    DaoHandler,
    Web4Handler,
    DnsHandler,
    ProtocolHandler,
};
use crate::session_manager::SessionManager;
use crate::server::http::router::HttpRouter;
use crate::server::zhtp::router::ZhtpRouter;

/// Register all API handlers with the HTTP and ZHTP routers
pub async fn register_api_handlers(
    http_router: &mut HttpRouter,
    zhtp_router: &mut ZhtpRouter,
    blockchain: Arc<RwLock<Blockchain>>,
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    identity_manager: Arc<RwLock<IdentityManager>>,
    _economic_model: Arc<RwLock<EconomicModel>>,
    _session_manager: Arc<SessionManager>,
    dht_handler: Arc<dyn ZhtpRequestHandler>,
) -> Result<()> {
    info!("📝 Registering comprehensive API handlers...");
    
    // ========================================================================
    // CORE API HANDLERS
    // ========================================================================
    
    // Blockchain operations
    let blockchain_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        BlockchainHandler::new(blockchain.clone())
    );
    http_router.register_handler("/api/v1/blockchain".to_string(), blockchain_handler);
    info!("   ✅ Blockchain handler registered");
    
    // Identity and wallet management
    // Note: Using lib_identity::economics::EconomicModel as expected by IdentityHandler
    let identity_economic_model = Arc::new(RwLock::new(
        lib_identity::economics::EconomicModel::new()
    ));

    // Create rate limiter for authentication endpoints
    let rate_limiter = Arc::new(crate::api::middleware::RateLimiter::new());
    // Start cleanup task to prevent memory leak
    rate_limiter.start_cleanup_task();

    // Create account lockout tracker for per-identity brute force protection
    let account_lockout = Arc::new(crate::api::handlers::identity::login_handlers::AccountLockout::new());

    // Create CSRF protection (P0-7)
    let csrf_protection = Arc::new(crate::api::middleware::CsrfProtection::new());

    // Create recovery phrase manager for backup/recovery (Issue #100)
    let recovery_phrase_manager = Arc::new(RwLock::new(
        lib_identity::RecoveryPhraseManager::new()
    ));

    let identity_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        IdentityHandler::new(
            identity_manager.clone(),
            identity_economic_model,
            _session_manager.clone(),
            rate_limiter.clone(),
            account_lockout,
            csrf_protection,
            recovery_phrase_manager,
        )
    );
    http_router.register_handler("/api/v1/identity".to_string(), identity_handler);
    info!("   ✅ Identity handler registered");

    // Guardian social recovery handler (Issue #101)
    let recovery_manager = Arc::new(RwLock::new(
        lib_identity::SocialRecoveryManager::new()
    ));

    let guardian_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        crate::api::handlers::guardian::GuardianHandler::new(
            identity_manager.clone(),
            _session_manager.clone(),
            recovery_manager,
            rate_limiter.clone(),
        )
    );
    http_router.register_handler("/api/v1/identity/guardians".to_string(), guardian_handler.clone());
    http_router.register_handler("/api/v1/identity/recovery".to_string(), guardian_handler);
    info!("   ✅ Guardian social recovery handler registered");

    // Zero-knowledge proof handler (Issue #102)
    let zkp_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        crate::api::handlers::zkp::ZkpHandler::new(
            identity_manager.clone(),
            _session_manager.clone(),
            rate_limiter.clone(),
        )
    );
    http_router.register_handler("/api/v1/zkp".to_string(), zkp_handler);
    info!("   ✅ Zero-knowledge proof handler registered");

    // ========================================================================
    // STORAGE AND CONTENT HANDLERS
    // ========================================================================
    
    // Wallet content ownership manager (shared across handlers)
    let wallet_content_manager = Arc::new(RwLock::new(lib_storage::WalletContentManager::new()));
    
    // Storage operations (with wallet content manager for ownership tracking)
    let storage_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        StorageHandler::new(storage.clone())
            .with_wallet_manager(Arc::clone(&wallet_content_manager))
    );
    http_router.register_handler("/api/v1/storage".to_string(), storage_handler);
    info!("   ✅ Storage handler registered");
    
    // Wallet operations
    let wallet_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        WalletHandler::new(identity_manager.clone())
    );
    http_router.register_handler("/api/v1/wallet".to_string(), wallet_handler);
    info!("   ✅ Wallet handler registered");
    
    // DAO operations
    let dao_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        DaoHandler::new(identity_manager.clone(), _session_manager.clone())
    );
    http_router.register_handler("/api/v1/dao".to_string(), dao_handler);
    info!("   ✅ DAO handler registered");
    
    // Register DHT handler for HTTP API (already registered on mesh_router for pure UDP)
    http_router.register_handler("/api/v1/dht".to_string(), dht_handler);
    info!("   ✅ DHT handler registered");
    
    // ========================================================================
    // WEB4 AND CONTENT MARKETPLACE
    // ========================================================================
    
    // Web4 domain and content (handle async creation first)
    // Pass existing storage, identity manager, AND blockchain for UTXO transaction creation
    let web4_handler = Web4Handler::new(storage.clone(), identity_manager.clone(), blockchain.clone()).await?;
    let web4_manager = web4_handler.get_web4_manager();
    info!("   ✅ Web4 manager initialized");
    
    let wallet_content_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        crate::api::handlers::WalletContentHandler::new(Arc::clone(&wallet_content_manager))
    );
    http_router.register_handler("/api/wallet".to_string(), Arc::clone(&wallet_content_handler));
    http_router.register_handler("/api/content".to_string(), wallet_content_handler);
    info!("   ✅ Wallet content handler registered");
    
    // Marketplace handler for buying/selling content (shares managers with wallet content)
    let marketplace_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        crate::api::handlers::MarketplaceHandler::new(
            Arc::clone(&wallet_content_manager),
            Arc::clone(&blockchain),
            Arc::clone(&identity_manager)
        )
    );
    http_router.register_handler("/api/marketplace".to_string(), marketplace_handler);
    info!("   ✅ Marketplace handler registered");
    
    // DNS resolution for .zhtp domains (connect to Web4Manager)
    let mut dns_handler = DnsHandler::new();
    dns_handler.set_web4_manager(web4_manager);
    let dns_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(dns_handler);
    http_router.register_handler("/api/v1/dns".to_string(), dns_handler);
    info!("   ✅ DNS handler registered");
    
    // Register Web4 handler
    let web4_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(web4_handler);
    http_router.register_handler("/api/v1/web4".to_string(), web4_handler);
    info!("   ✅ Web4 handler registered");
    
    // ========================================================================
    // NETWORK MANAGEMENT HANDLERS
    // ========================================================================
    
    // Validator management
    let validator_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        crate::api::handlers::ValidatorHandler::new(blockchain.clone())
    );
    http_router.register_handler("/api/v1/validator".to_string(), validator_handler);
    info!("   ✅ Validator handler registered");
    
    // Protocol management
    let protocol_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
        ProtocolHandler::new()
    );
    http_router.register_handler("/api/v1/protocol".to_string(), protocol_handler.clone());
    zhtp_router.register_handler("/api/v1/protocol".to_string(), protocol_handler);
    info!("   ✅ Protocol handler registered");
    
    info!("✅ All API handlers registered successfully (11 handlers)");
    Ok(())
}
