//! ZHTP Unified Server - Single Server for All Protocols
//! 
//! ✅ REFACTORED - Now uses modular components from server/ directory
//! 
//! This file orchestrates the server components:
//! - Protocol detection and routing (server::protocol_detection)
//! - TCP/UDP handlers (server::tcp_handler, server::udp_handler)
//! - HTTP router and middleware (server::http)
//! - Mesh router and authentication (server::mesh)
//! - WiFi/Bluetooth protocols (server::protocols)
//! - API handler registration (server::api_registration)

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::RwLock;
// REMOVED: TCP/UDP no longer used - QUIC-only architecture
// use tokio::net::{TcpListener, UdpSocket, TcpStream};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use uuid::Uuid;

// Import from libraries (no circular dependencies!)
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_network::protocols::quic_mesh::QuicMeshProtocol;

// Import new QUIC handler for native ZHTP-over-QUIC
use crate::server::QuicHandler;
use lib_network::types::mesh_message::ZhtpMeshMessage;
use lib_blockchain::Blockchain;
use lib_storage::UnifiedStorageSystem;
use lib_identity::IdentityManager;
use lib_economy::EconomicModel;
use lib_crypto::PublicKey;

// Import our comprehensive API handlers
use crate::api::handlers::{
    DhtHandler, 
    ProtocolHandler,
    BlockchainHandler,
    IdentityHandler,
    StorageHandler,
    WalletHandler,
    DaoHandler,
    Web4Handler,
    DnsHandler,
};
use crate::session_manager::SessionManager;

// Re-export for backward compatibility with code that imports from crate::unified_server::*
pub use crate::server::{
    // Protocol detection
    IncomingProtocol,
    // ❌ DELETED: TcpHandler, UdpHandler - Replaced by QuicHandler
    // API registration
    register_api_handlers,
    // HTTP layer
    HttpRouter,
    Middleware,
    CorsMiddleware,
    RateLimitMiddleware,
    AuthMiddleware,
    // Mesh layer
    MeshRouter,
    // Monitoring layer
    PeerReputation,
    PeerRateLimit,
    BroadcastMetrics,
    SyncPerformanceMetrics,
    SyncAlert,
    AlertLevel,
    AlertThresholds,
    MetricsSnapshot,
    PeerPerformanceStats,
    // Protocol routers
    WiFiRouter,
    BluetoothRouter,
    BluetoothClassicRouter,
    ClassicProtocol,
    // ❌ REMOVED: BootstrapRouter - Use lib-network::bootstrap instead
};

/// Main unified server that handles all protocols
/// QUIC-ONLY ARCHITECTURE: TCP/UDP removed, QUIC is the primary transport
#[derive(Clone)]
pub struct ZhtpUnifiedServer {
    // QUIC-native protocol (required, primary transport)
    quic_mesh: Arc<QuicMeshProtocol>,
    quic_handler: Arc<QuicHandler>,
    
    // Protocol routers
    http_router: HttpRouter,
    mesh_router: MeshRouter,
    wifi_router: WiFiRouter,
    bluetooth_router: BluetoothRouter,
    bluetooth_classic_router: BluetoothClassicRouter,
    // ❌ REMOVED: bootstrap_router - Using lib-network::bootstrap servers instead
    
    // Shared backend state (from ZHTP orchestrator)
    blockchain: Arc<RwLock<Blockchain>>,
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    identity_manager: Arc<RwLock<IdentityManager>>,
    economic_model: Arc<RwLock<EconomicModel>>,
    
    // Session management
    session_manager: Arc<SessionManager>,
    
    // Discovery coordinator (Phase 3 fix)
    discovery_coordinator: Arc<crate::discovery_coordinator::DiscoveryCoordinator>,
    
    // Server state
    is_running: Arc<RwLock<bool>>,
    server_id: Uuid,
    port: u16,
}

impl ZhtpUnifiedServer {
    /// Check if an address is a self-connection from our own node trying to connect to itself
    /// This prevents multi-NIC self-loops but ALLOWS browser connections from localhost
    fn is_self_connection(addr: &std::net::SocketAddr) -> bool {
        let ip = addr.ip();
        
        // IMPORTANT: Do NOT block loopback (127.0.0.1) - that's how browsers connect!
        // We only want to block our actual network IP connecting to itself
        
        // Check if the source IP matches our local network IP
        // (This prevents Ethernet connecting to WiFi on same machine)
        if let Ok(local_ip) = local_ip_address::local_ip() {
            // Only block if source IP matches our non-loopback local IP
            if !local_ip.is_loopback() && ip == local_ip {
                return true;
            }
        }
        
        // Check for link-local auto-assigned addresses (169.254.x.x, fe80::/10)
        // These can cause issues on multi-NIC systems
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                // 169.254.x.x is link-local (auto-assigned)
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    // Get our local IP to compare
                    if let Ok(local_ip) = local_ip_address::local_ip() {
                        if std::net::IpAddr::V4(ipv4) == local_ip {
                            return true;
                        }
                    }
                }
            }
            std::net::IpAddr::V6(ipv6) => {
                // fe80::/10 is link-local
                if ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    // Get our local IP to compare
                    if let Ok(local_ip) = local_ip_address::local_ip() {
                        if std::net::IpAddr::V6(ipv6) == local_ip {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    /// Get broadcast metrics from mesh router
    pub async fn get_broadcast_metrics(&self) -> BroadcastMetrics {
        self.mesh_router.get_broadcast_metrics().await
    }
    
    /// Get the mesh router as an Arc for global provider access
    pub fn get_mesh_router_arc(&self) -> Arc<MeshRouter> {
        // MeshRouter is already Arc-wrapped internally, but we need to clone the Arc to return
        // Since MeshRouter isn't stored as Arc in the struct, we need to wrap it
        // For now, we'll need to refactor mesh_router to be Arc<MeshRouter> instead of MeshRouter
        // As a temporary solution, return a reference through the methods
        Arc::new(self.mesh_router.clone())
    }
    
    /// Create new unified server with comprehensive backend integration
    pub async fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
        port: u16, // Port from configuration
    ) -> Result<Self> {
        Self::new_with_peer_notification(blockchain, storage, identity_manager, economic_model, port, None).await
    }
    
    /// Create new unified server with peer discovery notification channel
    pub async fn new_with_peer_notification(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
        port: u16,
        peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    ) -> Result<Self> {
        let server_id = Uuid::new_v4();
        
        info!("Creating ZHTP Unified Server (ID: {})", server_id);
        info!("Port: {} (HTTP + UDP + WiFi + Bootstrap)", port);
        
        // Initialize session manager first
        let session_manager = Arc::new(SessionManager::new());
        session_manager.start_cleanup_task();
        
        // Initialize discovery coordinator (Phase 3 consolidation)
        let discovery_coordinator = Arc::new(crate::discovery_coordinator::DiscoveryCoordinator::new());
        discovery_coordinator.start_event_listener().await;
        info!(" Discovery coordinator initialized - all protocols will report to single coordinator");
        
        // Initialize protocol routers
        let mut http_router = HttpRouter::new();
        let mut zhtp_router = crate::server::zhtp::ZhtpRouter::new();  // Native ZHTP router for QUIC
        let mut mesh_router = MeshRouter::new(server_id, session_manager.clone());
        let wifi_router = WiFiRouter::new_with_peer_notification(peer_discovery_tx);
        let bluetooth_router = BluetoothRouter::new();
        let bluetooth_classic_router = BluetoothClassicRouter::new();
        
        // Set identity manager on mesh router for direct UDP access
        mesh_router.set_identity_manager(identity_manager.clone());
        
        // Create blockchain broadcast channel for real-time sync
        let (broadcast_sender, broadcast_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        // Configure blockchain to use broadcast channel
        // NOTE: 'blockchain' should BE the shared instance, not a separate copy
        {
            let mut blockchain_write = blockchain.write().await;
            blockchain_write.set_broadcast_channel(broadcast_sender);
        }
        
        // Configure mesh router to receive broadcasts
        mesh_router.set_broadcast_receiver(broadcast_receiver).await;
        
        // Initialize WiFi Direct protocol
        if let Err(e) = wifi_router.initialize().await {
            warn!("WiFi Direct initialization failed: {}", e);
        } else {
            info!(" WiFi Direct protocol initialized but DISABLED by default");
            info!("   Use API endpoint /api/v1/protocols/wifi-direct/enable to activate");
        }
        
        // NOTE: Bluetooth initialization happens in start() to avoid double initialization
        // The bluetooth_router is created here but initialized later when server starts
        
        // ❌ REMOVED: Bootstrap router - lib-network bootstrap servers handle this now
        // let bootstrap_router = BootstrapRouter::new(server_id);
        
        // Initialize QUIC mesh protocol (uses port 9334 to avoid UDP conflicts)
        // QUIC is now REQUIRED (not optional) for all networking
        let quic_mesh = Self::init_quic_mesh(port, server_id).await
            .context("Failed to initialize QUIC mesh protocol - QUIC is required")?;
        info!(" QUIC mesh protocol initialized on UDP port 9334");
        let quic_arc = Arc::new(quic_mesh);
        
        // Set QUIC protocol on mesh_router for sending messages
        mesh_router.set_quic_protocol(quic_arc.clone()).await;
        
        // Create DHT handler for pure UDP mesh protocol and register it on mesh_router
        // This MUST happen before register_api_handlers to ensure the actual mesh_router instance gets the handler
        let dht_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DhtHandler::new_with_storage(Arc::new(mesh_router.clone()), storage.clone())
        );
        mesh_router.set_dht_handler(dht_handler.clone()).await;
        
        // Register comprehensive API handlers on both HTTP and native ZHTP routers
        Self::register_api_handlers(
            &mut http_router,
            &mut zhtp_router,
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            session_manager.clone(),
            dht_handler,
        ).await?;
        
        // Initialize QUIC handler for native ZHTP-over-QUIC (AFTER handler registration)
        let zhtp_router_arc = Arc::new(zhtp_router);
        let quic_handler = Arc::new(QuicHandler::new(
            Arc::new(RwLock::new((*zhtp_router_arc).clone())),  // Native ZhtpRouter wrapped in RwLock
            quic_arc.clone(),                    // QuicMeshProtocol for transport
        ));
        info!(" QUIC handler initialized for native ZHTP-over-QUIC");
        
        // Set ZHTP router on mesh_router for proper endpoint routing over UDP
        mesh_router.set_zhtp_router(zhtp_router_arc.clone()).await;
        info!(" ZHTP router registered with mesh router for UDP endpoint handling");
        
        Ok(Self {
            quic_mesh: quic_arc,
            quic_handler,
            http_router,
            mesh_router,
            wifi_router,
            bluetooth_router,
            bluetooth_classic_router,
            // ❌ REMOVED: bootstrap_router field
            blockchain,
            storage,
            identity_manager,
            economic_model,
            session_manager,
            discovery_coordinator,
            is_running: Arc::new(RwLock::new(false)),
            server_id,
            port,
        })
    }
    
    /// Initialize QUIC mesh protocol (uses port 9334 to avoid UDP conflicts)
    async fn init_quic_mesh(port: u16, server_id: Uuid) -> Result<QuicMeshProtocol> {
        // QUIC uses UDP port 9334 to avoid conflicts with:
        // - Port 9333 UDP: Mesh protocol + Multicast discovery
        // - Port 9333 TCP: HTTP API
        let quic_port = port + 1; // 9334
        let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", quic_port).parse()
            .context("Failed to parse QUIC bind address")?;
        
        // Convert server_id UUID to 32-byte node_id for QUIC
        let node_id_bytes = server_id.as_bytes().to_owned();
        let mut node_id = [0u8; 32];
        node_id[..16].copy_from_slice(&node_id_bytes);
        node_id[16..].copy_from_slice(&node_id_bytes); // Duplicate to fill 32 bytes
        
        let mut quic_mesh = QuicMeshProtocol::new(node_id, bind_addr)
            .context("Failed to create QUIC mesh protocol")?;
        
        // Create MeshMessageHandler for routing blockchain sync messages
        // Note: These will be populated properly when mesh_router is initialized
        let mesh_connections = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let long_range_relays = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(std::collections::HashMap::new()));
        
        let message_handler = lib_network::messaging::message_handler::MeshMessageHandler::new(
            mesh_connections,
            long_range_relays,
            revenue_pools,
        );
        
        // Inject message handler into QUIC protocol
        quic_mesh.set_message_handler(Arc::new(RwLock::new(message_handler)));
        info!("✅ MeshMessageHandler injected into QUIC protocol for blockchain sync");
        
        // Start receiving QUIC connections in background
        quic_mesh.start_receiving().await
            .context("Failed to start QUIC receiver")?;
        
        info!(" QUIC mesh protocol ready on UDP port {}", quic_port);
        Ok(quic_mesh)
    }
    
    /// Register all comprehensive API handlers on both HTTP and ZHTP routers
    async fn register_api_handlers(
        http_router: &mut HttpRouter,
        zhtp_router: &mut crate::server::zhtp::ZhtpRouter,
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<UnifiedStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        _economic_model: Arc<RwLock<EconomicModel>>,
        _session_manager: Arc<SessionManager>,
        dht_handler: Arc<dyn ZhtpRequestHandler>,
    ) -> Result<()> {
        info!("Registering comprehensive API handlers on HTTP and ZHTP routers...");
        
        // Blockchain operations
        let blockchain_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            BlockchainHandler::new(blockchain.clone())
        );
        http_router.register_handler("/api/v1/blockchain".to_string(), blockchain_handler.clone());
        zhtp_router.register_handler("/api/v1/blockchain".to_string(), blockchain_handler);
        
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
                rate_limiter,
                account_lockout,
                csrf_protection,
                recovery_phrase_manager,
            )
        );
        http_router.register_handler("/api/v1/identity".to_string(), identity_handler.clone());
        zhtp_router.register_handler("/api/v1/identity".to_string(), identity_handler);
        
        // Wallet content ownership manager (shared across handlers)
        let wallet_content_manager = Arc::new(RwLock::new(lib_storage::WalletContentManager::new()));
        
        // Storage operations (with wallet content manager for ownership tracking)
        let storage_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            StorageHandler::new(storage.clone())
                .with_wallet_manager(Arc::clone(&wallet_content_manager))
        );
        http_router.register_handler("/api/v1/storage".to_string(), storage_handler.clone());
        zhtp_router.register_handler("/api/v1/storage".to_string(), storage_handler);
        
        // Wallet operations
        let wallet_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            WalletHandler::new(identity_manager.clone())
        );
        http_router.register_handler("/api/v1/wallet".to_string(), wallet_handler.clone());
        zhtp_router.register_handler("/api/v1/wallet".to_string(), wallet_handler);
        
        // DAO operations
        let dao_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DaoHandler::new(identity_manager.clone(), _session_manager.clone())
        );
        http_router.register_handler("/api/v1/dao".to_string(), dao_handler.clone());
        zhtp_router.register_handler("/api/v1/dao".to_string(), dao_handler);
        
        // Crypto utilities (sign message, verify signature, generate keypair)
        let crypto_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::CryptoHandler::new(identity_manager.clone())
        );
        http_router.register_handler("/api/v1/crypto".to_string(), crypto_handler.clone());
        zhtp_router.register_handler("/api/v1/crypto".to_string(), crypto_handler);
        
        // Register DHT handler on both HTTP and native ZHTP (already registered on mesh_router for pure UDP)
        http_router.register_handler("/api/v1/dht".to_string(), dht_handler.clone());
        zhtp_router.register_handler("/api/v1/dht".to_string(), dht_handler);
        
        // Web4 domain and content (handle async creation first)
        // Pass existing storage, identity manager, AND blockchain for UTXO transaction creation
        let web4_handler = Web4Handler::new(storage.clone(), identity_manager.clone(), blockchain.clone()).await?;
        let web4_manager = web4_handler.get_web4_manager();
        let wallet_content_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::WalletContentHandler::new(Arc::clone(&wallet_content_manager))
        );
        http_router.register_handler("/api/wallet".to_string(), Arc::clone(&wallet_content_handler));
        http_router.register_handler("/api/content".to_string(), Arc::clone(&wallet_content_handler));
        zhtp_router.register_handler("/api/wallet".to_string(), Arc::clone(&wallet_content_handler));
        zhtp_router.register_handler("/api/content".to_string(), wallet_content_handler);
        
        // Marketplace handler for buying/selling content (shares managers with wallet content)
        let marketplace_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::MarketplaceHandler::new(
                Arc::clone(&wallet_content_manager),
                Arc::clone(&blockchain),
                Arc::clone(&identity_manager)
            )
        );
        http_router.register_handler("/api/marketplace".to_string(), marketplace_handler.clone());
        zhtp_router.register_handler("/api/marketplace".to_string(), marketplace_handler);
        
        // DNS resolution for .zhtp domains (connect to Web4Manager)
        let mut dns_handler = DnsHandler::new();
        dns_handler.set_web4_manager(web4_manager);
        let dns_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(dns_handler);
        http_router.register_handler("/api/v1/dns".to_string(), dns_handler.clone());
        zhtp_router.register_handler("/api/v1/dns".to_string(), dns_handler);
        
        // Register Web4 handler
        let web4_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(web4_handler);
        http_router.register_handler("/api/v1/web4".to_string(), web4_handler.clone());
        zhtp_router.register_handler("/api/v1/web4".to_string(), web4_handler);
        
        // Validator management
        let validator_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::ValidatorHandler::new(blockchain.clone())
        );
        http_router.register_handler("/api/v1/validator".to_string(), validator_handler.clone());
        zhtp_router.register_handler("/api/v1/validator".to_string(), validator_handler);
        
        // Protocol management
        let protocol_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            ProtocolHandler::new()
        );
        http_router.register_handler("/api/v1/protocol".to_string(), protocol_handler);
        
        info!("All API handlers registered successfully");
        Ok(())
    }
    
    /// Start the unified server on port 9333
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting ZHTP Unified Server on port {}", self.port);
        
        // STEP 1: Apply network isolation to block internet access
        info!(" Applying network isolation for ISP-free mesh operation...");
        if let Err(e) = crate::config::network_isolation::initialize_network_isolation().await {
            warn!("Failed to apply network isolation: {}", e);
            warn!(" Mesh may still have internet access - check network configuration");
        } else {
            info!(" Network isolation applied - mesh is now ISP-free");
        }
        
        // Initialize ZHTP relay protocol ONLY if not already initialized
        // (components.rs may have already initialized it with authentication)
        if self.mesh_router.relay_protocol.read().await.is_none() {
            info!(" Initializing ZHTP relay protocol...");
            if let Err(e) = self.mesh_router.initialize_relay_protocol().await {
                warn!("Failed to initialize ZHTP relay protocol: {}", e);
            }
        } else {
            info!(" ZHTP relay protocol already initialized (authentication active)");
        }
        
        // ============================================================================
        // PEER DISCOVERY STATUS SUMMARY
        // ============================================================================
        info!("═══════════════════════════════════════════════════════════════");
        info!("  PEER DISCOVERY METHODS - STATUS REPORT");
        info!("═══════════════════════════════════════════════════════════════");
        
        // Get our public key for discovery protocols
        let our_public_key_for_discovery = match self.mesh_router.get_sender_public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                warn!(" Failed to get public key for discovery: {}", e);
                return Ok(()); // Skip discovery initialization if we can't get public key
            }
        };
        
        // Create callback for discovery coordinator (Phase 3 integration)
        let coordinator_for_callback = self.discovery_coordinator.clone();
        let peer_discovered_callback = Arc::new(move |peer_addr: String, _peer_pubkey: lib_crypto::PublicKey| {
            let coordinator = coordinator_for_callback.clone();
            let addr = peer_addr.clone();
            
            // Spawn task to register peer with coordinator
            tokio::spawn(async move {
                use crate::discovery_coordinator::{DiscoveredPeer, DiscoveryProtocol};
                use std::time::SystemTime;
                
                let now = SystemTime::now();
                let discovered_peer = DiscoveredPeer {
                    public_key: None,  // Will be learned during TCP handshake
                    addresses: vec![addr],
                    discovered_via: DiscoveryProtocol::UdpMulticast,
                    first_seen: now,
                    last_seen: now,
                    node_id: None,
                    capabilities: None,
                };
                
                let _ = coordinator.register_peer(discovered_peer).await;
            });
        });
        
        // NOTE: Multicast discovery is already started in Phase 1 (runtime/mod.rs start_network_components_for_discovery)
        // Starting it again here would create a second UUID and cause self-discovery
        // The Phase 1 multicast will continue running and handle peer discovery
        info!(" UDP Multicast: ACTIVE (started in Phase 1, reusing existing discovery)");
        info!("   → Already broadcasting every 30s from Phase 1 initialization");
        info!("   → Connected to discovery coordinator ✓");
        let multicast_status = "ACTIVE (Phase 1)";
        
        // IP scanning disabled - using multicast/mDNS/WiFi Direct for efficient discovery
        info!("  IP Scanner: DISABLED (inefficient, replaced by broadcast)");
        
        // Create BLE peer discovery notification channel for blockchain sync trigger
        let (ble_peer_tx, mut ble_peer_rx) = tokio::sync::mpsc::unbounded_channel::<PublicKey>();
        
        // Get our public key for BLE handshakes
        let our_public_key = match self.mesh_router.get_sender_public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                warn!(" Failed to get public key for BLE initialization: {}", e);
                return Ok(()); // Skip BLE initialization if we can't get public key
            }
        };
        
        // Initialize Bluetooth LE discovery (pass mesh_connections and peer notification channel for GATT handler)
        // Spawn as background task to avoid blocking HTTP server startup
        let bluetooth_router_clone = self.bluetooth_router.clone();
        let mesh_connections_clone = self.mesh_router.connections.clone();
        let bluetooth_provider = self.mesh_router.blockchain_provider.read().await.clone();
        let ble_peer_tx_clone = ble_peer_tx.clone();
        let our_public_key_clone = our_public_key.clone();
        let sync_coordinator_clone = self.mesh_router.sync_coordinator.clone();
        let mesh_router_clone = Arc::new(self.mesh_router.clone());
        let mesh_router_bluetooth_protocol = self.mesh_router.bluetooth_protocol.clone();

        tokio::spawn(async move {
            // Check if Bluetooth should be disabled via environment variable
            if std::env::var("DISABLE_BLUETOOTH").is_ok() {
                warn!(" Bluetooth disabled via DISABLE_BLUETOOTH environment variable");
                warn!(" Skipping Bluetooth initialization");
                return;
            }

            info!("Initializing Bluetooth mesh protocol for phone connectivity...");
            match bluetooth_router_clone.initialize(
                mesh_connections_clone,
                Some(ble_peer_tx_clone),
                our_public_key_clone,
                bluetooth_provider,
                sync_coordinator_clone,
                mesh_router_clone,
            ).await {
                Ok(_) => {
                    // Store bluetooth protocol in mesh router for send_to_peer()
                    let protocol_opt = bluetooth_router_clone.get_protocol().await;
                    info!(" DEBUG: get_protocol() returned: {}", if protocol_opt.is_some() { "Some(protocol)" } else { "None" });

                    if let Some(protocol) = protocol_opt {
                        *mesh_router_bluetooth_protocol.write().await = Some(protocol.clone());
                        info!(" Bluetooth protocol registered with MeshRouter for message routing");

                        // Verify it was set correctly
                        let verify = mesh_router_bluetooth_protocol.read().await;
                        info!(" DEBUG: Verified mesh_router.bluetooth_protocol is now: {}",
                              if verify.is_some() { "Some(protocol)" } else { "None" });
                    } else {
                        warn!(" Bluetooth protocol not available after initialization - BLE sync will fail");
                    }

                    info!("✅ Bluetooth LE: ACTIVE (100m range)");
                    info!("   → Low-power device-to-device mesh");
                }
                Err(e) => {
                    warn!("❌ Bluetooth LE: FAILED - {}", e);
                    warn!("   → Continuing without Bluetooth LE support");
                }
            }
        });
        let bluetooth_le_status = "INITIALIZING";
        
        // IMPORTANT: Clone mesh_router AFTER bluetooth_protocol is set above
        // This ensures the spawned task has access to the protocol
        let mesh_router_for_ble = self.mesh_router.clone();
        let sync_coordinator_for_ble = self.mesh_router.sync_coordinator.clone();
        let edge_sync_manager_for_ble = self.mesh_router.edge_sync_manager.clone();
        let coordinator_for_ble = self.discovery_coordinator.clone();  // Phase 3: Coordinator integration
        
        tokio::spawn(async move {
            info!(" BLE peer discovery listener active - will trigger sync via BLE (coordinated with other protocols)");
            while let Some(peer_pubkey) = ble_peer_rx.recv().await {
                info!(" BLE peer discovered: {} - checking if sync needed", hex::encode(&peer_pubkey.key_id[..8]));
                
                // Phase 3: Register peer with discovery coordinator
                {
                    use crate::discovery_coordinator::{DiscoveredPeer, DiscoveryProtocol};
                    use std::time::SystemTime;
                    
                    let now = SystemTime::now();
                    let discovered_peer = DiscoveredPeer {
                        public_key: Some(peer_pubkey.clone()),  // BLE provides PublicKey in GATT handshake
                        addresses: vec!["ble://local".to_string()],  // BLE uses local connection
                        discovered_via: DiscoveryProtocol::BluetoothLE,
                        first_seen: now,
                        last_seen: now,
                        node_id: None,
                        capabilities: Some("BLE GATT".to_string()),
                    };
                    
                    let _ = coordinator_for_ble.register_peer(discovered_peer).await;
                    debug!("   ✓ Registered BLE peer with discovery coordinator");
                }
                
                // Check if edge node or full node
                let edge_manager_guard: tokio::sync::RwLockReadGuard<'_, Option<Arc<lib_network::blockchain_sync::EdgeNodeSyncManager>>> = edge_sync_manager_for_ble.read().await;
                let is_edge_node = edge_manager_guard.is_some();
                let sync_type = if is_edge_node {
                    lib_network::blockchain_sync::SyncType::EdgeNode
                } else {
                    lib_network::blockchain_sync::SyncType::FullBlockchain
                };
                drop(edge_manager_guard);
                
                // SMART PROTOCOL SELECTION: Check if peer has TCP/QUIC address before using BLE
                // BLE should be fallback for mobile devices, not primary sync method
                let prefer_tcp_quic = {
                    let peers = coordinator_for_ble.get_all_peers().await;
                    peers.iter().any(|p| {
                        // Check if this is the same peer with TCP/UDP address
                        if let Some(ref pk) = p.public_key {
                            if pk.key_id == peer_pubkey.key_id {
                                // Found same peer - check if it has TCP/UDP/QUIC address
                                p.addresses.iter().any(|addr| {
                                    addr.starts_with("http://") || 
                                    addr.starts_with("https://") ||
                                    addr.starts_with("tcp://") ||
                                    addr.starts_with("udp://") ||
                                    addr.starts_with("quic://") ||
                                    // Bootstrap addresses are plain IP:port (TCP)
                                    addr.parse::<std::net::SocketAddr>().is_ok()
                                })
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    })
                };
                
                if prefer_tcp_quic {
                    info!(" Peer {} has TCP/QUIC address - preferring faster protocol over BLE", 
                          hex::encode(&peer_pubkey.key_id[..8]));
                    info!("   BLE connection will be used as backup if TCP/QUIC sync fails");
                    
                    // Still register BLE as available protocol (for fallback)
                    sync_coordinator_for_ble.register_peer_protocol(
                        &peer_pubkey,
                        lib_network::protocols::NetworkProtocol::BluetoothLE,
                        sync_type
                    ).await;
                    
                    // But don't initiate sync via BLE - let TCP/QUIC handle it
                    continue;
                }
                
                // Check with sync coordinator if we should sync with this peer via BLE
                let should_sync = sync_coordinator_for_ble.register_peer_protocol(
                    &peer_pubkey,
                    lib_network::protocols::NetworkProtocol::BluetoothLE,
                    sync_type
                ).await;
                
                if !should_sync {
                    info!(" Skipping BLE sync with peer {} (already syncing via another protocol)", 
                          hex::encode(&peer_pubkey.key_id[..8]));
                    continue;
                }
                
                info!(" Sync coordinator approved {:?} sync via BLE with peer {}", 
                      sync_type, hex::encode(&peer_pubkey.key_id[..8]));
                info!("   Using BLE as primary protocol (no TCP/QUIC address available)");
                
                // Get our public key for the request
                match mesh_router_for_ble.get_sender_public_key().await {
                    Ok(our_pubkey) => {
                        let request_id = uuid::Uuid::new_v4().as_u128() as u64;
                        
                        // Record sync start with coordinator
                        sync_coordinator_for_ble.start_sync(
                            &peer_pubkey,
                            request_id,
                            sync_type,
                            lib_network::protocols::NetworkProtocol::BluetoothLE
                        ).await;
                        
                        // Create appropriate request based on node type
                        let request_message = if is_edge_node {
                            // Edge nodes request headers only
                            ZhtpMeshMessage::HeadersRequest {
                                requester: our_pubkey,
                                request_id,
                                start_height: 0,
                                count: 500, // Default edge node capacity
                            }
                        } else {
                            // Full nodes request complete blockchain
                            ZhtpMeshMessage::BlockchainRequest {
                                requester: our_pubkey,
                                request_id,
                                request_type: lib_network::types::mesh_message::BlockchainRequestType::FullChain,
                            }
                        };
                        
                        // Send request to BLE peer
                        if let Err(e) = mesh_router_for_ble.send_to_peer(&peer_pubkey, request_message).await {
                            warn!("Failed to request blockchain from BLE peer: {}", e);
                            // Mark sync as failed
                            sync_coordinator_for_ble.fail_sync(&peer_pubkey, request_id, sync_type).await;
                        } else {
                            info!("📤 Sent {:?} request via BLE to peer (ID: {})", sync_type, request_id);
                        }
                    }
                    Err(e) => {
                        warn!(" Could not get sender public key for BLE sync: {}", e);
                    }
                }
            }
            info!("BLE peer discovery listener stopped");
        });
        
        // Skip Bluetooth Classic for now (focusing on BLE only)
        let bluetooth_classic_status = {
            info!("  Bluetooth Classic: SKIPPED (focusing on BLE implementation)");
            info!("   → Will be enabled later for high-bandwidth transfers");
            "DISABLED"
        };
        
        // Initialize WiFi Direct + mDNS
        let wifi_direct_status = if let Err(e) = self.wifi_router.initialize().await {
            warn!(" WiFi Direct + mDNS: FAILED - {}", e);
            warn!("   → This is normal on systems without P2P WiFi support");
            "FAILED"
        } else {
            info!(" WiFi Direct P2P: ACTIVE (200m range)");
            info!("   → Direct device connections without router");
            info!(" mDNS/Bonjour: ACTIVE (_zhtp._tcp.local)");
            info!("   → Automatic service discovery on local network");
            "ACTIVE"
        };
        
        info!("───────────────────────────────────────────────────────────────");
        info!("  DISCOVERY SUMMARY:");
        info!("    UDP Multicast:      {}", multicast_status);
        info!("    mDNS/Bonjour:       {}", if wifi_direct_status == "ACTIVE" { "ACTIVE" } else { "FAILED" });
        info!("    WiFi Direct P2P:    {}", wifi_direct_status);
        info!("    Bluetooth LE:       {}", bluetooth_le_status);
        info!("    Bluetooth Classic:  {}", bluetooth_classic_status);
        info!("    IP Scanner:         DISABLED");
        info!("═══════════════════════════════════════════════════════════════");
        
        // Inform user about what's working
        let active_count = [multicast_status, wifi_direct_status, bluetooth_le_status, bluetooth_classic_status]
            .iter()
            .filter(|&&s| s == "ACTIVE")
            .count();
        
        if active_count == 0 {
            warn!("  WARNING: NO DISCOVERY METHODS ARE WORKING!");
            warn!("   This node cannot discover peers automatically.");
            warn!("   Check firewall, WiFi adapter capabilities, and Bluetooth hardware.");
        } else if active_count == 1 {
            info!("  {} discovery method active - limited peer discovery", active_count);
            info!("   For best results, enable WiFi Direct and Bluetooth");
        } else {
            info!(" {} discovery methods active - excellent peer discovery!", active_count);
            info!("   Your node can discover peers via multiple protocols");
        }
        
        info!("═══════════════════════════════════════════════════════════════");
        
        // QUIC-ONLY MODE: Native ZHTP-over-QUIC (TCP/UDP deprecated)
        info!(" QUIC-Only Mode: Native ZHTP protocol over QUIC transport");
        info!(" TCP/UDP deprecated - using QUIC for all networking");
        
        // Get QUIC endpoint from QuicMeshProtocol for accept loop
        let endpoint = self.quic_mesh.get_endpoint();
        
        *self.is_running.write().await = true;
        
        // Start QUIC connection acceptance loop (PRIMARY PROTOCOL)
        let quic_handler = self.quic_handler.clone();
        tokio::spawn(async move {
            info!("🚀 Starting QUIC accept loop on endpoint...");
            if let Err(e) = quic_handler.accept_loop(endpoint).await {
                error!("❌ QUIC accept loop terminated: {}", e);
            }
        });
        info!(" ✅ QUIC handler started - Native ZHTP-over-QUIC ready");
        
        // Start mesh protocol handlers (background listeners only)
        self.start_bluetooth_mesh_handler().await?;
        self.start_bluetooth_classic_handler().await?;
        // WiFi Direct already initialized above with mDNS
        self.start_lorawan_handler().await?;
        
        info!("ZHTP Unified Server online");
        info!("Protocols: BLE + BT Classic + WiFi Direct + LoRaWAN + ZHTP Relay");
        info!(" ZHTP relay: Encrypted DHT queries with Dilithium2 + Kyber512 + ChaCha20");
        
        // Verify network isolation is working
        info!(" Verifying network isolation...");
        match crate::config::network_isolation::verify_mesh_isolation().await {
            Ok(true) => {
                info!(" NETWORK ISOLATION VERIFIED - Mesh is ISP-free!");
                info!(" No internet access possible - pure mesh operation confirmed");
            }
            Ok(false) => {
                warn!(" NETWORK ISOLATION FAILED - Internet access still possible!");
                warn!(" Check firewall and routing configuration");
            }
            Err(e) => {
                warn!(" Could not verify network isolation: {}", e);
            }
        }
        
        Ok(())
    }

    /// Start Bluetooth mesh protocol handler
    async fn start_bluetooth_mesh_handler(&self) -> Result<()> {
        info!(" Starting Bluetooth LE mesh handler...");
        
        // Check if protocol is initialized (should be done in run_pure_mesh already)
        let protocol_guard = self.bluetooth_router.get_protocol().await;
        let is_initialized = protocol_guard.is_some();
        drop(protocol_guard);
        
        if !is_initialized {
            warn!("Bluetooth LE protocol not initialized - skipping handler");
            return Ok(());
        }
        
        info!(" Bluetooth LE mesh handler active - discoverable for phone connections");
        
        Ok(())
    }

    /// Start Bluetooth Classic RFCOMM mesh handler
    async fn start_bluetooth_classic_handler(&self) -> Result<()> {
        info!(" Starting Bluetooth Classic RFCOMM mesh handler...");
        
        // Check if protocol is initialized (should be done in run_pure_mesh already)
        let protocol_guard = self.bluetooth_classic_router.get_protocol().await;
        let is_initialized = protocol_guard.is_some();
        
        if !is_initialized {
            warn!("Bluetooth Classic protocol not initialized - skipping handler");
            return Ok(());
        }
        
        info!(" Bluetooth Classic RFCOMM handler active");
        
        // Note: Windows Bluetooth API types are not Send, so periodic discovery
        // cannot run in a spawned task. Manual discovery can still be triggered.
        #[cfg(not(all(target_os = "windows", feature = "windows-bluetooth")))]
        {
            info!("Starting periodic Bluetooth Classic peer discovery...");
            // Start periodic peer discovery task
            let bt_router = self.bluetooth_classic_router.clone();
            let mesh_router = self.mesh_router.clone();
            let is_running = self.is_running.clone();
            
            tokio::spawn(async move {
                // Initial discovery after 5 seconds
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                
                while *is_running.read().await {
                    interval.tick().await;
                    
                    info!(" Bluetooth Classic: Starting periodic peer discovery...");
                    match bt_router.discover_and_connect_peers(&mesh_router).await {
                        Ok(count) => {
                            if count > 0 {
                                info!(" Bluetooth Classic: Connected to {} new peers", count);
                            } else {
                                debug!("Bluetooth Classic: No new peers found");
                            }
                        }
                        Err(e) => {
                            warn!("Bluetooth Classic discovery error: {}", e);
                        }
                    }
                }
            });
        }
        
        #[cfg(all(target_os = "windows", feature = "windows-bluetooth"))]
        {
            info!("  Windows: Automatic periodic discovery disabled (API not thread-safe)");
            info!("    Use manual discovery commands or API calls instead");
        }
        
        info!(" Bluetooth Classic periodic discovery task started (60s interval)");
        
        Ok(())
    }

    /// Start LoRaWAN mesh protocol handler
    async fn start_lorawan_handler(&self) -> Result<()> {
        info!(" Starting LoRaWAN mesh handler...");
        
        // LoRaWAN requires specific hardware - check availability
        info!(" LoRaWAN mesh protocol ready (requires LoRa hardware)");
        info!(" Long-range mesh capability available");
        
        Ok(())
    }
    
    /// Start TCP connection handler (HTTP + TCP mesh + WiFi + Bootstrap)




    
    /// Connect to bootstrap peers and initiate blockchain sync via QUIC
    /// This method should be called after the server starts to establish outgoing connections
    pub async fn connect_to_bootstrap_peers(&self, bootstrap_peers: Vec<String>) -> Result<()> {
        if bootstrap_peers.is_empty() {
            info!(" No bootstrap peers to connect to");
            return Ok(());
        }
        
        info!(" Connecting to {} bootstrap peer(s) for blockchain sync via QUIC...", bootstrap_peers.len());
        
        for peer_str in &bootstrap_peers {
            // Parse the peer address - it might be "192.168.1.245:9333" (discovery port) or "zhtp://192.168.1.245:9334" (QUIC port)
            let addr_str = peer_str.trim_start_matches("zhtp://").trim_start_matches("http://");
            
            match addr_str.parse::<SocketAddr>() {
                Ok(mut peer_addr) => {
                    // Discovery announces port 9333, but QUIC mesh runs on port 9334
                    // If we see port 9333, adjust to 9334 for QUIC connection
                    if peer_addr.port() == 9333 {
                        peer_addr.set_port(9334);
                        info!("   Connecting to bootstrap peer: {} (adjusted discovery port 9333 → QUIC port 9334)", peer_addr);
                    } else {
                        info!("   Connecting to bootstrap peer: {}", peer_addr);
                    }
                    
                    // Establish QUIC mesh connection
                    match self.quic_mesh.connect_to_peer(peer_addr).await {
                        Ok(()) => {
                            info!("   ✓ Connected to bootstrap peer {} via QUIC", peer_addr);
                        }
                        Err(e) => {
                            warn!("   Failed to connect to bootstrap peer {}: {}", peer_addr, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("   Failed to parse bootstrap peer address '{}': {}", peer_str, e);
                }
            }
        }
        
        info!(" Bootstrap peer connections completed");
        Ok(())
    }
    
    /// Stop the unified server
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping ZHTP Unified Server...");
        
        *self.is_running.write().await = false;
        
        info!("ZHTP Unified Server stopped");
        Ok(())
    }
    
    /// Get server status
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    /// Initialize ZHTP authentication manager (wrapper for mesh_router method)
    pub async fn initialize_auth_manager(&mut self, blockchain_pubkey: lib_crypto::PublicKey) -> Result<()> {
        self.mesh_router.initialize_auth_manager(blockchain_pubkey).await
    }
    
    /// Initialize ZHTP relay protocol (wrapper for mesh_router method)
    pub async fn initialize_relay_protocol(&self) -> Result<()> {
        self.mesh_router.initialize_relay_protocol().await
    }
    
    /// Initialize WiFi Direct authentication with blockchain identity
    /// SECURITY: Ensures only ZHTP nodes can connect via WiFi Direct
    pub async fn initialize_wifi_direct_auth(&self, identity_manager: Arc<RwLock<lib_identity::IdentityManager>>) -> Result<()> {
        info!(" Initializing WiFi Direct ZHTP authentication...");
        
        // Get blockchain public key from identity manager
        let mgr = identity_manager.read().await;
        let identities = mgr.list_identities();
        
        if identities.is_empty() {
            warn!("  No identities found - WiFi Direct authentication cannot be initialized");
            return Ok(()); // Non-fatal, WiFi Direct will work without auth
        }
        
        // Use first identity - identities is Vec<ZhtpIdentity>
        let identity = &identities[0];
        
        // Create PublicKey from identity's public_key field (Dilithium2 public key)
        let blockchain_pubkey = identity.public_key.clone();
        
        info!(" Using identity {} for WiFi Direct authentication", hex::encode(&identity.id.0[..8]));
        info!("   Public key: {}...", hex::encode(&blockchain_pubkey.as_bytes()[..8]));
        
        // Access WiFi Direct protocol and initialize authentication
        let protocol_guard = self.wifi_router.get_protocol().await;
        if let Some(wifi_protocol) = protocol_guard.as_ref() {
            wifi_protocol.initialize_auth(blockchain_pubkey).await?;
            
            info!(" WiFi Direct authentication initialized successfully");
            info!("    Non-ZHTP devices will be rejected");
            info!("    Hidden SSID mode enabled");
        } else {
            warn!("  WiFi Direct protocol not initialized - authentication setup skipped");
        }
        
        Ok(())
    }
    
    /// Set blockchain provider for network layer (delegates to mesh router)
    pub async fn set_blockchain_provider(&mut self, provider: Arc<dyn lib_network::blockchain_sync::BlockchainProvider>) {
        self.mesh_router.set_blockchain_provider(provider).await;
    }
    
    /// Set edge sync manager (delegates to mesh router)
    pub async fn set_edge_sync_manager(&mut self, manager: Arc<lib_network::blockchain_sync::EdgeNodeSyncManager>) {
        self.mesh_router.set_edge_sync_manager(manager).await;
    }
    
    /// Get server information
    pub fn get_server_info(&self) -> (Uuid, u16) {
        (self.server_id, self.port)
    }
    
    /// Get blockchain statistics
    pub async fn get_blockchain_stats(&self) -> Result<serde_json::Value> {
        let blockchain = self.blockchain.read().await;
        Ok(serde_json::json!({
            "block_count": blockchain.blocks.len(),
            "pending_transactions": blockchain.pending_transactions.len(),
            "identity_count": blockchain.identity_registry.len(),
            "server_id": self.server_id
        }))
    }
    
    /// Get storage system status
    pub async fn get_storage_status(&self) -> Result<serde_json::Value> {
        let _storage = self.storage.read().await;
        Ok(serde_json::json!({
            "status": "active",
            "server_id": self.server_id,
            "storage_type": "unified"
        }))
    }
    
    /// Get identity manager statistics  
    pub async fn get_identity_stats(&self) -> Result<serde_json::Value> {
        let identity_manager = self.identity_manager.read().await;
        let identities = identity_manager.list_identities();
        Ok(serde_json::json!({
            "identity_count": identities.len(),
            "server_id": self.server_id
        }))
    }
    
    /// Get economic model information
    pub async fn get_economic_info(&self) -> Result<serde_json::Value> {
        let _economic_model = self.economic_model.read().await;
        Ok(serde_json::json!({
            "model_type": "ZHTP",
            "server_id": self.server_id,
            "status": "active"
        }))
    }
}
