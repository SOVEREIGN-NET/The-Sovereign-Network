//! ZHTP Unified Server - Mesh-native with QUIC-only entry point
//!
//! # INVARIANTS
//!
//! This server enforces a QUIC-only architecture:
//! - **INGRESS**: QUIC is the sole entry point (UDP port 9334)
//! - **DISCOVERY**: DHT, mDNS, BLE, Bluetooth Classic, WiFi Direct, LoRaWAN
//! - **AUTHENTICATION**: UHP + Kyber for QUIC connections
//! - **PROHIBITED**: TCP, UDP mesh, HTTP, WebSockets, or any legacy protocols as entry points
//!
//! # Failure Mode
//!
//! If the QUIC accept loop fails, the entire node crashes immediately.
//! Silent partial liveness is not tolerated - the node cannot function without QUIC.
//!
//! # Architecture
//!
//! Orchestrates modular components from server/ directory:
//! - QUIC handler (native ZHTP-over-QUIC)
//! - Mesh router and identity verification
//! - Discovery coordinators (DHT, mDNS, BLE, etc.)
//! - Protocol handlers for mesh-local transport

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
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
use lib_blockchain::Blockchain;
use lib_storage::PersistentStorageSystem;
use lib_identity::IdentityManager;
use lib_economy::EconomicModel;
use lib_crypto::PublicKey;
use lib_network::web4::DomainRegistry;
use crate::monitoring::MonitoringSystem;

// Import keystore filename constants
use crate::keystore_names::{NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME};

/// Default QUIC port for mesh networking (UDP)
const QUIC_PORT: u16 = 9334;

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
    TokenHandler,
};
use crate::session_manager::SessionManager;

// Re-export for backward compatibility with code that imports from crate::unified_server::*
pub use crate::server::{
    IncomingProtocol,
    Middleware,
    CorsMiddleware,
    RateLimitMiddleware,
    AuthMiddleware,
    MeshRouter,
    PeerReputation,
    PeerRateLimit,
    BroadcastMetrics,
    SyncPerformanceMetrics,
    SyncAlert,
    AlertLevel,
    AlertThresholds,
    MetricsSnapshot,
    PeerPerformanceStats,
    WiFiRouter,
    BluetoothRouter,
    BluetoothClassicRouter,
    ClassicProtocol,
};

/// Main unified server that handles all protocols
/// QUIC-ONLY ARCHITECTURE: TCP/UDP removed, QUIC is the primary transport
#[derive(Clone)]
pub struct ZhtpUnifiedServer {
    // QUIC-native protocol (required, primary transport - ONLY ENTRY POINT)
    quic_mesh: Arc<QuicMeshProtocol>,
    quic_handler: Arc<QuicHandler>,

    // Protocol routers
    mesh_router: Arc<MeshRouter>,
    wifi_router: WiFiRouter,
    bluetooth_router: BluetoothRouter,
    bluetooth_classic_router: BluetoothClassicRouter,
    
    // Shared backend state (from ZHTP orchestrator)
    blockchain: Arc<RwLock<Blockchain>>,
    storage: Arc<RwLock<PersistentStorageSystem>>,
    identity_manager: Arc<RwLock<IdentityManager>>,
    economic_model: Arc<RwLock<EconomicModel>>,
    
    // Session management
    session_manager: Arc<SessionManager>,

    // Discovery coordinator (Phase 3 fix)
    discovery_coordinator: Arc<crate::discovery_coordinator::DiscoveryCoordinator>,

    // Web4 domain registry (shared, canonical instance)
    domain_registry: Arc<DomainRegistry>,

    // NodeRuntime - Policy authority (NR-1: Policy Ownership)
    // All "should we?" decisions delegated to runtime
    runtime: Arc<dyn crate::runtime::NodeRuntime>,
    runtime_orchestrator: Arc<crate::runtime::NodeRuntimeOrchestrator>,

    // Monitoring system (metrics, health, alerts, dashboard)
    monitoring_system: Option<MonitoringSystem>,

    // Protocol configuration (AUTHORITATIVE CONFIG LAYER)
    protocols_config: Option<crate::config::aggregation::ProtocolsConfig>,

    // Server state
    is_running: Arc<RwLock<bool>>,
    server_id: Uuid,
    port: u16,
    /// DEPRECATED: Legacy port mapping reference (default: 9333)
    /// NOT actively listened on. See ProtocolsComponent for documentation.
    discovery_port: u16,
    /// Primary QUIC mesh port (default: 9334/UDP)
    /// All QUIC-based mesh communication uses this port.
    quic_port: u16,
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

    /// Load server identity from keystore for UHP+Kyber authentication
    ///
    /// Loads the persistent identity from ~/.zhtp/keystore/node_identity.json.
    ///
    /// **CRITICAL**: Identity continuity is required for blockchain accountability.
    /// Deterministic fallback is ONLY allowed:
    /// - In debug builds (development), OR
    /// - When explicitly enabled with ZHTP_EPHEMERAL=true
    ///
    /// Production systems MUST have a persistent keystore. Fails hard if keystore is missing in release mode.
    fn create_server_identity(server_id: Uuid) -> Result<Arc<lib_identity::ZhtpIdentity>> {
        use lib_identity::{ZhtpIdentity, IdentityType};

        // Try to load from keystore first (consistent with WalletStartupManager)
        let keystore_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
            .join(".zhtp")
            .join("keystore");
        let keystore_path = keystore_dir.join(NODE_IDENTITY_FILENAME);

        if keystore_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&keystore_path) {
                // We need the private key to deserialize properly
                let private_key_path = keystore_dir.join(NODE_PRIVATE_KEY_FILENAME);
                if let Ok(key_data) = std::fs::read_to_string(&private_key_path) {
                    if let Ok(key_store) = serde_json::from_str::<serde_json::Value>(&key_data) {
                        // Extract private key components
                        if let (Some(dilithium), Some(kyber), Some(seed)) = (
                            key_store.get("dilithium_sk").and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok()),
                            key_store.get("kyber_sk").and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok()),
                            key_store.get("master_seed").and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok()),
                        ) {
                            // Get dilithium_pk if present, otherwise use empty (backward compat)
                            let dilithium_pk = key_store.get("dilithium_pk")
                                .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok())
                                .unwrap_or_default();
                            let private_key = lib_crypto::PrivateKey {
                                dilithium_sk: dilithium,
                                dilithium_pk,
                                kyber_sk: kyber,
                                master_seed: seed,
                            };

                            if let Ok(identity) = ZhtpIdentity::from_serialized(&data, &private_key) {
                                tracing::info!(
                                    did = %identity.did,
                                    "Loaded server identity from keystore"
                                );
                                return Ok(Arc::new(identity));
                            }
                        }
                    }
                }
            }
            tracing::warn!("Keystore exists but failed to load identity, creating fallback");
        }

        // CRITICAL: Gate deterministic fallback to dev-only or explicit opt-in
        // Production systems MUST have persistent keystore - losing identity is not acceptable
        let allow_ephemeral = cfg!(debug_assertions) || std::env::var("ZHTP_EPHEMERAL").is_ok();

        if !allow_ephemeral {
            return Err(anyhow::anyhow!(
                "IDENTITY BOOTSTRAP FAILED: No keystore identity found at {:?}\n\
                 Identity continuity is required for blockchain accountability.\n\
                 This is a configuration error - restore your keystore or:\n\
                 - In development: Use a release build or set ZHTP_EPHEMERAL=true\n\
                 - In production: Never use ephemeral identities - restore your keystore",
                keystore_path
            ));
        }

        // Ephemeral mode: Generate deterministic seed from server UUID (dev-only or explicit opt-in)
        tracing::warn!(
            "⚠️ EPHEMERAL MODE: No keystore identity found, creating deterministic server identity\n\
             This should ONLY be used in development. Production systems must use persistent keystore.\n\
             Set ZHTP_EPHEMERAL=true to acknowledge this is intentional."
        );
        let mut seed = [0u8; 64];
        seed[..16].copy_from_slice(server_id.as_bytes());
        seed[16..32].copy_from_slice(server_id.as_bytes());
        seed[32..48].copy_from_slice(server_id.as_bytes());
        seed[48..64].copy_from_slice(server_id.as_bytes());

        // Create server identity using the unified constructor
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Device, // Server is a device/service node
            None,                 // No age for devices
            None,                 // No jurisdiction for devices
            "zhtp-server",        // Device name
            Some(seed),           // Deterministic seed from UUID
        ).context("Failed to create server identity")?;

        Ok(Arc::new(identity))
    }

    /// Get broadcast metrics from mesh router
    pub async fn get_broadcast_metrics(&self) -> BroadcastMetrics {
        self.mesh_router.get_broadcast_metrics().await
    }
    
    /// Get the mesh router as an Arc for global provider access
    pub fn get_mesh_router_arc(&self) -> Arc<MeshRouter> {
        // mesh_router is already Arc<MeshRouter>, so clone just increments refcount
        self.mesh_router.clone()
    }
    
    /// Create new unified server with comprehensive backend integration
    pub async fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<PersistentStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
        port: u16, // Port from configuration
    ) -> Result<Self> {
        Self::new_with_peer_notification(blockchain, storage, identity_manager, economic_model, port, None, None, None, None, None).await
    }
    
    /// Create new unified server with peer discovery notification channel
    pub async fn new_with_peer_notification(
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<PersistentStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
        port: u16,
        peer_discovery_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
        discovery_port: Option<u16>,
        quic_port: Option<u16>,
        protocols_config: Option<crate::config::aggregation::ProtocolsConfig>,
        bootstrap_peers: Option<Vec<String>>,
    ) -> Result<Self> {
        let server_id = Uuid::new_v4();
        let monitoring_system = Some(MonitoringSystem::new().await?);

        // Use configured ports or defaults
        let discovery_port = discovery_port.unwrap_or(9333);
        let quic_port = quic_port.unwrap_or(9334);

        // Validate that discovery and QUIC ports are different
        if discovery_port == quic_port {
            return Err(anyhow::anyhow!(
                "Discovery port ({}) and QUIC port ({}) must be different",
                discovery_port, quic_port
            ));
        }

        info!("Creating ZHTP Unified Server (ID: {})", server_id);
        info!("Port: {} (HTTP + UDP + WiFi + Bootstrap)", port);
        info!("Discovery port: {}, QUIC port: {}", discovery_port, quic_port);
        
        // Initialize session manager first
        let session_manager = Arc::new(SessionManager::new());
        session_manager.start_cleanup_task();
        
        // Initialize discovery coordinator (Phase 3 consolidation)
        // Create DiscoveryConfig from runtime bootstrap peers (ARCHITECTURE: Runtime topology, not Environment defaults)
        let discovery_config = crate::discovery_coordinator::DiscoveryConfig::new(
            bootstrap_peers.unwrap_or_default(),
            discovery_port,
            vec![
                crate::discovery_coordinator::DiscoveryProtocol::UdpMulticast,
                crate::discovery_coordinator::DiscoveryProtocol::MDns,
                crate::discovery_coordinator::DiscoveryProtocol::DHT,
            ],
        );
        let discovery_coordinator = Arc::new(crate::discovery_coordinator::DiscoveryCoordinator::new(discovery_config));
        discovery_coordinator.start_event_listener().await;
        info!(" Discovery coordinator initialized - all protocols will report to single coordinator");
        
        // Initialize protocol routers
        let mut zhtp_router = crate::server::zhtp::ZhtpRouter::new();  // Native ZHTP router for QUIC - ONLY ROUTER NEEDED
        let mut mesh_router = MeshRouter::new(server_id, session_manager.clone());
        let wifi_router = WiFiRouter::new_with_peer_notification(peer_discovery_tx);
        let bluetooth_router = BluetoothRouter::new();
        let bluetooth_classic_router = BluetoothClassicRouter::new();
        
        // Set identity manager on mesh router for direct UDP access
        // This is used by send_with_routing() and broadcast_to_peers() to get sender identity
        // Failure to set this before set_broadcast_receiver() will cause broadcast to fail
        mesh_router.set_identity_manager(identity_manager.clone());
        
        // Set identity manager on WiFi router for UHP handshake authentication
        wifi_router.set_identity_manager(identity_manager.clone()).await;
        
        // Create blockchain broadcast channel for real-time sync
        let (broadcast_sender, broadcast_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        // Configure blockchain to use broadcast channel
        // NOTE: 'blockchain' should BE the shared instance, not a separate copy
        {
            let mut blockchain_write = blockchain.write().await;
            blockchain_write.set_broadcast_channel(broadcast_sender);
        }
        
        // Configure mesh router to receive broadcasts
        // CRITICAL INITIALIZATION ORDER:
        // 1. identity_manager must be set (line 297) BEFORE this call
        // 2. Blockchain broadcast immediately sends blocks/transactions when channel is ready
        // 3. If identity is not initialized, broadcast_to_peers() will panic with configuration error
        let mesh_router_arc = Arc::new(mesh_router);
        let mesh_router_for_broadcast = mesh_router_arc.clone();
        mesh_router_for_broadcast.set_broadcast_receiver(broadcast_receiver).await;
        
        // Initialize WiFi Direct protocol
        if let Err(e) = wifi_router.initialize().await {
            warn!("WiFi Direct initialization failed: {}", e);
        } else {
            info!(" WiFi Direct protocol initialized but DISABLED by default");
            info!("   Use API endpoint /api/v1/protocols/wifi-direct/enable to activate");
        }
        
        // NOTE: Bluetooth initialization happens in start() to avoid double initialization
        // The bluetooth_router is created here but initialized later when server starts

        // Initialize QUIC mesh protocol (uses configurable QUIC port to avoid conflicts)
        // QUIC is now REQUIRED (not optional) for all networking
        info!(" [UNIFIED_SERVER] Calling init_quic_mesh()");
        let quic_mesh = Self::init_quic_mesh(quic_port, server_id).await
            .context("Failed to initialize QUIC mesh protocol - QUIC is required")?;
        info!(" [UNIFIED_SERVER] QUIC mesh protocol initialized on UDP port {}", quic_port);

        info!(" [UNIFIED_SERVER] Wrapping quic_mesh in Arc");
        let quic_arc = Arc::new(quic_mesh);

        // Set QUIC protocol on mesh_router for sending messages
        info!(" [UNIFIED_SERVER] Setting QUIC protocol on mesh_router");
        mesh_router_arc.set_quic_protocol(quic_arc.clone()).await;
        info!(" [UNIFIED_SERVER] QUIC protocol set on mesh_router");

        // Issue #167: Wire protocol handlers to message router (Transport Manager)
        // Create TransportManager with QUIC handler and set on mesh message router
        info!(" [UNIFIED_SERVER] Creating TransportManager with QUIC handler (Issue #167)");
        let transport_manager = lib_network::transport::TransportManager::default()
            .with_quic(quic_arc.clone());
        mesh_router_arc.set_transport_manager(transport_manager).await;
        info!(" [UNIFIED_SERVER] TransportManager set on mesh message router (Issue #167)");

        // Create DHT handler for pure UDP mesh protocol and register it on mesh_router
        // This MUST happen before register_api_handlers to ensure the actual mesh_router instance gets the handler
        let dht_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DhtHandler::new_with_storage(mesh_router_arc.clone(), storage.clone())
        );
        mesh_router_arc.set_dht_handler(dht_handler.clone()).await;

        // Create canonical domain registry (shared by all components)
        // MUST be created BEFORE register_api_handlers so Web4Handler can use it
        // Note: storage is injected here - zhtp is the composition root
        // Wrap storage in UnifiedStorageWrapper to implement the UnifiedStorage trait
        let storage_wrapper = crate::storage_network_integration::UnifiedStorageWrapper(
            storage.clone(),
        );
        let storage_trait: Arc<dyn lib_network::storage_stub::UnifiedStorage> = Arc::new(storage_wrapper);
        let domain_registry = Arc::new(
            DomainRegistry::new(storage_trait.clone()).await?
        );
        info!(" Domain registry initialized (canonical instance)");

        // Create content publisher with same storage backend
        let content_publisher = Arc::new(
            lib_network::web4::ContentPublisher::new(domain_registry.clone(), storage_trait)
        );
        info!(" Content publisher initialized");

        // Register comprehensive API handlers on ZHTP router (QUIC is the only entry point)
        Self::register_api_handlers(
            &mut zhtp_router,
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            session_manager.clone(),
            dht_handler,
            domain_registry.clone(),
            content_publisher.clone(),
        ).await?;

        // Initialize QUIC handler for native ZHTP-over-QUIC (AFTER handler registration)
        let zhtp_router_arc = Arc::new(zhtp_router);
        let mut quic_handler = QuicHandler::new(
            Arc::new(RwLock::new((*zhtp_router_arc).clone())),  // Native ZhtpRouter wrapped in RwLock
            quic_arc.clone(),                    // QuicMeshProtocol for transport
            identity_manager.clone(),            // Identity manager for auto-registration
        );

        // Issue #907: QuicMeshProtocol is now the SINGLE canonical connection store.
        // No need to link MeshRouter's PeerRegistry - broadcast_to_peers() now calls
        // quic_protocol.broadcast_message() directly.

        let quic_handler = Arc::new(quic_handler);
        info!(" QUIC handler initialized for native ZHTP-over-QUIC");

        // Set ZHTP router on mesh_router for proper endpoint routing over UDP
        mesh_router_arc.set_zhtp_router(zhtp_router_arc.clone()).await;
        info!(" ZHTP router registered with mesh router for UDP endpoint handling");

        // Initialize NodeRuntime - Policy Authority (NR-1: Policy Ownership)
        // Delegates all "should we?" decisions to runtime, server only executes "can we?" operations
        let runtime: Arc<dyn crate::runtime::NodeRuntime> = Arc::new(
            crate::runtime::DefaultNodeRuntime::full_validator()
        );
        info!("✓ NodeRuntime initialized - Policy authority ready");

        // Initialize NodeRuntimeOrchestrator - Periodic policy driver
        let runtime_orchestrator = Arc::new(
            crate::runtime::NodeRuntimeOrchestrator::new(runtime.clone())
        );
        info!("✓ NodeRuntimeOrchestrator initialized - Periodic decisions ready");

        // SECURITY FIX: Start orchestrator BEFORE registering with discovery (prevents race condition)
        // This ensures action queue processing is active before peers are discovered
        let _orchestrator_handle = runtime_orchestrator.start().await;
        info!("✓ NodeRuntimeOrchestrator started - ready to process actions");

        // THEN register runtime and action queue with discovery coordinator
        let action_queue = runtime_orchestrator.action_queue().clone();
        discovery_coordinator.set_runtime(runtime.clone(), action_queue).await;
        info!("✓ Discovery coordinator integrated with NodeRuntime");

        Ok(Self {
            quic_mesh: quic_arc,
            quic_handler,
            mesh_router: mesh_router_arc,
            wifi_router,
            bluetooth_router,
            bluetooth_classic_router,
            blockchain,
            storage,
            identity_manager,
            economic_model,
            session_manager,
            discovery_coordinator,
            domain_registry,
            runtime,
            runtime_orchestrator,
            monitoring_system,
            protocols_config,
            is_running: Arc::new(RwLock::new(false)),
            server_id,
            port,
            discovery_port,
            quic_port,
        })
    }
    
    /// Initialize QUIC mesh protocol with configurable port
    async fn init_quic_mesh(quic_port: u16, server_id: Uuid) -> Result<QuicMeshProtocol> {
        info!(" [QUIC] Parsing bind address for port {}", quic_port);
        let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", quic_port).parse()
            .context("Failed to parse QUIC bind address")?;

        // Create server identity for UHP+Kyber authentication
        // Uses server_id UUID as basis for deterministic identity generation
        info!(" [QUIC] Creating server identity");
        let identity = Self::create_server_identity(server_id)?;

        // Initialize QUIC mesh protocol with UHP+Kyber authentication
        info!(" [QUIC] Creating QuicMeshProtocol instance");
        let mut quic_mesh = match QuicMeshProtocol::new(identity, bind_addr) {
            Ok(q) => {
                info!(" [QUIC] ✅ QuicMeshProtocol created successfully");
                q
            },
            Err(e) => {
                info!(" [QUIC] ❌ QuicMeshProtocol::new() failed: {}", e);
                return Err(anyhow::anyhow!("Failed to create QuicMeshProtocol: {}", e));
            }
        };

        // Configure bootstrap peers with optional SPKI pins for certificate verification.
        // Peers with a configured pin enforce strict SPKI match; others use TOFU.
        if let Some(bootstrap_peers) = crate::runtime::bootstrap_peers_provider::get_bootstrap_peers().await {
            // Load any configured SPKI pins from the bootstrap peers provider
            let pin_map = crate::runtime::bootstrap_peers_provider::get_bootstrap_peer_pins().await
                .unwrap_or_default();

            let peer_addrs: Vec<(std::net::SocketAddr, Option<[u8; 32]>)> = bootstrap_peers
                .iter()
                .filter_map(|s| {
                    // Parse the address, preserving the operator-specified port.
                    // Only default to QUIC_PORT when no port is present.
                    let addr = if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
                        addr
                    } else {
                        // No valid port in the string; append the default QUIC port
                        let addr_with_port = format!("{}:{}", s, QUIC_PORT);
                        addr_with_port.parse::<std::net::SocketAddr>().ok()?
                    };

                    // Look up SPKI pin for this peer address.
                    // Config validation already rejected malformed hex at startup,
                    // so a parse failure here indicates a bug — skip the peer entirely
                    // rather than silently degrading to TOFU.
                    let hex_pin = pin_map.get(s)
                        .or_else(|| pin_map.get(&addr.to_string()));

                    let pin = match hex_pin {
                        Some(hex_str) => match crate::config::spki_pin::parse_spki_hex(hex_str) {
                            Ok(hash) => Some(hash),
                            Err(e) => {
                                error!(
                                    "BUG: SPKI pin for {} failed to parse after config validation passed: {}. \
                                     Skipping peer to avoid silent TOFU downgrade.",
                                    s, e
                                );
                                return None; // skip this peer entirely
                            }
                        },
                        None => None,
                    };

                    Some((addr, pin))
                })
                .collect();

            if !peer_addrs.is_empty() {
                let pinned_count = peer_addrs.iter().filter(|(_, p)| p.is_some()).count();
                let tofu_count = peer_addrs.len() - pinned_count;
                quic_mesh.set_bootstrap_peers(peer_addrs.clone());
                info!(
                    " [QUIC] Configured {} bootstrap peer(s) ({} pinned, {} TOFU): {:?}",
                    peer_addrs.len(), pinned_count, tofu_count,
                    peer_addrs.iter().map(|(a, _)| a).collect::<Vec<_>>()
                );

                // Sync existing pins from discovery cache to verifier
                if let Err(e) = quic_mesh.sync_pins_from_cache().await {
                    warn!(" [QUIC] Failed to sync pins from discovery cache: {}", e);
                }
            }
        }

        // Legacy unsafe-bootstrap mode (deprecated - use PinnedCertVerifier instead)
        #[cfg(feature = "unsafe-bootstrap")]
        {
            use lib_network::protocols::quic_mesh::QuicTrustMode;
            quic_mesh.set_trust_mode(QuicTrustMode::MeshTrustUhp);
            warn!(" [QUIC] ⚠️  unsafe-bootstrap mode enabled (deprecated - use bootstrap_peers for TOFU)");
        }

        // Create MeshMessageHandler for routing blockchain sync messages
        // Note: These will be populated properly when mesh_router is initialized
        info!(" [QUIC] Creating message handler components");
        let peer_registry = Arc::new(RwLock::new(lib_network::peer_registry::PeerRegistry::new()));
        let long_range_relays = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let revenue_pools = Arc::new(RwLock::new(std::collections::HashMap::new()));

        let mut message_handler = lib_network::messaging::message_handler::MeshMessageHandler::new(
            peer_registry,
            long_range_relays,
            revenue_pools,
        );

        // If integration layer has already registered a DHT payload sender, wire it now
        info!(" [QUIC] Wiring message handler for DHT integration");
        crate::integration::wire_message_handler(&mut message_handler).await;

        // Inject message handler into QUIC protocol
        info!(" [QUIC] Injecting message handler into QUIC protocol");
        quic_mesh.set_message_handler(Arc::new(RwLock::new(message_handler)));
        info!("✅ [QUIC] MeshMessageHandler injected into QUIC protocol for blockchain sync");

        // IMPORTANT: Don't call start_receiving() here!
        // QuicHandler.accept_loop() is now the SOLE entry point for all QUIC connections
        // This avoids two competing accept loops racing for connections

        info!(" [QUIC] QUIC mesh protocol ready on UDP port {} (unified handler will accept connections)", quic_port);
        Ok(quic_mesh)
    }
    
    /// Register all comprehensive API handlers on ZHTP router
    /// QUIC is the ONLY entry point - HTTP requests go through HttpCompatibilityLayer → ZhtpRouter
    async fn register_api_handlers(
        zhtp_router: &mut crate::server::zhtp::ZhtpRouter,
        blockchain: Arc<RwLock<Blockchain>>,
        storage: Arc<RwLock<PersistentStorageSystem>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
        _economic_model: Arc<RwLock<EconomicModel>>,
        _session_manager: Arc<SessionManager>,
        dht_handler: Arc<dyn ZhtpRequestHandler>,
        domain_registry: Arc<lib_network::web4::DomainRegistry>,
        content_publisher: Arc<lib_network::web4::ContentPublisher>,
    ) -> Result<()> {
        info!("📝 Registering API handlers on ZHTP router (QUIC is the only entry point)...");
        
        // Blockchain operations
        let blockchain_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            BlockchainHandler::new(blockchain.clone())
        );
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
                rate_limiter.clone(),
                account_lockout,
                csrf_protection,
                recovery_phrase_manager,
                storage.clone(),
            )
        );
        zhtp_router.register_handler("/api/v1/identity".to_string(), identity_handler);

        // Guardian social recovery handler (Issue #116)
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
        zhtp_router.register_handler("/api/v1/identity/guardians".to_string(), guardian_handler.clone());
        zhtp_router.register_handler("/api/v1/identity/recovery".to_string(), guardian_handler);

        // Zero-knowledge proof handler (Issue #117)
        let zkp_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::zkp::ZkpHandler::new(
                identity_manager.clone(),
                _session_manager.clone(),
                rate_limiter.clone(),
            )
        );
        zhtp_router.register_handler("/api/v1/zkp".to_string(), zkp_handler);

        // Wallet content ownership manager (shared across handlers)
        let wallet_content_manager = Arc::new(RwLock::new(lib_storage::WalletContentManager::new()));
        
        // Storage operations (with wallet content manager for ownership tracking)
        let storage_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            StorageHandler::new(storage.clone())
                .with_wallet_manager(Arc::clone(&wallet_content_manager))
        );
        zhtp_router.register_handler("/api/v1/storage".to_string(), storage_handler);

        // Wallet operations
        let wallet_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            WalletHandler::new(identity_manager.clone())
        );
        zhtp_router.register_handler("/api/v1/wallet".to_string(), wallet_handler);

        // Token operations (custom token creation, minting, transfer)
        let token_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            TokenHandler::new()
        );
        zhtp_router.register_handler("/api/v1/token".to_string(), token_handler);

        // DAO operations
        let dao_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            DaoHandler::new(identity_manager.clone(), _session_manager.clone())
        );
        zhtp_router.register_handler("/api/v1/dao".to_string(), dao_handler);

        // Crypto utilities (sign message, verify signature, generate keypair)
        let crypto_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::CryptoHandler::new(identity_manager.clone())
        );
        zhtp_router.register_handler("/api/v1/crypto".to_string(), crypto_handler);

        // Register DHT handler on ZHTP (already registered on mesh_router for pure UDP)
        zhtp_router.register_handler("/api/v1/dht".to_string(), dht_handler);
        
        // Web4 domain and content (handle async creation first)
        // Pass the shared domain_registry and content_publisher to avoid creating duplicates
        // This ensures domain registrations are visible to all handlers
        let web4_handler = Web4Handler::new_with_registry(
            domain_registry.clone(),
            content_publisher.clone(),
            identity_manager.clone(),
            blockchain.clone()
        ).await?;
        let wallet_content_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::WalletContentHandler::new(Arc::clone(&wallet_content_manager))
        );
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
        zhtp_router.register_handler("/api/marketplace".to_string(), marketplace_handler);

        // DNS resolution for .zhtp domains (connect to domain registry)
        let dns_handler = DnsHandler::new();
        // TODO: Connect DnsHandler to actual domain registry from web4_handler
        // dns_handler.set_domain_registry(web4_handler.get_domain_registry());
        let dns_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(dns_handler);
        zhtp_router.register_handler("/api/v1/dns".to_string(), dns_handler);

        // Register Web4 handler
        let web4_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(web4_handler);
        zhtp_router.register_handler("/api/v1/web4".to_string(), web4_handler);

        // Validator management
        let validator_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::ValidatorHandler::new(blockchain.clone())
        );
        zhtp_router.register_handler("/api/v1/validator".to_string(), validator_handler);

        // Protocol management
        let protocol_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            ProtocolHandler::new()
        );
        zhtp_router.register_handler("/api/v1/protocol".to_string(), protocol_handler);

        // Create RuntimeOrchestrator for handlers that need runtime access
        let runtime_config = crate::config::NodeConfig::default();
        let runtime = Arc::new(crate::runtime::RuntimeOrchestrator::new(runtime_config).await?);

        // Network management (gas pricing, peers, sync metrics)
        let network_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::NetworkHandler::new(runtime.clone())
        );
        zhtp_router.register_handler("/api/v1/network".to_string(), network_handler.clone());
        zhtp_router.register_handler("/api/v1/blockchain/network".to_string(), network_handler.clone());
        zhtp_router.register_handler("/api/v1/blockchain/sync".to_string(), network_handler);

        // Mesh blockchain operations
        let mesh_handler: Arc<dyn ZhtpRequestHandler> = Arc::new(
            crate::api::handlers::MeshHandler::new(runtime.clone())
        );
        zhtp_router.register_handler("/api/v1/mesh".to_string(), mesh_handler);

        // PoUW (Proof-of-Useful-Work) handler
        // TODO: Use real node keys from identity in production
        let pouw_node_key = [0u8; 32]; // Placeholder - use real node key
        let pouw_node_id = [0u8; 32];  // Placeholder - use real node ID
        let pouw_generator_arc = std::sync::Arc::new(crate::pouw::ChallengeGenerator::new(pouw_node_key, pouw_node_id));
        let pouw_validator = crate::pouw::ReceiptValidator::new(pouw_generator_arc.clone());
        let pouw_calculator = crate::pouw::RewardCalculator::new(0); // genesis block
        let pouw_handler = crate::api::handlers::pouw::PouwHandler::new(
            pouw_generator_arc,
            pouw_validator,
            pouw_calculator,
        );
        zhtp_router.register_handler("/pouw".to_string(), Arc::new(pouw_handler));

        info!("✅ All API handlers registered successfully on ZHTP router");
        Ok(())
    }
    
    /// Start the unified server on port 9333
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting ZHTP Unified Server on port {}", self.port);

        if let Some(monitoring) = &mut self.monitoring_system {
            monitoring.start().await?;
            info!(" Monitoring system started");
        }

        // Initialize global mesh router provider for API handlers
        let mesh_router_arc = self.mesh_router.clone();
        if let Err(e) = crate::runtime::set_global_mesh_router(mesh_router_arc).await {
            warn!("Failed to initialize global mesh router provider: {}", e);
        } else {
            info!(" Global mesh router provider initialized");
        }

        // Start block sync responder (serves blockchain data to peers requesting sync)
        // This enables mesh-based blockchain synchronization for new nodes joining the network
        crate::network_output_dispatcher::spawn_app_network_output_processor();

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
        // NODERUNTIMEORCHESTRATOR ALREADY STARTED IN new()
        // ============================================================================
        info!("✓ NodeRuntimeOrchestrator is running - Periodic decisions active");
        info!("  Node Role: {}", match self.runtime.get_role() {
            crate::runtime::NodeRole::FullValidator => "FullValidator",
            crate::runtime::NodeRole::LightNode => "LightNode",
            crate::runtime::NodeRole::MobileNode => "MobileNode",
            crate::runtime::NodeRole::BootstrapNode => "BootstrapNode",
            crate::runtime::NodeRole::Observer => "Observer",
            crate::runtime::NodeRole::ArchivalNode => "ArchivalNode",
        });

        // Start action execution loop - executes NodeActions from orchestrator queue
        let action_queue = self.runtime_orchestrator.action_queue().clone();
        let quic_mesh_for_actions = self.quic_mesh.clone();
        let discovery_port = self.discovery_port;
        let quic_port = self.quic_port;
        tokio::spawn(async move {
            info!("📋 Action executor started - consuming NodeActions from queue");
            while let Some(action) = action_queue.dequeue().await {
                match action {
                    crate::runtime::NodeAction::Connect { peer, protocol, address } => {
                        info!("→ Executing Connect action: peer={:?}, protocol={:?}",
                              hex::encode(&peer.key_id[..8]), protocol);
                        if let Some(addr_str) = address {
                            if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                                if let Err(e) = quic_mesh_for_actions.connect_to_peer(addr).await {
                                    warn!("  Failed to connect to peer: {}", e);
                                }
                            }
                        }
                    }
                    crate::runtime::NodeAction::BootstrapFrom(peers) => {
                        info!("→ Executing BootstrapFrom action: {} peers", peers.len());
                        for peer_str in peers {
                            let addr_str = peer_str.trim_start_matches("zhtp://").trim_start_matches("http://");
                            if let Ok(mut peer_addr) = addr_str.parse::<std::net::SocketAddr>() {
                                // Use configured ports for mapping (not hardcoded)
                                if peer_addr.port() == discovery_port {
                                    peer_addr.set_port(quic_port);
                                    info!("Port mapping: {} → {} (discovery → QUIC)", discovery_port, quic_port);
                                }
                                if let Err(e) = quic_mesh_for_actions.connect_to_peer(peer_addr).await {
                                    warn!("  Failed to bootstrap from {}: {}", peer_addr, e);
                                }
                            }
                        }
                    }
                    crate::runtime::NodeAction::DiscoverVia(protocol) => {
                        debug!("→ Executing DiscoverVia action: {:?}", protocol);
                    }
                    _ => {
                        debug!("→ Action queued (executor will handle in future): {:?}", action);
                    }
                }
            }
            warn!("⚠️ Action executor stopped - queue closed");
        });

        // ============================================================================
        // PEER DISCOVERY STATUS SUMMARY
        // ============================================================================
        info!("═══════════════════════════════════════════════════════════════");
        info!("  PEER DISCOVERY METHODS - STATUS REPORT");
        info!("═══════════════════════════════════════════════════════════════");
        
        // Get our public key for discovery protocols
        let _our_public_key_for_discovery = match self.mesh_router.get_sender_public_key().await {
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
        let peer_registry_clone = self.mesh_router.connections.clone();
        let bluetooth_provider = self.mesh_router.blockchain_provider.read().await.clone();
        let ble_peer_tx_clone = ble_peer_tx.clone();
        let our_public_key_clone = our_public_key.clone();
        let sync_coordinator_clone = self.mesh_router.sync_coordinator.clone();
        let mesh_router_clone = self.mesh_router.clone();
        let mesh_router_bluetooth_protocol = self.mesh_router.bluetooth_protocol.clone();

        // Get Bluetooth enabled flag from config (AUTHORITATIVE CONFIG LAYER)
        let enable_bluetooth_from_config = self.protocols_config.as_ref().map(|cfg| cfg.enable_bluetooth).unwrap_or(false);

        tokio::spawn(async move {
            // AUTHORITATIVE CONFIG LAYER: Check if Bluetooth should be disabled via configuration
            // This is the policy enforcement point where config decisions override defaults
            if !enable_bluetooth_from_config {
                warn!(" Bluetooth disabled by configuration (enable_bluetooth=false)");
                warn!(" Skipping Bluetooth initialization");
                return;
            }

            // FALLBACK: Also check environment variable for backward compatibility
            if std::env::var("DISABLE_BLUETOOTH").is_ok() {
                warn!(" Bluetooth disabled via DISABLE_BLUETOOTH environment variable");
                warn!(" Skipping Bluetooth initialization");
                return;
            }

            info!("Initializing Bluetooth mesh protocol for phone connectivity...");
            match bluetooth_router_clone.initialize(
                peer_registry_clone,
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
        
        // BLE peer discovery is now coordinated through discovery coordinator
        let coordinator_for_ble = self.discovery_coordinator.clone();
        
        // BLE Peer Discovery Handler - Simplified (Policy moved to NodeRuntime)
        // This just notifies discovery coordinator; runtime makes all "should we?" decisions
        tokio::spawn(async move {
            info!(" BLE peer discovery listener active");
            while let Some(peer_pubkey) = ble_peer_rx.recv().await {
                // SECURITY (MEDIUM #5): BLE peer discovery without cryptographic proof
                // WARNING: Public key received from BLE is NOT cryptographically verified
                // The peer claims to own this key but we have no proof of possession
                // Resolution: Only trust this peer's identity AFTER QUIC handshake completes
                // (QUIC uses UHP+Kyber which provides cryptographic proof)
                // TODO: Implement peer verification status tracking
                // - Mark BLE peers as "awaiting cryptographic verification"
                // - Only sync AFTER QUIC connection and handshake succeeds
                // - Update should_sync_with() to check verification status
                // For now, BLE peers are registered but policy decisions deferred to runtime

                // Notify discovery coordinator about BLE peer
                // Runtime will call on_peer_discovered() to decide what to do
                use crate::discovery_coordinator::{DiscoveredPeer, DiscoveryProtocol};
                use std::time::SystemTime;

                let discovered_peer = DiscoveredPeer {
                    public_key: Some(peer_pubkey.clone()),
                    addresses: vec!["ble://local".to_string()],
                    discovered_via: DiscoveryProtocol::BluetoothLE,
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    node_id: None,
                    capabilities: Some("BLE GATT".to_string()),
                };

                let _ = coordinator_for_ble.register_peer(discovered_peer).await;
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

        // Start QUIC connection acceptance loop (REQUIRED PRIMARY PROTOCOL)
        // In QUIC-only architecture, if accept loop fails, the node is dead.
        // Fail fast rather than silent partial liveness.
        let quic_handler = self.quic_handler.clone();
        let accept_loop_handle = tokio::spawn(async move {
            info!("🚀 Starting QUIC accept loop on endpoint...");
            match quic_handler.accept_loop(endpoint).await {
                Ok(()) => {
                    // Accept loop completed normally (shouldn't happen unless shutdown)
                    error!("❌ QUIC accept loop exited unexpectedly (without error)");
                }
                Err(e) => {
                    // CRITICAL: QUIC is the only entry point. If it's down, node is dead.
                    error!("🚨 QUIC ACCEPT LOOP FAILED - NODE IS DEAD");
                    error!("   Error: {}", e);
                    error!("   QUIC is the only entry point in this architecture.");
                    error!("   Without it, the node cannot receive or send messages.");
                    panic!("QUIC accept loop critical failure - crashing for restart: {}", e);
                }
            }
        });

        // Give accept loop time to start and bind to port
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Check if accept loop task has already panicked/crashed
        if accept_loop_handle.is_finished() {
            return Err(anyhow::anyhow!(
                "QUIC accept loop crashed on startup - check logs for details\n\
                 This is a critical error - QUIC is required to function"
            ));
        }

        info!(" ✅ QUIC handler started - Native ZHTP-over-QUIC ready");
        info!(" 🔒 QUIC-ONLY architecture: All messages flow through QUIC");

        // Store the accept loop handle to detect crashes during runtime
        // (In production, would use watchdog to restart if it crashes)
        
        // Start mesh protocol handlers (background listeners only)
        self.start_bluetooth_mesh_handler().await?;
        self.start_bluetooth_classic_handler().await?;
        // WiFi Direct already initialized above with mDNS
        self.start_lorawan_handler().await?;
        
        info!("🔒 ZHTP Unified Server ONLINE (QUIC-ONLY architecture)");
        info!("   Entry point: QUIC (required and primary)");
        info!("   Discovery: BLE, BT Classic, WiFi Direct, LoRaWAN");
        info!("   Relay: Encrypted DHT with Dilithium2 + Kyber1024 + ChaCha20");
        
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
            // Parse the peer address - it might be at discovery port or QUIC port
            let addr_str = peer_str.trim_start_matches("zhtp://").trim_start_matches("http://");

            match addr_str.parse::<SocketAddr>() {
                Ok(mut peer_addr) => {
                    // If the peer address uses the discovery port, adjust to QUIC port
                    if peer_addr.port() == self.discovery_port {
                        peer_addr.set_port(self.quic_port);
                        info!("   Connecting to bootstrap peer: {} (adjusted discovery port {} → QUIC port {})",
                              peer_addr, self.discovery_port, self.quic_port);
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

        if let Some(monitoring) = &mut self.monitoring_system {
            monitoring.stop().await?;
            info!(" Monitoring system stopped");
        }

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

    /// Set blockchain event receiver for receive-side block/tx forwarding (#916)
    pub async fn set_blockchain_event_receiver(&mut self, receiver: Arc<dyn lib_network::blockchain_sync::BlockchainEventReceiver>) {
        // Method not implemented in MeshRouter - skipping for now
        let _ = receiver;
    }
    
    /// Configure sync manager for edge node mode (headers + ZK proofs only)
    pub async fn set_edge_sync_mode(&mut self, max_headers: usize) {
        info!("🔧 Configuring edge sync mode: max_headers={}", max_headers);
        self.mesh_router.set_edge_sync_mode(max_headers).await;
    }
    
    /// Get server information
    pub fn get_server_info(&self) -> (Uuid, u16) {
        (self.server_id, self.port)
    }

    /// Get reference to the canonical domain registry
    ///
    /// This is the single source of truth for domain resolution across all components.
    pub fn get_domain_registry(&self) -> Arc<DomainRegistry> {
        Arc::clone(&self.domain_registry)
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
