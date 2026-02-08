// Protocols component - delegates to unified server and bootstrap service
// This file is a stub - full implementation to be extracted from components.rs

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
// Removed: create_default_storage_config - now using global storage provider
use crate::server::https_gateway::{HttpsGateway, GatewayTlsConfig};
use lib_protocols::{ZdnsServer, ZhtpIntegration};
use crate::web4_stub::{ZdnsResolver, ZdnsTransportServer, ZdnsServerConfig};

/// Protocols component - thin wrapper for unified server
pub struct ProtocolsComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    unified_server: Arc<RwLock<Option<crate::unified_server::ZhtpUnifiedServer>>>,
    zdns_server: Arc<RwLock<Option<ZdnsServer>>>,
    zdns_resolver: Arc<RwLock<Option<Arc<ZdnsResolver>>>>,
    zdns_transport: Arc<RwLock<Option<Arc<ZdnsTransportServer>>>>,
    lib_integration: Arc<RwLock<Option<ZhtpIntegration>>>,
    environment: crate::config::environment::Environment,
    api_port: u16,
    /// QUIC port for mesh connections (default: 9334)
    /// This is the PRIMARY port for all QUIC-based communication.
    quic_port: u16,
    /// DEPRECATED: Legacy port mapping reference (default: 9333).
    ///
    /// This port is NOT actively listened on for discovery (multicast uses 37775/UDP).
    /// It exists only for:
    /// 1. Port mapping when bootstrap peers are specified with 9333
    /// 2. WiFi Direct P2P TCP server (opt-in, requires group_owner=true)
    ///
    /// The node listens on:
    /// - 37775/UDP for multicast peer discovery
    /// - 9334/UDP for QUIC mesh connections
    ///
    /// See NETWORK_RULES.md for authoritative port documentation.
    discovery_port: u16,
    is_edge_node: bool,
    /// Enable ZDNS transport server (UDP/TCP DNS on port 53)
    enable_zdns_transport: bool,
    /// Gateway IP for ZDNS transport responses
    zdns_gateway_ip: std::net::Ipv4Addr,
    /// Bind address for ZDNS transport (defaults to localhost for safety)
    zdns_bind_addr: std::net::IpAddr,
    /// Enable HTTPS gateway for browser-based Web4 access
    enable_https_gateway: bool,
    /// HTTPS gateway configuration
    https_gateway_config: Option<GatewayTlsConfig>,
    /// HTTPS gateway instance
    https_gateway: Arc<RwLock<Option<HttpsGateway>>>,
}

impl std::fmt::Debug for ProtocolsComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolsComponent")
            .field("status", &"<ComponentStatus>")
            .field("environment", &self.environment)
            .field("api_port", &self.api_port)
            .finish()
    }
}

impl ProtocolsComponent {
    pub fn new(environment: crate::config::environment::Environment, api_port: u16) -> Self {
        Self::new_with_ports(environment, api_port, 9334, 9333)
    }

    pub fn new_with_ports(
        environment: crate::config::environment::Environment,
        api_port: u16,
        quic_port: u16,
        discovery_port: u16,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            zdns_resolver: Arc::new(RwLock::new(None)),
            zdns_transport: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            quic_port,
            discovery_port,
            is_edge_node: false,
            enable_zdns_transport: false, // Disabled by default (requires root for port 53)
            zdns_gateway_ip: std::net::Ipv4Addr::new(127, 0, 0, 1),
            zdns_bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            enable_https_gateway: false, // Disabled by default
            https_gateway_config: None,
            https_gateway: Arc::new(RwLock::new(None)),
        }
    }

    pub fn new_with_node_type(environment: crate::config::environment::Environment, api_port: u16, is_edge_node: bool) -> Self {
        Self::new_with_node_type_and_ports(environment, api_port, 9334, 9333, is_edge_node)
    }

    pub fn new_with_node_type_and_ports(
        environment: crate::config::environment::Environment,
        api_port: u16,
        quic_port: u16,
        discovery_port: u16,
        is_edge_node: bool,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            zdns_resolver: Arc::new(RwLock::new(None)),
            zdns_transport: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            quic_port,
            discovery_port,
            is_edge_node,
            enable_zdns_transport: false, // Disabled by default
            zdns_gateway_ip: std::net::Ipv4Addr::new(127, 0, 0, 1),
            zdns_bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            enable_https_gateway: false,
            https_gateway_config: None,
            https_gateway: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with ZDNS transport enabled (for gateway nodes)
    /// SECURITY: Binds to localhost by default - use with_zdns_bind_addr() for external exposure
    pub fn new_with_zdns_transport(
        environment: crate::config::environment::Environment,
        api_port: u16,
        gateway_ip: std::net::Ipv4Addr,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            zdns_resolver: Arc::new(RwLock::new(None)),
            zdns_transport: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            quic_port: 9334,
            discovery_port: 9333,
            is_edge_node: false,
            enable_zdns_transport: true,
            zdns_gateway_ip: gateway_ip,
            // SECURITY: Default to localhost even when enabled
            zdns_bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            enable_https_gateway: false,
            https_gateway_config: None,
            https_gateway: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with HTTPS gateway enabled for browser-based Web4 access
    /// SECURITY: Default config uses self-signed certs on port 8443
    pub fn new_with_https_gateway(
        environment: crate::config::environment::Environment,
        api_port: u16,
        gateway_config: GatewayTlsConfig,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            zdns_resolver: Arc::new(RwLock::new(None)),
            zdns_transport: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            quic_port: 9334,
            discovery_port: 9333,
            is_edge_node: false,
            enable_zdns_transport: false,
            zdns_gateway_ip: std::net::Ipv4Addr::new(127, 0, 0, 1),
            zdns_bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            enable_https_gateway: true,
            https_gateway_config: Some(gateway_config),
            https_gateway: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a full gateway node with both ZDNS transport and HTTPS gateway
    pub fn new_gateway_node(
        environment: crate::config::environment::Environment,
        api_port: u16,
        gateway_ip: std::net::Ipv4Addr,
        https_config: GatewayTlsConfig,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            unified_server: Arc::new(RwLock::new(None)),
            zdns_server: Arc::new(RwLock::new(None)),
            zdns_resolver: Arc::new(RwLock::new(None)),
            zdns_transport: Arc::new(RwLock::new(None)),
            lib_integration: Arc::new(RwLock::new(None)),
            environment,
            api_port,
            quic_port: 9334,
            discovery_port: 9333,
            is_edge_node: false,
            enable_zdns_transport: true,
            zdns_gateway_ip: gateway_ip,
            zdns_bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            enable_https_gateway: true,
            https_gateway_config: Some(https_config),
            https_gateway: Arc::new(RwLock::new(None)),
        }
    }

    /// Set ZDNS transport bind address (use with caution for 0.0.0.0)
    pub fn with_zdns_bind_addr(mut self, bind_addr: std::net::IpAddr) -> Self {
        self.zdns_bind_addr = bind_addr;
        self
    }

    /// Get reference to the ZDNS resolver (if initialized)
    pub async fn get_zdns_resolver(&self) -> Option<Arc<ZdnsResolver>> {
        self.zdns_resolver.read().await.clone()
    }
}

#[async_trait::async_trait]
impl Component for ProtocolsComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Protocols
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting protocols component with ZHTP Unified Server...");
        *self.status.write().await = ComponentStatus::Starting;

        lib_protocols::initialize().await?;

        info!("Initializing backend components for unified server...");

        // Use existing global blockchain (already initialized and syncing in Phase 2)
        info!(" Using existing global blockchain instance...");
        let blockchain = match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(shared_blockchain) => {
                info!(" ✓ Global blockchain found - continuing with synced data");
                shared_blockchain
            }
            Err(_) => {
                info!("⏳ Waiting for BlockchainComponent...");
                let mut attempts = 0;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    attempts += 1;
                    if let Ok(shared_blockchain) = crate::runtime::blockchain_provider::get_global_blockchain().await {
                        info!(" ✓ Global blockchain initialized");
                        break shared_blockchain;
                    }
                    if attempts >= 60 {
                        return Err(anyhow::anyhow!("Timeout waiting for BlockchainComponent"));
                    }
                }
            }
        };

        // Initialize network genesis hash for QUIC protocol (CRITICAL: must be before unified server creation)
        {
            let blockchain_read = blockchain.read().await;
            if !blockchain_read.blocks.is_empty() {
                let genesis_hash = blockchain_read.blocks[0].header.block_hash.as_array();
                // Use try_ version to avoid panic if already set (e.g., on restart)
                let _ = lib_identity::types::node_id::try_set_network_genesis(genesis_hash);
                info!(" ✓ Network genesis initialized for QUIC protocol");
            } else {
                return Err(anyhow::anyhow!("Blockchain has no genesis block"));
            }
        }

        // Get shared IdentityManager
        info!(" Getting shared IdentityManager...");
        let identity_manager = match crate::runtime::get_global_identity_manager().await {
            Ok(shared) => shared,
            Err(_) => {
                info!("⏳ Waiting for IdentityComponent...");
                let mut attempts = 0;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    attempts += 1;
                    if let Ok(shared) = crate::runtime::get_global_identity_manager().await {
                        break shared;
                    }
                    if attempts >= 60 {
                        return Err(anyhow::anyhow!("Timeout waiting for IdentityComponent"));
                    }
                }
            }
        };

        // Initialize economic model
        info!(" Initializing economic model...");
        let economic_model = Arc::new(RwLock::new(lib_economy::EconomicModel::new()));

        // Get storage from global provider (initialized by StorageComponent)
        info!(" Getting shared storage from global provider...");
        let storage = match crate::runtime::storage_provider::get_global_storage().await {
            Ok(storage) => {
                info!(" ✓ Using shared storage instance from StorageComponent");
                storage
            }
            Err(_) => {
                // Fallback: wait for StorageComponent to initialize
                info!("⏳ Waiting for StorageComponent to initialize storage...");
                let mut attempts = 0;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    attempts += 1;
                    if let Ok(storage) = crate::runtime::storage_provider::get_global_storage().await {
                        info!(" ✓ Storage became available after {} attempts", attempts);
                        break storage;
                    }
                    if attempts >= 30 {
                        return Err(anyhow::anyhow!("Timeout waiting for StorageComponent to initialize storage"));
                    }
                }
            }
        };

        info!("Creating ZHTP Unified Server...");
        let (peer_discovery_tx, _peer_discovery_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

        info!("Creating unified server with ports: API={}, QUIC={}, Discovery={}",
              self.api_port, self.quic_port, self.discovery_port);
        let mut unified_server = crate::unified_server::ZhtpUnifiedServer::new_with_peer_notification(
            blockchain.clone(),
            storage.clone(),
            identity_manager.clone(),
            economic_model.clone(),
            self.api_port,
            Some(peer_discovery_tx),
            Some(self.discovery_port),  // discovery_port from config
            Some(self.quic_port),       // quic_port from config
            None,  // protocols_config - will use defaults (Bluetooth disabled by default)
            None,  // bootstrap_peers - will use defaults
        ).await
            .map_err(|e| anyhow::anyhow!("Failed to create unified server: {}", e))?;
        
        // Initialize blockchain provider
        info!(" Setting up blockchain provider...");
        let blockchain_provider = Arc::new(crate::runtime::network_blockchain_provider::ZhtpBlockchainProvider::new());
        unified_server.set_blockchain_provider(blockchain_provider).await;

        // Inject receive-side event receiver for mesh block/tx forwarding (#916)
        let event_receiver = Arc::new(crate::runtime::network_blockchain_event_receiver::ZhtpBlockchainEventReceiver::new());
        unified_server.set_blockchain_event_receiver(event_receiver).await;
        info!("Blockchain event receiver injected for receive-side block/tx forwarding");
        
        // Configure sync mode based on node type
        if self.is_edge_node {
            info!("📱 Configuring Edge Node sync mode (headers + ZK proofs only)...");
            unified_server.set_edge_sync_mode(500).await;
        }
        
        // Initialize auth manager
        let mgr = identity_manager.read().await;
        let identities = mgr.list_identities();
        if !identities.is_empty() {
            let node_identity = if identities.len() >= 2 { &identities[1] } else { &identities[0] };
            let blockchain_pubkey = node_identity.public_key.clone();
            let _ = unified_server.initialize_auth_manager(blockchain_pubkey).await;
        }
        drop(mgr);
        
        // Initialize relay protocol
        let _ = unified_server.initialize_relay_protocol().await;
        
        // Initialize WiFi Direct auth
        let _ = unified_server.initialize_wifi_direct_auth(identity_manager.clone()).await;
        
        info!("Starting unified server on port {}...", self.api_port);
        unified_server.start().await?;

        // Initialize ZDNS resolver with caching, using the canonical domain registry
        info!(" Initializing ZDNS resolver with canonical domain registry...");
        let domain_registry = unified_server.get_domain_registry();
        let zdns_resolver = Arc::new(ZdnsResolver::new());
        *self.zdns_resolver.write().await = Some(zdns_resolver.clone());
        info!(" ✓ ZDNS resolver initialized with LRU cache (size: 10000, TTL: up to 1hr)");

        // Start ZDNS transport server if enabled (UDP/TCP DNS on port 53)
        if self.enable_zdns_transport {
            info!(" Starting ZDNS transport server (DNS on port 53)...");
            // SECURITY: Use builder pattern with explicit bind address
            let transport_config = ZdnsServerConfig::production(self.zdns_gateway_ip)
                .with_bind_addr(self.zdns_bind_addr);
            let transport_server = Arc::new(ZdnsTransportServer::new(
                zdns_resolver.clone(),
                transport_config,
            ));

            // Start the transport server in a background task
            let transport_clone: Arc<ZdnsTransportServer> = Arc::clone(&transport_server);
            tokio::spawn(async move {
                if let Err(e) = transport_clone.start().await {
                    warn!("ZDNS transport server error: {}", e);
                }
            });

            *self.zdns_transport.write().await = Some(transport_server);
            info!(" ✓ ZDNS transport server started (gateway IP: {}, bind: {})",
                  self.zdns_gateway_ip, self.zdns_bind_addr);
        }

        // Start HTTPS gateway if enabled (browser-based Web4 access)
        if self.enable_https_gateway {
            if let Some(ref gateway_config) = self.https_gateway_config {
                info!(" Starting HTTPS Gateway for browser-based Web4 access...");
                match HttpsGateway::new_with_zdns(
                    domain_registry.clone(),
                    zdns_resolver.clone(),
                    gateway_config.clone(),
                ).await {
                    Ok(gateway) => {
                        if let Err(e) = gateway.start().await {
                            warn!("Failed to start HTTPS gateway: {}", e);
                        } else {
                            info!(" ✓ HTTPS Gateway started on port {}", gateway_config.https_port);
                            if let Some(http_port) = gateway_config.http_port {
                                info!("   HTTP redirect on port {}", http_port);
                            }
                            *self.https_gateway.write().await = Some(gateway);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create HTTPS gateway: {}", e);
                    }
                }
            } else {
                warn!("HTTPS gateway enabled but no configuration provided");
            }
        }

        // Connect to bootstrap peers if configured
        let bootstrap_peers = crate::runtime::bootstrap_peers_provider::get_bootstrap_peers().await;
        if let Some(peers) = bootstrap_peers {
            if !peers.is_empty() {
                info!("Connecting to bootstrap peers via QUIC...");
                if let Err(e) = unified_server.connect_to_bootstrap_peers(peers).await {
                    warn!("Failed to connect to some bootstrap peers: {}", e);
                }
            }
        }
        
        *self.unified_server.write().await = Some(unified_server);
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("Protocols component started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping protocols component...");
        *self.status.write().await = ComponentStatus::Stopping;

        // Stop HTTPS gateway if running
        if let Some(gateway) = self.https_gateway.write().await.take() {
            info!(" Stopping HTTPS gateway...");
            gateway.stop().await;
        }

        // Stop ZDNS transport server if running
        if let Some(transport) = self.zdns_transport.write().await.take() {
            info!(" Stopping ZDNS transport server...");
            if let Err(e) = transport.stop().await {
                warn!("Failed to stop ZDNS transport server: {}", e);
            }
        }

        if let Some(mut server) = self.unified_server.write().await.take() {
            let _ = server.stop().await;
        }

        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        Ok(())
    }

    async fn health_check(&self) -> Result<ComponentHealth> {
        let status = self.status.read().await.clone();
        let start_time = *self.start_time.read().await;
        let uptime = start_time.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);
        
        Ok(ComponentHealth {
            status,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime,
            memory_usage: 0,
            cpu_usage: 0.0,
        })
    }

    async fn handle_message(&self, message: ComponentMessage) -> Result<()> {
        match message {
            ComponentMessage::HealthCheck => {
                debug!("Protocols component health check");
                Ok(())
            }
            _ => {
                debug!("Protocols component received message: {:?}", message);
                Ok(())
            }
        }
    }

    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        let start_time = *self.start_time.read().await;
        let uptime_secs = start_time.map(|t| t.elapsed().as_secs() as f64).unwrap_or(0.0);
        
        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert("is_running".to_string(), if matches!(*self.status.read().await, ComponentStatus::Running) { 1.0 } else { 0.0 });
        
        Ok(metrics)
    }
}
