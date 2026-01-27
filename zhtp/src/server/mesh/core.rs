//! Mesh Router Core
//! 
//! Core mesh networking infrastructure with connection management

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
// UdpSocket removed - using QUIC only
use uuid::Uuid;
use anyhow::Result;
use lib_crypto::PublicKey;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Rate limiting state for ZHTP getter requests (100 req/30s per identity)
#[derive(Debug, Clone)]
pub struct ZhtpRateLimitState {
    pub request_count: u32,
    pub window_start: u64, // Unix timestamp in seconds
}

impl ZhtpRateLimitState {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            request_count: 0,
            window_start: now,
        }
    }
    
    /// Check if rate limit exceeded (100 req/30s)
    pub fn check_and_increment(&mut self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Reset if window expired (30 seconds)
        if now - self.window_start >= 30 {
            self.request_count = 0;
            self.window_start = now;
        }
        
        // Check if within limit
        if self.request_count >= 100 {
            return false; // Rate limit exceeded
        }
        
        self.request_count += 1;
        true // Within limit
    }
}
use lib_network::protocols::bluetooth::BluetoothMeshProtocol;
use lib_network::protocols::quic_mesh::QuicMeshProtocol;
use lib_network::protocols::zhtp_encryption::{ZhtpEncryptionManager, ZhtpEncryptionSession};
use lib_network::protocols::zhtp_auth::ZhtpAuthManager;
use crate::web4_stub::ZhtpRelayProtocol;
use lib_network::routing::message_routing::MeshMessageRouter;
use lib_network::transport::TransportManager;
use lib_blockchain::types::Hash;
use lib_blockchain::BlockchainBroadcastMessage;
use lib_identity::IdentityManager;
use lib_types::NodeId;
use lib_protocols::zhtp::ZhtpRequestHandler;
use crate::integration::{
    dht_integration_channel,
    setup_mesh_dht_integration,
    DhtIntegrationDispatcher,
    DhtIntegrationEvent,
    DhtPayloadSender,
    DhtStorageHandle,
};
use super::rate_limiting::ConnectionRateLimiter;
use super::identity_verification::IdentityVerificationCache;

use crate::session_manager::SessionManager;
use super::super::monitoring::{
    PeerRateLimit, BroadcastMetrics, PeerReputation,
    SyncPerformanceMetrics, SyncAlert, AlertThresholds,
    MetricsHistory
};

/// Mesh routing, metadata tracking, and service orchestration.
///
/// NOTE (Issue #907): `connections` (PeerRegistry) is metadata/reputation ONLY.
/// It is NOT used for transport decisions (send, broadcast, receive).
/// The canonical transport store is `QuicMeshProtocol.connections` (DashMap).
pub struct MeshRouter {
    /// Metadata-only peer registry. NOT used for transport.
    /// See `QuicMeshProtocol.connections` for the canonical connection store.
    pub connections: Arc<RwLock<lib_network::peer_registry::PeerRegistry>>,
    pub server_id: Uuid,
    pub identity_manager: Option<Arc<RwLock<IdentityManager>>>,
    pub session_manager: Arc<SessionManager>,
    
    // Encryption and authentication
    pub relay_protocol: Arc<RwLock<Option<ZhtpRelayProtocol>>>,
    pub encryption_manager: Arc<RwLock<ZhtpEncryptionManager>>,
    pub zhtp_auth_manager: Arc<RwLock<Option<ZhtpAuthManager>>>,
    pub encryption_sessions: Arc<RwLock<HashMap<String, ZhtpEncryptionSession>>>,
    
    // Blockchain sync infrastructure
    pub sync_manager: Arc<lib_network::blockchain_sync::BlockchainSyncManager>,
    pub sync_coordinator: Arc<lib_network::blockchain_sync::SyncCoordinator>,
    // Note: edge_sync_manager removed - use sync_manager.new_edge_node() instead
    pub blockchain_provider: Arc<RwLock<Option<Arc<dyn lib_network::blockchain_sync::BlockchainProvider>>>>,
    pub is_edge_node: Arc<RwLock<bool>>, // Track if this node is in edge mode
    
    // Protocol instances for sending
    pub bluetooth_protocol: Arc<RwLock<Option<Arc<BluetoothMeshProtocol>>>>,
    pub quic_protocol: Arc<RwLock<Option<Arc<QuicMeshProtocol>>>>,
    // UDP socket removed - using QUIC only
    
    // Real-time block propagation - duplicate detection
    pub recent_blocks: Arc<RwLock<HashMap<Hash, u64>>>,
    pub recent_transactions: Arc<RwLock<HashMap<Hash, u64>>>,
    
    // Blockchain broadcast receiver
    pub broadcast_receiver: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedReceiver<BlockchainBroadcastMessage>>>>,
    
    // Monitoring and metrics
    pub peer_rate_limits: Arc<RwLock<HashMap<String, PeerRateLimit>>>,
    pub broadcast_metrics: Arc<RwLock<BroadcastMetrics>>,
    pub peer_reputations: Arc<RwLock<HashMap<String, PeerReputation>>>,
    pub performance_metrics: Arc<RwLock<SyncPerformanceMetrics>>,
    pub active_alerts: Arc<RwLock<Vec<SyncAlert>>>,
    pub alert_thresholds: Arc<RwLock<AlertThresholds>>,
    pub metrics_history: Arc<RwLock<MetricsHistory>>,
    pub latency_samples_blocks: Arc<RwLock<Vec<u64>>>,
    pub latency_samples_txs: Arc<RwLock<Vec<u64>>>,
    
    // Multi-hop routing
    pub mesh_message_router: Arc<RwLock<MeshMessageRouter>>,
    
    // DHT storage and routing
    pub dht_storage: DhtStorageHandle,
    pub dht_handler: Arc<RwLock<Option<Arc<dyn ZhtpRequestHandler>>>>,
    /// DHT payload sender for wiring to message handlers (Ticket #154)
    pub dht_payload_sender: DhtPayloadSender,
    /// DHT integration dispatcher (Phase 4 relocation)
    pub dht_integration: DhtIntegrationDispatcher,
    
    // ZHTP API router for all endpoints
    pub zhtp_router: Arc<RwLock<Option<Arc<crate::server::zhtp::ZhtpRouter>>>>,
    
    // ✅ Phase 4: Network health monitoring from lib-network
    pub network_health_monitor: Arc<RwLock<Option<Arc<lib_network::monitoring::health_monitoring::HealthMonitor>>>>,
    pub mesh_protocol_stats: Arc<RwLock<lib_network::mesh::statistics::MeshProtocolStats>>,
    
    // ZHTP rate limiting (100 req/30s for free getters)
    pub zhtp_rate_limits: Arc<RwLock<HashMap<String, ZhtpRateLimitState>>>,

    // HIGH-4 FIX: Connection rate limiter for DoS protection
    pub connection_rate_limiter: Arc<ConnectionRateLimiter>,

    // MEDIUM-3 FIX: Identity verification cache for routing
    pub identity_verification_cache: Arc<IdentityVerificationCache>,
}

impl MeshRouter {
    pub fn new(server_id: Uuid, session_manager: Arc<SessionManager>) -> Self {
        // Create shared peer registry (Ticket #149: replaces connections HashMap)
        let connections = Arc::new(RwLock::new(lib_network::peer_registry::PeerRegistry::new()));
        
        // Create blockchain sync manager (defaults to full node mode)
        let sync_manager = Arc::new(lib_network::blockchain_sync::BlockchainSyncManager::new_full_node());
        
        // Create sync coordinator
        let sync_coordinator = Arc::new(lib_network::blockchain_sync::SyncCoordinator::new());
        
        // Create duplicate tracking for block propagation
        let recent_blocks = Arc::new(RwLock::new(HashMap::new()));
        let recent_transactions = Arc::new(RwLock::new(HashMap::new()));
        
        // Spawn cleanup task for duplicate tracking
        let recent_blocks_cleanup = recent_blocks.clone();
        let recent_transactions_cleanup = recent_transactions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                let cutoff = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() - 3600; // Keep 1 hour history
                
                // Cleanup old blocks
                let mut blocks = recent_blocks_cleanup.write().await;
                blocks.retain(|_, &mut ts| ts > cutoff);
                
                // Cleanup old transactions
                let mut txs = recent_transactions_cleanup.write().await;
                txs.retain(|_, &mut ts| ts > cutoff);
                
                debug!("Cleaned up duplicate tracking maps (blocks: {}, txs: {})", 
                       blocks.len(), txs.len());
            }
        });
        
        // Clone connections for router initialization
        let connections_for_router = connections.clone();
        let mesh_message_router = Arc::new(RwLock::new(
            MeshMessageRouter::new(
                connections_for_router.clone(),
                Arc::new(RwLock::new(HashMap::new()))
            )
        ));

        let (dht_dispatcher, dht_events_rx) = dht_integration_channel();
        tokio::spawn(crate::integration::dht_dispatcher::drain_dht_events(dht_events_rx));

        let dht_handles = setup_mesh_dht_integration(
            server_id,
            mesh_message_router.clone(),
            &dht_dispatcher,
        );
        let dht_storage = dht_handles.dht_storage;

        // Create DHT mesh transport (Ticket #154: routes DHT through mesh network)
        // The dht_payload_sender is used to inject received DHT messages into the transport
        // Note: Using generated keypair for DHT signing - in production this should be
        // wired to the node's actual identity keypair after handshake completes
        let dht_payload_sender = dht_handles.dht_payload_sender;
        dht_dispatcher.dispatch(DhtIntegrationEvent::RegisterPayloadSender {
            sender: dht_payload_sender.as_ref().clone(),
        });

        // Spawn cleanup task for DHT rate limits (every 5 minutes)
        {
            let rate_limit_cleanup_interval = tokio::time::Duration::from_secs(300);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(rate_limit_cleanup_interval).await;
                    // Rate limit cleanup is handled internally by the message handler
                    debug!("DHT rate limit cleanup cycle completed");
                }
            });
        }
        
        Self {
            connections,
            server_id,
            identity_manager: None,
            session_manager,
            relay_protocol: Arc::new(RwLock::new(None)),
            encryption_manager: Arc::new(RwLock::new(ZhtpEncryptionManager::new())),
            zhtp_auth_manager: Arc::new(RwLock::new(None)),
            encryption_sessions: Arc::new(RwLock::new(HashMap::new())),
            sync_manager,
            sync_coordinator,
            // Note: edge_sync_manager removed - use sync_manager with EdgeNodeStrategy
            is_edge_node: Arc::new(RwLock::new(false)), // Defaults to full node mode
            blockchain_provider: Arc::new(RwLock::new(None)),
            bluetooth_protocol: Arc::new(RwLock::new(None)),
            quic_protocol: Arc::new(RwLock::new(None)),
            // udp_socket removed - using QUIC only
            recent_blocks,
            recent_transactions,
            broadcast_receiver: Arc::new(RwLock::new(None)),
            peer_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            broadcast_metrics: Arc::new(RwLock::new(BroadcastMetrics::new())),
            peer_reputations: Arc::new(RwLock::new(HashMap::new())),
            performance_metrics: Arc::new(RwLock::new(SyncPerformanceMetrics::new())),
            active_alerts: Arc::new(RwLock::new(Vec::new())),
            alert_thresholds: Arc::new(RwLock::new(AlertThresholds::default())),
            metrics_history: Arc::new(RwLock::new(MetricsHistory::new(720, 60))),
            latency_samples_blocks: Arc::new(RwLock::new(Vec::new())),
            latency_samples_txs: Arc::new(RwLock::new(Vec::new())),
            mesh_message_router,
            dht_storage,
            dht_handler: Arc::new(RwLock::new(None)),
            dht_payload_sender,
            dht_integration: dht_dispatcher,
            zhtp_router: Arc::new(RwLock::new(None)),
            // ✅ Phase 4: Initialize network health monitoring
            network_health_monitor: Arc::new(RwLock::new(None)),
            mesh_protocol_stats: Arc::new(RwLock::new(lib_network::mesh::statistics::MeshProtocolStats::default())),
            
            // Initialize rate limiter for ZHTP getters
            zhtp_rate_limits: Arc::new(RwLock::new(HashMap::new())),

            // HIGH-4 FIX: Initialize connection rate limiter for DoS protection
            connection_rate_limiter: Arc::new(ConnectionRateLimiter::new()),

            // MEDIUM-3 FIX: Initialize identity verification cache
            identity_verification_cache: Arc::new(IdentityVerificationCache::new()),
        }
    }

    /// Expose the shared DHT storage handle for consumers that need to index data.
    pub fn dht_storage(&self) -> DhtStorageHandle {
        self.dht_storage.clone()
    }
    
    /// Get broadcast metrics
    pub async fn get_broadcast_metrics(&self) -> BroadcastMetrics {
        self.broadcast_metrics.read().await.clone()
    }
    
    /// Get list of connected peer addresses
    pub async fn get_peer_addresses(&self) -> Vec<String> {
        self.connections.read().await
            .all_peers()
            .filter_map(|peer_entry| peer_entry.endpoints.first().map(|e| e.address.to_address_string()))
            .collect()
    }
    
    /// Get peer reputation
    pub async fn get_peer_reputation(&self, peer_id: &str) -> Option<PeerReputation> {
        self.peer_reputations.read().await.get(peer_id).cloned()
    }
    
    /// Set DHT handler for pure UDP mesh protocol
    pub async fn set_dht_handler(&self, handler: Arc<dyn ZhtpRequestHandler>) {
        use tracing::info;
        *self.dht_handler.write().await = Some(handler);
        info!("📡 DHT handler registered for pure UDP mesh protocol");
    }

    /// Wire DHT payload sender to a message handler (Ticket #154)
    ///
    /// This connects the message handler to the MeshDhtTransport's receiver,
    /// enabling DHT payloads received over mesh to be processed by DhtStorage.
    ///
    /// Call this method for each message handler that should process DHT messages.
    pub fn wire_dht_to_message_handler(
        &self,
        handler: &mut lib_network::messaging::MeshMessageHandler
    ) {
        use tracing::info;
        crate::integration::wire_dht_payload_sender(handler, &self.dht_payload_sender);
        info!("🔗 DHT payload sender wired to message handler (Ticket #154)");
    }

    /// Get the DHT payload sender for wiring to external message handlers
    pub fn get_dht_payload_sender(&self) -> tokio::sync::mpsc::UnboundedSender<(Vec<u8>, NodeId)> {
        (*self.dht_payload_sender).clone()
    }
    
    pub async fn set_zhtp_router(&self, router: Arc<crate::server::zhtp::ZhtpRouter>) {
        use tracing::info;
        *self.zhtp_router.write().await = Some(router);
        info!("🔀 ZHTP router registered for UDP endpoint routing");
    }

    /// Set transport manager on mesh message router for protocol handler selection (Issue #167)
    pub async fn set_transport_manager(&self, manager: TransportManager) {
        use tracing::info;
        let mut router = self.mesh_message_router.write().await;
        router.transport_manager = Some(manager);
        info!("🚚 Transport manager registered for protocol handler selection (Issue #167)");
    }

    /// List all peer reputations
    pub async fn list_peer_reputations(&self) -> Vec<PeerReputation> {
        self.peer_reputations.read().await.values().cloned().collect()
    }
    
    /// Initialize ZHTP relay protocol with post-quantum encryption
    pub async fn initialize_relay_protocol(&self) -> Result<()> {
        use tracing::info;
        info!("Initializing ZHTP relay protocol with post-quantum encryption...");
        
        // Generate Dilithium2 keypair for signing relay messages
        let (dilithium_pubkey, dilithium_privkey) = lib_crypto::post_quantum::dilithium::dilithium2_keypair();
        
        // Create node capabilities for relay protocol
        let capabilities = lib_network::protocols::zhtp_auth::NodeCapabilities {
            has_dht: true,
            can_relay: true,
            max_bandwidth: 1000000, // 1 Gbps
            protocols: vec!["zhtp".to_string(), "dht".to_string()],
            reputation: 100,
            quantum_secure: true,
        };
        
        // Create relay protocol instance
        let relay = ZhtpRelayProtocol::new(
            dilithium_privkey,
            dilithium_pubkey,
            capabilities,
        );
        
        *self.relay_protocol.write().await = Some(relay);
        
        info!("✅ ZHTP relay protocol initialized (Dilithium2 + Kyber1024 + ChaCha20)");
        Ok(())
    }
    
    /// Initialize ZHTP authentication manager with blockchain identity
    pub async fn initialize_auth_manager(&self, blockchain_pubkey: PublicKey) -> Result<()> {
        use tracing::info;
        info!("🔐 Initializing ZHTP authentication manager...");
        
        let auth_manager = ZhtpAuthManager::new(blockchain_pubkey)?;
        *self.zhtp_auth_manager.write().await = Some(auth_manager);
        
        info!("✅ ZHTP authentication manager initialized");
        Ok(())
    }
    
    /// Bridge Bluetooth messages to DHT
    pub async fn bridge_bluetooth_to_dht(&self, message_data: &[u8], source_addr: &std::net::SocketAddr) -> Result<()> {
        // Delegate to the helper function
        super::helpers::bridge_bluetooth_to_dht(message_data, source_addr).await
    }
    
    /// Configure sync manager for edge node mode (headers + ZK proofs only)
    pub async fn set_edge_sync_mode(&self, max_headers: usize) {
        use tracing::info;
        
        // Set edge node flag
        *self.is_edge_node.write().await = true;
        
        // Create new edge node sync manager
        let new_sync_manager = Arc::new(lib_network::blockchain_sync::BlockchainSyncManager::new_edge_node(max_headers));
        
        // Update the QUIC message handler's sync manager
        if let Some(quic) = self.quic_protocol.read().await.as_ref() {
            if let Some(handler) = quic.message_handler.as_ref() {
                let mut handler_write = handler.write().await;
                handler_write.sync_manager = new_sync_manager.clone();
                info!("✅ Updated QUIC message handler to use EdgeNodeStrategy (max_headers={})", max_headers);
            }
        }
        
        info!("📱 Edge node mode configured with {} headers capacity", max_headers);
    }
}

impl Clone for MeshRouter {
    fn clone(&self) -> Self {
        Self {
            connections: Arc::new(RwLock::new(lib_network::peer_registry::PeerRegistry::new())),
            server_id: self.server_id,
            identity_manager: self.identity_manager.clone(),
            session_manager: self.session_manager.clone(),
            relay_protocol: self.relay_protocol.clone(),
            encryption_manager: self.encryption_manager.clone(),
            zhtp_auth_manager: self.zhtp_auth_manager.clone(),
            encryption_sessions: self.encryption_sessions.clone(),
            sync_manager: self.sync_manager.clone(),
            sync_coordinator: self.sync_coordinator.clone(),
            is_edge_node: self.is_edge_node.clone(),
            blockchain_provider: self.blockchain_provider.clone(),
            bluetooth_protocol: self.bluetooth_protocol.clone(),
            quic_protocol: self.quic_protocol.clone(),
            // udp_socket removed - using QUIC only
            recent_blocks: self.recent_blocks.clone(),
            recent_transactions: self.recent_transactions.clone(),
            broadcast_receiver: self.broadcast_receiver.clone(),
            peer_rate_limits: self.peer_rate_limits.clone(),
            broadcast_metrics: self.broadcast_metrics.clone(),
            peer_reputations: self.peer_reputations.clone(),
            performance_metrics: self.performance_metrics.clone(),
            active_alerts: self.active_alerts.clone(),
            alert_thresholds: self.alert_thresholds.clone(),
            metrics_history: self.metrics_history.clone(),
            latency_samples_blocks: self.latency_samples_blocks.clone(),
            latency_samples_txs: self.latency_samples_txs.clone(),
            mesh_message_router: self.mesh_message_router.clone(),
            dht_storage: self.dht_storage.clone(),
            dht_handler: self.dht_handler.clone(),
            dht_payload_sender: self.dht_payload_sender.clone(),
            dht_integration: self.dht_integration.clone(),
            zhtp_router: self.zhtp_router.clone(),
            // ✅ Phase 4: Clone network health monitoring
            network_health_monitor: self.network_health_monitor.clone(),
            mesh_protocol_stats: self.mesh_protocol_stats.clone(),
            zhtp_rate_limits: self.zhtp_rate_limits.clone(),
            connection_rate_limiter: self.connection_rate_limiter.clone(),
            identity_verification_cache: self.identity_verification_cache.clone(),
        }
    }
}
