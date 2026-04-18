//! Runtime Orchestration System
//!
//! Coordinates the lifecycle and interactions of all ZHTP components

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use super::config::NodeConfig;
use crate::api::handlers::constants::{SOV_WELCOME_BONUS, SOV_WELCOME_BONUS_SOV};
use crate::runtime::node_identity::{
    derive_node_id, log_runtime_node_identity, resolve_device_name, set_runtime_node_identity,
    RuntimeNodeIdentity,
};
// Removed ZK coordinator - using unified lib-proofs system directly

/// Information about an existing network discovered during startup
#[derive(Debug, Clone)]
pub struct ExistingNetworkInfo {
    pub peer_count: u32,
    pub chain_state: RemoteChainState,
    pub network_id: String,
    pub bootstrap_peers: Vec<String>,
    pub environment: crate::config::Environment,
}

/// Truth model for remote peer chain availability during startup.
///
/// A discovered peer address does not imply that chain state is known or syncable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteChainState {
    /// Discovery found peers, but their chain state could not be proven yet.
    Unknown,
    /// At least one peer explicitly reported genesis height with no committed blocks beyond it.
    GenesisOnly,
    /// At least one peer proved committed blocks beyond genesis.
    Committed(u64),
}

impl RemoteChainState {
    pub fn has_committed_blocks(&self) -> bool {
        matches!(self, Self::Committed(height) if *height > 0)
    }
}

impl std::fmt::Display for RemoteChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::GenesisOnly => write!(f, "genesis-only"),
            Self::Committed(height) => write!(f, "committed(height={height})"),
        }
    }
}

pub mod blockchain_provider;
pub mod bootstrap_peers_provider; // FIX: Global access to bootstrap peers for UnifiedServer
pub mod components;
pub mod dht_indexing;
pub mod did_startup;
pub mod edge_state_provider; // Global access to edge node state for header-only sync
pub mod identity_manager_provider;
pub mod mesh_router_provider;
pub mod network_blockchain_event_receiver;
pub mod network_blockchain_provider;
pub mod node_identity;
pub mod node_runtime;
pub mod node_runtime_orchestrator;
pub mod reward_orchestrator;
pub mod routing_rewards;
pub mod seed_storage;
pub mod services;
pub mod shared_blockchain;
pub mod shared_dht;
pub mod storage_provider; // Global access to storage for component sharing
pub mod storage_rewards;
#[cfg(test)]
pub mod test_api_integration;
pub mod token_utils;

pub use blockchain_provider::{
    initialize_global_blockchain_provider, is_global_blockchain_available, set_global_blockchain,
    set_global_catchup_trigger, trigger_global_catchup,
};
pub use components::*;
pub use identity_manager_provider::{
    get_global_identity_manager, initialize_global_identity_manager_provider,
    set_global_identity_manager,
};
pub use mesh_router_provider::{
    get_broadcast_metrics, initialize_global_mesh_router_provider, set_global_mesh_router,
};
pub use network_blockchain_provider::ZhtpBlockchainProvider;
pub use node_runtime::{
    DefaultNodeRuntime, DiscoveryProtocol, NodeAction, NodeRole, NodeRuntime, PeerInfo, PeerState,
    PeerStateChange, SyncType, Tick,
};
pub use node_runtime_orchestrator::NodeRuntimeOrchestrator;
pub use shared_blockchain::*;
pub use shared_dht::*;

/// Try to sync blockchain from bootstrap peers using paginated block-range QUIC requests.
///
/// Uses the same `/api/v1/blockchain/blocks/{start}/{end}` endpoint as the catch-up
/// sync path, fetching 50 blocks per page. This avoids the single-shot export which
/// hits the 16 MB QUIC message-size limit for any chain longer than ~700 blocks.
///
/// Returns:
///   `Ok(true)`  — synced successfully; caller should load from store and proceed.
///   `Ok(false)` — no peers had chain data at height > 0; creating genesis is safe.
///   `Err(_)`    — at least one peer had height > 0 but all sync attempts failed;
///                 the caller MUST NOT create genesis — it must retry until synced.
async fn try_initial_sync_from_peer(
    store: std::sync::Arc<lib_blockchain::storage::SledStore>,
    peers: &[String],
    trusted_sync_sources: &[crate::config::TrustedSyncSource],
) -> anyhow::Result<bool> {
    use lib_blockchain::storage::BlockchainStore;
    use lib_blockchain::sync::ChainSync;

    const BLOCKS_PER_PAGE: u64 = 50;
    // Safety cap: 50 000 pages × 50 = 2.5 M blocks
    const MAX_PAGES_PER_PEER: usize = 50_000;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let temp_identity = match lib_identity::ZhtpIdentity::new_unified(
        lib_identity::IdentityType::Device,
        None,
        None,
        &format!("temp-initial-sync-{}", timestamp),
        None,
    ) {
        Ok(id) => id,
        Err(e) => {
            error!(
                "❌ Failed to generate temporary identity for initial sync: {}",
                e
            );
            // Cannot verify peers — treat as "no data" so genesis is allowed.
            return Ok(false);
        }
    };

    // Determine local height and first block to fetch.
    // latest_height() returns Err(NotInitialized) when the store has no genesis yet —
    // in that case we must fetch starting from block 0 (genesis).
    // When Ok(h), genesis exists and blocks 0..=h are committed; fetch from h+1.
    let (local_height, first_start) = match (store.as_ref() as &dyn BlockchainStore).latest_height()
    {
        Ok(h) => (h, h.saturating_add(1)),
        Err(_) => (0u64, 0u64), // empty store — fetch genesis (block 0) first
    };

    let mut highest_peer_height: u64 = 0;

    for peer in peers {
        let peer_addr = match peer.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                warn!("⚠️  Skipping invalid bootstrap peer address: {}", peer);
                continue;
            }
        };

        info!(
            "🔄 Initial sync: checking peer {} (local height={}, first fetch from={})",
            peer_addr, local_height, first_start
        );

        use lib_network::client::{ZhtpClient, ZhtpClientConfig};
        let mut client = match ZhtpClient::new_bootstrap_with_config(
            temp_identity.clone(),
            ZhtpClientConfig {
                allow_bootstrap: true,
            },
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!("⚠️  Failed to create QUIC client for {}: {}", peer_addr, e);
                continue;
            }
        };

        match tokio::time::timeout(std::time::Duration::from_secs(10), client.connect(peer)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!("⚠️  Connect failed to {}: {}", peer_addr, e);
                continue;
            }
            Err(_) => {
                warn!("⚠️  Connect timeout to {}", peer_addr);
                continue;
            }
        }

        let peer_did = client.peer_did().map(str::to_owned);
        if !is_trusted_sync_source(peer, peer_did.as_deref(), trusted_sync_sources) {
            warn!(
                "⚠️  Skipping untrusted sync source {} (peer_did={})",
                peer_addr,
                peer_did.as_deref().unwrap_or("unknown")
            );
            continue;
        }

        // Check the peer's chain tip.
        let tip_resp = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.get("/api/v1/blockchain/tip"),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!("⚠️  Tip request failed for {}: {}", peer_addr, e);
                continue;
            }
            Err(_) => {
                warn!("⚠️  Tip request timeout for {}", peer_addr);
                continue;
            }
        };

        if !tip_resp.is_success() {
            warn!("⚠️  Peer {} returned non-success for /tip", peer_addr);
            continue;
        }

        #[derive(serde::Deserialize)]
        struct TipInfo {
            height: u64,
        }
        let tip: TipInfo = match serde_json::from_slice(&tip_resp.body) {
            Ok(t) => t,
            Err(e) => {
                warn!("⚠️  Failed to parse tip from {}: {}", peer_addr, e);
                continue;
            }
        };

        if tip.height == 0 || tip.height <= local_height {
            debug!(
                "Peer {} at height {} (local={}): no sync needed",
                peer_addr, tip.height, local_height
            );
            continue;
        }

        highest_peer_height = highest_peer_height.max(tip.height);
        info!(
            "📥 Peer {} at height {} — fetching blocks {}-{}",
            peer_addr,
            tip.height,
            local_height + 1,
            tip.height
        );

        // Paginated import: 200 blocks per request, same as consensus catch-up.
        let sync = ChainSync::new(store.clone() as std::sync::Arc<dyn BlockchainStore>);
        let mut cursor = local_height;
        let mut next_start = first_start; // may be 0 (empty store) or local_height+1
        let mut total_imported = 0usize;
        let mut page_error = false;

        for _ in 0..MAX_PAGES_PER_PEER {
            if next_start > tip.height {
                break;
            }
            let start = next_start;
            let end = tip.height.min(start + BLOCKS_PER_PAGE - 1);
            let url = format!("/api/v1/blockchain/blocks/{}/{}", start, end);

            let blocks_resp =
                match tokio::time::timeout(std::time::Duration::from_secs(60), client.get(&url))
                    .await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        warn!(
                            "⚠️  Blocks {}-{} request failed from {}: {}",
                            start, end, peer_addr, e
                        );
                        page_error = true;
                        break;
                    }
                    Err(_) => {
                        warn!(
                            "⚠️  Blocks {}-{} request timed out from {}",
                            start, end, peer_addr
                        );
                        page_error = true;
                        break;
                    }
                };

            if !blocks_resp.is_success() {
                warn!(
                    "⚠️  Blocks {}-{} from {} returned error: {}",
                    start, end, peer_addr, blocks_resp.status_message
                );
                page_error = true;
                break;
            }

            let blocks: Vec<lib_blockchain::Block> = match bincode::deserialize(&blocks_resp.body) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        "⚠️  Failed to deserialize blocks {}-{} from {}: {}",
                        start, end, peer_addr, e
                    );
                    page_error = true;
                    break;
                }
            };

            if blocks.is_empty() {
                break;
            }

            let page_count = blocks.len();
            match sync.import_blocks(blocks) {
                Ok(result) => {
                    total_imported += page_count;
                    cursor = result.final_height.unwrap_or(end);
                    next_start = cursor + 1;
                    info!(
                        "✅ Imported {} blocks (page), cursor now {}",
                        page_count, cursor
                    );
                }
                Err(e) => {
                    error!(
                        "❌ Failed to import blocks {}-{} from {}: {}",
                        start, end, peer_addr, e
                    );
                    page_error = true;
                    break;
                }
            }
        }

        if total_imported > 0 {
            info!(
                "✅ Initial sync complete: {} blocks from {} (height {}→{})",
                total_imported, peer_addr, local_height, cursor
            );
            return Ok(true);
        }

        if page_error {
            warn!("⚠️  Sync from {} failed mid-transfer", peer_addr);
        }
    }

    if highest_peer_height > 0 {
        // At least one peer had data but we could not import any of it.
        // The caller must NOT create genesis — it must wait and retry.
        Err(anyhow::anyhow!(
            "Peers have chain data (max height={}) but all sync attempts failed",
            highest_peer_height
        ))
    } else {
        // All peers were unreachable or at height 0 — safe to create genesis.
        Ok(false)
    }
}

pub(crate) fn is_trusted_sync_source(
    peer_address: &str,
    peer_did: Option<&str>,
    trusted_sync_sources: &[crate::config::TrustedSyncSource],
) -> bool {
    if trusted_sync_sources.is_empty() {
        return true;
    }

    trusted_sync_sources.iter().any(|trusted| {
        trusted.address == peer_address
            && trusted
                .peer_did
                .as_deref()
                .map(|expected_did| Some(expected_did) == peer_did)
                .unwrap_or(true)
    })
}

/// Component status information
#[derive(Debug, Clone, PartialEq)]
pub enum ComponentStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error(String),
    Registered,
    Failed,
}

/// Component health metrics
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub status: ComponentStatus,
    pub last_heartbeat: Instant,
    pub error_count: u64,
    pub restart_count: u64,
    pub uptime: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f32,
}

/// Inter-component message types
#[derive(Debug, Clone)]
pub enum ComponentMessage {
    // Lifecycle messages
    Start,
    Stop,
    Restart,
    HealthCheck,

    // Network messages
    PeerConnected(String),
    PeerDisconnected(String),
    NetworkUpdate(String),

    // Blockchain messages
    BlockMined(String),
    TransactionReceived(String),

    // Identity messages
    IdentityCreated(String),
    IdentityUpdated(String),

    // Storage messages
    FileStored(String),
    FileRequested(String),

    // Economics messages
    UbiPayment(String, u64),
    DaoProposal(String),

    // Blockchain access messages
    GetBlockchain,
    GetBlockchainResponse(Arc<RwLock<Option<lib_blockchain::Blockchain>>>),
    BlockchainOperation(String, Vec<u8>),

    // Custom messages
    Custom(String, Vec<u8>),
}

/// Component identifier
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ComponentId {
    Crypto,
    ZK,
    Identity,
    Storage,
    Network,
    NeuralMesh,
    Blockchain,
    Consensus,
    Economics,
    Protocols,
    Api,
}

impl std::fmt::Display for ComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentId::Crypto => write!(f, "crypto"),
            ComponentId::ZK => write!(f, "zk"),
            ComponentId::Identity => write!(f, "identity"),
            ComponentId::Storage => write!(f, "storage"),
            ComponentId::Network => write!(f, "network"),
            ComponentId::Blockchain => write!(f, "blockchain"),
            ComponentId::Consensus => write!(f, "consensus"),
            ComponentId::Economics => write!(f, "economics"),
            ComponentId::NeuralMesh => write!(f, "neural_mesh"),
            ComponentId::Protocols => write!(f, "protocols"),
            ComponentId::Api => write!(f, "api"),
        }
    }
}

/// Component interface trait
#[async_trait::async_trait]
pub trait Component: Send + Sync + std::fmt::Debug {
    /// Component identifier
    fn id(&self) -> ComponentId;

    /// Start the component
    async fn start(&self) -> Result<()>;

    /// Stop the component
    async fn stop(&self) -> Result<()>;

    /// Force stop the component (for emergency shutdown)
    async fn force_stop(&self) -> Result<()> {
        // Default implementation just calls regular stop
        self.stop().await
    }

    /// Check component health
    async fn health_check(&self) -> Result<ComponentHealth>;

    /// Handle inter-component messages
    async fn handle_message(&self, message: ComponentMessage) -> Result<()>;

    /// Get component metrics
    async fn get_metrics(&self) -> Result<HashMap<String, f64>>;

    /// Downcast to Any for type-specific access
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Runtime orchestrator that manages all ZHTP components
#[derive(Clone)]
pub struct RuntimeOrchestrator {
    config: NodeConfig,
    components: Arc<RwLock<HashMap<ComponentId, Arc<dyn Component>>>>,
    component_health: Arc<RwLock<HashMap<ComponentId, ComponentHealth>>>,
    message_bus: Arc<Mutex<mpsc::UnboundedSender<(ComponentId, ComponentMessage)>>>,
    shutdown_signal: Arc<Mutex<Option<mpsc::UnboundedSender<()>>>>,
    startup_order: Vec<ComponentId>,
    shared_blockchain: Arc<RwLock<Option<SharedBlockchainService>>>,
    user_wallet: Arc<RwLock<Option<crate::runtime::did_startup::WalletStartupResult>>>,

    // Genesis identities to be registered with IdentityManager on startup (PUBLIC DATA ONLY)
    genesis_identities: Arc<RwLock<Vec<lib_identity::ZhtpIdentity>>>,

    // Genesis private keys to be securely added to IdentityManager (NEVER touches blockchain)
    genesis_private_data: Arc<
        RwLock<
            Vec<(
                lib_identity::IdentityId,
                lib_identity::identity::PrivateIdentityData,
            )>,
        >,
    >,

    // Track if we joined an existing network (vs creating genesis)
    joined_existing_network: Arc<RwLock<bool>>,

    // Unified reward orchestrator
    reward_orchestrator: Arc<RwLock<Option<Arc<reward_orchestrator::RewardOrchestrator>>>>,

    // Node type detection
    is_edge_node: Arc<RwLock<bool>>,

    // Edge node configuration
    edge_max_headers: Arc<RwLock<usize>>,

    // Pending identity for blockchain registration after startup
    pending_identity: Arc<RwLock<Option<lib_identity::ZhtpIdentity>>>,

    /// Node role determines what services this node can run (mining, validation, etc.)
    node_role: Arc<RwLock<node_runtime::NodeRole>>,

    /// Channel for server-layer code to emit events to the NeuralMesh component.
    /// Call `emit_neural_event(msg)` to fire a `ComponentMessage` that reaches the
    /// NeuralMeshComponent's `handle_message()` via the message bus.
    neural_mesh_tx: Arc<Mutex<mpsc::UnboundedSender<ComponentMessage>>>,
}

impl RuntimeOrchestrator {
    /// Create a new runtime orchestrator
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
        let (neural_tx, mut neural_rx) = mpsc::unbounded_channel::<ComponentMessage>();

        // Spawn shutdown monitor task
        let shutdown_monitor = tokio::spawn(async move {
            if let Some(_shutdown_signal) = shutdown_rx.recv().await {
                tracing::info!("Shutdown signal received, initiating graceful shutdown");
            }
        });

        // Store shutdown monitor handle for cleanup
        let _shutdown_handle = shutdown_monitor;

        // ========================================================================
        // Issue #454 / PR #1120 feedback: Use canonical NodeType (already validated)
        // ========================================================================
        // config.node_type has been validated by the start_* method and represents
        // the SINGLE SOURCE OF TRUTH for node type. Use it to derive NodeRole
        // instead of re-detecting edge mode with different criteria, which could
        // cause divergence between dispatch and runtime behavior.
        // ========================================================================

        let node_type = config.node_type.expect(
            "NodeType must be set before RuntimeOrchestrator::new. \
             This should have been validated by the start_* method.",
        );

        // Derive is_edge_node from the canonical NodeType
        let is_edge_node = node_type == crate::config::NodeType::EdgeNode;

        // Debug output for node role derivation
        tracing::debug!("   canonical node_type: {:?}", node_type);
        tracing::debug!("   is_edge_node: {}", is_edge_node);

        // Derive NodeRole from canonical NodeType
        // This determines what services (mining, validation) the node can run
        let node_role = Self::derive_node_role_from_node_type(node_type);
        info!("🎭 Node role determined: {:?}", node_role);
        info!(
            "   can_mine: {}, can_validate: {}, can_verify_blocks: {}",
            node_role.can_mine(),
            node_role.can_validate(),
            node_role.can_verify_blocks()
        );

        let orchestrator = Self {
            config,
            components: Arc::new(RwLock::new(HashMap::new())),
            component_health: Arc::new(RwLock::new(HashMap::new())),
            message_bus: Arc::new(Mutex::new(message_tx)),
            shutdown_signal: Arc::new(Mutex::new(Some(shutdown_tx))),
            shared_blockchain: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(None)),
            genesis_identities: Arc::new(RwLock::new(Vec::new())),
            genesis_private_data: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: Arc::new(RwLock::new(false)),
            reward_orchestrator: Arc::new(RwLock::new(None)),
            is_edge_node: Arc::new(RwLock::new(is_edge_node)),
            edge_max_headers: Arc::new(RwLock::new(500)), // Default 500 headers (~100 KB)
            pending_identity: Arc::new(RwLock::new(None)),
            node_role: Arc::new(RwLock::new(node_role)),
            neural_mesh_tx: Arc::new(Mutex::new(neural_tx)),
            startup_order: vec![
                ComponentId::Crypto,     // Foundation layer
                ComponentId::ZK,         // Zero-knowledge proofs
                ComponentId::Identity,   // Identity management
                ComponentId::Storage,    // Distributed storage
                ComponentId::Network,    // Mesh networking
                ComponentId::NeuralMesh, // ML/AI optimization (routing, prefetch, anomaly)
                ComponentId::Blockchain, // Blockchain layer
                ComponentId::Protocols, // High-level protocols - MUST start before Consensus for mesh router
                ComponentId::Consensus, // Consensus mechanism - uses mesh router from Protocols
                ComponentId::Economics, // Economic incentives
            ],
        };

        // Start message handling task
        let components_clone = orchestrator.components.clone();
        tokio::spawn(async move {
            while let Some((component_id, message)) = message_rx.recv().await {
                let components = components_clone.read().await;
                if let Some(component) = components.get(&component_id) {
                    if let Err(e) = component.handle_message(message).await {
                        error!("Component {} failed to handle message: {}", component_id, e);
                    }
                }
            }
        });

        // Relay neural mesh events from the server layer → NeuralMeshComponent
        // Server-layer code (mesh, QUIC, DHT) calls emit_neural_event() which
        // pushes into neural_rx. This task forwards to the NeuralMeshComponent.
        let neural_components = orchestrator.components.clone();
        tokio::spawn(async move {
            while let Some(message) = neural_rx.recv().await {
                let components = neural_components.read().await;
                if let Some(component) = components.get(&ComponentId::NeuralMesh) {
                    if let Err(e) = component.handle_message(message).await {
                        debug!("Neural mesh event relay error: {}", e);
                    }
                }
            }
        });

        // Start health monitoring task
        let health_clone = orchestrator.component_health.clone();
        let components_clone = orchestrator.components.clone();
        let health_interval = orchestrator
            .config
            .integration_settings
            .health_check_interval_ms;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(health_interval));
            loop {
                interval.tick().await;

                let components = components_clone.read().await;
                let mut health = health_clone.write().await;

                for (id, component) in components.iter() {
                    match component.health_check().await {
                        Ok(health_info) => {
                            health.insert(id.clone(), health_info);
                        }
                        Err(e) => {
                            warn!("Health check failed for {}: {}", id, e);
                            let error_health = ComponentHealth {
                                status: ComponentStatus::Error(e.to_string()),
                                last_heartbeat: Instant::now(),
                                error_count: health.get(id).map(|h| h.error_count + 1).unwrap_or(1),
                                restart_count: health.get(id).map(|h| h.restart_count).unwrap_or(0),
                                uptime: health.get(id).map(|h| h.uptime).unwrap_or(Duration::ZERO),
                                memory_usage: 0,
                                cpu_usage: 0.0,
                            };
                            health.insert(id.clone(), error_health);
                        }
                    }
                }
            }
        });

        info!(
            "Runtime orchestrator initialized with {} components",
            orchestrator.startup_order.len()
        );
        Ok(orchestrator)
    }

    /// Derive the NodeRole from configuration settings
    ///
    /// This is the single source of truth for node role determination.
    /// The role determines what services (mining, validation) the node can run.
    ///
    /// # Role Determination Logic
    /// - FullValidator: validator_enabled=true (can mine and validate)
    /// - Observer: stores full blockchain but validator_enabled=false
    /// - LightNode: edge node with header-only sync
    /// - MobileNode: edge node optimized for BLE
    /// Derive NodeRole from the canonical NodeType
    ///
    /// This ensures NodeRole is always consistent with the dispatched NodeType,
    /// preventing divergence between config.node_type and runtime behavior.
    fn derive_node_role_from_node_type(
        node_type: crate::config::NodeType,
    ) -> node_runtime::NodeRole {
        use node_runtime::NodeRole;

        match node_type {
            crate::config::NodeType::Validator => {
                // Validator nodes participate in consensus and can mine blocks
                NodeRole::FullValidator
            }
            crate::config::NodeType::EdgeNode => {
                // Edge nodes are resource-constrained, only store headers
                // For now, treat all edge nodes as LightNode
                // TODO: Add mobile_mode detection for MobileNode role
                NodeRole::LightNode
            }
            crate::config::NodeType::FullNode => {
                // Full nodes store complete blockchain but don't mine
                NodeRole::Observer
            }
            crate::config::NodeType::Relay => {
                // Relay nodes only route messages, don't maintain blockchain state
                // They should not need a traditional NodeRole, but for now
                // treat them as Observer to avoid breaking existing code
                NodeRole::Observer
            }
            crate::config::NodeType::Gateway => {
                // Gateway nodes are public ingress proxies; they do not
                // maintain blockchain state and have their own NodeRole.
                NodeRole::Gateway
            }
        }
    }

    /// Get the current node role
    pub async fn get_node_role(&self) -> node_runtime::NodeRole {
        self.node_role.read().await.clone()
    }

    /// Get configuration for runtime operations
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Register a component with the orchestrator
    pub async fn register_component(&self, component: Arc<dyn Component>) -> Result<()> {
        let id = component.id();
        info!("Registering component: {}", id);

        let mut components = self.components.write().await;
        components.insert(id.clone(), component);

        // Initialize health tracking
        let mut health = self.component_health.write().await;
        health.insert(
            id.clone(),
            ComponentHealth {
                status: ComponentStatus::Stopped,
                last_heartbeat: Instant::now(),
                error_count: 0,
                restart_count: 0,
                uptime: Duration::ZERO,
                memory_usage: 0,
                cpu_usage: 0.0,
            },
        );

        debug!("Component {} registered successfully", id);
        Ok(())
    }

    /// Register all component instances (with singleton guard)
    pub async fn register_all_components(&self) -> Result<()> {
        info!("Registering all ZHTP component instances...");

        // Import all component types
        use crate::runtime::components::{
            ApiComponent, BlockchainComponent, ConsensusComponent, CryptoComponent,
            EconomicsComponent, IdentityComponent, NetworkComponent, ProtocolsComponent,
            StorageComponent, ZKComponent,
        };

        // Helper to check if component exists
        let is_registered =
            |id: ComponentId| async move { self.components.read().await.contains_key(&id) };

        // Register components in dependency order

        if !is_registered(ComponentId::Crypto).await {
            self.register_component(Arc::new(CryptoComponent::new()))
                .await?;
        }

        if !is_registered(ComponentId::ZK).await {
            self.register_component(Arc::new(ZKComponent::new()))
                .await?;
        }

        // Create Identity component with genesis identities AND private keys if available
        if !is_registered(ComponentId::Identity).await {
            let genesis_identities = self.genesis_identities.read().await.clone();
            let genesis_private_data = self.genesis_private_data.read().await.clone();
            let node_role_for_identity = self.node_role.read().await.clone();
            let is_bootstrap_leader = self.is_local_bootstrap_leader().await.unwrap_or(false);

            if genesis_identities.is_empty() {
                info!("Registering Identity component without genesis identities");
                self.register_component(Arc::new(IdentityComponent::new(
                    node_role_for_identity,
                    is_bootstrap_leader,
                )))
                .await?;
            } else {
                info!(" Registering Identity component with {} genesis identities and {} private keys",
                    genesis_identities.len(), genesis_private_data.len());
                self.register_component(Arc::new(
                    IdentityComponent::new_with_identities_and_private_data(
                        node_role_for_identity,
                        genesis_identities,
                        genesis_private_data,
                        is_bootstrap_leader,
                    ),
                ))
                .await?;
            }
        }

        if !is_registered(ComponentId::Storage).await {
            self.register_component(Arc::new(StorageComponent::new()))
                .await?;
        }

        if !is_registered(ComponentId::Network).await {
            self.register_component(Arc::new(NetworkComponent::new()))
                .await?;
        }

        if !is_registered(ComponentId::NeuralMesh).await {
            self.register_component(Arc::new(
                crate::runtime::components::NeuralMeshComponent::new(),
            ))
            .await?;
        }

        if !is_registered(ComponentId::Blockchain).await {
            // Pass user wallet, environment AND bootstrap validators to blockchain component for proper network initialization
            let user_wallet_guard = self.user_wallet.read().await;
            let user_wallet = user_wallet_guard.clone();
            let environment = self.config.environment; // Get environment from config
            let bootstrap_validators = self.config.network_config.bootstrap_validators.clone(); // Get bootstrap validators from config
            let bootstrap_peers = self.config.network_config.bootstrap_peers.clone();
            let joined_existing_network = *self.joined_existing_network.read().await; // Check if we joined existing network
            let node_role = self.node_role.read().await.clone();

            let blockchain_component = BlockchainComponent::new_with_full_config(
                node_role,
                user_wallet,
                environment,
                bootstrap_validators,
                bootstrap_peers,
                joined_existing_network,
            );
            self.register_component(Arc::new(blockchain_component))
                .await?;
        }

        // Protocols must start before Consensus so mesh router is available
        if !is_registered(ComponentId::Protocols).await {
            let environment = self.config.environment;
            let api_port = self.config.protocols_config.api_port;
            let quic_port = self.config.protocols_config.quic_port;
            let discovery_port = self.config.protocols_config.discovery_port;
            let is_edge_node = *self.is_edge_node.read().await;
            self.register_component(Arc::new(ProtocolsComponent::new_with_node_type_and_ports(
                environment,
                api_port,
                quic_port,
                discovery_port,
                is_edge_node,
            )))
            .await?;
        }

        if !is_registered(ComponentId::Consensus).await {
            let environment = self.config.environment;
            let node_role = self.node_role.read().await.clone();
            let min_stake = self.config.consensus_config.min_stake;
            let propose_timeout_ms = self.config.consensus_config.propose_timeout_ms;
            let prevote_timeout_ms = self.config.consensus_config.prevote_timeout_ms;
            let precommit_timeout_ms = self.config.consensus_config.precommit_timeout_ms;
            let bootstrap_validators = self.config.network_config.bootstrap_validators.clone();
            let oracle_mock_price = self.config.consensus_config.oracle_mock_sov_usd_price;
            self.register_component(Arc::new(
                ConsensusComponent::new_with_bootstrap_validators_and_oracle(
                    environment,
                    node_role,
                    min_stake,
                    bootstrap_validators,
                    oracle_mock_price,
                    propose_timeout_ms,
                    prevote_timeout_ms,
                    precommit_timeout_ms,
                ),
            ))
            .await?;
        }

        if !is_registered(ComponentId::Economics).await {
            self.register_component(Arc::new(EconomicsComponent::new()))
                .await?;
        }

        if !is_registered(ComponentId::Api).await {
            self.register_component(Arc::new(ApiComponent::new()))
                .await?;
        }

        info!("All components registered successfully");
        Ok(())
    }

    /// Set user wallet data for components that need it (replaces identity-based approach)
    pub async fn set_user_identity(
        &self,
        wallet: crate::runtime::did_startup::WalletStartupResult,
    ) -> Result<()> {
        let mut user_wallet = self.user_wallet.write().await;
        *user_wallet = Some(wallet);
        Ok(())
    }

    /// Set user wallet data for components that need it
    pub async fn set_user_wallet(
        &self,
        wallet: crate::runtime::did_startup::WalletStartupResult,
    ) -> Result<()> {
        // Store wallet in orchestrator for use during component creation
        let mut user_wallet = self.user_wallet.write().await;
        *user_wallet = Some(wallet.clone());
        info!("User wallet stored in orchestrator for component initialization");
        drop(user_wallet);

        // Extract and store genesis identities for IdentityManager registration (PUBLIC DATA ONLY)
        let mut genesis_identities = self.genesis_identities.write().await;
        genesis_identities.push(wallet.user_identity.clone());
        genesis_identities.push(wallet.node_identity.clone());
        info!(
            "Stored {} genesis identities (public data) for IdentityManager registration",
            genesis_identities.len()
        );
        drop(genesis_identities);

        // Store PRIVATE KEYS separately in secure memory (NEVER touches blockchain)
        let mut genesis_private_data = self.genesis_private_data.write().await;
        genesis_private_data.push((
            wallet.user_identity.id.clone(),
            wallet.user_private_data.clone(),
        ));
        genesis_private_data.push((
            wallet.node_identity.id.clone(),
            wallet.node_private_data.clone(),
        ));
        info!(
            " Stored {} private keys in secure memory (never stored on blockchain)",
            genesis_private_data.len()
        );
        info!(
            "    USER Identity ID: {}",
            hex::encode(&wallet.user_identity.id.0)
        );
        info!(
            "    NODE Identity ID: {}",
            hex::encode(&wallet.node_identity.id.0)
        );
        info!(
            "    USER Public Key (first 32): {}",
            hex::encode(&wallet.user_private_data.quantum_keypair.public_key[..32])
        );
        info!(
            "    NODE Public Key (first 32): {}",
            hex::encode(&wallet.node_private_data.quantum_keypair.public_key[..32])
        );
        drop(genesis_private_data);

        // Try to store identities in global IdentityManager if already available
        // Note: Private keys are now stored in identity.private_key field (P1-7)
        if let Ok(identity_manager_arc) =
            crate::runtime::identity_manager_provider::get_global_identity_manager().await
        {
            let mut manager = identity_manager_arc.write().await;
            manager.add_identity(wallet.user_identity.clone());
            manager.add_identity(wallet.node_identity.clone());
            info!(" Stored genesis identities in IdentityManager");
        } else {
            info!("  IdentityManager not yet initialized - identities will be loaded when IdentityComponent starts");
        }

        // CRITICAL: Check if global blockchain already has data (loaded from disk or synced)
        // This prevents double-loading and ensures we don't overwrite persisted data
        let blockchain_has_data =
            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(blockchain_arc) => {
                    let blockchain = blockchain_arc.read().await;
                    let has_data = blockchain.height > 0
                        || !blockchain.utxo_set.is_empty()
                        || !blockchain.token_contracts.is_empty();
                    if has_data {
                        info!(
                            "✓ Global blockchain has data (height: {}, UTXOs: {}, tokens: {})",
                            blockchain.height,
                            blockchain.utxo_set.len(),
                            blockchain.token_contracts.len()
                        );
                    }
                    has_data
                }
                Err(_) => false,
            };

        if blockchain_has_data {
            // Blockchain already loaded with data - don't create genesis
            info!("✓ Using existing blockchain data - skipping genesis creation");

            // CRITICAL: Ensure SOV token contract is always initialized
            // This handles upgrades from older blockchain data that didn't have the SOV token
            {
                let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get global blockchain: {}", e))?;
                let mut blockchain = blockchain_arc.write().await;

                let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();
                if !blockchain.token_contracts.contains_key(&sov_token_id) {
                    let sov_token = lib_blockchain::contracts::TokenContract::new_sov_native();
                    blockchain.token_contracts.insert(sov_token_id, sov_token);
                    info!(
                        "🪙 SOV token contract initialized (upgrade migration): {}",
                        hex::encode(&sov_token_id[..8])
                    );
                } else {
                    info!(
                        "✓ SOV token contract already present: {}",
                        hex::encode(&sov_token_id[..8])
                    );
                }
            }

            // Push wallet to BlockchainComponent if already registered
            let components = self.components.read().await;
            if let Some(component) = components.get(&ComponentId::Blockchain) {
                if let Some(blockchain_comp) =
                    component.as_any().downcast_ref::<BlockchainComponent>()
                {
                    blockchain_comp.set_user_wallet(wallet).await;
                    info!("✓ User wallet propagated to BlockchainComponent");
                }
            }

            return Ok(());
        }

        // No blockchain data - need to create genesis
        // IMPORTANT: Use the existing global blockchain (which has SledStore attached)
        // instead of loading from file - Phase 3 uses SledStore exclusively
        info!("📂 No existing blockchain data - creating genesis network");
        info!(" Using existing global blockchain with SledStore (Phase 3 storage)");

        // Get the existing blockchain that was set up with SledStore in start_node()
        let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get global blockchain for genesis: {}", e))?;

        // Creating NEW genesis network - no persisted blockchain found
        info!(" Creating NEW genesis network with user wallet funding...");

        // Get mutable access to the existing blockchain with SledStore attached
        {
            let mut blockchain = blockchain_arc.write().await;

            // Set development difficulty (easy mining for testing)
            // TODO: In production, keep the default INITIAL_DIFFICULTY (0x1d00ffff)
            if matches!(
                self.config.environment,
                crate::config::Environment::Development
            ) {
                blockchain.difficulty = lib_blockchain::types::Difficulty::from_bits(0x1fffffff);
                info!(" Development mode: Set blockchain mining profile difficulty to 0x1fffffff");
            }

            let genesis_validators = if !self.config.network_config.bootstrap_validators.is_empty()
            {
                let mut validators = Vec::new();
                for bootstrap in &self.config.network_config.bootstrap_validators {
                    let identity_id =
                        lib_identity::did::parse_did_to_identity_id(&bootstrap.identity_id)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "Invalid bootstrap validator DID {}: {}",
                                    bootstrap.identity_id,
                                    e
                                )
                            })?;
                    // Handle 0x prefix for consensus key (ref: commit 124ff65d)
                    let consensus_key = crate::runtime::components::consensus::decode_bootstrap_consensus_key(&bootstrap.consensus_key)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Bootstrap validator {} must have a valid hex consensus_key (with or without 0x prefix) in canonical genesis setup",
                                bootstrap.identity_id
                            )
                        })?;

                    // Validate network address (ref: commit 124ff65d)
                    let network_address = bootstrap.endpoints.first().ok_or_else(|| {
                        anyhow::anyhow!(
                            "Bootstrap validator {} must have at least one endpoint configured",
                            bootstrap.identity_id
                        )
                    })?;
                    Self::validate_validator_endpoint(network_address)?;

                    validators.push(crate::runtime::components::GenesisValidator {
                        identity_id,
                        node_device_id: None,
                        stake: bootstrap.stake.max(1_000),
                        storage_provided: bootstrap.storage_provided,
                        commission_rate: bootstrap.commission_rate,
                        consensus_key,
                        network_address: network_address.clone(),
                    });
                }
                validators
            } else {
                vec![crate::runtime::components::GenesisValidator {
                    identity_id: wallet.node_identity.id.clone(),
                    node_device_id: Some(wallet.node_identity_id.clone()),
                    stake: 1_000,
                    storage_provided: 0,
                    commission_rate: 500,
                    consensus_key: wallet.node_private_data.quantum_keypair.public_key.as_slice().try_into().unwrap_or([0u8; 2592]),
                    network_address: std::env::var("ZHTP_VALIDATOR_ENDPOINT").unwrap_or_default(),
                }]
            };

            // Extract primary wallet ID and public key from user identity
            let primary_wallet_info = {
                let primary_wallet = wallet
                    .user_identity
                    .wallet_manager
                    .wallets
                    .iter()
                    .find(|(_, w)| w.wallet_type == lib_identity::wallets::WalletType::Primary)
                    .map(|(id, w)| (id.clone(), w.public_key.clone()));

                if primary_wallet.is_none() {
                    warn!("  No primary wallet found in user identity - genesis will not fund user wallet");
                }

                primary_wallet
            };

            // Get genesis private data for wallet registry initialization
            let genesis_private_data = self.genesis_private_data.read().await.clone();

            // Fund the blockchain genesis with user wallet
            // Note: blockchain is already in global provider, this just funds it
            crate::runtime::components::BlockchainComponent::create_genesis_funding(
                &mut blockchain,
                genesis_validators,
                &self.config.environment,
                primary_wallet_info,
                Some(wallet.user_identity.id.clone()), // Pass user identity ID
                genesis_private_data, // Pass private data for Dilithium5 public key extraction
            )
            .await?;

            // Persist genesis in-memory SOV mints to the sled token_balances tree.
            // genesis_funding mints via token.mint() directly into token_contracts —
            // those mints are NOT in any block transaction, so they are invisible to
            // load_from_store on the next restart. Writing them to token_balances here
            // (idempotent) ensures every restart finds the correct genesis balances.
            if let Some(store) = blockchain.store.as_ref() {
                let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();
                if let Some(sov_contract) = blockchain.token_contracts.get(&sov_token_id) {
                    let entries: Vec<([u8; 32], u128)> = sov_contract
                        .balances_iter()
                        .map(|(pk, &bal)| (pk.key_id, bal))
                        .collect();
                    let token_id = lib_blockchain::storage::TokenId(sov_token_id);
                    match store.backfill_token_balances_from_contract(&token_id, &entries) {
                        Ok(n) if n > 0 => info!(
                            "💰 Persisted {} genesis SOV balances to token_balances tree",
                            n
                        ),
                        Ok(_) => {}
                        Err(e) => warn!(
                            "⚠️ Failed to persist genesis SOV balances to sled: {}",
                            e
                        ),
                    }
                }
            }
        } // Release write lock

        info!(" Global blockchain provider initialized with user wallet funding");

        // CRITICAL: Also push wallet to BlockchainComponent if already registered
        let components = self.components.read().await;
        if let Some(component) = components.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>()
            {
                blockchain_comp.set_user_wallet(wallet).await;
                info!(" User wallet propagated to BlockchainComponent");
            }
        }

        Ok(())
    }

    /// Set whether we joined an existing network (vs creating genesis)
    pub async fn set_joined_existing_network(&self, joined: bool) -> Result<()> {
        let mut joined_network = self.joined_existing_network.write().await;
        *joined_network = joined;
        if joined {
            info!(" Orchestrator: Joining existing network - genesis will NOT be created");
        } else {
            info!(" Orchestrator: Creating new genesis network");
        }
        Ok(())
    }

    /// Get current blockchain height (returns 0 if blockchain not initialized)
    pub async fn get_blockchain_height(&self) -> Result<u64> {
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let blockchain = blockchain_arc.read().await;
                Ok(blockchain.height)
            }
            Err(_) => Ok(0),
        }
    }

    /// Returns true when this node matches the first bootstrap validator identity.
    async fn is_local_bootstrap_leader(&self) -> Result<bool> {
        let leader_did = match self.config.network_config.bootstrap_validators.first() {
            Some(v) => v.identity_id.clone(),
            None => return Ok(false),
        };

        let keystore_path = crate::node_data_dir().join("keystore");

        let local_identity =
            crate::runtime::did_startup::load_node_identity_from_keystore(&keystore_path).await?;
        let Some(identity) = local_identity else {
            return Ok(false);
        };

        Ok(identity.did == leader_did)
    }

    /// Returns true if local persistent chain artifacts already exist.
    fn has_local_chain_data(&self) -> bool {
        let data_dir = self.config.environment.data_directory();
        let sled_path = std::path::Path::new(&data_dir).join("sled");
        if !sled_path.exists() {
            return false;
        }

        match std::fs::read_dir(sled_path) {
            Ok(mut entries) => entries.next().is_some(),
            Err(_) => false,
        }
    }

    fn should_skip_startup_sync(
        local_is_bootstrap_leader: bool,
        has_local_chain_data: bool,
    ) -> bool {
        local_is_bootstrap_leader && has_local_chain_data
    }

    /// Standalone observers must join an existing network unless they already have
    /// local chain state. They are not allowed to create a fresh genesis on an
    /// empty store, and discovery must distinguish unknown remote state from an
    /// explicit genesis-only network until blocks beyond genesis are committed.
    fn observer_requires_existing_network(config: &NodeConfig, has_local_chain_data: bool) -> bool {
        matches!(config.node_type, Some(crate::config::NodeType::FullNode)) && !has_local_chain_data
    }

    fn observer_admission_required(config: &NodeConfig) -> bool {
        matches!(config.node_type, Some(crate::config::NodeType::FullNode))
            && config.network_config.observer_admission.required
    }

    fn trusted_sync_sources(config: &NodeConfig) -> &[crate::config::TrustedSyncSource] {
        &config.network_config.observer_admission.trusted_sync_sources
    }

    fn validate_observer_admission_policy_config(
        config: &NodeConfig,
        has_local_chain_data: bool,
    ) -> Result<()> {
        if !Self::observer_admission_required(config) {
            return Ok(());
        }

        if config
            .network_config
            .observer_admission
            .authorized_observer_dids
            .is_empty()
        {
            return Err(anyhow::anyhow!(
                "Observer admission is required, but no authorized observer DIDs were configured."
            ));
        }

        if Self::observer_requires_existing_network(config, has_local_chain_data)
            && Self::trusted_sync_sources(config).is_empty()
        {
            return Err(anyhow::anyhow!(
                "Observer admission is required for a fresh observer, but no trusted sync sources were configured."
            ));
        }

        for trusted_source in Self::trusted_sync_sources(config) {
            Self::validate_validator_endpoint(&trusted_source.address).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid trusted observer sync source `{}`: {}",
                    trusted_source.address,
                    e
                )
            })?;
        }

        Ok(())
    }

    async fn validate_local_observer_admission(&self) -> Result<()> {
        if !Self::observer_admission_required(&self.config) {
            return Ok(());
        }

        let keystore_path = std::env::var_os("ZHTP_KEYSTORE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| crate::node_data_dir().join("keystore"));

        let local_identity =
            crate::runtime::did_startup::load_node_identity_from_keystore(&keystore_path).await?;
        let local_identity = local_identity.ok_or_else(|| {
            anyhow::anyhow!(
                "Observer admission is required, but no local node DID was available in the keystore."
            )
        })?;

        let admitted = self
            .config
            .network_config
            .observer_admission
            .authorized_observer_dids
            .iter()
            .any(|did| did == &local_identity.did);

        if admitted {
            info!("✓ Local observer DID admitted: {}", local_identity.did);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Observer DID `{}` is not admitted by config-backed observer admission policy.",
                local_identity.did
            ))
        }
    }

    fn validate_observer_join_policy(
        config: &NodeConfig,
        has_local_chain_data: bool,
        network_info: Option<&ExistingNetworkInfo>,
    ) -> Result<()> {
        if !Self::observer_requires_existing_network(config, has_local_chain_data) {
            return Ok(());
        }

        if network_info
            .map(|info| info.chain_state.has_committed_blocks())
            .unwrap_or(false)
        {
            return Ok(());
        }

        let configured_bootstrap_peers = config.network_config.bootstrap_peers.len();
        let discovered_peer_count = network_info.map(|info| info.peer_count).unwrap_or(0);
        let discovered_chain_state = network_info
            .map(|info| info.chain_state.to_string())
            .unwrap_or_else(|| RemoteChainState::Unknown.to_string());

        Err(anyhow::anyhow!(
            "Observer/full-node startup requires an existing network with committed blocks beyond genesis. \
             Local chain state is empty, discovered peers={}, discovered_chain_state={}, \
             configured_bootstrap_peers={}. Refusing to create genesis in observer mode.",
            discovered_peer_count,
            discovered_chain_state,
            configured_bootstrap_peers
        ))
    }

    fn should_retry_network_discovery_continuously(
        config: &NodeConfig,
        is_edge_node: bool,
        has_local_chain_data: bool,
    ) -> bool {
        is_edge_node || Self::observer_requires_existing_network(config, has_local_chain_data)
    }

    fn validate_validator_endpoint(network_address: &str) -> Result<()> {
        if network_address.trim().is_empty() {
            return Err(anyhow::anyhow!("Validator endpoint is empty"));
        }

        if let Ok(socket_addr) = network_address.parse::<std::net::SocketAddr>() {
            if socket_addr.ip().is_unspecified() {
                return Err(anyhow::anyhow!(
                    "Validator endpoint {} is not reachable by peers. Configure a concrete host/IP, not 0.0.0.0.",
                    network_address
                ));
            }
        }

        Ok(())
    }

    /// Wait for initial blockchain sync to reach at least height 1
    pub async fn wait_for_initial_sync(&self, timeout: std::time::Duration) -> Result<()> {
        let start = std::time::Instant::now();

        info!(
            "⏳ Waiting for initial blockchain sync (timeout: {:?})...",
            timeout
        );

        loop {
            if start.elapsed() > timeout {
                return Err(anyhow::anyhow!("Initial sync timeout after {:?}", timeout));
            }

            let height = self.get_blockchain_height().await?;
            if height > 0 {
                info!("✓ Initial sync complete: height = {}", height);
                return Ok(());
            }

            // Check every 500ms
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Start blockchain sync from existing network (called before identity setup)
    pub async fn start_blockchain_sync(
        &mut self,
        network_info: &ExistingNetworkInfo,
    ) -> Result<()> {
        info!(
            "📦 Starting blockchain sync from {} peers...",
            network_info.peer_count
        );

        // Initialize a temporary blockchain to receive sync data
        // This will be populated by the mesh sync before the full BlockchainComponent starts
        let blockchain = lib_blockchain::Blockchain::new()?;
        let blockchain_arc = Arc::new(RwLock::new(blockchain));

        // Set in global provider so sync handlers can access it
        crate::runtime::blockchain_provider::set_global_blockchain(blockchain_arc.clone()).await?;
        info!("✓ Temporary blockchain initialized for sync reception");

        // FIX: Store bootstrap peers in global provider so UnifiedServer can access them
        let peers = network_info.bootstrap_peers.clone();
        if !peers.is_empty() {
            info!(" Bootstrap peers available for sync: {:?}", peers);
            crate::runtime::bootstrap_peers_provider::set_bootstrap_peers(peers).await?;
        }

        // Store bootstrap peer SPKI pins in global provider (Issue #922)
        if !self.config.network_config.bootstrap_peer_pins.is_empty() {
            let pin_count = self.config.network_config.bootstrap_peer_pins.len();
            info!(
                " Storing {} bootstrap peer SPKI pin(s) from config",
                pin_count
            );
            crate::runtime::bootstrap_peers_provider::set_bootstrap_peer_pins(
                self.config.network_config.bootstrap_peer_pins.clone(),
            )
            .await;
        }

        // FIX(#916): Attempt QUIC-based blockchain sync from bootstrap peers BEFORE
        // wait_for_initial_sync(). Without this, the node always creates its own genesis.
        // Bootstrap peers are already QUIC addresses (e.g. 77.42.37.161:9334).
        if !network_info.bootstrap_peers.is_empty() {
            // Load node identity for QUIC client authentication
            match crate::runtime::create_or_load_node_identity(&self.config.environment).await {
                Ok(node_identity) => {
                    use lib_network::client::{ZhtpClient, ZhtpClientConfig};
                    use lib_network::web4::trust::TrustConfig;

                    let client_config = ZhtpClientConfig {
                        allow_bootstrap: true,
                    };
                    match ZhtpClient::new_with_config(
                        node_identity,
                        TrustConfig::bootstrap(),
                        client_config,
                    )
                    .await
                    {
                        Ok(mut client) => {
                            for peer in &network_info.bootstrap_peers {
                                info!("Attempting blockchain bootstrap sync from peer: {}", peer);
                                match client.connect(peer).await {
                                    Ok(()) => {
                                        info!("QUIC connection established to {}", peer);
                                        match crate::runtime::services::bootstrap_service::BootstrapService::try_bootstrap_blockchain_from_peer(
                                            &blockchain_arc,
                                            &client,
                                            peer,
                                        ).await {
                                            Ok(synced_chain) => {
                                                let synced_height = synced_chain.height;
                                                if synced_height > 0 {
                                                    *blockchain_arc.write().await = synced_chain;
                                                    info!("Bootstrap sync success: height={} from {}", synced_height, peer);
                                                    break; // Got data, stop trying peers
                                                } else {
                                                    info!("Peer {} has empty blockchain, trying next", peer);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Bootstrap sync from {} failed: {}", peer, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("QUIC connection to {} failed: {}", peer, e);
                                    }
                                }
                            }
                            client.close().await;
                        }
                        Err(e) => {
                            warn!("Failed to create QUIC client for bootstrap sync: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to load node identity for bootstrap sync: {}", e);
                }
            }
        }

        info!("✓ Blockchain ready to receive sync from network peers");
        Ok(())
    }

    /// Check if this node is configured as an edge node
    pub async fn is_edge_node(&self) -> bool {
        *self.is_edge_node.read().await
    }

    /// Set edge node mode (overrides auto-detection)
    pub async fn set_edge_node(&self, is_edge: bool) {
        *self.is_edge_node.write().await = is_edge;
    }

    /// Set edge node max headers configuration
    pub async fn set_edge_max_headers(&self, max_headers: usize) {
        *self.edge_max_headers.write().await = max_headers;
    }

    /// Get edge node max headers configuration
    pub async fn get_edge_max_headers(&self) -> usize {
        *self.edge_max_headers.read().await
    }

    // ========================================================================
    // CANONICAL STARTUP METHODS - Issue #454
    // ========================================================================
    // These are THE canonical entry points per node type. CLI dispatches to one
    // of these based on NodeType (not NodeRole). All node-type-specific initialization happens
    // within these methods, not scattered across component init functions.
    // ========================================================================

    /// Internal helper for validating NodeType matches expected type.
    /// Returns the validated NodeType if it matches, or an error if it doesn't.
    fn validate_node_type(
        config: &NodeConfig,
        expected: crate::config::NodeType,
    ) -> Result<crate::config::NodeType> {
        match config.node_type {
            Some(actual_type) => {
                if actual_type == expected {
                    Ok(actual_type)
                } else {
                    Err(anyhow::anyhow!(
                        "NodeType mismatch: expected {:?}, got {:?}",
                        expected,
                        actual_type
                    ))
                }
            }
            None => Err(anyhow::anyhow!(
                "NodeType is not set (expected {:?}). Runtime requires node_type to be derived during config aggregation.",
                expected
            )),
        }
    }

    /// Enforce the standalone observer startup contract for `NodeType::FullNode`.
    ///
    /// Full-node dispatch is the canonical observer startup path in this runtime.
    /// A config that explicitly requests `FullNode` but still enables validator behavior
    /// is internally contradictory and must be rejected at startup.
    fn validate_observer_startup_config(config: &NodeConfig) -> Result<()> {
        if config.consensus_config.validator_enabled {
            return Err(anyhow::anyhow!(
                "Invalid observer/full-node config: `node_type = full` requires \
                 `consensus_config.validator_enabled = false`."
            ));
        }

        if !matches!(
            config.node_role,
            crate::runtime::node_runtime::NodeRole::Observer
        ) {
            return Err(anyhow::anyhow!(
                "Invalid observer/full-node config: `node_type = full` must resolve to \
                 `NodeRole::Observer`, got {:?}.",
                config.node_role
            ));
        }

        Ok(())
    }

    /// Start a full node - THE canonical way
    ///
    /// Full nodes (FullNode type) store the complete blockchain and verify all blocks,
    /// but do NOT participate in consensus or mining.
    ///
    /// # Errors
    /// Returns an error if config.node_type is not FullNode.
    pub async fn start_full_node(config: NodeConfig) -> Result<Self> {
        Self::validate_node_type(&config, crate::config::NodeType::FullNode)?;
        Self::validate_observer_startup_config(&config)?;
        let orchestrator = Self::new(config).await?;
        orchestrator.start_node().await?;
        Ok(orchestrator)
    }

    /// Start an edge node - THE canonical way
    ///
    /// Edge nodes (EdgeNode type) only store block headers and ZK proofs,
    /// optimized for resource-constrained devices.
    ///
    /// # Errors
    /// Returns an error if config.node_type is not EdgeNode.
    pub async fn start_edge_node(config: NodeConfig) -> Result<Self> {
        Self::validate_node_type(&config, crate::config::NodeType::EdgeNode)?;
        let orchestrator = Self::new(config).await?;
        orchestrator.start_node().await?;
        Ok(orchestrator)
    }

    /// Start a validator node - THE canonical way
    ///
    /// Validator nodes (Validator type) store the complete blockchain, participate
    /// in consensus, and can mine blocks.
    ///
    /// # Errors
    /// Returns an error if config.node_type is not Validator.
    pub async fn start_validator(config: NodeConfig) -> Result<Self> {
        Self::validate_node_type(&config, crate::config::NodeType::Validator)?;
        let orchestrator = Self::new(config).await?;
        orchestrator.start_node().await?;
        Ok(orchestrator)
    }

    /// Start a relay node - THE canonical way
    ///
    /// Relay nodes act as routers on the network, forwarding messages and peer
    /// discovery information but NOT maintaining blockchain state or validating blocks.
    /// They are useful for improving network connectivity and message routing.
    ///
    /// # Errors
    /// Returns an error if config.node_type is not Relay.
    pub async fn start_relay(config: NodeConfig) -> Result<Self> {
        Self::validate_node_type(&config, crate::config::NodeType::Relay)?;

        let orchestrator = Self::new(config).await?;

        // For relay nodes, initialize ONLY mesh routing/networking components,
        // NOT the full blockchain startup sequence. Relays should not maintain
        // blockchain state or validate blocks - they only forward messages.
        use crate::runtime::components::{CryptoComponent, NetworkComponent};

        info!("Starting Relay Node - initializing mesh/routing only (no blockchain state)");

        // Initialize crypto and network components for routing
        orchestrator
            .register_component(Arc::new(CryptoComponent::new()))
            .await?;
        orchestrator.start_component(ComponentId::Crypto).await?;

        orchestrator
            .register_component(Arc::new(NetworkComponent::new()))
            .await?;
        orchestrator.start_component(ComponentId::Network).await?;

        info!("Relay node initialized (routing-only mode - ready for routing)");

        Ok(orchestrator)
    }

    /// Start a Gateway node (remote QUIC ingress proxy).
    ///
    /// Gateways accept native ZHTP over QUIC from clients, perform UHP v2
    /// handshake when required, and forward requests to backend validators
    /// via `BackendPool` / `Web4Client`.  No blockchain state, no consensus,
    /// no mining — pure ingress + forwarding.
    ///
    /// Configuration:
    /// - Uses `config.network_config.bootstrap_peers` as static backends.
    /// - Listens on UDP `0.0.0.0:7840` for QUIC (configurable via `ZHTP_GATEWAY_ADDR`).
    /// - Loads or creates a gateway identity in the node data directory.
    pub async fn start_gateway(config: NodeConfig) -> Result<Self> {
        Self::validate_node_type(&config, crate::config::NodeType::Gateway)?;

        let orchestrator = Self::new(config.clone()).await?;

        use crate::runtime::components::{CryptoComponent, NetworkComponent};

        info!("Starting Gateway Node - QUIC ingress proxy (no blockchain state)");

        // Initialize crypto and network components
        orchestrator
            .register_component(Arc::new(CryptoComponent::new()))
            .await?;
        orchestrator.start_component(ComponentId::Crypto).await?;

        orchestrator
            .register_component(Arc::new(NetworkComponent::new()))
            .await?;
        orchestrator.start_component(ComponentId::Network).await?;

        // ------------------------------------------------------------------
        // Gateway-specific: load identity, create service, start QUIC server
        // ------------------------------------------------------------------
        let data_dir = std::path::PathBuf::from(&config.data_directory);
        let identity = zhtp_daemon::identity::load_or_create(&data_dir)
            .context("Failed to load gateway identity")?;

        let _ = lib_identity::types::node_id::try_set_network_genesis(
            lib_identity::constants::TESTNET_GENESIS_HASH,
        );

        // Build a minimal daemon config from NodeConfig
        let bootstrap_peers = config.network_config.bootstrap_peers.clone();
        let daemon_config = zhtp_daemon::config::DaemonConfig {
            listen_addr: std::env::var("ZHTP_GATEWAY_HTTP_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:7840".to_string()),
            backend_nodes: bootstrap_peers.clone(),
            trust: zhtp_daemon::config::TrustSettings::default(),
            gateway: Some(zhtp_daemon::config::GatewayConfig {
                listen_addr: std::env::var("ZHTP_GATEWAY_HTTP_ADDR")
                    .unwrap_or_else(|_| "127.0.0.1:7840".to_string()),
                quic_listen_addr: std::env::var("ZHTP_GATEWAY_ADDR")
                    .unwrap_or_else(|_| "0.0.0.0:7840".to_string()),
                request_timeout_ms: 8000,
                connect_timeout_ms: 1500,
                backend_selection: zhtp_daemon::config::BackendSelectionPolicy::LowestLatency,
                retry_idempotent_requests: true,
                static_backends: bootstrap_peers,
                dynamic_backend_discovery: false,
                dynamic_backend_routing: false,
                health_check_interval_ms: 5000,
                unhealthy_threshold: 3,
                recovery_threshold: 2,
                cooldown_ms: 15000,
                max_in_flight_per_backend: 200,
            }),
        };

        let service = Arc::new(
            zhtp_daemon::service::ZhtpDaemonService::new(daemon_config.clone(), identity.clone())
                .await
                .context("Failed to create gateway service")?,
        );

        let gateway_cfg = daemon_config.effective_gateway_config();
        let quic_bind: std::net::SocketAddr = gateway_cfg
            .quic_listen_addr
            .parse()
            .with_context(|| format!("Invalid quic_listen_addr: {}", gateway_cfg.quic_listen_addr))?;

        let cert_path = data_dir.join("gateway-cert.pem");
        let key_path = data_dir.join("gateway-key.pem");

        let quic_server = zhtp_daemon::quic_server::QuicGatewayServer::new(
            quic_bind,
            service.clone(),
            Arc::new(identity),
            &cert_path,
            &key_path,
        )
        .await
        .context("Failed to create QUIC gateway server")?;

        info!(
            quic_addr = %quic_bind,
            backends = %gateway_cfg.static_backends.len(),
            "Gateway QUIC server starting"
        );

        // Spawn QUIC server into background; orchestrator keeps ownership.
        tokio::spawn(async move {
            if let Err(e) = quic_server.run().await {
                tracing::error!("QUIC gateway server error: {}", e);
            }
        });

        info!("Gateway node initialized and listening");

        Ok(orchestrator)
    }

    // ========================================================================
    // END CANONICAL STARTUP METHODS
    // ========================================================================

    /// Start the node with full startup sequence
    ///
    /// This is the main entry point called by CLI after configuration is loaded.
    /// It handles:
    /// 1. Network discovery and peer bootstrapping (delegated to lib-network)
    /// 2. Identity/wallet setup (delegated to lib-identity + lib-blockchain)
    /// 3. Blockchain sync coordination
    /// 4. Component registration and startup
    ///
    /// Architecture:
    /// - lib-identity: Creates identity/wallet objects (in-memory)
    /// - lib-blockchain: Registers them on-chain (permanent storage)
    /// - RuntimeOrchestrator: Coordinates the flow
    pub async fn start_node(&self) -> Result<()> {
        info!("🚀 Starting ZHTP node with full startup sequence");

        // ========================================================================
        // PHASE 1: Network Components (for peer discovery)
        // ========================================================================
        info!("📡 Starting network components for peer discovery...");
        use crate::runtime::components::{CryptoComponent, NetworkComponent};

        self.register_component(Arc::new(CryptoComponent::new()))
            .await?;
        self.start_component(ComponentId::Crypto).await?;

        self.register_component(Arc::new(NetworkComponent::new()))
            .await?;
        self.start_component(ComponentId::Network).await?;

        // Start Neural Mesh (ML/AI optimization layer)
        self.register_component(Arc::new(
            crate::runtime::components::NeuralMeshComponent::new(),
        ))
        .await?;
        self.start_component(ComponentId::NeuralMesh).await?;

        // Give network time to initialize
        tokio::time::sleep(Duration::from_secs(2)).await;

        // ========================================================================
        // PHASE 2: Peer Discovery
        // ========================================================================
        info!("🔍 Discovering peers on local network...");

        // Start local network discovery via multicast
        let node_uuid = uuid::Uuid::new_v4();
        let mesh_port = self.config.network_config.mesh_port;

        // Generate a temporary public key for discovery
        let keypair = lib_crypto::generate_keypair()?;
        let public_key = lib_crypto::PublicKey {
            dilithium_pk: keypair.public_key.dilithium_pk.clone(),
            kyber_pk: keypair.public_key.kyber_pk.clone(),
            key_id: keypair.public_key.key_id.clone(),
        };

        // Create signing context for TLS certificate pinning (Issue #739)
        // This requires the TLS certificate to exist (created by QUIC server)
        let signing_ctx = lib_network::protocols::quic_mesh::get_tls_spki_hash_from_default_cert()
            .map(|tls_spki_sha256| {
                lib_network::discovery::local_network::DiscoverySigningContext {
                    dilithium_sk: keypair.private_key.dilithium_sk.clone(),
                    dilithium_pk: keypair.public_key.dilithium_pk.clone(),
                    tls_spki_sha256,
                }
            });

        if signing_ctx.is_some() {
            info!("TLS certificate pinning enabled for discovery announcements");
        } else {
            debug!("TLS certificate not yet available - discovery announcements will be unsigned");
        }

        // Start local discovery service (runs in background)
        if let Err(e) = lib_network::discovery::start_local_discovery(
            node_uuid,
            mesh_port,
            public_key,
            None, // No callback needed for now
            signing_ctx,
        )
        .await
        {
            warn!("Failed to start local discovery: {}", e);
        }

        // Discover existing network using bootstrap peers and DHT
        let is_edge_node = *self.is_edge_node.read().await;
        let network_info = self
            .discover_network_with_retry(is_edge_node)
            .await
            .ok()
            .flatten();

        let has_local_chain_data = self.has_local_chain_data();
        Self::validate_observer_admission_policy_config(&self.config, has_local_chain_data)?;
        self.validate_local_observer_admission().await?;

        // Always store bootstrap peers for persistent QUIC outbound connections.
        // start_blockchain_sync() (which normally does this) is skipped for bootstrap leaders
        // with local data, so we must store here unconditionally. Without this the consensus
        // broadcaster has no peers to send votes to.
        {
            let cfg_peers = self.config.network_config.bootstrap_peers.clone();
            if !cfg_peers.is_empty() {
                match crate::runtime::bootstrap_peers_provider::set_bootstrap_peers(
                    cfg_peers.clone(),
                )
                .await
                {
                    Ok(()) => info!(
                        "Stored {} bootstrap peer(s) for persistent QUIC connections: {:?}",
                        cfg_peers.len(),
                        cfg_peers
                    ),
                    Err(e) => warn!("Failed to store bootstrap peers: {}", e),
                }
            }
        }

        // Only join an existing network if at least one peer proves committed blocks.
        // Unknown remote state and explicit genesis-only peers are both non-joinable,
        // but they remain distinct conditions for observer startup policy and logging.
        //
        // Bootstrap leader with local chain data must NOT wait on peer startup/sync.
        // This keeps G1 deterministic across restarts and avoids startup races.
        let local_is_bootstrap_leader = match self.is_local_bootstrap_leader().await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Failed to determine bootstrap leader identity from keystore: {}",
                    e
                );
                false
            }
        };
        let leader_has_local_data =
            Self::should_skip_startup_sync(local_is_bootstrap_leader, has_local_chain_data);
        let joined_existing_network = if leader_has_local_data {
            info!("🌱 Bootstrap leader with local chain data detected - skipping startup sync");
            false
        } else {
            network_info
                .as_ref()
                .map(|ni| ni.chain_state.has_committed_blocks())
                .unwrap_or(false)
        };
        self.set_joined_existing_network(joined_existing_network)
            .await?;

        // Phase 3: Use SledStore for persistent blockchain storage
        // This replaces the deprecated file-based storage with incremental Sled DB
        let data_dir = self.config.environment.data_directory();
        let sled_path = std::path::Path::new(&data_dir).join("sled");

        info!("📂 Opening SledStore at {:?}", sled_path);

        // Create data directory if it doesn't exist
        if let Some(parent) = sled_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Try to open SledStore.
        //
        // On error we do NOT assume corruption and do NOT delete data automatically —
        // the failure could be a permission issue, a file lock from another process,
        // or a transient I/O error. Unconditionally wiping the store on any error
        // risks data loss for non-corruption failures.
        //
        // Operators who are certain the store is corrupted and want to reset it can
        // opt in by setting ZHTP_SLED_RESET_ON_ERROR=true (or =1) before restarting.
        let store = match lib_blockchain::storage::SledStore::open(&sled_path) {
            Ok(s) => std::sync::Arc::new(s),
            Err(e) => {
                let allow_reset = std::env::var("ZHTP_SLED_RESET_ON_ERROR")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                if !allow_reset {
                    error!(
                        "Failed to open SledStore at {:?}: {}. \
                         To attempt a destructive reset, set ZHTP_SLED_RESET_ON_ERROR=true and restart.",
                        sled_path, e
                    );
                    return Err(anyhow::anyhow!(
                        "Failed to open SledStore at {:?}: {}",
                        sled_path,
                        e
                    ));
                }

                warn!(
                    "⚠️  SledStore open error ({}). ZHTP_SLED_RESET_ON_ERROR is set — \
                     wiping store directory and continuing with canonical startup flow",
                    e
                );
                if let Err(rm_err) = std::fs::remove_dir_all(&sled_path) {
                    warn!(
                        "   Failed to remove sled directory during reset: {}",
                        rm_err
                    );
                }
                std::fs::create_dir_all(&sled_path)?;
                std::sync::Arc::new(
                    lib_blockchain::storage::SledStore::open(&sled_path).map_err(|e2| {
                        anyhow::anyhow!("Failed to re-open fresh SledStore after reset: {}", e2)
                    })?,
                )
            }
        };

        let mut synced_blockchain: Option<lib_blockchain::Blockchain> = None;
        let emergency_restore_enabled = self.config.emergency_restore_from_local;
        if emergency_restore_enabled {
            warn!(
                "⚠️  Emergency restore mode enabled: local blockchain.dat reads are permitted for recovery only"
            );
            if self.config.allow_emergency_restore_genesis_mismatch {
                warn!(
                    "⚠️  Emergency restore genesis mismatch override enabled: incompatible local files will be accepted with warnings"
                );
            }
        }

        let dat_path = std::path::PathBuf::from(self.config.environment.blockchain_data_path());

        let (blockchain, was_loaded) = match lib_blockchain::Blockchain::load_from_store(
            store.clone(),
        )? {
            Some(mut bc) => {
                info!(
                    "📂 Loaded existing blockchain from SledStore (height: {}, tokens: {})",
                    bc.height,
                    bc.token_contracts.len()
                );

                // CRITICAL: Ensure SOV token contract is always initialized
                // This handles upgrades from older blockchain data that didn't have the SOV token
                let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();
                if !bc.token_contracts.contains_key(&sov_token_id) {
                    let sov_token = lib_blockchain::contracts::TokenContract::new_sov_native();
                    bc.token_contracts.insert(sov_token_id, sov_token.clone());

                    info!("🪙 SOV token contract initialized (persistence deferred to next block commit): {}", hex::encode(&sov_token_id[..8]));
                }

                if bc.oracle_state.committee.members().is_empty() {
                    if emergency_restore_enabled {
                        let restored = try_restore_oracle_from_dat(
                            &mut bc,
                            &dat_path,
                            self.config.allow_emergency_restore_genesis_mismatch,
                        )?;
                        if !restored {
                            warn!(
                                "⚠️  Oracle committee missing after canonical Sled load and no compatible emergency backup was restored. \
                                 Will attempt bootstrap from validator registry during startup."
                            );
                        }
                    } else {
                        // Oracle state is not persisted in the reset/genesis sled — it will be
                        // bootstrapped from the validator registry during startup_sequence.
                        // Do not hard-fail here: the bootstrap at ensure_oracle_committee_bootstrapped()
                        // handles this case for fresh chains and post-reset nodes.
                        warn!(
                            "⚠️  Oracle committee missing after canonical Sled load. \
                             Will bootstrap from validator registry during startup."
                        );
                    }
                } else {
                    info!(
                        "[startup] oracle_state: reconstructed from blockchain state (height {})",
                        bc.height
                    );
                }

                if bc.get_active_validators().is_empty() {
                    let restored = if emergency_restore_enabled {
                        try_restore_validators_from_dat(
                            &mut bc,
                            &dat_path,
                            self.config.allow_emergency_restore_genesis_mismatch,
                        )?
                    } else {
                        false
                    };
                    if !restored {
                        seed_validators_from_bootstrap_config(
                            &mut bc,
                            &self.config.network_config.bootstrap_validators,
                        );
                    }
                }

                (bc, true)
            }
            None => {
                if emergency_restore_enabled {
                    if let Some(mut bc) = load_validated_blockchain_dat(
                        &dat_path,
                        self.config.allow_emergency_restore_genesis_mismatch,
                    )? {
                        warn!(
                            "⚠️  Emergency restore: recovered blockchain from local backup file (height: {})",
                            bc.height
                        );
                        bc.set_store(store.clone());
                        let store_ref: &dyn lib_blockchain::storage::BlockchainStore =
                            store.as_ref();
                        let mut migration_ok = true;
                        for block in &bc.blocks {
                            let h = block.height();
                            if let Err(e) = store_ref.begin_block(h) {
                                warn!(
                                    "⚠️  Failed to begin emergency migration tx for block {}: {}",
                                    h, e
                                );
                                migration_ok = false;
                                break;
                            }
                            let write_result = store_ref
                                .append_block(block)
                                .and_then(|_| store_ref.commit_block());
                            if let Err(e) = write_result {
                                warn!(
                                    "⚠️  Failed to migrate emergency backup block {} to SledStore: {}",
                                    h, e
                                );
                                if let Err(rb) = store_ref.rollback_block() {
                                    warn!("   rollback_block also failed: {}", rb);
                                }
                                migration_ok = false;
                                break;
                            }
                        }
                        if migration_ok {
                            warn!(
                                "⚠️  Emergency restore migrated {} blocks from blockchain.dat to SledStore",
                                bc.blocks.len()
                            );
                            synced_blockchain = Some(bc);
                        }
                    }
                } else if dat_path.exists() {
                    warn!(
                        "Ignoring blockchain.dat during standard startup. Use --emergency-restore-from-local to permit explicit local recovery."
                    );
                }

                // If we discovered peers, sync via paginated block-range protocol.
                //
                // Hard gate: if any peer has chain data we MUST NOT create genesis.
                // Loop until fully caught up to peer tip before allowing mining.
                //
                // After each successful sync round we immediately retry: the peer
                // may have mined additional blocks while we were importing, so we
                // keep draining until the peer reports no blocks ahead (Ok(false))
                // or we've closed the gap enough (MAX_CATCHUP_ROUNDS limit).
                let is_validator_node = self.config.consensus_config.validator_enabled;
                let observer_requires_existing_network = Self::observer_requires_existing_network(
                    &self.config,
                    self.has_local_chain_data(),
                );

                if let Some(ref net_info) = network_info {
                    if !net_info.bootstrap_peers.is_empty() {
                        const MAX_CATCHUP_ROUNDS: u32 = 10;
                        let mut rounds = 0u32;
                        loop {
                            match try_initial_sync_from_peer(
                                store.clone(),
                                &net_info.bootstrap_peers,
                                Self::trusted_sync_sources(&self.config),
                            )
                            .await
                            {
                                Ok(true) => {
                                    // Imported blocks this round; check if peer has advanced further.
                                    rounds += 1;
                                    if rounds >= MAX_CATCHUP_ROUNDS {
                                        info!(
                                            "ℹ️  Reached max catch-up rounds ({}); proceeding.",
                                            MAX_CATCHUP_ROUNDS
                                        );
                                        if let Some(bc) =
                                            lib_blockchain::Blockchain::load_from_store(
                                                store.clone(),
                                            )?
                                        {
                                            info!(
                                                "📂 Loaded chain after sync (height: {})",
                                                bc.height
                                            );
                                            synced_blockchain = Some(bc);
                                        }
                                        break;
                                    }
                                    // Loop immediately to drain any blocks the peer mined
                                    // during our import pass.
                                }
                                Ok(false) => {
                                    // No peer is ahead of us — fully caught up (or no data at all).
                                    if rounds > 0 {
                                        // We synced at least one round; load the chain.
                                        if let Some(bc) =
                                            lib_blockchain::Blockchain::load_from_store(
                                                store.clone(),
                                            )?
                                        {
                                            info!(
                                                "📂 Fully synced to peer tip (height: {})",
                                                bc.height
                                            );
                                            synced_blockchain = Some(bc);
                                        }
                                    } else if observer_requires_existing_network {
                                        info!(
                                            "ℹ️  No bootstrap peer has committed blocks yet; \
                                             observer startup will keep waiting for an existing network."
                                        );
                                    } else {
                                        info!("ℹ️  No peers have chain data; this node will create genesis.");
                                    }
                                    break;
                                }
                                Err(e) => {
                                    // Peers have data but sync failed — block mining/genesis.
                                    error!(
                                        "❌ {}. Retrying initial sync in 30s \
                                         (mining/genesis blocked until synced)...",
                                        e
                                    );
                                    rounds = 0; // reset round counter on failure
                                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                }
                            }
                        }
                    }
                }

                // ─────────────────────────────────────────────────────────────
                // GENESIS GATE: only the bootstrap leader may create genesis.
                //
                // If we have no synced chain AND we are not the designated leader,
                // the leader hasn't mined block 1 yet (or we haven't found peers).
                // Keep retrying until we either sync a chain from a peer or the
                // process is killed.  This prevents every node from spawning its
                // own incompatible genesis when all nodes start simultaneously.
                // ─────────────────────────────────────────────────────────────
                Self::validate_observer_join_policy(
                    &self.config,
                    self.has_local_chain_data(),
                    network_info.as_ref(),
                )?;

                // Observers must never fall through to the genesis creation branch.
                // Once startup has established that no committed peer data is available
                // yet, stay in an explicit observer-only wait loop until a peer advances
                // beyond genesis and can serve block data.
                if synced_blockchain.is_none() && observer_requires_existing_network {
                    let retry_peers: Vec<_> = network_info
                        .as_ref()
                        .map(|ni| ni.bootstrap_peers.clone())
                        .unwrap_or_default();

                    loop {
                        info!(
                            "⏳ Observer has no local chain yet; waiting for bootstrap peers \
                             to expose committed blocks. Retrying peer sync in 30s (peers: {})...",
                            retry_peers.len()
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

                        if retry_peers.is_empty() {
                            info!("No peers known yet; waiting for discovery...");
                            continue;
                        }

                        match try_initial_sync_from_peer(
                            store.clone(),
                            &retry_peers,
                            Self::trusted_sync_sources(&self.config),
                        )
                        .await
                        {
                            Ok(true) => {
                                if let Some(bc) =
                                    lib_blockchain::Blockchain::load_from_store(store.clone())?
                                {
                                    info!(
                                        "📂 Observer synced committed blocks from peer \
                                         (height: {})",
                                        bc.height
                                    );
                                    synced_blockchain = Some(bc);
                                    break;
                                }
                            }
                            Ok(false) => {
                                info!(
                                    "⏳ Bootstrap peers are still advertising height 0; \
                                     observer will keep waiting for committed blocks..."
                                );
                            }
                            Err(e) => {
                                warn!("⚠️  Observer peer sync retry failed: {}; will retry...", e);
                            }
                        }
                    }
                }

                if let Some(bc) = synced_blockchain {
                    (bc, true)
                } else if local_is_bootstrap_leader || is_validator_node {
                    // ─────────────────────────────────────────────────────────────
                    // GENESIS CREATION: Bootstrap leader or validators with no peer
                    // data may create genesis. Genesis is deterministic (same config
                    // → same block hash on all nodes), so this is safe: all validators
                    // that reach this path produce an identical genesis block.
                    // Non-validator observer nodes still require syncing from a peer.
                    // ─────────────────────────────────────────────────────────────
                    if local_is_bootstrap_leader {
                        info!("📂 SledStore is empty - creating new blockchain (bootstrap leader)");
                    } else {
                        info!("📂 SledStore is empty - creating genesis (validator, peers all at height 0)");
                    }
                    let mut bc = lib_blockchain::Blockchain::new()?;
                    bc.set_store(store.clone());

                    // Log the genesis block hash for verification/debugging.
                    // Note: Full hash verification against CANONICAL_GENESIS_HASH is done
                    // inside lib_blockchain::Blockchain::new() -> GenesisConfig::verify_hash().
                    if let Some(genesis_block) = bc.blocks.first() {
                        let genesis_hash = hex::encode(genesis_block.header.block_hash.as_bytes());
                        info!("🔗 Genesis block hash: {}", genesis_hash);

                        // CRITICAL: Persist genesis block (height 0) to SledStore
                        // SledStore requires sequential block storage starting from 0
                        let store_ref: &dyn lib_blockchain::storage::BlockchainStore =
                            store.as_ref();
                        store_ref
                            .begin_block(0)
                            .map_err(|e| anyhow::anyhow!("Failed to begin genesis block: {}", e))?;
                        store_ref.append_block(genesis_block).map_err(|e| {
                            anyhow::anyhow!("Failed to append genesis block: {}", e)
                        })?;
                        store_ref.commit_block().map_err(|e| {
                            anyhow::anyhow!("Failed to commit genesis block: {}", e)
                        })?;
                        info!("💾 Genesis block (height 0) persisted to SledStore");
                    }

                    (bc, false)
                } else {
                    // ─────────────────────────────────────────────────────────────
                    // GENESIS GATE: Non-bootstrap leader nodes CANNOT create genesis.
                    //
                    // This prevents the "divergent genesis" bug where multiple nodes
                    // starting with wiped sled produce different genesis blocks.
                    //
                    // To fix this, you must either:
                    // 1. Start the bootstrap leader first (node with identity matching
                    //    the first entry in bootstrap_validators)
                    // 2. Copy sled/ directory from a healthy node
                    // 3. Sync from an existing peer with valid chain data
                    // ─────────────────────────────────────────────────────────────
                    error!("🚫 GENESIS GATE VIOLATION");
                    error!("   This node is NOT the bootstrap leader, but has no blockchain data.");
                    error!("   Creating genesis is forbidden to prevent chain divergence.");
                    error!("");
                    error!("   Solutions:");
                    error!(
                        "   1. Start the bootstrap leader first (identity: {:?})",
                        self.config
                            .network_config
                            .bootstrap_validators
                            .first()
                            .map(|v| &v.identity_id)
                    );
                    error!("   2. Copy the 'sled/' directory from a healthy node");
                    error!("   3. Ensure at least one peer with valid chain data is reachable");
                    error!("");
                    error!("   If you ARE the bootstrap leader, verify your identity matches");
                    error!("   the first entry in bootstrap_validators config.");

                    bail!("Genesis creation denied: this node is not the bootstrap leader. See logs above for solutions.");
                }
            }
        };

        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        set_global_blockchain(blockchain_arc.clone()).await?;

        if was_loaded {
            info!("✓ Blockchain provider initialized with persisted data");
        } else {
            info!("✓ Blockchain provider initialized with fresh blockchain");
        }

        // Bootstrap Council (dao-1): idempotently populate from config
        {
            let mut bc = blockchain_arc.write().await;
            bc.ensure_council_bootstrap(&self.config.consensus_config.council);
        }

        if let Some(ref net_info) = network_info {
            info!(
                "✓ Discovered network candidate with {} peers ({})",
                net_info.peer_count, net_info.chain_state
            );

            // Store bootstrap peers for mesh sync
            if !net_info.bootstrap_peers.is_empty() {
                crate::runtime::bootstrap_peers_provider::set_bootstrap_peers(
                    net_info.bootstrap_peers.clone(),
                )
                .await?;
            }

            // Store bootstrap peer SPKI pins (Issue #922)
            if !self.config.network_config.bootstrap_peer_pins.is_empty() {
                crate::runtime::bootstrap_peers_provider::set_bootstrap_peer_pins(
                    self.config.network_config.bootstrap_peer_pins.clone(),
                )
                .await;
            }
        }

        // ========================================================================
        // PHASE 3: Identity/Wallet Setup
        // ========================================================================
        info!("🆔 Setting up node identity and wallet...");

        // Use existing wallet startup flow from did_startup module
        let wallet_result =
            crate::runtime::did_startup::WalletStartupManager::handle_startup_wallet_flow()
                .await
                .context("Failed to complete wallet startup flow")?;

        info!("✅ Identity and wallet setup complete:");
        info!(
            "   User Identity: {}",
            hex::encode(&wallet_result.user_identity.id.0[..8])
        );
        info!(
            "   Node Identity: {}",
            hex::encode(&wallet_result.node_identity.id.0[..8])
        );
        info!(
            "   Primary Wallet: {}",
            hex::encode(&wallet_result.node_wallet_id.0[..8])
        );

        // Store wallet result for blockchain component
        self.set_user_wallet(wallet_result.clone()).await?;

        // Derive deterministic NodeId from DID + device name and cache for runtime access
        let device_name = resolve_device_name(Some(&wallet_result.node_identity.primary_device))
            .context(
                "Device name resolution failed (set ZHTP_DEVICE_NAME or configure device name)",
            )?;
        let node_id = derive_node_id(&wallet_result.node_identity.did, &device_name)
            .context("Failed to derive NodeId from DID + device name")?;
        set_runtime_node_identity(RuntimeNodeIdentity {
            did: wallet_result.node_identity.did.clone(),
            device_name,
            node_id,
        })
        .context("Failed to cache runtime NodeId")?;
        log_runtime_node_identity();

        // Store user identity for blockchain registration in Phase 6
        self.set_pending_identity_registration(wallet_result.user_identity.clone())
            .await;

        // ========================================================================
        // PHASE 4: Register Remaining Components
        // ========================================================================
        info!("📦 Registering remaining components...");
        use crate::runtime::components::{
            ApiComponent, BlockchainComponent, ConsensusComponent, EconomicsComponent,
            IdentityComponent, ProtocolsComponent, StorageComponent, ZKComponent,
        };

        self.register_component(Arc::new(ZKComponent::new()))
            .await?;

        // CRITICAL: Pass genesis identities explicitly to IdentityComponent
        // These were created in PHASE 3 and must be injected as a dependency
        // This ensures deterministic initialization and prevents silent empty state
        let genesis_ids = self.genesis_identities.read().await.clone();
        let genesis_private = self.genesis_private_data.read().await.clone();
        let node_role_for_identity = self.node_role.read().await.clone();
        let is_bootstrap_leader = self.is_local_bootstrap_leader().await.unwrap_or(false);
        self.register_component(Arc::new(
            IdentityComponent::new_with_identities_and_private_data(
                node_role_for_identity,
                genesis_ids,
                genesis_private,
                is_bootstrap_leader,
            ),
        ))
        .await?;

        self.register_component(Arc::new(StorageComponent::new()))
            .await?;

        let user_wallet = self.get_user_wallet().await;
        let environment = self.get_environment();
        let bootstrap_validators = self.get_bootstrap_validators();
        let bootstrap_peers = self.config.network_config.bootstrap_peers.clone();
        let joined_existing_network = self.get_joined_existing_network().await;
        let node_role = self.node_role.read().await.clone();

        let blockchain_component = BlockchainComponent::new_with_full_config(
            node_role.clone(),
            user_wallet,
            environment,
            bootstrap_validators,
            bootstrap_peers,
            joined_existing_network,
        );
        self.register_component(Arc::new(blockchain_component))
            .await?;

        // Protocols must start before Consensus so mesh router is available
        self.register_component(Arc::new(ProtocolsComponent::new_with_ports(
            environment,
            self.config.protocols_config.api_port,
            self.config.protocols_config.quic_port,
            self.config.protocols_config.discovery_port,
        )))
        .await?;
        self.register_component(Arc::new(
            ConsensusComponent::new_with_bootstrap_validators_and_oracle(
                environment,
                node_role,
                self.config.consensus_config.min_stake,
                self.config.network_config.bootstrap_validators.clone(),
                self.config.consensus_config.oracle_mock_sov_usd_price,
                self.config.consensus_config.propose_timeout_ms,
                self.config.consensus_config.prevote_timeout_ms,
                self.config.consensus_config.precommit_timeout_ms,
            ),
        ))
        .await?;
        self.register_component(Arc::new(EconomicsComponent::new()))
            .await?;
        self.register_component(Arc::new(ApiComponent::new()))
            .await?;

        // ========================================================================
        // PHASE 5: Start Remaining Components
        // ========================================================================
        info!("▶️  Starting remaining components...");
        self.start_component(ComponentId::ZK).await?;
        self.start_component(ComponentId::Storage).await?; // Data layer first
        self.start_component(ComponentId::Identity).await?; // Needs Storage for DHT bootstrap
        self.start_component(ComponentId::Blockchain).await?; // Needs Storage, Identity
        self.start_component(ComponentId::Protocols).await?; // MUST start before Consensus - provides mesh router
        self.start_component(ComponentId::Consensus).await?; // Needs Blockchain + mesh router from Protocols
        self.start_component(ComponentId::Economics).await?; // Needs Blockchain
        self.start_component(ComponentId::Api).await?; // Endpoint layer, last

        // ========================================================================
        // PHASE 6: Post-Startup Blockchain Registration
        // ========================================================================
        info!("📝 Registering identity on blockchain...");

        // Get pending identity from Phase 3
        if let Some(identity) = self.get_pending_identity_registration().await {
            // Prefer the global blockchain provider for registration.
            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(blockchain_arc) => {
                    let mut blockchain = blockchain_arc.write().await;
                    let blockchain_ref = &mut *blockchain;

                    // Create identity transaction data for blockchain registration
                    let identity_data = lib_blockchain::transaction::IdentityTransactionData {
                        did: format!("did:zhtp:{}", hex::encode(&identity.id.0)),
                        display_name: format!("User {}", hex::encode(&identity.id.0[..4])),
                        public_key: identity.public_key.as_bytes(),
                        ownership_proof: vec![], // Convert ZK proof to bytes if needed
                        identity_type: format!("{:?}", identity.identity_type).to_lowercase(),
                        did_document_hash: identity
                            .did_document_hash
                            .map(|h| lib_blockchain::Hash::from_slice(&h.0))
                            .unwrap_or(lib_blockchain::Hash::zero()),
                        created_at: identity.created_at,
                        registration_fee: 0,
                        dao_fee: 0,
                        controlled_nodes: vec![],
                        owned_wallets: identity
                            .wallet_manager
                            .wallets
                            .keys()
                            .map(|id| hex::encode(&id.0))
                            .collect(),
                    };

                    // Register identity on blockchain
                    match blockchain_ref.register_identity(identity_data.clone()) {
                        Ok(tx_hash) => {
                            info!(
                                "✅ Identity registered on blockchain: {}",
                                hex::encode(&tx_hash.as_bytes()[..8])
                            );
                        }
                        Err(e) => {
                            warn!("⚠️  Failed to register identity on blockchain: {}", e);
                        }
                    }

                    // Register wallets on blockchain
                    for (wallet_id, wallet) in &identity.wallet_manager.wallets {
                        let initial_balance = if format!("{:?}", wallet.wallet_type) == "Primary" {
                            SOV_WELCOME_BONUS
                        } else {
                            0
                        };

                        let wallet_data = lib_blockchain::transaction::WalletTransactionData {
                            wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
                            owner_identity_id: Some(lib_blockchain::Hash::from_slice(
                                &identity.id.0,
                            )),
                            alias: wallet.alias.clone(),
                            wallet_name: wallet.name.clone(),
                            wallet_type: format!("{:?}", wallet.wallet_type),
                            public_key: wallet.public_key.clone(),
                            capabilities: 0,
                            created_at: wallet.created_at,
                            registration_fee: 0,
                            initial_balance,
                            seed_commitment: wallet
                                .seed_commitment
                                .as_ref()
                                .map(|s| {
                                    // Hash the seed commitment string to create blockchain hash
                                    lib_blockchain::types::hash::blake3_hash(s.as_bytes())
                                })
                                .unwrap_or_else(|| {
                                    // Generate deterministic commitment from wallet ID + pubkey if no seed commitment
                                    // This ensures a valid non-zero commitment for blockchain validation
                                    let commitment_data = format!(
                                        "wallet_commitment:{}:{}",
                                        hex::encode(&wallet_id.0),
                                        hex::encode(&wallet.public_key)
                                    );
                                    lib_blockchain::types::hash::blake3_hash(
                                        commitment_data.as_bytes(),
                                    )
                                }),
                        };

                        match blockchain_ref.register_wallet(wallet_data) {
                            Ok(tx_hash) => {
                                info!(
                                    "✅ Wallet registered: {} ({})",
                                    hex::encode(&wallet_id.0[..8]),
                                    hex::encode(&tx_hash.as_bytes()[..8])
                                );

                                // Add welcome bonus for Primary wallets (new identity registration)
                                if format!("{:?}", wallet.wallet_type) == "Primary" {
                                    let wallet_id_hex = hex::encode(&wallet_id.0);
                                    let welcome_bonus = SOV_WELCOME_BONUS;

                                    // Update wallet registry balance
                                    if let Some(wallet_entry) =
                                        blockchain_ref.wallet_registry.get_mut(&wallet_id_hex)
                                    {
                                        wallet_entry.initial_balance = welcome_bonus;
                                    }

                                    // Create spendable UTXO for the welcome bonus
                                    let utxo_output =
                                        lib_blockchain::transaction::TransactionOutput {
                                            commitment: lib_blockchain::types::hash::blake3_hash(
                                                format!(
                                                    "welcome_bonus_commitment_{}_{}",
                                                    wallet_id_hex, welcome_bonus
                                                )
                                                .as_bytes(),
                                            ),
                                            note: lib_blockchain::types::hash::blake3_hash(
                                                format!("welcome_bonus_note_{}", wallet_id_hex)
                                                    .as_bytes(),
                                            ),
                                            recipient: lib_crypto::PublicKey::new([0u8; 2592]),
                                                                                    merkle_leaf: lib_blockchain::Hash::default(),
};
                                    let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                                        format!("welcome_bonus_utxo:{}", wallet_id_hex).as_bytes(),
                                    );
                                    blockchain_ref.utxo_set.insert(utxo_hash, utxo_output);

                                    info!(
                                        "🎁 Welcome bonus: {} SOV recorded for wallet {} (UTXO created; TokenMint queued by backfill)",
                                        SOV_WELCOME_BONUS_SOV, &wallet_id_hex[..16]
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("⚠️  Failed to register wallet: {}", e);
                            }
                        }
                    }

                    // Save blockchain to disk after all registrations complete (legacy mode only)
                    if blockchain_ref.get_store().is_none() {
                        let persist_path_str = self.config.environment.blockchain_data_path();
                        let persist_path = std::path::Path::new(&persist_path_str);
                        #[allow(deprecated)]
                        if let Err(e) = blockchain_ref.save_to_file(persist_path) {
                            warn!(
                                "⚠️  Failed to save blockchain after identity registration: {}",
                                e
                            );
                        } else {
                            info!("💾 Blockchain saved after new identity registration");
                        }
                    } else {
                        info!("💾 Blockchain persisted via store after identity registration");
                    }
                }
                Err(e) => {
                    warn!(
                        "⚠️  Blockchain service not available for identity registration: {}",
                        e
                    );
                }
            }
        } else {
            // Check if existing identity needs to be registered on blockchain
            // This handles the case where identity was created but blockchain wasn't available
            info!("ℹ️  Checking if existing identity needs blockchain registration...");

            let user_wallet_guard = self.user_wallet.read().await;
            if let Some(wallet_result) = user_wallet_guard.as_ref() {
                let user_identity = &wallet_result.user_identity;
                let user_did = format!("did:zhtp:{}", hex::encode(&user_identity.id.0));

                match crate::runtime::blockchain_provider::get_global_blockchain().await {
                    Ok(blockchain_arc) => {
                        let mut blockchain = blockchain_arc.write().await;
                        let blockchain_ref = &mut *blockchain;

                        // Check if identity already exists on blockchain
                        if !blockchain_ref.identity_exists(&user_did) {
                            info!("📝 Registering existing identity on blockchain (not found in registry)...");

                            let identity_data =
                                lib_blockchain::transaction::IdentityTransactionData {
                                    did: user_did.clone(),
                                    display_name: format!(
                                        "User {}",
                                        hex::encode(&user_identity.id.0[..4])
                                    ),
                                    public_key: user_identity.public_key.as_bytes(),
                                    ownership_proof: vec![],
                                    identity_type: format!("{:?}", user_identity.identity_type)
                                        .to_lowercase(),
                                    did_document_hash: user_identity
                                        .did_document_hash
                                        .as_ref()
                                        .map(|h| lib_blockchain::Hash::from_slice(&h.0))
                                        .unwrap_or(lib_blockchain::Hash::zero()),
                                    created_at: user_identity.created_at,
                                    registration_fee: 0,
                                    dao_fee: 0,
                                    controlled_nodes: vec![],
                                    owned_wallets: user_identity
                                        .wallet_manager
                                        .wallets
                                        .keys()
                                        .map(|id| hex::encode(&id.0))
                                        .collect(),
                                };

                            match blockchain_ref.register_identity(identity_data) {
                                Ok(tx_hash) => {
                                    info!(
                                        "✅ Existing identity registered on blockchain: {}",
                                        hex::encode(&tx_hash.as_bytes()[..8])
                                    );
                                }
                                Err(e) => {
                                    warn!("⚠️  Failed to register existing identity: {}", e);
                                }
                            }

                            // Register wallets too
                            for (wallet_id, wallet) in &user_identity.wallet_manager.wallets {
                                let wallet_id_hex = hex::encode(&wallet_id.0);
                                if !blockchain_ref.wallet_exists(&wallet_id_hex) {
                                    let initial_balance =
                                        if format!("{:?}", wallet.wallet_type) == "Primary" {
                                            let current = wallet.balance;
                                            if current == 0 {
                                                SOV_WELCOME_BONUS
                                            } else {
                                                current
                                            }
                                        } else {
                                            0
                                        };

                                    let wallet_data =
                                        lib_blockchain::transaction::WalletTransactionData {
                                            wallet_id: lib_blockchain::Hash::from_slice(
                                                &wallet_id.0,
                                            ),
                                            owner_identity_id: Some(
                                                lib_blockchain::Hash::from_slice(
                                                    &user_identity.id.0,
                                                ),
                                            ),
                                            alias: wallet.alias.clone(),
                                            wallet_name: wallet.name.clone(),
                                            wallet_type: format!("{:?}", wallet.wallet_type),
                                            public_key: wallet.public_key.clone(),
                                            capabilities: 0,
                                            created_at: wallet.created_at,
                                            registration_fee: 0,
                                            initial_balance,
                                            seed_commitment: wallet
                                                .seed_commitment
                                                .as_ref()
                                                .map(|s| {
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        s.as_bytes(),
                                                    )
                                                })
                                                .unwrap_or_else(|| {
                                                    let commitment_data = format!(
                                                        "wallet_commitment:{}:{}",
                                                        hex::encode(&wallet_id.0),
                                                        hex::encode(&wallet.public_key)
                                                    );
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        commitment_data.as_bytes(),
                                                    )
                                                }),
                                        };

                                    match blockchain_ref.register_wallet(wallet_data.clone()) {
                                        Ok(tx_hash) => {
                                            info!(
                                                "✅ Existing wallet registered: {} ({})",
                                                hex::encode(&wallet_id.0[..8]),
                                                hex::encode(&tx_hash.as_bytes()[..8])
                                            );

                                            // Give welcome bonus to newly registered Primary wallets (like genesis)
                                            // Create actual UTXO so funds are spendable
                                            if format!("{:?}", wallet.wallet_type) == "Primary" {
                                                let wallet_id_hex = hex::encode(&wallet_id.0);
                                                let welcome_bonus = SOV_WELCOME_BONUS;

                                                // Update wallet registry balance
                                                if let Some(wallet_entry) = blockchain_ref
                                                    .wallet_registry
                                                    .get_mut(&wallet_id_hex)
                                                {
                                                    wallet_entry.initial_balance = welcome_bonus;
                                                }

                                                // Create spendable UTXO for the welcome bonus
                                                let utxo_output = lib_blockchain::transaction::TransactionOutput {
                                                    commitment: lib_blockchain::types::hash::blake3_hash(
                                                        format!("welcome_bonus_commitment_{}_{}", wallet_id_hex, welcome_bonus).as_bytes()
                                                    ),
                                                    note: lib_blockchain::types::hash::blake3_hash(
                                                        format!("welcome_bonus_note_{}", wallet_id_hex).as_bytes()
                                                    ),
                                                    recipient: lib_crypto::PublicKey::new([0u8; 2592]),
                                                                                                    merkle_leaf: lib_blockchain::Hash::default(),
};
                                                let utxo_hash =
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        format!(
                                                            "welcome_bonus_utxo:{}",
                                                            wallet_id_hex
                                                        )
                                                        .as_bytes(),
                                                    );
                                                blockchain_ref
                                                    .utxo_set
                                                    .insert(utxo_hash, utxo_output);
                                                info!("🎁 Welcome bonus: {} SOV credited to wallet {} (UTXO created)", SOV_WELCOME_BONUS_SOV, &wallet_id_hex[..16]);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("⚠️  Failed to register existing wallet: {}", e);
                                        }
                                    }
                                }
                            }
                        } else {
                            info!("✅ Identity already registered on blockchain: {}", user_did);

                            // Check if any wallets need registration or welcome bonus funding
                            for (wallet_id, wallet) in &user_identity.wallet_manager.wallets {
                                let wallet_id_hex = hex::encode(&wallet_id.0);

                                // Check if wallet exists in registry
                                if let Some(wallet_entry) =
                                    blockchain_ref.wallet_registry.get(&wallet_id_hex)
                                {
                                    // Wallet exists - check if it needs funding
                                    if wallet_entry.initial_balance == 0
                                        && format!("{:?}", wallet.wallet_type) == "Primary"
                                    {
                                        info!(
                                            "📝 Funding existing zero-balance Primary wallet: {}",
                                            &wallet_id_hex[..16]
                                        );

                                        let welcome_bonus = SOV_WELCOME_BONUS;

                                        // Update wallet registry
                                        if let Some(wallet_mut) =
                                            blockchain_ref.wallet_registry.get_mut(&wallet_id_hex)
                                        {
                                            wallet_mut.initial_balance = welcome_bonus;
                                        }

                                        // Create spendable UTXO
                                        let utxo_output =
                                            lib_blockchain::transaction::TransactionOutput {
                                                commitment:
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        format!(
                                                            "welcome_bonus_commitment_{}_{}",
                                                            wallet_id_hex, welcome_bonus
                                                        )
                                                        .as_bytes(),
                                                    ),
                                                note: lib_blockchain::types::hash::blake3_hash(
                                                    format!("welcome_bonus_note_{}", wallet_id_hex)
                                                        .as_bytes(),
                                                ),
                                                recipient: lib_crypto::PublicKey::new([0u8; 2592]),
                                                                                            merkle_leaf: lib_blockchain::Hash::default(),
};
                                        let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                                            format!("welcome_bonus_utxo:{}", wallet_id_hex)
                                                .as_bytes(),
                                        );
                                        blockchain_ref.utxo_set.insert(utxo_hash, utxo_output);

                                        info!("🎁 Welcome bonus: {} SOV credited to wallet {} (UTXO created)", SOV_WELCOME_BONUS_SOV, &wallet_id_hex[..16]);
                                    }
                                } else {
                                    // Wallet NOT in registry - register it now
                                    info!(
                                        "📝 Registering missing wallet for existing identity: {}",
                                        &wallet_id_hex[..16]
                                    );

                                    let initial_balance =
                                        if format!("{:?}", wallet.wallet_type) == "Primary" {
                                            let current = wallet.balance;
                                            if current == 0 {
                                                SOV_WELCOME_BONUS
                                            } else {
                                                current
                                            }
                                        } else {
                                            0
                                        };

                                    let wallet_data =
                                        lib_blockchain::transaction::WalletTransactionData {
                                            wallet_id: lib_blockchain::Hash::from_slice(
                                                &wallet_id.0,
                                            ),
                                            owner_identity_id: Some(
                                                lib_blockchain::Hash::from_slice(
                                                    &user_identity.id.0,
                                                ),
                                            ),
                                            alias: wallet.alias.clone(),
                                            wallet_name: wallet.name.clone(),
                                            wallet_type: format!("{:?}", wallet.wallet_type),
                                            public_key: wallet.public_key.clone(),
                                            capabilities: 0,
                                            created_at: wallet.created_at,
                                            registration_fee: 0,
                                            initial_balance,
                                            seed_commitment: wallet
                                                .seed_commitment
                                                .as_ref()
                                                .map(|s| {
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        s.as_bytes(),
                                                    )
                                                })
                                                .unwrap_or_else(|| {
                                                    let commitment_data = format!(
                                                        "wallet_commitment:{}:{}",
                                                        hex::encode(&wallet_id.0),
                                                        hex::encode(&wallet.public_key)
                                                    );
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        commitment_data.as_bytes(),
                                                    )
                                                }),
                                        };

                                    match blockchain_ref.register_wallet(wallet_data.clone()) {
                                        Ok(tx_hash) => {
                                            info!(
                                                "✅ Missing wallet registered: {} ({})",
                                                &wallet_id_hex[..16],
                                                hex::encode(&tx_hash.as_bytes()[..8])
                                            );

                                            // Give welcome bonus to Primary wallets
                                            if format!("{:?}", wallet.wallet_type) == "Primary" {
                                                let welcome_bonus = SOV_WELCOME_BONUS;

                                                // Update wallet registry balance
                                                if let Some(wallet_entry) = blockchain_ref
                                                    .wallet_registry
                                                    .get_mut(&wallet_id_hex)
                                                {
                                                    wallet_entry.initial_balance = welcome_bonus;
                                                }

                                                // Create spendable UTXO for the welcome bonus
                                                let utxo_output = lib_blockchain::transaction::TransactionOutput {
                                                    commitment: lib_blockchain::types::hash::blake3_hash(
                                                        format!("welcome_bonus_commitment_{}_{}", wallet_id_hex, welcome_bonus).as_bytes()
                                                    ),
                                                    note: lib_blockchain::types::hash::blake3_hash(
                                                        format!("welcome_bonus_note_{}", wallet_id_hex).as_bytes()
                                                    ),
                                                    recipient: lib_crypto::PublicKey::new([0u8; 2592]),
                                                                                                    merkle_leaf: lib_blockchain::Hash::default(),
};
                                                let utxo_hash =
                                                    lib_blockchain::types::hash::blake3_hash(
                                                        format!(
                                                            "welcome_bonus_utxo:{}",
                                                            wallet_id_hex
                                                        )
                                                        .as_bytes(),
                                                    );
                                                blockchain_ref
                                                    .utxo_set
                                                    .insert(utxo_hash, utxo_output);

                                                info!("🎁 Welcome bonus: {} SOV credited to wallet {} (UTXO created)",
                                                    SOV_WELCOME_BONUS_SOV, &wallet_id_hex[..16]);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("⚠️  Failed to register missing wallet: {}", e);
                                        }
                                    }
                                }
                            }
                        }

                        // Save blockchain after any modifications in existing identity path (legacy mode only)
                        if blockchain_ref.get_store().is_none() {
                            let persist_path_str = self.config.environment.blockchain_data_path();
                            let persist_path = std::path::Path::new(&persist_path_str);
                            #[allow(deprecated)]
                            if let Err(e) = blockchain_ref.save_to_file(persist_path) {
                                warn!("⚠️  Failed to save blockchain after existing identity check: {}", e);
                            } else {
                                info!("💾 Blockchain saved after existing identity check/registration");
                            }
                        } else {
                            info!("💾 Blockchain persisted via store after identity check/registration");
                        }
                    }
                    Err(e) => {
                        warn!(
                            "⚠️  Blockchain not available to check identity registration: {}",
                            e
                        );
                    }
                }
            }
        }

        // Submit a ValidatorRegistration tx for this node if validator_enabled.
        // Note: Validator seeding from runtime config is disabled per Issue #1862.
        // Validators must come from canonical genesis state or on-chain registration.
        if self.config.consensus_config.validator_enabled {
            if let Err(e) = self.submit_self_validator_registration().await {
                warn!("⚠️ Failed to submit self validator registration: {}", e);
            }
        }

        // Unconditionally attempt to bootstrap the oracle committee from the validator
        // registry if it is still empty after Sled load and the dat-restore attempt above.
        // This must run regardless of whether bootstrap_validators is configured, because
        // validators may be present from on-chain ValidatorRegistration transactions even
        // when no bootstrap_validators are declared in config.
        if let Err(e) = self.ensure_oracle_committee_bootstrapped().await {
            warn!("⚠️ Failed to ensure oracle committee bootstrap: {}", e);
        }

        info!("✅ ZHTP node started successfully");
        info!(
            "🌐 ZHTP server active on port {}",
            self.config.protocols_config.api_port
        );

        Ok(())
    }

    /// Log that validator seeding from runtime config is disabled (canonical genesis only).
    ///
    /// This method exists for documentation purposes only. Startup seeding from runtime config
    /// is intentionally disabled per Issue #1862. Canonical validator membership must come
    /// from genesis or persisted chain state, not a local bootstrap list.
    ///
    /// DO NOT ADD VALIDATOR SEEDING LOGIC HERE. Use canonical genesis state instead.
    async fn log_validator_seeding_disabled(&self) -> anyhow::Result<()> {
        info!("Canonical validator startup: runtime bootstrap validator seeding disabled (validators must come from genesis state)");
        Ok(())
    }

    /// Bootstrap the oracle committee from active validator consensus keys if it is still empty.
    ///
    /// Called unconditionally during startup — after Sled load and dat-restore
    /// — so that nodes without `bootstrap_validators`
    /// configured (e.g. nodes whose validators are registered purely on-chain) still get
    /// their oracle committee populated and can validate attestations without receiving
    /// NonCommitteeSigner errors.
    async fn ensure_oracle_committee_bootstrapped(&self) -> anyhow::Result<()> {
        let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;

        if !blockchain.oracle_state.committee.members().is_empty() {
            return Ok(()); // already populated — nothing to do
        }

        const DILITHIUM5_PK_LEN: usize = 2592;

        let mut committee_members_with_pubkeys: Vec<([u8; 32], Vec<u8>)> = blockchain
            .validator_registry
            .values()
            .filter(|v| v.status == "active")
            .filter_map(|v| {
                if v.consensus_key == [0u8; 2592] {
                    return None;
                }
                let key_id = lib_blockchain::blake3_hash(&v.consensus_key).as_array();
                Some((key_id, v.consensus_key.to_vec()))
            })
            .collect();

        committee_members_with_pubkeys.sort_by(|(a, _), (b, _)| a.cmp(b));
        committee_members_with_pubkeys.dedup_by(|(a, _), (b, _)| a == b);

        if !committee_members_with_pubkeys.is_empty() {
            match blockchain.bootstrap_oracle_committee(committee_members_with_pubkeys) {
                Ok(()) => {
                    info!(
                        "🔮 Bootstrapped oracle committee from validator registry (members={})",
                        blockchain.oracle_state.committee.members().len()
                    );
                }
                Err(e) => {
                    warn!(
                        "⚠️ Failed to bootstrap oracle committee from validator registry: {}",
                        e
                    );
                }
            }
        } else {
            warn!("⚠️ Oracle committee is empty and no active validator consensus keys were found");
        }

        Ok(())
    }

    /// Submit a ValidatorRegistration transaction for this node.
    ///
    /// Reads the node's Dilithium public key from the keystore and constructs a
    /// `ValidatorRegistration` transaction that gets mined into the next block.
    /// All nodes that see this block will then add this node to their
    /// `validator_registry` via `process_and_commit_block`.
    async fn submit_self_validator_registration(&self) -> Result<()> {
        use crate::keyfile_names::{
            KeystorePrivateKey, NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME,
        };
        use std::path::PathBuf;

        let keystore_dir = std::env::var("ZHTP_KEYSTORE_DIR")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::node_data_dir().join("keystore"));

        let node_identity_json =
            tokio::fs::read_to_string(keystore_dir.join(NODE_IDENTITY_FILENAME))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read node identity: {}", e))?;
        let node_identity_val: serde_json::Value = serde_json::from_str(&node_identity_json)?;
        let node_did = node_identity_val
            .get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing .did in node identity"))?
            .to_string();

        let key_json = tokio::fs::read_to_string(keystore_dir.join(NODE_PRIVATE_KEY_FILENAME))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read node private key: {}", e))?;
        let ks: KeystorePrivateKey = serde_json::from_str(&key_json)?;

        let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain().await?;
        let mut blockchain = blockchain_arc.write().await;

        // Idempotent: skip if this node is already in validator_registry
        if blockchain.validator_registry.contains_key(&node_did) {
            info!(
                "ℹ️ Node {} already in validator_registry, skipping self-registration",
                &node_did[..40]
            );
            return Ok(());
        }

        let consensus_key = ks.dilithium_pk.to_vec();
        let networking_key =
            lib_crypto::hash_blake3(&[ks.dilithium_pk.as_slice(), b"networking"].concat()).to_vec();
        let rewards_key =
            lib_crypto::hash_blake3(&[ks.dilithium_pk.as_slice(), b"rewards"].concat()).to_vec();

        // Use explicit endpoint configuration so peers can dial this validator.
        // Priority:
        //   1) bootstrap_validators[].endpoints for this DID
        //   2) ZHTP_VALIDATOR_ENDPOINT env var
        let network_address = self.config.network_config.bootstrap_validators.iter()
            .find(|bv| bv.identity_id == node_did)
            .and_then(|bv| bv.endpoints.first().cloned())
            .or_else(|| std::env::var("ZHTP_VALIDATOR_ENDPOINT").ok())
            .ok_or_else(|| anyhow::anyhow!(
                "No validator endpoint configured for {}. Set bootstrap_validators[].endpoints or ZHTP_VALIDATOR_ENDPOINT.",
                node_did
            ))?;

        Self::validate_validator_endpoint(&network_address)?;

        let validator_data = lib_blockchain::transaction::ValidatorTransactionData {
            identity_id: node_did.clone(),
            stake: 1000,
            storage_provided: 0,
            consensus_key,
            networking_key,
            rewards_key,
            network_address,
            commission_rate: 5,
            operation: lib_blockchain::transaction::ValidatorOperation::Register,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let tx = lib_blockchain::Transaction::new_validator_registration(
            validator_data,
            Vec::new(),
            lib_crypto::Signature::default(),
            Vec::new(),
        );

        match blockchain.add_pending_transaction(tx) {
            Ok(()) => {
                info!(
                    "✅ Self validator registration tx queued for node {}",
                    &node_did[..40]
                );
            }
            Err(e) => {
                warn!("⚠️ Failed to queue validator registration tx: {}", e);
            }
        }

        Ok(())
    }

    /// Helper: Store pending identity for blockchain registration after startup
    async fn set_pending_identity_registration(&self, identity: lib_identity::ZhtpIdentity) {
        let mut pending = self.pending_identity.write().await;
        *pending = Some(identity);
    }

    /// Helper: Get pending identity registration
    async fn get_pending_identity_registration(&self) -> Option<lib_identity::ZhtpIdentity> {
        let pending = self.pending_identity.read().await;
        pending.clone()
    }

    /// Start all components in the correct order
    pub async fn start_all_components(&self) -> Result<()> {
        info!(" Starting all ZHTP components...");

        // Register components once if not already registered
        self.register_all_components().await?;

        // Initialize blockchain BEFORE starting components (only if not already set by genesis)
        if !is_global_blockchain_available().await {
            info!(" Creating blockchain instance...");
            let blockchain = lib_blockchain::Blockchain::new()?;
            let blockchain_arc = Arc::new(RwLock::new(blockchain));

            // Set in global provider so BlockchainComponent can access it
            set_global_blockchain(blockchain_arc.clone()).await?;
            info!(" Global blockchain provider initialized");
        } else {
            info!(" Using existing global blockchain instance (genesis already set)");
        }

        for component_id in &self.startup_order {
            self.start_component(component_id.clone())
                .await
                .with_context(|| format!("Failed to start component {}", component_id))?;

            // Wait between component starts for proper initialization
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // CRITICAL: Verify all critical components are healthy before declaring operational
        self.verify_critical_components().await?;

        info!(" All components started and verified successfully");
        Ok(())
    }

    /// Verify critical components are actually healthy after startup
    ///
    /// This prevents declaring the node "operational" when critical subsystems
    /// have failed silently. Each component must report Running status and
    /// pass a health check.
    async fn verify_critical_components(&self) -> Result<()> {
        info!("Verifying critical components are healthy...");

        // List of components that MUST be healthy for node to be operational
        let critical_components = [
            ComponentId::Storage,
            ComponentId::Blockchain,
            ComponentId::Protocols,
        ];

        let mut failures = Vec::new();

        for component_id in &critical_components {
            // Check component status
            let health = self.component_health.read().await;
            if let Some(health_info) = health.get(component_id) {
                if !matches!(health_info.status, ComponentStatus::Running) {
                    failures.push(format!(
                        "{}: status is {:?} (expected Running)",
                        component_id, health_info.status
                    ));
                    continue;
                }
            } else {
                failures.push(format!("{}: no health info available", component_id));
                continue;
            }
            drop(health);

            // Perform actual health check
            let components = self.components.read().await;
            if let Some(component) = components.get(component_id) {
                match component.health_check().await {
                    Ok(health) if matches!(health.status, ComponentStatus::Running) => {
                        info!("  {} is healthy", component_id);
                    }
                    Ok(health) => {
                        failures.push(format!(
                            "{}: health check returned {:?}",
                            component_id, health.status
                        ));
                    }
                    Err(e) => {
                        failures.push(format!("{}: health check failed: {}", component_id, e));
                    }
                }
            } else {
                failures.push(format!("{}: component not found", component_id));
            }
        }

        // Verify global providers are available
        if !crate::runtime::storage_provider::is_global_storage_available().await {
            failures.push("Global storage provider not available".to_string());
        }

        if !is_global_blockchain_available().await {
            failures.push("Global blockchain provider not available".to_string());
        }

        if !failures.is_empty() {
            let msg = format!(
                "CRITICAL: Node startup verification failed. {} critical component(s) unhealthy:\n{}",
                failures.len(),
                failures.iter().map(|f| format!("  - {}", f)).collect::<Vec<_>>().join("\n")
            );
            error!("{}", msg);
            return Err(anyhow::anyhow!(msg));
        }

        info!("All critical components verified healthy");
        Ok(())
    }

    /// Start a specific component
    pub async fn start_component(&self, component_id: ComponentId) -> Result<()> {
        // Check if component is already running to prevent duplicate starts
        {
            let health = self.component_health.read().await;
            if let Some(health_info) = health.get(&component_id) {
                if matches!(health_info.status, ComponentStatus::Running) {
                    info!(
                        "Component {} is already running, skipping start",
                        component_id
                    );
                    return Ok(());
                }
            }
        }

        info!(" Starting component: {}", component_id);

        // Update status to starting
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.status = ComponentStatus::Starting;
                health_info.last_heartbeat = Instant::now();
            }
        }

        // Wire blockchain to consensus BEFORE starting the consensus component,
        // since ConsensusComponent::start() reads self.blockchain to load the
        // canonical validator set. Wiring is a hard prerequisite — if it fails,
        // we must not start consensus to avoid noisy repeated failures.
        if component_id == ComponentId::Consensus {
            match self.wire_blockchain_to_consensus().await {
                Ok(()) => {
                    info!(" Blockchain wired to consensus before start");
                }
                Err(e) => {
                    {
                        let mut health = self.component_health.write().await;
                        if let Some(health_info) = health.get_mut(&component_id) {
                            health_info.status = ComponentStatus::Error(e.to_string());
                            health_info.error_count += 1;
                        }
                    }
                    error!(
                        "Failed to wire blockchain to consensus before start: {}. \
                         Consensus component will not be started.",
                        e
                    );
                    return Err(e);
                }
            }
        }

        // Get component and start it
        let components = self.components.read().await;
        if let Some(component) = components.get(&component_id) {
            let start_time = Instant::now();

            match component.start().await {
                Ok(()) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Running;
                        health_info.last_heartbeat = Instant::now();
                        health_info.uptime = start_time.elapsed();
                    }

                    info!("Component {} started successfully", component_id);

                    // Initialize shared blockchain service after BlockchainComponent starts
                    if component_id == ComponentId::Blockchain {
                        if let Err(e) = self.initialize_shared_blockchain().await {
                            warn!("Failed to initialize shared blockchain service: {}", e);
                        }

                        // NOTE: Reward orchestrator moved to after ProtocolsComponent
                        // (needs mesh server to be initialized)
                    }

                    // Start reward orchestrator after ProtocolsComponent (mesh server now ready)
                    if component_id == ComponentId::Protocols {
                        // Give mesh server a moment to fully initialize
                        tokio::time::sleep(Duration::from_millis(500)).await;

                        if let Err(e) = self.start_reward_orchestrator().await {
                            warn!("Failed to start reward orchestrator: {}", e);
                        } else {
                            info!(
                                " Reward orchestrator started (mesh server ready for statistics)"
                            );
                        }

                        // NOTE: Runtime-dependent handlers (NetworkHandler, MeshHandler) are now
                        // registered from main.rs after wrapping RuntimeOrchestrator in Arc.
                        // See register_runtime_handlers() call in main.rs after node startup.
                    }

                    // Sync wallet balances from blockchain after BLOCKCHAIN component starts
                    // (Must run after blockchain starts, not after Identity, since we need blockchain data)
                    if component_id == ComponentId::Blockchain {
                        if let Err(e) = self.sync_wallet_balances_from_blockchain().await {
                            warn!("Failed to sync wallet balances from blockchain: {}", e);
                        } else {
                            info!(" Wallet balances synced from blockchain wallet registry");
                        }
                    }

                    // Send start notification to other components
                    self.broadcast_message(ComponentMessage::Custom(
                        format!("component_started:{}", component_id),
                        vec![],
                    ))
                    .await?;

                    Ok(())
                }
                Err(e) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Error(e.to_string());
                        health_info.error_count += 1;
                    }

                    error!("Failed to start component {}: {}", component_id, e);
                    Err(e)
                }
            }
        } else {
            let error_msg = format!("Component {} not found", component_id);
            error!("{}", error_msg);
            Err(anyhow::anyhow!(error_msg))
        }
    }

    /// Stop all components in reverse order with timeout
    pub async fn shutdown_all_components(&self) -> Result<()> {
        info!("Shutting down all ZHTP components...");

        // Stop unified reward orchestrator first
        if let Err(e) = self.stop_reward_orchestrator().await {
            warn!("Failed to stop reward orchestrator: {}", e);
        }

        // Set overall shutdown timeout
        let shutdown_future = async {
            // Stop components in reverse order
            for component_id in self.startup_order.iter().rev() {
                if let Err(e) = self.stop_component(component_id.clone()).await {
                    error!("Failed to stop component {}: {}", component_id, e);
                    // Continue with other components even if one fails
                }

                // Wait between component stops
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };

        // Apply overall timeout for shutdown
        let shutdown_timeout_ms = self
            .config
            .integration_settings
            .cross_package_timeouts
            .get("shutdown")
            .copied()
            .unwrap_or(30000);
        match tokio::time::timeout(Duration::from_millis(shutdown_timeout_ms), shutdown_future)
            .await
        {
            Ok(()) => {
                info!("All components shut down normally");
            }
            Err(_timeout) => {
                warn!("Shutdown timeout reached - forcing termination");

                // Force stop all remaining components
                let components = self.components.read().await;
                for component_id in components.keys() {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(component_id) {
                        if !matches!(health_info.status, ComponentStatus::Stopped) {
                            health_info.status = ComponentStatus::Stopped;
                            health_info.last_heartbeat = Instant::now();
                        }
                    }
                }
                warn!(" Forced shutdown completed");
            }
        }

        // Send shutdown signal
        if let Some(shutdown_tx) = self.shutdown_signal.lock().await.take() {
            let _ = shutdown_tx.send(());
        }

        info!("All components shut down");
        Ok(())
    }

    /// Stop a specific component with timeout
    pub async fn stop_component(&self, component_id: ComponentId) -> Result<()> {
        info!("Stopping component: {}", component_id);

        // Update status to stopping
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.status = ComponentStatus::Stopping;
                health_info.last_heartbeat = Instant::now();
            }
        }

        // Get component and stop it with timeout
        let components = self.components.read().await;
        if let Some(component) = components.get(&component_id) {
            // Add timeout to prevent hanging on shutdown
            match tokio::time::timeout(Duration::from_secs(10), component.stop()).await {
                Ok(Ok(())) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Stopped;
                        health_info.last_heartbeat = Instant::now();
                    }

                    info!("Component {} stopped successfully", component_id);
                    Ok(())
                }
                Ok(Err(e)) => {
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Error(e.to_string());
                        health_info.error_count += 1;
                    }

                    error!("Failed to stop component {}: {}", component_id, e);
                    Err(e)
                }
                Err(_timeout) => {
                    warn!(
                        "Timeout stopping component {}, forcing shutdown",
                        component_id
                    );

                    // Try force stop if available
                    match tokio::time::timeout(Duration::from_secs(5), component.force_stop()).await
                    {
                        Ok(Ok(())) => {
                            info!("Component {} force stopped", component_id);
                        }
                        Ok(Err(e)) => {
                            warn!("Force stop failed for {}: {}", component_id, e);
                        }
                        Err(_) => {
                            warn!("Force stop timeout for {}", component_id);
                        }
                    }

                    // Mark as stopped regardless
                    let mut health = self.component_health.write().await;
                    if let Some(health_info) = health.get_mut(&component_id) {
                        health_info.status = ComponentStatus::Stopped;
                        health_info.last_heartbeat = Instant::now();
                    }

                    Ok(())
                }
            }
        } else {
            warn!("Component {} not found during shutdown", component_id);
            Ok(()) // Not an error during shutdown
        }
    }

    /// Get status of all components
    pub async fn get_component_status(&self) -> Result<HashMap<String, bool>> {
        let health = self.component_health.read().await;
        let mut status = HashMap::new();

        for (id, health_info) in health.iter() {
            let is_running = matches!(health_info.status, ComponentStatus::Running);
            status.insert(id.to_string(), is_running);
        }

        Ok(status)
    }

    /// Get detailed health information for all components
    pub async fn get_detailed_health(&self) -> Result<HashMap<ComponentId, ComponentHealth>> {
        let health = self.component_health.read().await;
        Ok(health.clone())
    }

    /// Get the node configuration
    pub fn get_config(&self) -> &NodeConfig {
        &self.config
    }

    /// Send a message to a specific component
    pub async fn send_message(
        &self,
        component_id: ComponentId,
        message: ComponentMessage,
    ) -> Result<()> {
        let message_bus = self.message_bus.lock().await;
        message_bus
            .send((component_id, message))
            .context("Failed to send message")?;
        Ok(())
    }

    /// Emit a neural mesh event from the server/mesh layer.
    /// This is the primary entry point for live network events to reach the
    /// ML models (RL Router, Anomaly Sentry, Prefetcher, Compressor).
    pub async fn emit_neural_event(&self, message: ComponentMessage) {
        let tx = self.neural_mesh_tx.lock().await;
        if tx.send(message).is_err() {
            debug!("Neural mesh event channel closed (component may be stopped)");
        }
    }

    /// Get a clone of the neural mesh event sender.
    /// Returns an UnboundedSender that server-layer code can use to emit
    /// events without awaiting a lock on every call.
    pub async fn get_neural_mesh_sender(&self) -> mpsc::UnboundedSender<ComponentMessage> {
        self.neural_mesh_tx.lock().await.clone()
    }

    /// Broadcast a message to all components
    pub async fn broadcast_message(&self, message: ComponentMessage) -> Result<()> {
        let components = self.components.read().await;
        let message_bus = self.message_bus.lock().await;

        for component_id in components.keys() {
            message_bus
                .send((component_id.clone(), message.clone()))
                .context("Failed to broadcast message")?;
        }

        Ok(())
    }

    /// Restart a component
    pub async fn restart_component(&self, component_id: ComponentId) -> Result<()> {
        info!(" Restarting component: {}", component_id);

        // Update restart count
        {
            let mut health = self.component_health.write().await;
            if let Some(health_info) = health.get_mut(&component_id) {
                health_info.restart_count += 1;
            }
        }

        self.stop_component(component_id.clone()).await?;
        tokio::time::sleep(Duration::from_millis(1000)).await; // Wait for cleanup
        self.start_component(component_id.clone()).await?;

        info!("Component {} restarted successfully", component_id);
        Ok(())
    }

    /// Get aggregated metrics from all components
    pub async fn get_system_metrics(&self) -> Result<HashMap<String, f64>> {
        let components = self.components.read().await;
        let mut aggregated_metrics = HashMap::new();

        for (id, component) in components.iter() {
            match component.get_metrics().await {
                Ok(metrics) => {
                    for (key, value) in metrics {
                        let prefixed_key = format!("{}_{}", id, key);
                        aggregated_metrics.insert(prefixed_key, value);
                    }
                }
                Err(e) => {
                    warn!("Failed to get metrics from {}: {}", id, e);
                }
            }
        }

        // Add orchestrator metrics
        let health = self.component_health.read().await;
        aggregated_metrics.insert("total_components".to_string(), components.len() as f64);
        aggregated_metrics.insert(
            "running_components".to_string(),
            health
                .values()
                .filter(|h| matches!(h.status, ComponentStatus::Running))
                .count() as f64,
        );
        aggregated_metrics.insert(
            "error_components".to_string(),
            health
                .values()
                .filter(|h| matches!(h.status, ComponentStatus::Error(_)))
                .count() as f64,
        );

        Ok(aggregated_metrics)
    }

    // implementations using lib-network APIs

    /// Get connected peers from network component
    pub async fn get_connected_peers(&self) -> Result<Vec<String>> {
        // Get peer information from lib-network
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                let mut peers = Vec::new();

                // Add peer information from mesh status
                if mesh_status.local_peers > 0 {
                    for i in 1..=mesh_status.local_peers.min(10) {
                        peers.push(format!("local-mesh-peer-{}", i));
                    }
                }

                if mesh_status.regional_peers > 0 {
                    for i in 1..=mesh_status.regional_peers.min(5) {
                        peers.push(format!("regional-mesh-peer-{}", i));
                    }
                }

                if mesh_status.global_peers > 0 {
                    for i in 1..=mesh_status.global_peers.min(3) {
                        peers.push(format!("global-mesh-peer-{}", i));
                    }
                }

                if mesh_status.relay_peers > 0 {
                    for i in 1..=mesh_status.relay_peers.min(2) {
                        peers.push(format!("relay-peer-{}", i));
                    }
                }

                if peers.is_empty() {
                    peers.push("No peers connected".to_string());
                }

                Ok(peers)
            }
            Err(e) => {
                warn!("Failed to get mesh status: {}", e);
                Ok(vec!["Network status unavailable".to_string()])
            }
        }
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, addr: &str) -> Result<()> {
        info!("Attempting to connect to peer: {}", addr);

        // Send connect message to network component
        self.send_message(
            ComponentId::Network,
            ComponentMessage::Custom(
                format!("connect_to_peer:{}", addr),
                addr.as_bytes().to_vec(),
            ),
        )
        .await?;

        info!(
            "Connect request sent to network component for peer: {}",
            addr
        );
        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect_from_peer(&self, addr: &str) -> Result<()> {
        info!(" Attempting to disconnect from peer: {}", addr);

        // Send disconnect message to network component
        self.send_message(
            ComponentId::Network,
            ComponentMessage::Custom(
                format!("disconnect_from_peer:{}", addr),
                addr.as_bytes().to_vec(),
            ),
        )
        .await?;

        info!(
            "Disconnect request sent to network component for peer: {}",
            addr
        );
        Ok(())
    }

    /// Get network information
    pub async fn get_network_info(&self) -> Result<String> {
        // Get comprehensive network information from lib-network
        let mut info = String::new();

        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                info.push_str("ZHTP Mesh Network Status\n");
                info.push_str("===========================\n");
                info.push_str(&format!(
                    "Internet Connected: {}\n",
                    if mesh_status.internet_connected {
                        "Yes"
                    } else {
                        "No"
                    }
                ));
                info.push_str(&format!(
                    "Mesh Connected: {}\n",
                    if mesh_status.mesh_connected {
                        "Yes"
                    } else {
                        "No"
                    }
                ));
                info.push_str(&format!(
                    "Connectivity: {:.1}%\n",
                    mesh_status.connectivity_percentage
                ));
                info.push_str(&format!("Active Peers: {}\n", mesh_status.active_peers));
                info.push_str(&format!("  • Local: {}\n", mesh_status.local_peers));
                info.push_str(&format!("  • Regional: {}\n", mesh_status.regional_peers));
                info.push_str(&format!("  • Global: {}\n", mesh_status.global_peers));
                info.push_str(&format!("  • Relays: {}\n", mesh_status.relay_peers));
                info.push_str(&format!("Coverage: {:.1}%\n", mesh_status.coverage));
                info.push_str(&format!("Stability: {:.1}%\n", mesh_status.stability));
            }
            Err(e) => {
                info.push_str(&format!("Failed to get mesh status: {}\n", e));
            }
        }

        match lib_network::get_network_statistics().await {
            Ok(net_stats) => {
                info.push_str("\nNetwork Statistics\n");
                info.push_str("=====================\n");
                info.push_str(&format!(
                    "Bytes Sent: {} MB\n",
                    net_stats.bytes_sent / 1_000_000
                ));
                info.push_str(&format!(
                    "Bytes Received: {} MB\n",
                    net_stats.bytes_received / 1_000_000
                ));
                info.push_str(&format!("Packets Sent: {}\n", net_stats.packets_sent));
                info.push_str(&format!(
                    "Packets Received: {}\n",
                    net_stats.packets_received
                ));
                info.push_str(&format!("Connections: {}\n", net_stats.connection_count));
            }
            Err(e) => {
                info.push_str(&format!("Failed to get network statistics: {}\n", e));
            }
        }

        Ok(info)
    }

    /// Get mesh status
    pub async fn get_mesh_status(&self) -> Result<String> {
        match lib_network::get_mesh_status().await {
            Ok(mesh_status) => {
                let status = if mesh_status.connectivity_percentage > 80.0 {
                    "[EXCELLENT]"
                } else if mesh_status.connectivity_percentage > 60.0 {
                    "🟡 Good"
                } else if mesh_status.connectivity_percentage > 30.0 {
                    "🟠 Fair"
                } else {
                    "[POOR]"
                };

                Ok(format!(
                    "{} - {:.1}% connectivity, {} peers ({} local, {} regional, {} global, {} relays)",
                    status,
                    mesh_status.connectivity_percentage,
                    mesh_status.active_peers,
                    mesh_status.local_peers,
                    mesh_status.regional_peers,
                    mesh_status.global_peers,
                    mesh_status.relay_peers
                ))
            }
            Err(e) => Ok(format!("Mesh status unavailable: {}", e)),
        }
    }

    /// Run the main operational loop
    pub async fn run_main_loop(&self) -> Result<()> {
        info!(" Starting main operational loop...");

        // Wait a moment for components to fully initialize
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        info!("ZHTP system fully operational - ready for identity and transaction testing");

        // Create a future that never completes to keep the node running
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Perform periodic maintenance
                    if let Err(e) = self.perform_maintenance().await {
                        warn!("Maintenance cycle error: {}", e);
                    }
                }
            }

            // Check if shutdown was requested more frequently to improve responsiveness
            {
                let shutdown_signal = self.shutdown_signal.lock().await;
                if shutdown_signal.is_none() {
                    info!("Shutdown signal received, exiting main loop");
                    break;
                }
            }

            // Brief pause to allow other tasks to run and improve shutdown responsiveness
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Perform periodic maintenance tasks
    async fn perform_maintenance(&self) -> Result<()> {
        // Get system metrics
        let metrics = self.get_system_metrics().await?;
        debug!("System metrics: {} total metrics collected", metrics.len());

        // Check component health
        let health = self.get_detailed_health().await?;
        let unhealthy_components: Vec<_> = health
            .iter()
            .filter(|(_, h)| !matches!(h.status, ComponentStatus::Running))
            .map(|(id, _)| id.to_string())
            .collect();

        if !unhealthy_components.is_empty() {
            warn!("Unhealthy components: {:?}", unhealthy_components);
        }

        // Log summary
        let running_count = health
            .values()
            .filter(|h| matches!(h.status, ComponentStatus::Running))
            .count();
        debug!(
            "{}/{} components running normally",
            running_count,
            health.len()
        );

        Ok(())
    }

    /// Get the shared blockchain service
    pub async fn get_shared_blockchain_service(&self) -> Option<SharedBlockchainService> {
        self.shared_blockchain.read().await.clone()
    }

    /// Initialize the shared blockchain service once the blockchain component is started
    pub async fn initialize_shared_blockchain(&self) -> Result<()> {
        // Initialize the global blockchain provider first
        initialize_global_blockchain_provider();

        // Get the blockchain component's blockchain instance
        if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            // Try to get the blockchain instance from the blockchain component
            if let Some(blockchain_component) =
                component.as_any().downcast_ref::<BlockchainComponent>()
            {
                // Wait for blockchain to be initialized and get the actual instance
                if let Ok(blockchain_arc) = blockchain_component.get_initialized_blockchain().await
                {
                    // Set up the shared service
                    let shared_service = SharedBlockchainService::new(blockchain_arc.clone());
                    *self.shared_blockchain.write().await = Some(shared_service);

                    // Also set the global blockchain for protocol access
                    if let Err(e) = set_global_blockchain(blockchain_arc).await {
                        warn!("Failed to set global blockchain: {}", e);
                    } else {
                        info!("Global blockchain provider updated");
                    }

                    info!("Shared blockchain service initialized");
                    return Ok(());
                }
            }
        }

        warn!("Failed to initialize shared blockchain service - blockchain component not found");
        Ok(())
    }

    /// Wire the blockchain to the consensus component for validator synchronization
    ///
    /// This connects the blockchain's validator registry to the consensus layer's
    /// ValidatorManager, enabling multi-node consensus.
    pub async fn wire_blockchain_to_consensus(&self) -> Result<()> {
        info!("Wiring blockchain to consensus component...");

        // Get the blockchain Arc from BlockchainComponent
        let blockchain_arc = if let Some(component) =
            self.components.read().await.get(&ComponentId::Blockchain)
        {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>()
            {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };

        // Get the ConsensusComponent and set the blockchain reference
        if let Some(component) = self.components.read().await.get(&ComponentId::Consensus) {
            if let Some(consensus_comp) = component.as_any().downcast_ref::<ConsensusComponent>() {
                // Set the blockchain reference in consensus
                consensus_comp.set_blockchain(blockchain_arc).await;

                // Sync validators from blockchain to consensus
                consensus_comp.sync_validators_from_blockchain().await?;

                // Get the validator manager from consensus
                let validator_manager = consensus_comp.get_validator_manager().await;

                // Wire validator manager and node identity back to BlockchainComponent for mining coordination
                if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain)
                {
                    if let Some(blockchain_comp) =
                        component.as_any().downcast_ref::<BlockchainComponent>()
                    {
                        // Set validator manager
                        blockchain_comp
                            .set_validator_manager(validator_manager)
                            .await;
                        info!(" Validator manager connected to blockchain mining loop");

                        // Set node owner identity from wallet startup (secure node identity)
                        let wallet_guard = self.user_wallet.read().await;
                        if let Some(ref wallet_data) = *wallet_guard {
                            blockchain_comp
                                .set_node_identity(wallet_data.node_identity_id.clone())
                                .await;
                            info!(
                                " Node owner identity connected: {}",
                                hex::encode(&wallet_data.node_identity_id.0[..8])
                            );
                        } else {
                            warn!("  Node owner identity not available yet - mining will use bootstrap mode");
                        }
                    }
                }

                info!("Blockchain successfully connected to consensus validator manager");
                return Ok(());
            }
        }

        Err(anyhow::anyhow!("Consensus component not found"))
    }

    /// Sync wallet balances from blockchain UTXO set
    ///
    /// This ensures that in-memory wallet balances reflect the actual
    /// on-chain state, including genesis funding and any transactions.
    pub async fn sync_wallet_balances_from_blockchain(&self) -> Result<()> {
        info!(" Syncing wallet balances from blockchain wallet registry...");

        // Get the global IdentityManager
        let identity_manager_arc =
            match crate::runtime::identity_manager_provider::get_global_identity_manager().await {
                Ok(arc) => arc,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to get global IdentityManager: {}",
                        e
                    ));
                }
            };

        // Get the blockchain Arc from BlockchainComponent
        let blockchain_arc = if let Some(component) =
            self.components.read().await.get(&ComponentId::Blockchain)
        {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>()
            {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };

        // Extract wallet balance data from blockchain wallet_registry
        let wallet_balances = {
            let blockchain = blockchain_arc.read().await;
            let mut balances = std::collections::HashMap::new();

            info!(
                " Scanning blockchain wallet_registry (total entries: {})...",
                blockchain.wallet_registry.len()
            );

            for (wallet_id_hex, wallet_data) in blockchain.wallet_registry.iter() {
                if wallet_data.initial_balance > 0 {
                    info!(
                        "   Found funded wallet: {} → {} SOV",
                        &wallet_id_hex[..16],
                        wallet_data.initial_balance
                    );
                    balances.insert(wallet_id_hex.clone(), wallet_data.initial_balance);
                } else {
                    info!("   Skipping zero-balance wallet: {}", &wallet_id_hex[..16]);
                }
            }

            info!(
                " Extracted {} wallet balance entries from blockchain",
                balances.len()
            );
            balances
        };

        // Lock identity manager and perform sync
        let mut identity_manager = identity_manager_arc.write().await;

        // Sync balances from blockchain to identity wallets
        let mut synced_count = 0;
        let mut total_synced_amount = 0u128;

        for identity in identity_manager.list_identities_mut() {
            for (wallet_id, wallet) in identity.wallet_manager.wallets.iter_mut() {
                // Convert wallet_id to hex string to match blockchain registry
                let wallet_id_hex = hex::encode(wallet_id.0);

                if let Some(&blockchain_balance) = wallet_balances.get(&wallet_id_hex) {
                    // Only sync if blockchain has more than current balance (UBI accumulates)
                    if blockchain_balance > wallet.balance {
                        let diff = blockchain_balance - wallet.balance;
                        info!(
                            "   Syncing wallet {} ({}): {} → {} SOV (+{})",
                            wallet.alias.as_deref().unwrap_or("unnamed"),
                            &wallet_id_hex[..16],
                            wallet.balance,
                            blockchain_balance,
                            diff
                        );
                        wallet.balance = blockchain_balance;
                        synced_count += 1;
                        total_synced_amount += diff;
                    }
                }
            }
            identity.wallet_manager.calculate_total_balance();
        }

        info!(
            " Wallet balance sync complete: {} wallets updated, {} SOV synced",
            synced_count, total_synced_amount
        );
        Ok(())
    }

    /// Create a blockchain transaction consuming UTXOs for a wallet payment
    ///
    /// This is the proper UTXO-based payment flow:
    /// 1. Find UTXOs owned by the wallet's public key in blockchain.utxo_set
    /// 2. Select enough UTXOs to cover the payment amount
    /// 3. Ask IdentityManager to create and sign transaction (has access to private key)
    /// 4. Submit signed transaction to blockchain
    /// 5. Blockchain will consume UTXOs and create new outputs
    pub async fn create_wallet_payment_transaction(
        &self,
        _identity_id: &lib_identity::IdentityId,
        wallet_pubkey: &[u8],
        _recipient_pubkey: &[u8],
        amount: u64,
        purpose: &str,
    ) -> Result<lib_blockchain::Hash> {
        info!(
            " Creating blockchain transaction for wallet payment: {} SOV for '{}'",
            amount, purpose
        );

        // Step 1: Get blockchain and scan for UTXOs matching wallet_pubkey
        let blockchain_arc = if let Some(component) =
            self.components.read().await.get(&ComponentId::Blockchain)
        {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>()
            {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };

        let blockchain = blockchain_arc.read().await;

        // Scan UTXO set for outputs owned by this wallet
        let mut wallet_utxos: Vec<(lib_blockchain::Hash, u32, u128)> = Vec::new();

        info!(
            " Scanning {} UTXOs for wallet pubkey: {}",
            blockchain.utxo_set.len(),
            hex::encode(&wallet_pubkey[..8.min(wallet_pubkey.len())])
        );

        for (utxo_hash, output) in &blockchain.utxo_set {
            // Check if this UTXO belongs to our wallet
            // Compare recipient public key bytes with wallet pubkey
            if output.recipient.as_bytes() == wallet_pubkey {
                // NOTE: Amount is hidden in Pedersen commitment, so we need to get it from wallet_registry
                // For genesis UTXOs, we know the amount from wallet_registry initial_balance
                // In production, we'd need to decrypt the note or track amounts separately

                // For now, use a placeholder amount - this would come from wallet's UTXO tracking
                let utxo_amount = SOV_WELCOME_BONUS; // Genesis wallet funding amount

                wallet_utxos.push((*utxo_hash, 0, utxo_amount));
                info!("   Found UTXO: {}", hex::encode(utxo_hash.as_bytes()));
            }
        }

        if wallet_utxos.is_empty() {
            warn!("  No UTXOs found for wallet");
            return Err(anyhow::anyhow!("No UTXOs found for wallet"));
        }

        info!(" Found {} UTXOs for wallet", wallet_utxos.len());

        // Step 2: Select UTXOs to cover amount + fee
        let fee = 100u128; // 100 micro-SOV fee
        let required_amount = amount as u128 + fee;

        let mut selected_utxos = Vec::new();
        let mut total_selected = 0u128;

        for utxo in wallet_utxos {
            selected_utxos.push(utxo.clone());
            total_selected += utxo.2;

            if total_selected >= required_amount {
                break;
            }
        }

        if total_selected < required_amount {
            return Err(anyhow::anyhow!(
                "Insufficient UTXO balance: need {}, have {}",
                required_amount,
                total_selected
            ));
        }

        info!(
            " Selected {} UTXOs totaling {} SOV",
            selected_utxos.len(),
            total_selected
        );

        drop(blockchain); // Release read lock

        // Step 3: Get IdentityManager to create signed transaction
        let identity_mgr_arc = if let Some(component) =
            self.components.read().await.get(&ComponentId::Identity)
        {
            if let Some(identity_comp) = component.as_any().downcast_ref::<IdentityComponent>() {
                identity_comp.get_identity_manager_arc()
            } else {
                return Err(anyhow::anyhow!("Identity component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Identity component not found"));
        };

        let identity_mgr_opt = identity_mgr_arc.read().await;
        let _identity_mgr: &lib_identity::IdentityManager = identity_mgr_opt
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IdentityManager not initialized"))?;

        // Convert lib_blockchain::Hash to lib_crypto::Hash for IdentityManager
        let _selected_utxos_crypto: Vec<(lib_crypto::Hash, u32, u128)> = selected_utxos
            .iter()
            .map(|(hash, idx, amt)| (lib_crypto::Hash::from_bytes(hash.as_bytes()), *idx, *amt))
            .collect();

        // TODO: P1-7 - create_payment_transaction method removed
        // Need to implement transaction creation using new WalletManager API
        // For now, return error as this functionality needs to be reimplemented
        drop(identity_mgr_opt);

        return Err(anyhow::anyhow!(
            "Payment transaction creation not yet implemented in P1-7 architecture. \
             This functionality needs to be reimplemented using the new WalletManager API."
        ));

        /* TODO: P1-7 - Uncomment and reimplement this code using WalletManager API
        info!("💳 Building payment transaction: {} SOV to recipient, {} SOV change", amount, change_amount);

        // Step 4: Build Transaction using lib-blockchain TransactionBuilder
        use lib_blockchain::transaction::{TransactionInput, TransactionOutput, TransactionBuilder};
        use lib_blockchain::types::transaction_type::TransactionType;
        use lib_crypto::PrivateKey;

        // Create PrivateKey struct
        let private_key = PrivateKey {
            dilithium_sk: private_key_bytes,
            kyber_sk: Vec::new(),
            master_seed: vec![0u8; 32],
        };

        // Create transaction inputs from selected UTXOs
        let mut inputs = Vec::new();
        for (utxo_hash, output_index, _amount) in &selected_utxos {
            // Generate nullifier for this UTXO
            let nullifier_data = [utxo_hash.as_bytes(), &output_index.to_le_bytes()].concat();
            let nullifier = lib_blockchain::Hash::from_slice(&lib_crypto::hash_blake3(&nullifier_data)[..32]);

            // Create ZK proof - TransactionBuilder will generate proper proofs
            let zk_proof = lib_blockchain::integration::zk_integration::ZkTransactionProof::prove_transaction(
                total_input,     // sender_balance
                0,              // receiver_balance (not needed for input)
                amount,         // amount
                fee,            // fee
                [0u8; 32],     // sender_blinding (placeholder)
                [0u8; 32],     // receiver_blinding
                [0u8; 32],     // nullifier
            ).unwrap_or_else(|_| {
                // Fallback to empty proof if generation fails
                use lib_proofs::types::ZkProof;
                lib_proofs::ZkTransactionProof::new(
                    ZkProof::new("plonky2".to_string(), vec![], vec![], vec![], None),
                    ZkProof::new("plonky2".to_string(), vec![], vec![], vec![], None),
                    ZkProof::new("plonky2".to_string(), vec![], vec![], vec![], None),
                )
            });

            let input = TransactionInput::new(
                *utxo_hash,
                *output_index,
                nullifier,
                zk_proof,
            );
            inputs.push(input);
        }

        // Create transaction outputs
        let mut outputs = Vec::new();

        // Output 1: Payment to recipient
        let recipient_commitment = lib_blockchain::Hash::from_slice(
            &lib_crypto::hash_blake3(&[&b"commitment:"[..], recipient_pubkey, &amount.to_le_bytes()].concat())[..32]
        );
        let recipient_note = lib_blockchain::Hash::from_slice(
            &lib_crypto::hash_blake3(&[&b"note:"[..], recipient_pubkey, &amount.to_le_bytes()].concat())[..32]
        );
        let recipient_pk = lib_blockchain::integration::crypto_integration::PublicKey::new(recipient_pubkey.to_vec());

        outputs.push(TransactionOutput::new(
            recipient_commitment,
            recipient_note,
            recipient_pk,
        ));

        // Output 2: Change back to wallet (if any)
        if change_amount > 0 {
            let change_commitment = lib_blockchain::Hash::from_slice(
                &lib_crypto::hash_blake3(&[&b"commitment:"[..], &wallet_pubkey[..], &change_amount.to_le_bytes()].concat())[..32]
            );
            let change_note = lib_blockchain::Hash::from_slice(
                &lib_crypto::hash_blake3(&[&b"note:"[..], &wallet_pubkey[..], &change_amount.to_le_bytes()].concat())[..32]
            );
            let change_pk = lib_blockchain::integration::crypto_integration::PublicKey::new(wallet_pubkey.clone());

            outputs.push(TransactionOutput::new(
                change_commitment,
                change_note,
                change_pk,
            ));
        }

        // Build and sign the transaction
        let transaction = TransactionBuilder::new()
            .transaction_type(TransactionType::Transfer)
            .add_inputs(inputs)
            .add_outputs(outputs)
            .fee(fee)
            .build(&private_key)
            .context("Failed to build transaction")?;

        let tx_hash = transaction.hash();

        info!(" Built signed transaction: {}", hex::encode(tx_hash.as_bytes()));

        // Step 5: Submit transaction to blockchain
        let mut blockchain = blockchain_arc.write().await;

        blockchain.add_pending_transaction(transaction.clone())
            .context("Failed to add transaction to blockchain")?;

        info!("📤 Transaction submitted to mempool");

        drop(blockchain);

        Ok(tx_hash)
        */
    }

    /// Start the unified reward orchestrator
    async fn start_reward_orchestrator(&self) -> Result<()> {
        // Get NetworkComponent
        let network_component =
            if let Some(component) = self.components.read().await.get(&ComponentId::Network) {
                if let Some(network_comp) = component.as_any().downcast_ref::<NetworkComponent>() {
                    Arc::new(network_comp.clone())
                } else {
                    warn!("Network component found but type mismatch");
                    return Err(anyhow::anyhow!("Network component type mismatch"));
                }
            } else {
                warn!("Network component not found");
                return Err(anyhow::anyhow!("Network component not found"));
            };

        // Get BlockchainComponent's blockchain Arc
        let blockchain_arc = if let Some(component) =
            self.components.read().await.get(&ComponentId::Blockchain)
        {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>()
            {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                warn!("Blockchain component found but type mismatch");
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            warn!("Blockchain component not found");
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };

        // Wrap blockchain_arc in Option to match expected type
        let blockchain_with_option =
            Arc::new(RwLock::new(Some((*blockchain_arc.read().await).clone())));

        // Convert rewards config to orchestrator config
        let orchestrator_config =
            reward_orchestrator::RewardOrchestratorConfig::from(&self.config.rewards_config);

        // Create the unified reward orchestrator with configuration
        let orchestrator = Arc::new(reward_orchestrator::RewardOrchestrator::with_config(
            network_component,
            blockchain_with_option,
            self.config.environment.clone(),
            orchestrator_config,
        ));

        // Start all enabled reward processors
        orchestrator.start_all().await?;

        // Store the orchestrator instance
        *self.reward_orchestrator.write().await = Some(orchestrator);

        info!("Unified reward orchestrator started successfully");
        Ok(())
    }

    /// Register runtime-dependent handlers on ProtocolsComponent
    ///
    /// Called after ProtocolsComponent has started to register handlers that require
    /// Arc<RuntimeOrchestrator> (NetworkHandler, MeshHandler). These handlers couldn't
    /// be registered during UnifiedServer construction because RuntimeOrchestrator
    /// wasn't available yet.
    ///
    /// This must be called from main.rs or another location that has access to
    /// Arc<RuntimeOrchestrator>.
    pub async fn register_runtime_handlers(
        &self,
        runtime_arc: Arc<RuntimeOrchestrator>,
    ) -> Result<()> {
        // Get ProtocolsComponent from the components HashMap
        let components = self.components.read().await;
        let component = components
            .get(&ComponentId::Protocols)
            .ok_or_else(|| anyhow::anyhow!("ProtocolsComponent not found"))?;

        // Downcast to ProtocolsComponent
        let protocols_component = component
            .as_any()
            .downcast_ref::<crate::runtime::components::ProtocolsComponent>()
            .ok_or_else(|| anyhow::anyhow!("Failed to downcast to ProtocolsComponent"))?;

        // Register the runtime handlers on the protocols component
        protocols_component
            .register_runtime_handlers(runtime_arc.clone())
            .await?;

        // Wire neural mesh event sender into the global MeshRouter so that live
        // network events (peer connect/disconnect, blocks, shard access) reach
        // the RL Router, Anomaly Sentry, Prefetcher, and Compressor for training.
        let neural_tx = runtime_arc.get_neural_mesh_sender().await;
        if let Ok(mesh_router) =
            crate::runtime::mesh_router_provider::get_global_mesh_router().await
        {
            mesh_router.set_neural_mesh_sender(neural_tx).await;
            info!("🧠 Neural mesh live-training wired into MeshRouter");
        } else {
            warn!("MeshRouter not available — neural mesh will not receive live events");
        }

        Ok(())
    }

    /// Stop the unified reward orchestrator
    async fn stop_reward_orchestrator(&self) -> Result<()> {
        if let Some(orchestrator) = self.reward_orchestrator.write().await.take() {
            info!("Stopping unified reward orchestrator...");
            orchestrator.stop_all().await?;
            info!("Unified reward orchestrator stopped");
        }
        Ok(())
    }

    /// Get the shared blockchain instance from the blockchain component
    pub async fn get_shared_blockchain(
        &self,
    ) -> Result<Option<Arc<RwLock<Option<lib_blockchain::Blockchain>>>>> {
        // Create a channel for the response
        let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel();

        // Store response sender for potential cleanup
        let _response_sender = response_tx.clone();

        // Send a request to the blockchain component
        let blockchain_request = ComponentMessage::Custom(
            "get_blockchain_instance".to_string(),
            vec![], // Empty data since we can't serialize channels
        );

        if let Err(e) = self
            .send_message(ComponentId::Blockchain, blockchain_request)
            .await
        {
            warn!("Failed to request blockchain instance: {}", e);
            return Ok(None);
        }

        // Wait for response with timeout
        match tokio::time::timeout(Duration::from_secs(5), response_rx.recv()).await {
            Ok(Some(blockchain_arc)) => {
                info!("Received shared blockchain instance from blockchain component");
                Ok(Some(blockchain_arc))
            }
            Ok(None) => {
                warn!("Blockchain component channel closed");
                Ok(None)
            }
            Err(_) => {
                warn!("Timeout waiting for blockchain instance");
                Ok(None)
            }
        }
    }

    /// Send a blockchain operation to the blockchain component
    pub async fn execute_blockchain_operation(&self, operation: &str, data: Vec<u8>) -> Result<()> {
        let message = ComponentMessage::BlockchainOperation(operation.to_string(), data);
        self.send_message(ComponentId::Blockchain, message).await
    }

    /// Complete node startup sequence - orchestrates discovery, identity, and component initialization
    ///
    /// This is the main entry point for starting a ZHTP node. It handles:
    /// 1. Network component initialization
    /// 2. Peer discovery (via DiscoveryCoordinator)
    /// 3. Identity/wallet setup
    /// 4. Blockchain initialization or sync
    /// 5. Starting remaining components
    pub async fn startup_sequence(
        config: NodeConfig,
        is_edge_node: bool,
        edge_max_headers: usize,
    ) -> Result<Self> {
        info!("🚀 Starting ZHTP node startup sequence...");

        // Create orchestrator
        let mut orchestrator = Self::new(config.clone()).await?;

        // Configure edge node settings
        if is_edge_node {
            orchestrator.set_edge_node(true).await;
            orchestrator.set_edge_max_headers(edge_max_headers).await;
            info!("⚡ Edge mode: max_headers={}", edge_max_headers);
        }

        // PHASE 1: Start minimal components for peer discovery (Crypto + Network)
        info!("🔌 Phase 1: Starting network components for peer discovery...");
        orchestrator
            .start_network_components_for_discovery()
            .await?;

        // Wait for network stack initialization
        tokio::time::sleep(Duration::from_secs(2)).await;

        // PHASE 2: Discover existing network
        info!("🔍 Phase 2: Discovering ZHTP network...");
        let network_info = orchestrator
            .discover_network_with_retry(is_edge_node)
            .await?;

        // PHASE 3: Setup identity and blockchain
        info!("🔑 Phase 3: Setting up identity and blockchain...");

        // Always store bootstrap peers so the protocols/QUIC component can establish
        // outbound connections to validators regardless of whether we're syncing the chain.
        // Without this, nodes that skip startup sync (bootstrap leader with local data) never
        // call start_blockchain_sync() and therefore never populate the global peer provider,
        // leaving the consensus broadcaster with zero peers to send votes to.
        // Use the config peers directly — network_info.bootstrap_peers only includes "trusted
        // sync sources" which may be empty even when bootstrap_peers are configured.
        {
            let cfg_peers = orchestrator.config.network_config.bootstrap_peers.clone();
            if !cfg_peers.is_empty() {
                if let Err(e) = crate::runtime::bootstrap_peers_provider::set_bootstrap_peers(
                    cfg_peers.clone(),
                )
                .await
                {
                    warn!("Failed to store bootstrap peers for QUIC connections: {}", e);
                } else {
                    info!(
                        "Stored {} bootstrap peer(s) for persistent QUIC connections: {:?}",
                        cfg_peers.len(),
                        cfg_peers
                    );
                }
            }
        }

        // Skip startup sync for the bootstrap leader when local chain data exists.
        // This keeps G1 independent on restart and avoids pointless sync waits.
        let local_is_bootstrap_leader = match orchestrator.is_local_bootstrap_leader().await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Failed to determine bootstrap leader identity from keystore: {}",
                    e
                );
                false
            }
        };
        let leader_has_local_data = Self::should_skip_startup_sync(
            local_is_bootstrap_leader,
            orchestrator.has_local_chain_data(),
        );

        // Only join if peers have actual committed blocks.
        let peers_have_blocks = network_info
            .as_ref()
            .map(|ni| ni.chain_state.has_committed_blocks())
            .unwrap_or(false);
        if leader_has_local_data {
            orchestrator.set_joined_existing_network(false).await?;
            info!("🌱 Bootstrap leader with local chain data detected - skipping startup sync");
        } else if let Some(net_info) = network_info.as_ref().filter(|_| peers_have_blocks) {
            // Joining existing network
            orchestrator.set_joined_existing_network(true).await?;
            orchestrator.start_blockchain_sync(net_info).await?;

            // Wait for initial sync
            info!("⏳ Waiting for initial blockchain sync...");
            match orchestrator
                .wait_for_initial_sync(Duration::from_secs(30))
                .await
            {
                Ok(()) => {
                    let height = orchestrator.get_blockchain_height().await?;
                    info!("✓ Sync started: height {}", height);
                }
                Err(e) => {
                    warn!(
                        "⚠ Initial sync timeout: {} - will continue in background",
                        e
                    );
                }
            }
        } else {
            Self::validate_observer_join_policy(
                &orchestrator.config,
                orchestrator.has_local_chain_data(),
                network_info.as_ref(),
            )?;

            // Creating genesis network
            if is_edge_node {
                return Err(anyhow::anyhow!("Edge nodes must find an existing network"));
            }
            orchestrator.set_joined_existing_network(false).await?;
            info!("🌱 Creating genesis network");
        }

        // PHASE 4: Register and start all remaining components
        info!("⚙️ Phase 4: Starting all components...");
        orchestrator.register_all_components().await?;
        orchestrator.start_all_components().await?;

        info!("✅ ZHTP node startup sequence complete");
        Ok(orchestrator)
    }

    /// Start only Crypto and Network components for initial peer discovery
    pub async fn start_network_components_for_discovery(&mut self) -> Result<()> {
        use crate::runtime::components::{CryptoComponent, NetworkComponent};

        info!("   → Registering CryptoComponent...");
        self.register_component(Arc::new(CryptoComponent::new()))
            .await?;
        info!("   → Starting CryptoComponent...");
        self.start_component(ComponentId::Crypto).await?;

        info!("   → Registering NetworkComponent...");
        self.register_component(Arc::new(NetworkComponent::new()))
            .await?;
        info!("   → Starting NetworkComponent...");
        self.start_component(ComponentId::Network).await?;

        // Start peer discovery (via lib-network DHT, mDNS, etc.)
        info!("   → Starting peer discovery...");
        let node_uuid = uuid::Uuid::new_v4();
        let mesh_port = self.config.network_config.mesh_port;

        // Generate a temporary public key for discovery
        let keypair = lib_crypto::generate_keypair()?;
        let public_key = lib_crypto::PublicKey {
            dilithium_pk: keypair.public_key.dilithium_pk.clone(),
            kyber_pk: keypair.public_key.kyber_pk.clone(),
            key_id: keypair.public_key.key_id.clone(),
        };

        // Create signing context for TLS certificate pinning (Issue #739)
        let signing_ctx = lib_network::protocols::quic_mesh::get_tls_spki_hash_from_default_cert()
            .map(|tls_spki_sha256| {
                lib_network::discovery::local_network::DiscoverySigningContext {
                    dilithium_sk: keypair.private_key.dilithium_sk.clone(),
                    dilithium_pk: keypair.public_key.dilithium_pk.clone(),
                    tls_spki_sha256,
                }
            });

        // Start local discovery service (broadcasts immediately, then every 30s)
        if let Err(e) = lib_network::discovery::local_network::start_local_discovery(
            node_uuid,
            mesh_port,
            public_key,
            None, // No callback needed for discovery phase
            signing_ctx,
        )
        .await
        {
            warn!("      Failed to start local discovery: {}", e);
        } else {
            let signed =
                lib_network::protocols::quic_mesh::get_tls_spki_hash_from_default_cert().is_some();
            info!(
                "      ✓ Multicast broadcasting started (224.0.1.75:37775, TLS pinning: {})",
                signed
            );
        }

        Ok(())
    }

    /// Discover network with retry logic for edge nodes
    pub async fn discover_network_with_retry(
        &self,
        is_edge_node: bool,
    ) -> Result<Option<ExistingNetworkInfo>> {
        use crate::discovery_coordinator::DiscoveryCoordinator;

        let mut discovery_protocols =
            Self::discovery_protocols_from_config(&self.config.network_config.protocols);
        if discovery_protocols.is_empty() {
            discovery_protocols =
                vec![crate::discovery_coordinator::DiscoveryProtocol::UdpMulticast];
        }

        let config = crate::discovery_coordinator::DiscoveryConfig::new(
            self.config.network_config.bootstrap_peers.clone(),
            self.config.protocols_config.api_port,
            discovery_protocols,
            Self::trusted_sync_sources(&self.config).to_vec(),
        );
        let discovery = DiscoveryCoordinator::new(config);
        discovery.start_event_listener().await;

        let retry_continuously = Self::should_retry_network_discovery_continuously(
            &self.config,
            is_edge_node,
            self.has_local_chain_data(),
        );

        if retry_continuously {
            if is_edge_node {
                info!("🔍 Edge node: Continuously searching for ZHTP network...");
                info!("   Will retry every 5 seconds until a full node is found");
            } else {
                info!("🔍 Observer/full node: waiting for an existing ZHTP network...");
                info!("   Will retry every 5 seconds until committed blocks are discoverable");
            }

            let mut attempt = 1;
            loop {
                info!("📡 Discovery attempt #{}", attempt);
                match discovery.discover_network(&self.config.environment).await {
                    Ok(network_info) => {
                        if !is_edge_node && !network_info.chain_state.has_committed_blocks() {
                            match &network_info.chain_state {
                                RemoteChainState::Unknown => info!(
                                    "   ⏳ Found peers on attempt #{} but remote chain state is still unknown; \
                                     observer startup will keep waiting for a committed sync source",
                                    attempt
                                ),
                                RemoteChainState::GenesisOnly => info!(
                                    "   ⏳ Found peers on attempt #{} but they only advertise genesis; \
                                     observer startup will keep waiting for committed blocks",
                                    attempt
                                ),
                                RemoteChainState::Committed(_) => unreachable!(
                                    "guard excludes committed chain state"
                                ),
                            }
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            attempt += 1;
                            continue;
                        }

                        info!("✓ Found network on attempt #{}", attempt);
                        return Ok(Some(network_info));
                    }
                    Err(e) => {
                        warn!("   ✗ Attempt #{} failed: {}", attempt, e);
                        info!("   ⏳ Waiting 5 seconds before retry #{}", attempt + 1);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        attempt += 1;
                    }
                }
            }
        } else {
            info!("🔍 Attempting to discover existing ZHTP network...");
            info!("   Discovery timeout: 30 seconds");

            match discovery.discover_network(&self.config.environment).await {
                Ok(network_info) => {
                    info!("✓ Discovered ZHTP network peers");
                    info!("   Network peers: {}", network_info.peer_count);
                    info!("   Remote chain state: {}", network_info.chain_state);
                    Ok(Some(network_info))
                }
                Err(e) => {
                    info!("✗ No ZHTP peers discovered: {}", e);
                    Ok(None) // Full nodes can create genesis
                }
            }
        }
    }

    fn discovery_protocols_from_config(
        protocols: &[String],
    ) -> Vec<crate::discovery_coordinator::DiscoveryProtocol> {
        use crate::discovery_coordinator::DiscoveryProtocol;

        let mut mapped = Vec::new();
        for protocol in protocols {
            let normalized = protocol.to_ascii_lowercase();
            let discovery = match normalized.as_str() {
                "mesh" | "udp_multicast" | "udp" => Some(DiscoveryProtocol::UdpMulticast),
                "mdns" | "bonjour" => Some(DiscoveryProtocol::MDns),
                "bluetooth" | "bluetooth_le" | "ble" => Some(DiscoveryProtocol::BluetoothLE),
                "bluetooth_classic" => Some(DiscoveryProtocol::BluetoothClassic),
                "wifi_direct" | "wifi" => Some(DiscoveryProtocol::WiFiDirect),
                "dht" => Some(DiscoveryProtocol::DHT),
                "port_scan" => Some(DiscoveryProtocol::PortScan),
                "lorawan" => Some(DiscoveryProtocol::LoRaWAN),
                "satellite" => Some(DiscoveryProtocol::Satellite),
                _ => None,
            };

            if let Some(protocol) = discovery {
                if !mapped.contains(&protocol) {
                    mapped.push(protocol);
                }
            }
        }

        mapped
    }

    /// Graceful shutdown of the orchestrator
    pub async fn graceful_shutdown(&self) -> Result<()> {
        info!("Initiating graceful shutdown...");

        // Stop all components
        if let Err(e) = self.shutdown_all_components().await {
            error!("Error during component shutdown: {}", e);
        }

        // Signal shutdown completion
        {
            let mut shutdown_signal = self.shutdown_signal.lock().await;
            if let Some(tx) = shutdown_signal.take() {
                let _ = tx.send(());
            }
        }

        info!("Graceful shutdown completed");
        Ok(())
    }

    // ========================================================================
    // Public Getter Methods for Private Fields
    // ========================================================================

    /// Get a read-only clone of genesis identities
    pub async fn get_genesis_identities(&self) -> Vec<lib_identity::ZhtpIdentity> {
        self.genesis_identities.read().await.clone()
    }

    /// Get genesis private data for identity initialization
    pub async fn get_genesis_private_data(
        &self,
    ) -> Vec<(
        lib_identity::IdentityId,
        lib_identity::identity::PrivateIdentityData,
    )> {
        self.genesis_private_data.read().await.clone()
    }

    /// Get a read-only clone of user wallet
    pub async fn get_user_wallet(
        &self,
    ) -> Option<crate::runtime::did_startup::WalletStartupResult> {
        self.user_wallet.read().await.clone()
    }

    /// Get the environment configuration
    pub fn get_environment(&self) -> crate::config::environment::Environment {
        self.config.environment
    }

    /// Get bootstrap validators from network config
    pub fn get_bootstrap_validators(&self) -> Vec<crate::config::aggregation::BootstrapValidator> {
        self.config.network_config.bootstrap_validators.clone()
    }

    /// Check if node joined an existing network
    pub async fn get_joined_existing_network(&self) -> bool {
        *self.joined_existing_network.read().await
    }
}

fn canonical_genesis_hash() -> Result<lib_blockchain::Hash> {
    let bc = lib_blockchain::genesis::GenesisConfig::from_embedded()?.build_block0()?;
    let genesis = bc
        .blocks
        .first()
        .ok_or_else(|| anyhow::anyhow!("embedded genesis config produced no block 0"))?;
    Ok(genesis.header.calculate_hash())
}

fn validate_local_restore_compatibility(
    dat_bc: &lib_blockchain::Blockchain,
    allow_genesis_mismatch: bool,
) -> Result<()> {
    let expected_genesis_hash = canonical_genesis_hash()?;
    let actual_genesis_hash = dat_bc
        .blocks
        .first()
        .ok_or_else(|| anyhow::anyhow!("blockchain.dat contains no genesis block"))?
        .header
        .calculate_hash();

    if actual_genesis_hash != expected_genesis_hash {
        let message = format!(
            "blockchain.dat genesis hash mismatch: local={}, expected={}",
            actual_genesis_hash, expected_genesis_hash
        );
        if allow_genesis_mismatch {
            warn!("⚠️  {}", message);
            warn!(
                "⚠️  Proceeding because --allow-emergency-restore-genesis-mismatch was set"
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "{}. Emergency restore requires a compatible canonical genesis unless override is set.",
                message
            ))
        }
    } else {
        Ok(())
    }
}

fn load_validated_blockchain_dat(
    dat_path: &std::path::Path,
    allow_genesis_mismatch: bool,
) -> Result<Option<lib_blockchain::Blockchain>> {
    if !dat_path.exists() {
        return Ok(None);
    }
    #[allow(deprecated)]
    let dat_bc = lib_blockchain::Blockchain::load_from_file(dat_path)?;
    validate_local_restore_compatibility(&dat_bc, allow_genesis_mismatch)?;
    Ok(Some(dat_bc))
}

/// Tries to restore the oracle committee from an explicitly requested `blockchain.dat` backup.
///
/// Returns `true` if the committee was restored, `false` otherwise (dat absent or dat also has
/// an empty committee). Invalid or incompatible local files return an error.
pub(super) fn try_restore_oracle_from_dat(
    bc: &mut lib_blockchain::Blockchain,
    dat_path: &std::path::Path,
    allow_genesis_mismatch: bool,
) -> Result<bool> {
    match load_validated_blockchain_dat(dat_path, allow_genesis_mismatch)? {
        Some(dat_bc) if !dat_bc.oracle_state.committee.members().is_empty() => {
            let count = dat_bc.oracle_state.committee.members().len();
            bc.oracle_state = dat_bc.oracle_state;
            warn!(
                "⚠️  Emergency restore loaded oracle committee from blockchain.dat ({} members)",
                count
            );
            if let Some(store_ref) = bc.store.as_ref() {
                if let Err(e) = store_ref.save_oracle_state(&bc.oracle_state) {
                    warn!("⚠️ Failed to persist restored oracle_state to Sled: {}", e);
                }
            }
            Ok(true)
        }
        Some(_) => {
            warn!(
                "⚠️  Emergency restore requested, but blockchain.dat has no oracle committee"
            );
            Ok(false)
        }
        None => Ok(false),
    }
}

/// Seed validator_registry from bootstrap config when neither sled nor blockchain.dat
/// contains any validators (i.e. validators were never committed as on-chain transactions).
///
/// Uses blake3 domain separation to derive distinct placeholder keys for the networking and
/// rewards roles from the identity ID — these only need to be non-empty and mutually distinct
/// for the in-memory registry; they are not used for actual signing.
pub(super) fn seed_validators_from_bootstrap_config(
    bc: &mut lib_blockchain::Blockchain,
    bootstrap_validators: &[crate::config::aggregation::BootstrapValidator],
) {
    if bootstrap_validators.is_empty() {
        return;
    }
    let mut count = 0usize;
    for bv in bootstrap_validators {
        // Decode bootstrap consensus key (must be 2592 bytes for Dilithium5)
        // If not provided, generate a deterministic key from identity hash
        let consensus_key = crate::runtime::components::consensus::decode_bootstrap_consensus_key(
            &bv.consensus_key,
        )
        .unwrap_or_else(|| {
            // Generate deterministic Dilithium5 key from identity hash
            // This is for testing/bootstrap only - real validators must provide real keys
            let mut key = [0u8; 2592];
            let hash = blake3::hash(format!("{}::consensus", bv.identity_id).as_bytes());
            key[..32].copy_from_slice(hash.as_bytes());
            // Fill rest with derived data to avoid all-zeros
            for i in 1..(2592/32) {
                let chunk_hash = blake3::hash(&[hash.as_bytes(), &[i as u8][..]].concat());
                key[i*32..(i+1)*32].copy_from_slice(chunk_hash.as_bytes());
            }
            key
        });
        let networking_key = blake3::hash(format!("{}::networking", bv.identity_id).as_bytes())
            .as_bytes()
            .to_vec();
        let rewards_key = blake3::hash(format!("{}::rewards", bv.identity_id).as_bytes())
            .as_bytes()
            .to_vec();
        let vi = lib_blockchain::ValidatorInfo {
            identity_id: bv.identity_id.clone(),
            stake: bv.stake.max(1),
            storage_provided: bv.storage_provided,
            consensus_key,
            networking_key,
            rewards_key,
            network_address: bv.endpoints.first().cloned().unwrap_or_default(),
            commission_rate: bootstrap_commission_percent(bv.commission_rate),
            status: "active".to_string(),
            registered_at: 0,
            last_activity: 0,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: lib_blockchain::ADMISSION_SOURCE_BOOTSTRAP_GENESIS.to_string(),
            governance_proposal_id: None,
            oracle_key_id: None,
        };
        bc.validator_registry.insert(bv.identity_id.clone(), vi);
        count += 1;
    }
    info!(
        "validator_registry empty — seeded {} validator(s) from bootstrap config (in-memory only)",
        count
    );
}

fn bootstrap_commission_percent(commission_rate_bps: u16) -> u8 {
    (commission_rate_bps.min(10_000) / 100) as u8
}
pub(super) fn try_restore_validators_from_dat(
    bc: &mut lib_blockchain::Blockchain,
    dat_path: &std::path::Path,
    allow_genesis_mismatch: bool,
) -> Result<bool> {
    match load_validated_blockchain_dat(dat_path, allow_genesis_mismatch)? {
        Some(dat_bc) if !dat_bc.get_active_validators().is_empty() => {
            let count = dat_bc.get_active_validators().len();
            bc.validator_registry = dat_bc.validator_registry;
            warn!(
                "⚠️  Emergency restore loaded validator_registry from blockchain.dat ({} validators)",
                count
            );
            Ok(true)
        }
        Some(_) => {
            warn!(
                "⚠️  Emergency restore requested, but blockchain.dat has no validator_registry entries"
            );
            Ok(false)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod runtime_orchestrator_tests {
    use super::RuntimeOrchestrator;
    use crate::config::Environment;
    use crate::config::NodeType;
    use crate::runtime::node_runtime::NodeRole;
    use std::sync::Arc;
    use std::sync::{Mutex, OnceLock};
    use tokio::sync::RwLock;

    fn runtime_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn should_skip_startup_sync_only_for_leader_with_local_data() {
        assert!(RuntimeOrchestrator::should_skip_startup_sync(true, true));
        assert!(!RuntimeOrchestrator::should_skip_startup_sync(true, false));
        assert!(!RuntimeOrchestrator::should_skip_startup_sync(false, true));
        assert!(!RuntimeOrchestrator::should_skip_startup_sync(false, false));
    }

    #[test]
    fn validate_validator_endpoint_rejects_unspecified_ip() {
        let result = RuntimeOrchestrator::validate_validator_endpoint("0.0.0.0:9334");
        assert!(result.is_err());
    }

    #[test]
    fn validate_validator_endpoint_accepts_reachable_formats() {
        assert!(RuntimeOrchestrator::validate_validator_endpoint("10.1.2.3:9334").is_ok());
        assert!(
            RuntimeOrchestrator::validate_validator_endpoint("validator-g2.example.net:9334")
                .is_ok()
        );
    }

    #[test]
    fn full_node_startup_contract_accepts_observer_config() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        assert!(RuntimeOrchestrator::validate_observer_startup_config(&config).is_ok());
    }

    #[test]
    fn full_node_startup_contract_rejects_validator_enabled() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::FullValidator;
        config.consensus_config.validator_enabled = true;

        let err = RuntimeOrchestrator::validate_observer_startup_config(&config)
            .expect_err("full-node observer contract should reject validator-enabled config");
        assert!(
            err.to_string().contains("validator_enabled = false"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn full_node_startup_contract_rejects_non_observer_role() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::LightNode;
        config.consensus_config.validator_enabled = false;

        let err = RuntimeOrchestrator::validate_observer_startup_config(&config)
            .expect_err("full-node observer contract should reject non-observer role");
        assert!(
            err.to_string().contains("NodeRole::Observer") || err.to_string().contains("Observer"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn observer_join_policy_requires_existing_network_when_local_state_is_empty() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        let err = RuntimeOrchestrator::validate_observer_join_policy(&config, false, None)
            .expect_err("observer with empty local state must not create genesis");
        assert!(
            err.to_string().contains("requires an existing network"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn observer_join_policy_allows_restart_from_local_chain_data() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        assert!(RuntimeOrchestrator::validate_observer_join_policy(&config, true, None).is_ok());
    }

    #[test]
    fn observer_join_policy_allows_joining_network_with_committed_blocks() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        let network_info = crate::runtime::ExistingNetworkInfo {
            peer_count: 3,
            chain_state: crate::runtime::RemoteChainState::Committed(42),
            network_id: "testnet".to_string(),
            bootstrap_peers: vec!["127.0.0.1:9334".to_string()],
            environment: crate::config::Environment::Development,
        };

        assert!(RuntimeOrchestrator::validate_observer_join_policy(
            &config,
            false,
            Some(&network_info)
        )
        .is_ok());
    }

    #[test]
    fn observer_join_policy_rejects_genesis_only_networks() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        let network_info = crate::runtime::ExistingNetworkInfo {
            peer_count: 3,
            chain_state: crate::runtime::RemoteChainState::GenesisOnly,
            network_id: "testnet".to_string(),
            bootstrap_peers: vec!["127.0.0.1:9334".to_string()],
            environment: crate::config::Environment::Development,
        };

        let err =
            RuntimeOrchestrator::validate_observer_join_policy(&config, false, Some(&network_info))
                .expect_err("observer should keep waiting when peers only advertise genesis");

        assert!(
            err.to_string().contains("beyond genesis"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn observer_join_policy_rejects_unknown_remote_chain_state() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        let network_info = crate::runtime::ExistingNetworkInfo {
            peer_count: 2,
            chain_state: crate::runtime::RemoteChainState::Unknown,
            network_id: "testnet".to_string(),
            bootstrap_peers: vec!["127.0.0.1:9334".to_string()],
            environment: crate::config::Environment::Development,
        };

        let err =
            RuntimeOrchestrator::validate_observer_join_policy(&config, false, Some(&network_info))
                .expect_err("observer should not treat unknown remote state as sync-ready");

        assert!(
            err.to_string().contains("discovered_chain_state=unknown"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn full_node_role_derivation_disables_consensus_capabilities() {
        let role = RuntimeOrchestrator::derive_node_role_from_node_type(NodeType::FullNode);

        assert!(matches!(role, NodeRole::Observer));
        assert!(!role.can_mine(), "observer/full-node must not mine");
        assert!(!role.can_validate(), "observer/full-node must not validate");
        assert!(
            role.stores_full_blockchain(),
            "observer/full-node must retain full chain state"
        );
    }

    #[test]
    fn observer_startup_sync_contract_requires_discovery_before_serving() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        assert!(RuntimeOrchestrator::validate_observer_startup_config(&config).is_ok());

        let err = RuntimeOrchestrator::validate_observer_join_policy(&config, false, None)
            .expect_err("fresh observer must not create genesis without discovering a network");
        assert!(
            err.to_string().contains("requires an existing network"),
            "unexpected error: {err}"
        );

        assert!(
            RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, false),
            "fresh observer should keep retrying peer discovery until it can bootstrap"
        );
    }

    #[test]
    fn observer_admission_policy_requires_authorized_dids_when_enabled() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;
        config.network_config.observer_admission.required = true;
        config.network_config.observer_admission.trusted_sync_sources = vec![
            crate::config::TrustedSyncSource {
                address: "127.0.0.1:9334".to_string(),
                peer_did: None,
            },
        ];

        let err = RuntimeOrchestrator::validate_observer_admission_policy_config(&config, false)
            .expect_err("observer admission should require an explicit local DID allowlist");
        assert!(
            err.to_string().contains("authorized observer DIDs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn observer_admission_policy_requires_trusted_sync_sources_for_fresh_observer() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;
        config.network_config.observer_admission.required = true;
        config
            .network_config
            .observer_admission
            .authorized_observer_dids = vec!["did:zhtp:testobserver".to_string()];

        let err = RuntimeOrchestrator::validate_observer_admission_policy_config(&config, false)
            .expect_err("fresh admitted observer should require at least one trusted sync source");
        assert!(
            err.to_string().contains("trusted sync sources"),
            "unexpected error: {err}"
        );

        assert!(
            RuntimeOrchestrator::validate_observer_admission_policy_config(&config, true).is_ok(),
            "restarted observer with local chain should be allowed to run without remote sync sources"
        );
    }

    #[test]
    fn trusted_sync_source_matching_respects_endpoint_and_optional_did() {
        let trusted = vec![
            crate::config::TrustedSyncSource {
                address: "10.1.2.3:9334".to_string(),
                peer_did: Some("did:zhtp:trusted".to_string()),
            },
            crate::config::TrustedSyncSource {
                address: "10.1.2.4:9334".to_string(),
                peer_did: None,
            },
        ];

        assert!(crate::runtime::is_trusted_sync_source(
            "10.1.2.3:9334",
            Some("did:zhtp:trusted"),
            &trusted
        ));
        assert!(!crate::runtime::is_trusted_sync_source(
            "10.1.2.3:9334",
            Some("did:zhtp:other"),
            &trusted
        ));
        assert!(crate::runtime::is_trusted_sync_source(
            "10.1.2.4:9334",
            Some("did:zhtp:anything"),
            &trusted
        ));
        assert!(!crate::runtime::is_trusted_sync_source(
            "10.1.2.5:9334",
            Some("did:zhtp:trusted"),
            &trusted
        ));
    }

    #[test]
    fn observer_restart_contract_uses_local_chain_without_forcing_discovery() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        assert!(RuntimeOrchestrator::validate_observer_startup_config(&config).is_ok());
        assert!(RuntimeOrchestrator::validate_observer_join_policy(&config, true, None).is_ok());
        assert!(
            !RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, true),
            "observer restart with local chain state should not be forced back into discovery"
        );
    }

    #[test]
    fn observer_sync_contract_transitions_to_bootstrap_when_network_exists() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        let network_info = crate::runtime::ExistingNetworkInfo {
            peer_count: 4,
            chain_state: crate::runtime::RemoteChainState::Committed(128),
            network_id: "observer-testnet".to_string(),
            bootstrap_peers: vec!["127.0.0.1:9334".to_string()],
            environment: Environment::Development,
        };

        assert!(RuntimeOrchestrator::validate_observer_startup_config(&config).is_ok());
        assert!(
            RuntimeOrchestrator::validate_observer_join_policy(
                &config,
                false,
                Some(&network_info)
            )
            .is_ok(),
            "observer should be allowed to sync from an existing network instead of creating genesis"
        );
        assert!(
            RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, false),
            "fresh observer should continue discovery/sync attempts until chain data is local"
        );
    }

    #[test]
    fn observer_without_local_chain_retries_discovery_continuously() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        assert!(
            RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, false)
        );
    }

    #[test]
    fn observer_with_local_chain_does_not_force_continuous_discovery() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        assert!(
            !RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, true)
        );
    }

    #[test]
    fn observer_lifecycle_sequence_preserves_join_then_restart_contract() {
        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;

        let discovered_network = crate::runtime::ExistingNetworkInfo {
            peer_count: 4,
            chain_state: crate::runtime::RemoteChainState::Committed(128),
            network_id: "observer-sequence-testnet".to_string(),
            bootstrap_peers: vec!["127.0.0.1:9334".to_string(), "127.0.0.1:9335".to_string()],
            environment: Environment::Development,
        };

        assert!(RuntimeOrchestrator::validate_observer_startup_config(&config).is_ok());

        let fresh_start_err =
            RuntimeOrchestrator::validate_observer_join_policy(&config, false, None)
                .expect_err("fresh observer without discovery must not serve");
        assert!(
            fresh_start_err
                .to_string()
                .contains("requires an existing network"),
            "unexpected error: {fresh_start_err}"
        );
        assert!(
            RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, false),
            "fresh observer should stay in discovery until a network is found"
        );

        assert!(
            RuntimeOrchestrator::validate_observer_join_policy(
                &config,
                false,
                Some(&discovered_network)
            )
            .is_ok(),
            "observer should join once an existing network is discovered"
        );
        assert!(
            RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, false),
            "observer should keep trying until local chain state exists"
        );

        assert!(RuntimeOrchestrator::validate_observer_join_policy(&config, true, None).is_ok());
        assert!(
            !RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, false, true),
            "observer restart with local chain should not fall back into endless discovery"
        );
    }

    #[test]
    fn edge_nodes_always_retry_discovery_continuously() {
        let config = crate::config::NodeConfig::default();

        assert!(
            RuntimeOrchestrator::should_retry_network_discovery_continuously(&config, true, true)
        );
    }

    #[tokio::test]
    async fn observer_start_blockchain_sync_wires_runtime_state_for_joined_network() {
        let _guard = runtime_test_lock().lock().expect("runtime test lock");
        crate::runtime::bootstrap_peers_provider::clear_bootstrap_peers().await;

        let mut config = crate::config::NodeConfig::default();
        config.node_type = Some(NodeType::FullNode);
        config.node_role = NodeRole::Observer;
        config.consensus_config.validator_enabled = false;
        config.network_config.bootstrap_peers = vec!["127.0.0.1:1".to_string()];

        let mut orchestrator = RuntimeOrchestrator::new(config)
            .await
            .expect("observer runtime should initialize");
        let network_info = crate::runtime::ExistingNetworkInfo {
            peer_count: 1,
            chain_state: crate::runtime::RemoteChainState::Committed(42),
            network_id: "observer-runtime-join".to_string(),
            bootstrap_peers: vec!["127.0.0.1:1".to_string()],
            environment: Environment::Development,
        };

        orchestrator
            .set_joined_existing_network(true)
            .await
            .expect("join state should be writable");
        orchestrator
            .start_blockchain_sync(&network_info)
            .await
            .expect("start_blockchain_sync should wire temporary sync state");

        assert!(
            orchestrator.get_joined_existing_network().await,
            "observer should remain marked as joining an existing network"
        );

        let bootstrap_peers = crate::runtime::bootstrap_peers_provider::get_bootstrap_peers()
            .await
            .expect("bootstrap peers should be stored globally");
        assert_eq!(bootstrap_peers, network_info.bootstrap_peers);

        let global_blockchain = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .expect("temporary blockchain should be installed globally");
        assert_eq!(
            orchestrator
                .get_blockchain_height()
                .await
                .expect("height should be readable"),
            0
        );

        {
            let mut blockchain = global_blockchain.write().await;
            blockchain.height = 7;
        }

        assert_eq!(
            orchestrator
                .get_blockchain_height()
                .await
                .expect("height should reflect synced progress"),
            7
        );

        let restarted = RuntimeOrchestrator::new({
            let mut cfg = crate::config::NodeConfig::default();
            cfg.node_type = Some(NodeType::FullNode);
            cfg.node_role = NodeRole::Observer;
            cfg.consensus_config.validator_enabled = false;
            cfg
        })
        .await
        .expect("restart orchestrator should initialize");

        assert_eq!(
            restarted
                .get_blockchain_height()
                .await
                .expect("restart should see shared blockchain height"),
            7
        );

        crate::runtime::blockchain_provider::set_global_blockchain(Arc::new(RwLock::new(
            lib_blockchain::Blockchain::new().expect("fresh blockchain"),
        )))
        .await
        .expect("global blockchain reset should succeed");
        crate::runtime::bootstrap_peers_provider::clear_bootstrap_peers().await;
    }

    #[tokio::test]
    async fn observer_multi_orchestrator_join_sync_restart_sequence_preserves_shared_network_state()
    {
        let _guard = runtime_test_lock().lock().expect("runtime test lock");
        crate::runtime::bootstrap_peers_provider::clear_bootstrap_peers().await;

        let mut observer_a_config = crate::config::NodeConfig::default();
        observer_a_config.node_type = Some(NodeType::FullNode);
        observer_a_config.node_role = NodeRole::Observer;
        observer_a_config.consensus_config.validator_enabled = false;
        observer_a_config.network_config.bootstrap_peers = vec!["127.0.0.1:9334".to_string()];

        let mut observer_b_config = crate::config::NodeConfig::default();
        observer_b_config.node_type = Some(NodeType::FullNode);
        observer_b_config.node_role = NodeRole::Observer;
        observer_b_config.consensus_config.validator_enabled = false;
        observer_b_config.network_config.bootstrap_peers = vec!["127.0.0.1:9335".to_string()];

        let discovered_network = crate::runtime::ExistingNetworkInfo {
            peer_count: 3,
            chain_state: crate::runtime::RemoteChainState::Committed(64),
            network_id: "observer-shared-network".to_string(),
            bootstrap_peers: vec![
                "127.0.0.1:9334".to_string(),
                "127.0.0.1:9335".to_string(),
                "127.0.0.1:9336".to_string(),
            ],
            environment: Environment::Development,
        };

        let mut observer_a = RuntimeOrchestrator::new(observer_a_config)
            .await
            .expect("first observer runtime should initialize");
        let mut observer_b = RuntimeOrchestrator::new(observer_b_config)
            .await
            .expect("second observer runtime should initialize");

        observer_a
            .set_joined_existing_network(true)
            .await
            .expect("first observer join state should be writable");
        observer_a
            .start_blockchain_sync(&discovered_network)
            .await
            .expect("first observer should wire sync state from discovered network");

        assert!(
            observer_a.get_joined_existing_network().await,
            "first observer should remain marked as joined"
        );

        let bootstrap_peers = crate::runtime::bootstrap_peers_provider::get_bootstrap_peers()
            .await
            .expect("bootstrap peers should be stored after first observer joins");
        assert_eq!(bootstrap_peers, discovered_network.bootstrap_peers);

        {
            let blockchain = crate::runtime::blockchain_provider::get_global_blockchain()
                .await
                .expect("global blockchain should exist after first observer join");
            let mut blockchain = blockchain.write().await;
            blockchain.height = 9;
        }

        observer_b
            .set_joined_existing_network(true)
            .await
            .expect("second observer join state should be writable");
        observer_b
            .start_blockchain_sync(&discovered_network)
            .await
            .expect("second observer should reuse discovered network state");

        assert!(
            observer_b.get_joined_existing_network().await,
            "second observer should remain marked as joined"
        );
        assert_eq!(
            observer_b
                .get_blockchain_height()
                .await
                .expect("second observer should start from a fresh sync blockchain"),
            0
        );

        {
            let blockchain = crate::runtime::blockchain_provider::get_global_blockchain()
                .await
                .expect("second observer should install a fresh shared sync blockchain");
            let mut blockchain = blockchain.write().await;
            blockchain.height = 15;
        }

        let restarted_observer_a = RuntimeOrchestrator::new({
            let mut cfg = crate::config::NodeConfig::default();
            cfg.node_type = Some(NodeType::FullNode);
            cfg.node_role = NodeRole::Observer;
            cfg.consensus_config.validator_enabled = false;
            cfg.network_config.bootstrap_peers = vec!["127.0.0.1:9334".to_string()];
            cfg
        })
        .await
        .expect("restarted first observer should initialize");

        assert_eq!(
            restarted_observer_a
                .get_blockchain_height()
                .await
                .expect("restart should keep observing the shared synced height"),
            15
        );

        crate::runtime::blockchain_provider::set_global_blockchain(Arc::new(RwLock::new(
            lib_blockchain::Blockchain::new().expect("fresh blockchain"),
        )))
        .await
        .expect("global blockchain reset should succeed");
        crate::runtime::bootstrap_peers_provider::clear_bootstrap_peers().await;
    }
}

#[cfg(test)]
mod oracle_startup_tests {
    use super::{load_validated_blockchain_dat, try_restore_oracle_from_dat};
    use lib_blockchain::{Blockchain, ValidatorInfo};
    use tempfile::tempdir;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Build a fresh `Blockchain` (no Sled store) with the oracle committee
    /// seeded from the given key_ids.
    fn make_blockchain_with_committee(member_ids: Vec<[u8; 32]>) -> Blockchain {
        let mut bc = Blockchain::new().expect("Blockchain::new");
        if !member_ids.is_empty() {
            let members_with_pubkeys: Vec<([u8; 32], Vec<u8>)> =
                member_ids.into_iter().map(|id| (id, vec![])).collect();
            bc.bootstrap_oracle_committee(members_with_pubkeys)
                .expect("bootstrap_oracle_committee");
        }
        bc
    }

    fn write_incompatible_dat(dat_path: &std::path::Path) {
        let mut bc = Blockchain::new().expect("Blockchain::new");
        bc.blocks[0].header.version = bc.blocks[0].header.version.saturating_add(1);
        #[allow(deprecated)]
        bc.save_to_file(dat_path).expect("save_to_file");
    }

    // ------------------------------------------------------------------
    // try_restore_oracle_from_dat
    // ------------------------------------------------------------------

    #[test]
    fn restore_succeeds_when_dat_has_committee() {
        let dir = tempdir().unwrap();
        let dat_path = dir.path().join("blockchain.dat");

        // Persist a blockchain that has an oracle committee to the dat file.
        let src = make_blockchain_with_committee(vec![[1u8; 32], [2u8; 32]]);
        #[allow(deprecated)]
        src.save_to_file(&dat_path).expect("save_to_file");

        // Target blockchain loaded from Sled with empty oracle committee.
        let mut target = Blockchain::new().expect("Blockchain::new");
        assert!(target.oracle_state.committee.members().is_empty());

        let restored = try_restore_oracle_from_dat(&mut target, &dat_path, false)
            .expect("try_restore_oracle_from_dat");

        assert!(restored, "expected restoration to succeed");
        assert_eq!(
            target.oracle_state.committee.members().len(),
            2,
            "committee should have been restored from dat"
        );
    }

    #[test]
    fn restore_is_noop_when_dat_committee_is_empty() {
        let dir = tempdir().unwrap();
        let dat_path = dir.path().join("blockchain.dat");

        // Persist a blockchain with NO oracle committee.
        let empty_src = Blockchain::new().expect("Blockchain::new");
        #[allow(deprecated)]
        empty_src.save_to_file(&dat_path).expect("save_to_file");

        let mut target = Blockchain::new().expect("Blockchain::new");
        let restored = try_restore_oracle_from_dat(&mut target, &dat_path, false)
            .expect("try_restore_oracle_from_dat");

        assert!(
            !restored,
            "should not restore when dat also has empty committee"
        );
        assert!(
            target.oracle_state.committee.members().is_empty(),
            "committee should remain empty"
        );
    }

    #[test]
    fn restore_is_noop_when_dat_file_absent() {
        let dir = tempdir().unwrap();
        let nonexistent = dir.path().join("does_not_exist.dat");

        let mut target = Blockchain::new().expect("Blockchain::new");
        let restored = try_restore_oracle_from_dat(&mut target, &nonexistent, false)
            .expect("try_restore_oracle_from_dat");

        assert!(!restored, "should not restore when dat file does not exist");
        assert!(target.oracle_state.committee.members().is_empty());
    }

    #[test]
    fn emergency_restore_rejects_mismatched_genesis_without_override() {
        let dir = tempdir().unwrap();
        let dat_path = dir.path().join("blockchain.dat");
        write_incompatible_dat(&dat_path);

        let err = load_validated_blockchain_dat(&dat_path, false)
            .expect_err("mismatched genesis should be rejected");
        assert!(
            err.to_string().contains("genesis hash mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn emergency_restore_allows_mismatched_genesis_with_override() {
        let dir = tempdir().unwrap();
        let dat_path = dir.path().join("blockchain.dat");
        write_incompatible_dat(&dat_path);

        let restored = load_validated_blockchain_dat(&dat_path, true)
            .expect("override should allow incompatible dat");
        assert!(restored.is_some(), "override should still load local dat");
    }

    // ------------------------------------------------------------------
    // Bootstrap from validator registry (ensure_oracle_committee_bootstrapped logic)
    // ------------------------------------------------------------------

    #[test]
    fn bootstrap_from_validator_registry_populates_committee() {
        let mut bc = Blockchain::new().expect("Blockchain::new");
        assert!(bc.oracle_state.committee.members().is_empty());

        // Insert an active validator with a Dilithium5-sized consensus key.
        let consensus_key = [0xABu8; 2592];
        let key_id = lib_blockchain::blake3_hash(&consensus_key).as_array();
        bc.validator_registry.insert(
            "did:zhtp:validator-test".to_string(),
            ValidatorInfo {
                identity_id: "did:zhtp:validator-test".to_string(),
                stake: 1_000_000,
                storage_provided: 0,
                consensus_key,
                networking_key: vec![0xCDu8; 32],
                rewards_key: vec![0xEFu8; 32],
                network_address: "10.0.0.1:9334".to_string(),
                commission_rate: 5,
                status: "active".to_string(),
                registered_at: 0,
                last_activity: 0,
                blocks_validated: 0,
                slash_count: 0,
                admission_source: "test".to_string(),
                governance_proposal_id: None,
                oracle_key_id: None,
            },
        );

        // Replicate the bootstrap logic from seed_blockchain_validator_registry.
        // Type system now enforces 2592-byte keys, no length check needed.
        let mut committee_members: Vec<([u8; 32], Vec<u8>)> = bc
            .validator_registry
            .values()
            .filter(|v| v.status == "active")
            .map(|v| {
                let kid = lib_blockchain::blake3_hash(&v.consensus_key).as_array();
                (kid, v.consensus_key.to_vec())
            })
            .collect();
        committee_members.sort_by(|(a, _), (b, _)| a.cmp(b));
        committee_members.dedup_by(|(a, _), (b, _)| a == b);

        bc.bootstrap_oracle_committee(committee_members)
            .expect("bootstrap_oracle_committee");

        assert_eq!(bc.oracle_state.committee.members().len(), 1);
        assert!(bc.oracle_state.committee.members().contains(&key_id));
    }

    #[test]
    fn bootstrap_skips_validators_with_all_zeros_key() {
        let mut bc = Blockchain::new().expect("Blockchain::new");

        // Insert a validator with an all-zeros consensus key (invalid).
        // Type system enforces 2592-byte size, but we can still test for invalid content.
        bc.validator_registry.insert(
            "did:zhtp:bad-validator".to_string(),
            ValidatorInfo {
                identity_id: "did:zhtp:bad-validator".to_string(),
                stake: 1_000_000,
                storage_provided: 0,
                consensus_key: [0u8; 2592], // all zeros — invalid key
                networking_key: vec![0x01u8; 32],
                rewards_key: vec![0x02u8; 32],
                network_address: "10.0.0.2:9334".to_string(),
                commission_rate: 0,
                status: "active".to_string(),
                registered_at: 0,
                last_activity: 0,
                blocks_validated: 0,
                slash_count: 0,
                admission_source: "test".to_string(),
                governance_proposal_id: None,
                oracle_key_id: None,
            },
        );

        // Filter out validators with all-zeros keys (invalid)
        let committee_members: Vec<([u8; 32], [u8; 2592])> = bc
            .validator_registry
            .values()
            .filter(|v| v.status == "active")
            .filter(|v| v.consensus_key != [0u8; 2592]) // skip all-zeros
            .map(|v| {
                let kid = lib_blockchain::blake3_hash(&v.consensus_key).as_array();
                (kid, v.consensus_key)
            })
            .collect();

        // No valid keys — bootstrap should not be called, committee stays empty.
        assert!(
            committee_members.is_empty(),
            "all-zeros keys should be filtered out"
        );
        assert!(bc.oracle_state.committee.members().is_empty());
    }
}

#[cfg(test)]
mod validator_startup_tests {
    use super::{bootstrap_commission_percent, try_restore_validators_from_dat};
    use lib_blockchain::{Blockchain, ValidatorInfo};
    use tempfile::tempdir;

    fn make_validator(id: &str) -> ValidatorInfo {
        ValidatorInfo {
            identity_id: id.to_string(),
            stake: 1,
            storage_provided: 0,
            consensus_key: [0u8; 2592], // Dilithium5 public key size
            networking_key: vec![0u8; 32],
            rewards_key: vec![0u8; 32],
            network_address: String::new(),
            commission_rate: 0,
            status: "active".to_string(),
            registered_at: 0,
            last_activity: 0,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: lib_blockchain::ADMISSION_SOURCE_BOOTSTRAP_GENESIS.to_string(),
            governance_proposal_id: None,
            oracle_key_id: None,
        }
    }

    #[test]
    fn restore_succeeds_when_dat_has_validators() {
        let dir = tempdir().unwrap();
        let dat_path = dir.path().join("blockchain.dat");

        let mut src = Blockchain::new().expect("Blockchain::new");
        src.validator_registry
            .insert("validator-1".to_string(), make_validator("validator-1"));
        src.validator_registry
            .insert("validator-2".to_string(), make_validator("validator-2"));
        #[allow(deprecated)]
        src.save_to_file(&dat_path).expect("save_to_file");

        let mut target = Blockchain::new().expect("Blockchain::new");
        assert!(target.get_active_validators().is_empty());

        let restored = try_restore_validators_from_dat(&mut target, &dat_path, false)
            .expect("try_restore_validators_from_dat");

        assert!(restored, "expected restoration to succeed");
        assert_eq!(
            target.get_active_validators().len(),
            2,
            "validator_registry should have been restored from dat"
        );
    }

    #[test]
    fn restore_is_noop_when_dat_validator_registry_is_empty() {
        let dir = tempdir().unwrap();
        let dat_path = dir.path().join("blockchain.dat");

        let empty_src = Blockchain::new().expect("Blockchain::new");
        #[allow(deprecated)]
        empty_src.save_to_file(&dat_path).expect("save_to_file");

        let mut target = Blockchain::new().expect("Blockchain::new");
        let restored = try_restore_validators_from_dat(&mut target, &dat_path, false)
            .expect("try_restore_validators_from_dat");

        assert!(
            !restored,
            "should not restore when dat also has empty registry"
        );
        assert!(target.get_active_validators().is_empty());
    }

    #[test]
    fn bootstrap_commission_rate_converts_basis_points_to_percent() {
        assert_eq!(bootstrap_commission_percent(0), 0);
        assert_eq!(bootstrap_commission_percent(500), 5);
        assert_eq!(bootstrap_commission_percent(9_999), 99);
        assert_eq!(bootstrap_commission_percent(10_000), 100);
        assert_eq!(bootstrap_commission_percent(20_000), 100);
    }

    #[test]
    fn restore_is_noop_when_dat_file_absent() {
        let dir = tempdir().unwrap();
        let nonexistent = dir.path().join("does_not_exist.dat");

        let mut target = Blockchain::new().expect("Blockchain::new");
        let restored = try_restore_validators_from_dat(&mut target, &nonexistent, false)
            .expect("try_restore_validators_from_dat");

        assert!(!restored, "should not restore when dat file does not exist");
        assert!(target.get_active_validators().is_empty());
    }
}

/// Create or load persistent node identity
///
/// Uses the standard keystore path (~/.zhtp/keystore/) for identity persistence.
/// This ensures consistency with WalletStartupManager and prevents identity loss.
pub async fn create_or_load_node_identity(
    _environment: &crate::config::Environment,
) -> Result<lib_identity::ZhtpIdentity> {
    // Use the standard keystore path for ALL environments
    // This matches WalletStartupManager and ensures identity persistence
    let keystore_path = crate::node_data_dir().join("keystore");

    // SECURITY REVIEW: ZHTP_DEVICE_NAME env var is checked inside resolve_device_name()
    // to allow operators to configure deterministic NodeId across restarts and cluster
    // deployments. The value is validated by normalize_device_name() which enforces:
    // alphanumeric + .-_ only, max 64 chars, lowercased. Changing this value changes
    // the node's network identity (NodeId), which affects peer discovery and mesh routing.
    // An attacker with env var access could cause identity instability but cannot
    // impersonate other nodes (requires private key for DID). This is a configuration
    // integrity concern, not data exposure. See resolve_device_name_with_host() for
    // audit logging when the env var is set.
    let device_name =
        resolve_device_name(Some("zhtp-node")).context("Failed to resolve node device name")?;
    info!("Using node device name: {}", device_name);

    // Try to load an existing identity (with private key) from the keystore
    if let Some(identity) =
        crate::runtime::did_startup::load_node_identity_from_keystore(&keystore_path)
            .await
            .context("Failed to load node identity from keystore")?
    {
        info!(
            "Loaded existing node identity from keystore: {}",
            identity.did
        );
        return Ok(identity);
    }

    // Create new identity using P1-7 architecture
    info!(
        "Creating new node identity (no existing keystore found)... device={}",
        device_name
    );
    let node_identity = lib_identity::ZhtpIdentity::new_unified(
        lib_identity::types::IdentityType::Device,
        None, // No age for device
        None, // No jurisdiction for device
        &device_name,
        None, // Random seed
    )
    .context("Failed to create new unified node identity")?;

    crate::runtime::did_startup::persist_node_identity_to_keystore(&keystore_path, &node_identity)
        .await
        .context("Failed to persist node identity to keystore")?;
    info!(
        "Created and saved node identity to keystore at {:?}",
        keystore_path
    );
    Ok(node_identity)
}
