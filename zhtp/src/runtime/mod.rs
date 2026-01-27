//! Runtime Orchestration System
//! 
//! Coordinates the lifecycle and interactions of all ZHTP components

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, error, debug};

use super::config::NodeConfig;
use crate::runtime::node_identity::{
    derive_node_id,
    log_runtime_node_identity,
    resolve_device_name,
    set_runtime_node_identity,
    RuntimeNodeIdentity,
};
// Removed ZK coordinator - using unified lib-proofs system directly

/// Information about an existing network discovered during startup
#[derive(Debug, Clone)]
pub struct ExistingNetworkInfo {
    pub peer_count: u32,
    pub blockchain_height: u64,
    pub network_id: String,
    pub bootstrap_peers: Vec<String>,
    pub environment: crate::config::Environment,
}


pub mod components;
pub mod services;
pub mod shared_blockchain;
pub mod shared_dht;
pub mod blockchain_provider;
pub mod storage_provider;  // Global access to storage for component sharing
pub mod edge_state_provider;  // Global access to edge node state for header-only sync
pub mod identity_manager_provider;
pub mod network_blockchain_provider;
pub mod network_blockchain_event_receiver;
pub mod mesh_router_provider;
pub mod bootstrap_peers_provider;  // FIX: Global access to bootstrap peers for UnifiedServer
pub mod did_startup;
pub mod dht_indexing;
pub mod routing_rewards;
pub mod storage_rewards;
pub mod reward_orchestrator;
pub mod node_identity;
pub mod node_runtime;
pub mod node_runtime_orchestrator;
#[cfg(test)]
pub mod test_api_integration;

pub use components::*;
pub use node_runtime::{
    NodeRuntime, DefaultNodeRuntime, NodeRole, NodeAction, PeerInfo, PeerState,
    PeerStateChange, DiscoveryProtocol, SyncType, Tick,
};
pub use node_runtime_orchestrator::NodeRuntimeOrchestrator;
pub use shared_blockchain::*;
pub use shared_dht::*;
pub use blockchain_provider::{initialize_global_blockchain_provider, set_global_blockchain, is_global_blockchain_available};
pub use identity_manager_provider::{initialize_global_identity_manager_provider, set_global_identity_manager, get_global_identity_manager};
pub use network_blockchain_provider::ZhtpBlockchainProvider;
pub use mesh_router_provider::{initialize_global_mesh_router_provider, set_global_mesh_router, get_broadcast_metrics};

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
    genesis_private_data: Arc<RwLock<Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>>>,
    
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
}

impl RuntimeOrchestrator {
    /// Create a new runtime orchestrator
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
        
        // Spawn shutdown monitor task
        let shutdown_monitor = tokio::spawn(async move {
            if let Some(_shutdown_signal) = shutdown_rx.recv().await {
                tracing::info!("Shutdown signal received, initiating graceful shutdown");
            }
        });
        
        // Store shutdown monitor handle for cleanup
        let _shutdown_handle = shutdown_monitor;
        // Detect node type from config
        // Edge nodes are constrained devices that:
        // 1. Don't validate blocks (validator_enabled = false)
        // 2. Don't run smart contracts (resource constrained)
        // 3. Don't host storage for others (hosted_storage_gb = 0 or very small)
        //
        // Note: blockchain_storage_gb is NOT counted - it grows dynamically
        // Note: personal_storage_gb is NOT counted - user's own data
        //
        // hosted_storage_gb=0 is a valid value meaning "no hosted storage" (edge node)
        // Only use storage_capacity_gb fallback if hosted_storage_gb was NOT explicitly configured
        // The default hosted_storage_gb is 100, so if it equals default AND storage_capacity_gb differs,
        // use storage_capacity_gb for backward compatibility
        let hosted_storage = config.storage_config.hosted_storage_gb;
        
        let is_edge_node = !config.consensus_config.validator_enabled 
            && !config.blockchain_config.smart_contracts
            && hosted_storage < 100;  // Less than 100 GB hosted storage = edge node
        
        // Debug output for node role derivation
        tracing::debug!("   validator_enabled (config): {}", config.consensus_config.validator_enabled);
        tracing::debug!("   smart_contracts (config): {}", config.blockchain_config.smart_contracts);
        tracing::debug!("   hosted_storage: {} GB", hosted_storage);
        tracing::debug!("   is_edge_node: {}", is_edge_node);
        
        // Derive NodeRole from configuration
        // This determines what services (mining, validation) the node can run
        let node_role = Self::derive_node_role_from_config(&config, is_edge_node);
        info!("🎭 Node role determined: {:?}", node_role);
        info!("   can_mine: {}, can_validate: {}, can_verify_blocks: {}", 
              node_role.can_mine(), node_role.can_validate(), node_role.can_verify_blocks());
        
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
            edge_max_headers: Arc::new(RwLock::new(500)),  // Default 500 headers (~100 KB)
            pending_identity: Arc::new(RwLock::new(None)),
            node_role: Arc::new(RwLock::new(node_role)),
            startup_order: vec![
                ComponentId::Crypto,      // Foundation layer
                ComponentId::ZK,          // Zero-knowledge proofs
                ComponentId::Identity,    // Identity management
                ComponentId::Storage,     // Distributed storage
                ComponentId::Network,     // Mesh networking
                ComponentId::Blockchain,  // Blockchain layer
                ComponentId::Consensus,   // Consensus mechanism
                ComponentId::Economics,   // Economic incentives
                ComponentId::Protocols,   // High-level protocols (includes ZHTP server with comprehensive handlers)
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

        // Start health monitoring task
        let health_clone = orchestrator.component_health.clone();
        let components_clone = orchestrator.components.clone();
        let health_interval = orchestrator.config.integration_settings.health_check_interval_ms;
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

        info!("Runtime orchestrator initialized with {} components", orchestrator.startup_order.len());
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
    fn derive_node_role_from_config(config: &NodeConfig, is_edge_node: bool) -> node_runtime::NodeRole {
        use node_runtime::NodeRole;
        
        // Edge nodes are either LightNode or MobileNode
        if is_edge_node {
            // Check if this is a mobile/BLE-optimized node
            // For now, we determine this by checking if BLE is the primary transport
            // TODO: Add explicit mobile_mode config flag
            return NodeRole::LightNode;
        }
        
        // Full nodes: check if they're validators
        if config.consensus_config.validator_enabled {
            // This node participates in consensus and can mine blocks
            return NodeRole::FullValidator;
        }
        
        // Non-validator full nodes are Observers
        // They store the full blockchain and verify blocks for themselves
        // but don't participate in consensus voting
        NodeRole::Observer
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
        health.insert(id.clone(), ComponentHealth {
            status: ComponentStatus::Stopped,
            last_heartbeat: Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime: Duration::ZERO,
            memory_usage: 0,
            cpu_usage: 0.0,
        });
        
        debug!("Component {} registered successfully", id);
        Ok(())
    }

    /// Register all component instances (with singleton guard)
    pub async fn register_all_components(&self) -> Result<()> {
        info!("Registering all ZHTP component instances...");
        
        // Import all component types
        use crate::runtime::components::{
            CryptoComponent, ZKComponent, IdentityComponent, StorageComponent, 
            NetworkComponent, BlockchainComponent, ConsensusComponent, 
            EconomicsComponent, ProtocolsComponent, ApiComponent
        };
        
        // Helper to check if component exists
        let is_registered = |id: ComponentId| async move {
            self.components.read().await.contains_key(&id)
        };

        // Register components in dependency order
        
        if !is_registered(ComponentId::Crypto).await {
            self.register_component(Arc::new(CryptoComponent::new())).await?;
        }
        
        if !is_registered(ComponentId::ZK).await {
            self.register_component(Arc::new(ZKComponent::new())).await?;
        }
        
        // Create Identity component with genesis identities AND private keys if available
        if !is_registered(ComponentId::Identity).await {
            let genesis_identities = self.genesis_identities.read().await.clone();
            let genesis_private_data = self.genesis_private_data.read().await.clone();
            
            if genesis_identities.is_empty() {
                info!("Registering Identity component without genesis identities");
                self.register_component(Arc::new(IdentityComponent::new())).await?;
            } else {
                info!(" Registering Identity component with {} genesis identities and {} private keys", 
                    genesis_identities.len(), genesis_private_data.len());
                self.register_component(Arc::new(
                    IdentityComponent::new_with_identities_and_private_data(genesis_identities, genesis_private_data)
                )).await?;
            }
        }
        
        if !is_registered(ComponentId::Storage).await {
            self.register_component(Arc::new(StorageComponent::new())).await?;
        }
        
        if !is_registered(ComponentId::Network).await {
            self.register_component(Arc::new(NetworkComponent::new())).await?;
        }
        
        if !is_registered(ComponentId::Blockchain).await {
            // Pass user wallet, environment AND bootstrap validators to blockchain component for proper network initialization
            let user_wallet_guard = self.user_wallet.read().await;
            let user_wallet = user_wallet_guard.clone();
            let environment = self.config.environment;  // Get environment from config
            let bootstrap_validators = self.config.network_config.bootstrap_validators.clone();  // Get bootstrap validators from config
            let joined_existing_network = *self.joined_existing_network.read().await;  // Check if we joined existing network
            let node_role = self.node_role.read().await.clone();

            let blockchain_component = BlockchainComponent::new_with_full_config(node_role, user_wallet, environment, bootstrap_validators, joined_existing_network);
            self.register_component(Arc::new(blockchain_component)).await?;
        }

        if !is_registered(ComponentId::Consensus).await {
            let environment = self.config.environment;
            let node_role = self.node_role.read().await.clone();
            self.register_component(Arc::new(ConsensusComponent::new(environment, node_role))).await?;
        }
        
        if !is_registered(ComponentId::Economics).await {
            self.register_component(Arc::new(EconomicsComponent::new())).await?;
        }
        
        if !is_registered(ComponentId::Protocols).await {
            let environment = self.config.environment;
            let api_port = self.config.protocols_config.api_port;
            let quic_port = self.config.protocols_config.quic_port;
            let discovery_port = self.config.protocols_config.discovery_port;
            let is_edge_node = *self.is_edge_node.read().await;
            self.register_component(Arc::new(ProtocolsComponent::new_with_node_type_and_ports(
                environment, api_port, quic_port, discovery_port, is_edge_node
            ))).await?;
        }
        
        if !is_registered(ComponentId::Api).await {
            self.register_component(Arc::new(ApiComponent::new())).await?;
        }
        
        info!("All components registered successfully");
        Ok(())
    }

    /// Set user wallet data for components that need it (replaces identity-based approach)
    pub async fn set_user_identity(&self, wallet: crate::runtime::did_startup::WalletStartupResult) -> Result<()> {
        let mut user_wallet = self.user_wallet.write().await;
        *user_wallet = Some(wallet);
        Ok(())
    }

    /// Set user wallet data for components that need it
    pub async fn set_user_wallet(&self, wallet: crate::runtime::did_startup::WalletStartupResult) -> Result<()> {
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
        genesis_private_data.push((wallet.user_identity.id.clone(), wallet.user_private_data.clone()));
        genesis_private_data.push((wallet.node_identity.id.clone(), wallet.node_private_data.clone()));
        info!(" Stored {} private keys in secure memory (never stored on blockchain)", genesis_private_data.len());
        info!("    USER Identity ID: {}", hex::encode(&wallet.user_identity.id.0));
        info!("    NODE Identity ID: {}", hex::encode(&wallet.node_identity.id.0));
        info!("    USER Public Key (first 32): {}", hex::encode(&wallet.user_private_data.quantum_keypair.public_key[..32]));
        info!("    NODE Public Key (first 32): {}", hex::encode(&wallet.node_private_data.quantum_keypair.public_key[..32]));
        drop(genesis_private_data);
        
        // Try to store identities in global IdentityManager if already available
        // Note: Private keys are now stored in identity.private_key field (P1-7)
        if let Ok(identity_manager_arc) = crate::runtime::identity_manager_provider::get_global_identity_manager().await {
            let mut manager = identity_manager_arc.write().await;
            manager.add_identity(wallet.user_identity.clone());
            manager.add_identity(wallet.node_identity.clone());
            info!(" Stored genesis identities in IdentityManager");
        } else {
            info!("  IdentityManager not yet initialized - identities will be loaded when IdentityComponent starts");
        }
        
        // CRITICAL: Check if we're joining existing network - if so, DON'T create genesis!
        // BUT: If the blockchain is empty after joining (sync failed), fall back to genesis creation
        let joined_existing = *self.joined_existing_network.read().await;

        if joined_existing {
            // Check if the global blockchain actually has data (sync may have failed)
            let blockchain_has_data = match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(blockchain_arc) => {
                    let blockchain = blockchain_arc.read().await;
                    let has_data = blockchain.height > 0 || !blockchain.utxo_set.is_empty();
                    if has_data {
                        info!(" Joined network has blockchain data (height: {}, UTXOs: {})",
                              blockchain.height, blockchain.utxo_set.len());
                    } else {
                        warn!("⚠ Joined network but blockchain is empty - sync may have failed");
                    }
                    has_data
                }
                Err(_) => {
                    warn!("⚠ No global blockchain initialized - will create genesis");
                    false
                }
            };

            if blockchain_has_data {
                // Successfully joined network with synced data
                info!(" Joining existing network - skipping genesis creation");
                info!("  User wallet will be added to synced blockchain after sync completes");

                // Just store the wallet for later use, don't create blockchain
                // The blockchain will be synced from network peers

                // CRITICAL: Push wallet to BlockchainComponent if already registered
                let components = self.components.read().await;
                if let Some(component) = components.get(&ComponentId::Blockchain) {
                    if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                        blockchain_comp.set_user_wallet(wallet).await;
                        info!(" User wallet propagated to BlockchainComponent for sync");
                    }
                }

                return Ok(());
            } else {
                // Sync failed - fall back to genesis creation
                warn!("⚠ Network sync failed or incomplete - falling back to genesis creation");
                info!(" This node will create its own genesis and become a new network origin");
                // Continue to genesis creation below...
            }
        }
        
        // Try to load existing blockchain from disk, or create new genesis
        let persist_path_string = self.config.environment.blockchain_data_path();
        let persist_path = std::path::Path::new(&persist_path_string);
        let (mut blockchain, was_loaded) = lib_blockchain::Blockchain::load_or_create(persist_path)?;

        if was_loaded {
            info!("📂 Loaded existing blockchain from {} (height: {}, identities: {}, wallets: {})",
                  persist_path.display(),
                  blockchain.height,
                  blockchain.identity_registry.len(),
                  blockchain.wallet_registry.len());
            info!("  Skipping genesis creation - using persisted state");

            // Set the blockchain as global immediately since we loaded it
            let blockchain_arc = Arc::new(RwLock::new(blockchain));
            set_global_blockchain(blockchain_arc.clone()).await?;
            info!(" Global blockchain provider initialized with loaded blockchain");

            // Push wallet to BlockchainComponent if already registered
            let components = self.components.read().await;
            if let Some(component) = components.get(&ComponentId::Blockchain) {
                if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                    blockchain_comp.set_user_wallet(wallet).await;
                    info!(" User wallet propagated to BlockchainComponent");
                }
            }

            return Ok(());
        }

        // Creating NEW genesis network - no persisted blockchain found
        info!(" Creating NEW genesis network with user wallet funding...");
        
        // Set development difficulty (easy mining for testing)
        // TODO: In production, keep the default INITIAL_DIFFICULTY (0x1d00ffff)
        if matches!(self.config.environment, crate::config::Environment::Development) {
            blockchain.difficulty = lib_blockchain::types::Difficulty::from_bits(0x1fffffff);
            // Also update genesis block difficulty to match
            if let Some(genesis) = blockchain.blocks.get_mut(0) {
                genesis.header.difficulty = lib_blockchain::types::Difficulty::from_bits(0x1fffffff);
            }
            info!(" Development mode: Set blockchain difficulty to 0x1fffffff (easy mining)");
        }
        
        // Create genesis validator from USER identity (not node identity)
        // NOTE: A person can only be a validator once, regardless of how many nodes they own
        // Nodes are just devices controlled by the user's identity
        // Development mode: 1,000 SOV minimum stake (configurable in blockchain)
        let genesis_validator = crate::runtime::components::GenesisValidator {
            identity_id: wallet.user_identity.id.clone(), // Use USER identity, not node identity
            stake: 1_000, // Development mode: 1k SOV meets minimum (blockchain validates based on mode)
            storage_provided: 0, // Storage requirements enforced separately for production validators
            commission_rate: 500, // 5% commission

            node_device_id: Some(wallet.node_identity_id.clone()), // Track which node is running validator
        };
        
        // Extract primary wallet ID and public key from user identity
        let primary_wallet_info = {
            let primary_wallet = wallet.user_identity.wallet_manager.wallets
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
        crate::runtime::components::BlockchainComponent::create_genesis_funding(
            &mut blockchain,
            vec![genesis_validator],
            &self.config.environment,
            primary_wallet_info,
            Some(wallet.user_identity.id.clone()), // Pass user identity ID
            genesis_private_data, // Pass private data for Dilithium2 public key extraction
        ).await?;
        
        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        
        // Set in global provider BEFORE BlockchainComponent starts
        set_global_blockchain(blockchain_arc.clone()).await?;
        info!(" Global blockchain provider initialized with user wallet funding");
        
        // CRITICAL: Also push wallet to BlockchainComponent if already registered
        let components = self.components.read().await;
        if let Some(component) = components.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
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
            Err(_) => Ok(0)
        }
    }
    
    /// Wait for initial blockchain sync to reach at least height 1
    pub async fn wait_for_initial_sync(&self, timeout: std::time::Duration) -> Result<()> {
        let start = std::time::Instant::now();
        
        info!("⏳ Waiting for initial blockchain sync (timeout: {:?})...", timeout);
        
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
    pub async fn start_blockchain_sync(&mut self, network_info: &ExistingNetworkInfo) -> Result<()> {
        info!("📦 Starting blockchain sync from {} peers...", network_info.peer_count);
        
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

        // FIX(#916): Attempt QUIC-based blockchain sync from bootstrap peers BEFORE
        // wait_for_initial_sync(). Without this, the node always creates its own genesis.
        // Bootstrap peers are already QUIC addresses (e.g. 77.42.37.161:9334).
        if !network_info.bootstrap_peers.is_empty() {
            // Load node identity for QUIC client authentication
            match crate::runtime::create_or_load_node_identity(&self.config.environment).await {
                Ok(node_identity) => {
                    use lib_network::client::{ZhtpClient, ZhtpClientConfig};
                    use lib_network::web4::trust::TrustConfig;

                    let client_config = ZhtpClientConfig { allow_bootstrap: true };
                    match ZhtpClient::new_with_config(node_identity, TrustConfig::bootstrap(), client_config).await {
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
        
        self.register_component(Arc::new(CryptoComponent::new())).await?;
        self.start_component(ComponentId::Crypto).await?;
        
        self.register_component(Arc::new(NetworkComponent::new())).await?;
        self.start_component(ComponentId::Network).await?;
        
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
        ).await {
            warn!("Failed to start local discovery: {}", e);
        }
        
        // Discover existing network using bootstrap peers and DHT
        let is_edge_node = *self.is_edge_node.read().await;
        let network_info = self.discover_network_with_retry(is_edge_node).await.ok().flatten();

        let joined_existing_network = network_info.is_some();
        self.set_joined_existing_network(joined_existing_network).await;

        if let Some(ref net_info) = network_info {
            info!("✓ Found existing network with {} peers at height {}",
                  net_info.peer_count, net_info.blockchain_height);

            // Initialize blockchain provider for sync reception
            // This allows ProtocolsComponent to start the unified server
            let blockchain = lib_blockchain::Blockchain::new()?;
            let blockchain_arc = Arc::new(RwLock::new(blockchain));
            set_global_blockchain(blockchain_arc.clone()).await?;
            info!("✓ Blockchain provider initialized for network sync");

            // Store bootstrap peers for mesh sync
            if !net_info.bootstrap_peers.is_empty() {
                crate::runtime::bootstrap_peers_provider::set_bootstrap_peers(
                    net_info.bootstrap_peers.clone()
                ).await?;
            }
        }
        
        // ========================================================================
        // PHASE 3: Identity/Wallet Setup
        // ========================================================================
        info!("🆔 Setting up node identity and wallet...");
        
        // Use existing wallet startup flow from did_startup module
        let wallet_result = crate::runtime::did_startup::WalletStartupManager::handle_startup_wallet_flow()
            .await
            .context("Failed to complete wallet startup flow")?;
        
        info!("✅ Identity and wallet setup complete:");
        info!("   User Identity: {}", hex::encode(&wallet_result.user_identity.id.0[..8]));
        info!("   Node Identity: {}", hex::encode(&wallet_result.node_identity.id.0[..8]));
        info!("   Primary Wallet: {}", hex::encode(&wallet_result.node_wallet_id.0[..8]));
        
        // Store wallet result for blockchain component
        self.set_user_wallet(wallet_result.clone()).await?;

        // Derive deterministic NodeId from DID + device name and cache for runtime access
        let device_name = resolve_device_name(Some(&wallet_result.node_identity.primary_device))
            .context("Device name resolution failed (set ZHTP_DEVICE_NAME or configure device name)")?;
        let node_id = derive_node_id(&wallet_result.node_identity.did, &device_name)
            .context("Failed to derive NodeId from DID + device name")?;
        set_runtime_node_identity(RuntimeNodeIdentity {
            did: wallet_result.node_identity.did.clone(),
            device_name,
            node_id,
        }).context("Failed to cache runtime NodeId")?;
        log_runtime_node_identity();
        
        // Store user identity for blockchain registration in Phase 6
        self.set_pending_identity_registration(wallet_result.user_identity.clone()).await;
        
        // ========================================================================
        // PHASE 4: Register Remaining Components
        // ========================================================================
        info!("📦 Registering remaining components...");
        use crate::runtime::components::{
            ZKComponent, IdentityComponent, StorageComponent, BlockchainComponent,
            ConsensusComponent, EconomicsComponent, ProtocolsComponent, ApiComponent
        };
        
        self.register_component(Arc::new(ZKComponent::new())).await?;

        // CRITICAL: Pass genesis identities explicitly to IdentityComponent
        // These were created in PHASE 3 and must be injected as a dependency
        // This ensures deterministic initialization and prevents silent empty state
        let genesis_ids = self.genesis_identities.read().await.clone();
        let genesis_private = self.genesis_private_data.read().await.clone();
        self.register_component(
            Arc::new(IdentityComponent::new_with_identities_and_private_data(genesis_ids, genesis_private))
        ).await?;

        self.register_component(Arc::new(StorageComponent::new())).await?;
        
        let user_wallet = self.get_user_wallet().await;
        let environment = self.get_environment();
        let bootstrap_validators = self.get_bootstrap_validators();
        let joined_existing_network = self.get_joined_existing_network().await;
        let node_role = self.node_role.read().await.clone();

        let blockchain_component = BlockchainComponent::new_with_full_config(
            node_role.clone(),
            user_wallet,
            environment,
            bootstrap_validators,
            joined_existing_network
        );
        self.register_component(Arc::new(blockchain_component)).await?;

        self.register_component(Arc::new(ConsensusComponent::new(environment, node_role))).await?;
        self.register_component(Arc::new(ProtocolsComponent::new_with_ports(
            environment,
            self.config.protocols_config.api_port,
            self.config.protocols_config.quic_port,
            self.config.protocols_config.discovery_port,
        ))).await?;
        self.register_component(Arc::new(EconomicsComponent::new())).await?;
        self.register_component(Arc::new(ApiComponent::new())).await?;
        
        // ========================================================================
        // PHASE 5: Start Remaining Components
        // ========================================================================
        info!("▶️  Starting remaining components...");
        self.start_component(ComponentId::ZK).await?;
        self.start_component(ComponentId::Storage).await?;     // Data layer first
        self.start_component(ComponentId::Identity).await?;    // Needs Storage for DHT bootstrap
        self.start_component(ComponentId::Blockchain).await?;  // Needs Storage, Identity
        self.start_component(ComponentId::Consensus).await?;   // Needs Blockchain
        self.start_component(ComponentId::Economics).await?;   // Needs Blockchain
        self.start_component(ComponentId::Protocols).await?;   // Main server, needs everything
        self.start_component(ComponentId::Api).await?;         // Endpoint layer, last
        
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
                        did_document_hash: identity.did_document_hash
                            .map(|h| lib_blockchain::Hash::from_slice(&h.0))
                            .unwrap_or(lib_blockchain::Hash::zero()),
                        created_at: identity.created_at,
                        registration_fee: 0,
                        dao_fee: 0,
                        controlled_nodes: vec![],
                        owned_wallets: identity.wallet_manager.wallets.keys()
                            .map(|id| hex::encode(&id.0))
                            .collect(),
                    };
                    
                    // Register identity on blockchain
                    match blockchain_ref.register_identity(identity_data.clone()) {
                        Ok(tx_hash) => {
                            info!("✅ Identity registered on blockchain: {}", hex::encode(&tx_hash.as_bytes()[..8]));
                        }
                        Err(e) => {
                            warn!("⚠️  Failed to register identity on blockchain: {}", e);
                        }
                    }
                    
                    // Register wallets on blockchain
                    for (wallet_id, wallet) in &identity.wallet_manager.wallets {
                        let wallet_data = lib_blockchain::transaction::WalletTransactionData {
                            wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
                            owner_identity_id: Some(lib_blockchain::Hash::from_slice(&identity.id.0)),
                            alias: wallet.alias.clone(),
                            wallet_name: wallet.name.clone(),
                            wallet_type: format!("{:?}", wallet.wallet_type),
                            public_key: wallet.public_key.clone(),
                            capabilities: 0,
                            created_at: wallet.created_at,
                            registration_fee: 0,
                            initial_balance: wallet.balance,
                            seed_commitment: wallet.seed_commitment.as_ref()
                                .map(|s| {
                                    // Hash the seed commitment string to create blockchain hash
                                    lib_blockchain::types::hash::blake3_hash(s.as_bytes())
                                })
                                .unwrap_or_else(|| {
                                    // Generate deterministic commitment from wallet ID + pubkey if no seed commitment
                                    // This ensures a valid non-zero commitment for blockchain validation
                                    let commitment_data = format!("wallet_commitment:{}:{}",
                                        hex::encode(&wallet_id.0),
                                        hex::encode(&wallet.public_key));
                                    lib_blockchain::types::hash::blake3_hash(commitment_data.as_bytes())
                                }),
                        };
                        
                        match blockchain_ref.register_wallet(wallet_data) {
                            Ok(tx_hash) => {
                                info!("✅ Wallet registered: {} ({})",
                                    hex::encode(&wallet_id.0[..8]),
                                    hex::encode(&tx_hash.as_bytes()[..8]));

                                // Add welcome bonus for Primary wallets (new identity registration)
                                if format!("{:?}", wallet.wallet_type) == "Primary" {
                                    let wallet_id_hex = hex::encode(&wallet_id.0);
                                    let welcome_bonus = 5000u64;

                                    // Update wallet registry balance
                                    if let Some(wallet_entry) = blockchain_ref.wallet_registry.get_mut(&wallet_id_hex) {
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
                                        recipient: lib_crypto::PublicKey::new(identity.id.0.to_vec()),
                                    };
                                    let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                                        format!("welcome_bonus_utxo:{}", wallet_id_hex).as_bytes()
                                    );
                                    blockchain_ref.utxo_set.insert(utxo_hash, utxo_output);

                                    info!("🎁 Welcome bonus: {} ZHTP credited to wallet {} (UTXO created)",
                                        welcome_bonus, &wallet_id_hex[..16]);
                                }
                            }
                            Err(e) => {
                                warn!("⚠️  Failed to register wallet: {}", e);
                            }
                        }
                    }

                    // Save blockchain to disk after all registrations complete
                    let persist_path_str = self.config.environment.blockchain_data_path();
                    let persist_path = std::path::Path::new(&persist_path_str);
                    if let Err(e) = blockchain_ref.save_to_file(persist_path) {
                        warn!("⚠️  Failed to save blockchain after identity registration: {}", e);
                    } else {
                        info!("💾 Blockchain saved after new identity registration");
                    }
                }
                Err(e) => {
                    warn!("⚠️  Blockchain service not available for identity registration: {}", e);
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

                            let identity_data = lib_blockchain::transaction::IdentityTransactionData {
                                did: user_did.clone(),
                                display_name: format!("User {}", hex::encode(&user_identity.id.0[..4])),
                                public_key: user_identity.public_key.as_bytes(),
                                ownership_proof: vec![],
                                identity_type: format!("{:?}", user_identity.identity_type).to_lowercase(),
                                did_document_hash: user_identity.did_document_hash.as_ref()
                                    .map(|h| lib_blockchain::Hash::from_slice(&h.0))
                                    .unwrap_or(lib_blockchain::Hash::zero()),
                                created_at: user_identity.created_at,
                                registration_fee: 0,
                                dao_fee: 0,
                                controlled_nodes: vec![],
                                owned_wallets: user_identity.wallet_manager.wallets.keys()
                                    .map(|id| hex::encode(&id.0))
                                    .collect(),
                            };

                            match blockchain_ref.register_identity(identity_data) {
                                Ok(tx_hash) => {
                                    info!("✅ Existing identity registered on blockchain: {}", hex::encode(&tx_hash.as_bytes()[..8]));
                                }
                                Err(e) => {
                                    warn!("⚠️  Failed to register existing identity: {}", e);
                                }
                            }

                            // Register wallets too
                            for (wallet_id, wallet) in &user_identity.wallet_manager.wallets {
                                let wallet_id_hex = hex::encode(&wallet_id.0);
                                if !blockchain_ref.wallet_exists(&wallet_id_hex) {
                                    let wallet_data = lib_blockchain::transaction::WalletTransactionData {
                                        wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
                                        owner_identity_id: Some(lib_blockchain::Hash::from_slice(&user_identity.id.0)),
                                        alias: wallet.alias.clone(),
                                        wallet_name: wallet.name.clone(),
                                        wallet_type: format!("{:?}", wallet.wallet_type),
                                        public_key: wallet.public_key.clone(),
                                        capabilities: 0,
                                        created_at: wallet.created_at,
                                        registration_fee: 0,
                                        initial_balance: wallet.balance,
                                        seed_commitment: wallet.seed_commitment.as_ref()
                                            .map(|s| lib_blockchain::types::hash::blake3_hash(s.as_bytes()))
                                            .unwrap_or_else(|| {
                                                let commitment_data = format!("wallet_commitment:{}:{}",
                                                    hex::encode(&wallet_id.0),
                                                    hex::encode(&wallet.public_key));
                                                lib_blockchain::types::hash::blake3_hash(commitment_data.as_bytes())
                                            }),
                                    };

                                    match blockchain_ref.register_wallet(wallet_data.clone()) {
                                        Ok(tx_hash) => {
                                            info!("✅ Existing wallet registered: {} ({})",
                                                hex::encode(&wallet_id.0[..8]),
                                                hex::encode(&tx_hash.as_bytes()[..8]));

                                            // Give welcome bonus to newly registered Primary wallets (like genesis)
                                            // Create actual UTXO so funds are spendable
                                            if format!("{:?}", wallet.wallet_type) == "Primary" {
                                                let wallet_id_hex = hex::encode(&wallet_id.0);
                                                let welcome_bonus = 5000u64;

                                                // Update wallet registry balance
                                                if let Some(wallet_entry) = blockchain_ref.wallet_registry.get_mut(&wallet_id_hex) {
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
                                                    recipient: lib_crypto::PublicKey::new(user_identity.id.0.to_vec()),
                                                };
                                                let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                                                    format!("welcome_bonus_utxo:{}", wallet_id_hex).as_bytes()
                                                );
                                                blockchain_ref.utxo_set.insert(utxo_hash, utxo_output);
                                                info!("🎁 Welcome bonus: {} ZHTP credited to wallet {} (UTXO created)", welcome_bonus, &wallet_id_hex[..16]);
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
                                if let Some(wallet_entry) = blockchain_ref.wallet_registry.get(&wallet_id_hex) {
                                    // Wallet exists - check if it needs funding
                                    if wallet_entry.initial_balance == 0 && format!("{:?}", wallet.wallet_type) == "Primary" {
                                        info!("📝 Funding existing zero-balance Primary wallet: {}", &wallet_id_hex[..16]);

                                        let welcome_bonus = 5000u64;

                                        // Update wallet registry
                                        if let Some(wallet_mut) = blockchain_ref.wallet_registry.get_mut(&wallet_id_hex) {
                                            wallet_mut.initial_balance = welcome_bonus;
                                        }

                                        // Create spendable UTXO
                                        let utxo_output = lib_blockchain::transaction::TransactionOutput {
                                            commitment: lib_blockchain::types::hash::blake3_hash(
                                                format!("welcome_bonus_commitment_{}_{}", wallet_id_hex, welcome_bonus).as_bytes()
                                            ),
                                            note: lib_blockchain::types::hash::blake3_hash(
                                                format!("welcome_bonus_note_{}", wallet_id_hex).as_bytes()
                                            ),
                                            recipient: lib_crypto::PublicKey::new(user_identity.id.0.to_vec()),
                                        };
                                        let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                                            format!("welcome_bonus_utxo:{}", wallet_id_hex).as_bytes()
                                        );
                                        blockchain_ref.utxo_set.insert(utxo_hash, utxo_output);

                                        info!("🎁 Welcome bonus: {} ZHTP credited to wallet {} (UTXO created)", welcome_bonus, &wallet_id_hex[..16]);
                                    }
                                } else {
                                    // Wallet NOT in registry - register it now
                                    info!("📝 Registering missing wallet for existing identity: {}", &wallet_id_hex[..16]);

                                    let wallet_data = lib_blockchain::transaction::WalletTransactionData {
                                        wallet_id: lib_blockchain::Hash::from_slice(&wallet_id.0),
                                        owner_identity_id: Some(lib_blockchain::Hash::from_slice(&user_identity.id.0)),
                                        alias: wallet.alias.clone(),
                                        wallet_name: wallet.name.clone(),
                                        wallet_type: format!("{:?}", wallet.wallet_type),
                                        public_key: wallet.public_key.clone(),
                                        capabilities: 0,
                                        created_at: wallet.created_at,
                                        registration_fee: 0,
                                        initial_balance: wallet.balance,
                                        seed_commitment: wallet.seed_commitment.as_ref()
                                            .map(|s| lib_blockchain::types::hash::blake3_hash(s.as_bytes()))
                                            .unwrap_or_else(|| {
                                                let commitment_data = format!("wallet_commitment:{}:{}",
                                                    hex::encode(&wallet_id.0),
                                                    hex::encode(&wallet.public_key));
                                                lib_blockchain::types::hash::blake3_hash(commitment_data.as_bytes())
                                            }),
                                    };

                                    match blockchain_ref.register_wallet(wallet_data.clone()) {
                                        Ok(tx_hash) => {
                                            info!("✅ Missing wallet registered: {} ({})",
                                                &wallet_id_hex[..16],
                                                hex::encode(&tx_hash.as_bytes()[..8]));

                                            // Give welcome bonus to Primary wallets
                                            if format!("{:?}", wallet.wallet_type) == "Primary" {
                                                let welcome_bonus = 5000u64;

                                                // Update wallet registry balance
                                                if let Some(wallet_entry) = blockchain_ref.wallet_registry.get_mut(&wallet_id_hex) {
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
                                                    recipient: lib_crypto::PublicKey::new(user_identity.id.0.to_vec()),
                                                };
                                                let utxo_hash = lib_blockchain::types::hash::blake3_hash(
                                                    format!("welcome_bonus_utxo:{}", wallet_id_hex).as_bytes()
                                                );
                                                blockchain_ref.utxo_set.insert(utxo_hash, utxo_output);

                                                info!("🎁 Welcome bonus: {} ZHTP credited to wallet {} (UTXO created)",
                                                    welcome_bonus, &wallet_id_hex[..16]);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("⚠️  Failed to register missing wallet: {}", e);
                                        }
                                    }
                                }
                            }
                        }

                        // Save blockchain after any modifications in existing identity path
                        let persist_path_str = self.config.environment.blockchain_data_path();
                        let persist_path = std::path::Path::new(&persist_path_str);
                        if let Err(e) = blockchain_ref.save_to_file(persist_path) {
                            warn!("⚠️  Failed to save blockchain after existing identity check: {}", e);
                        } else {
                            info!("💾 Blockchain saved after existing identity check/registration");
                        }
                    }
                    Err(e) => {
                        warn!("⚠️  Blockchain not available to check identity registration: {}", e);
                    }
                }
            }
        }

        info!("✅ ZHTP node started successfully");
        info!("🌐 ZHTP server active on port {}", self.config.protocols_config.api_port);
        
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
            self.start_component(component_id.clone()).await
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
                    info!("Component {} is already running, skipping start", component_id);
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
                    
                    // Wire blockchain to consensus component after consensus starts
                    if component_id == ComponentId::Consensus {
                        if let Err(e) = self.wire_blockchain_to_consensus().await {
                            warn!("Failed to wire blockchain to consensus: {}", e);
                        } else {
                            info!(" Blockchain successfully wired to consensus component");
                        }
                    }
                    
                    // Start reward orchestrator after ProtocolsComponent (mesh server now ready)
                    if component_id == ComponentId::Protocols {
                        // Give mesh server a moment to fully initialize
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        
                        if let Err(e) = self.start_reward_orchestrator().await {
                            warn!("Failed to start reward orchestrator: {}", e);
                        } else {
                            info!(" Reward orchestrator started (mesh server ready for statistics)");
                        }
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
                        vec![]
                    )).await?;
                    
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
        let shutdown_timeout_ms = self.config.integration_settings.cross_package_timeouts
            .get("shutdown").copied().unwrap_or(30000);
        match tokio::time::timeout(Duration::from_millis(shutdown_timeout_ms), shutdown_future).await {
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
                    warn!("Timeout stopping component {}, forcing shutdown", component_id);
                    
                    // Try force stop if available
                    match tokio::time::timeout(Duration::from_secs(5), component.force_stop()).await {
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
    pub async fn send_message(&self, component_id: ComponentId, message: ComponentMessage) -> Result<()> {
        let message_bus = self.message_bus.lock().await;
        message_bus.send((component_id, message))
            .context("Failed to send message")?;
        Ok(())
    }

    /// Broadcast a message to all components
    pub async fn broadcast_message(&self, message: ComponentMessage) -> Result<()> {
        let components = self.components.read().await;
        let message_bus = self.message_bus.lock().await;
        
        for component_id in components.keys() {
            message_bus.send((component_id.clone(), message.clone()))
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
        aggregated_metrics.insert("running_components".to_string(), 
            health.values().filter(|h| matches!(h.status, ComponentStatus::Running)).count() as f64);
        aggregated_metrics.insert("error_components".to_string(),
            health.values().filter(|h| matches!(h.status, ComponentStatus::Error(_))).count() as f64);
        
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
        self.send_message(ComponentId::Network, ComponentMessage::Custom(
            format!("connect_to_peer:{}", addr),
            addr.as_bytes().to_vec()
        )).await?;
        
        info!("Connect request sent to network component for peer: {}", addr);
        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect_from_peer(&self, addr: &str) -> Result<()> {
        info!(" Attempting to disconnect from peer: {}", addr);
        
        // Send disconnect message to network component
        self.send_message(ComponentId::Network, ComponentMessage::Custom(
            format!("disconnect_from_peer:{}", addr),
            addr.as_bytes().to_vec()
        )).await?;
        
        info!("Disconnect request sent to network component for peer: {}", addr);
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
                info.push_str(&format!("Internet Connected: {}\n", 
                    if mesh_status.internet_connected { "Yes" } else { "No" }));
                info.push_str(&format!("Mesh Connected: {}\n", 
                    if mesh_status.mesh_connected { "Yes" } else { "No" }));
                info.push_str(&format!("Connectivity: {:.1}%\n", mesh_status.connectivity_percentage));
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
                info.push_str(&format!("Bytes Sent: {} MB\n", net_stats.bytes_sent / 1_000_000));
                info.push_str(&format!("Bytes Received: {} MB\n", net_stats.bytes_received / 1_000_000));
                info.push_str(&format!("Packets Sent: {}\n", net_stats.packets_sent));
                info.push_str(&format!("Packets Received: {}\n", net_stats.packets_received));
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
            Err(e) => {
                Ok(format!("Mesh status unavailable: {}", e))
            }
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
        let unhealthy_components: Vec<_> = health.iter()
            .filter(|(_, h)| !matches!(h.status, ComponentStatus::Running))
            .map(|(id, _)| id.to_string())
            .collect();
            
        if !unhealthy_components.is_empty() {
            warn!("Unhealthy components: {:?}", unhealthy_components);
        }
        
        // Log summary
        let running_count = health.values()
            .filter(|h| matches!(h.status, ComponentStatus::Running))
            .count();
        debug!("{}/{} components running normally", running_count, health.len());
        
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
            if let Some(blockchain_component) = component.as_any().downcast_ref::<BlockchainComponent>() {
                // Wait for blockchain to be initialized and get the actual instance
                if let Ok(blockchain_arc) = blockchain_component.get_initialized_blockchain().await {
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
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
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
                if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
                    if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                        // Set validator manager
                        blockchain_comp.set_validator_manager(validator_manager).await;
                        info!(" Validator manager connected to blockchain mining loop");
                        
                        // Set node owner identity from wallet startup (secure node identity)
                        let wallet_guard = self.user_wallet.read().await;
                        if let Some(ref wallet_data) = *wallet_guard {
                            blockchain_comp.set_node_identity(wallet_data.node_identity_id.clone()).await;
                            info!(" Node owner identity connected: {}", hex::encode(&wallet_data.node_identity_id.0[..8]));
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
        let identity_manager_arc = match crate::runtime::identity_manager_provider::get_global_identity_manager().await {
            Ok(arc) => arc,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to get global IdentityManager: {}", e));
            }
        };
        
        // Get the blockchain Arc from BlockchainComponent
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
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
            
            info!(" Scanning blockchain wallet_registry (total entries: {})...", blockchain.wallet_registry.len());
            
            for (wallet_id_hex, wallet_data) in blockchain.wallet_registry.iter() {
                if wallet_data.initial_balance > 0 {
                    info!("   Found funded wallet: {} → {} ZHTP", 
                        &wallet_id_hex[..16], wallet_data.initial_balance);
                    balances.insert(wallet_id_hex.clone(), wallet_data.initial_balance);
                } else {
                    info!("   Skipping zero-balance wallet: {}", &wallet_id_hex[..16]);
                }
            }
            
            info!(" Extracted {} wallet balance entries from blockchain", balances.len());
            balances
        };
        
        // Lock identity manager and perform sync
        let mut identity_manager = identity_manager_arc.write().await;

        // Sync balances from blockchain to identity wallets
        let mut synced_count = 0;
        let mut total_synced_amount = 0u64;

        for identity in identity_manager.list_identities_mut() {
            for (wallet_id, wallet) in identity.wallet_manager.wallets.iter_mut() {
                // Convert wallet_id to hex string to match blockchain registry
                let wallet_id_hex = hex::encode(wallet_id.0);

                if let Some(&blockchain_balance) = wallet_balances.get(&wallet_id_hex) {
                    // Only sync if blockchain has more than current balance (UBI accumulates)
                    if blockchain_balance > wallet.balance {
                        let diff = blockchain_balance - wallet.balance;
                        info!(
                            "   Syncing wallet {} ({}): {} → {} ZHTP (+{})",
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
            " Wallet balance sync complete: {} wallets updated, {} ZHTP synced",
            synced_count,
            total_synced_amount
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
        identity_id: &lib_identity::IdentityId,
        wallet_pubkey: &[u8],
        recipient_pubkey: &[u8],
        amount: u64,
        purpose: &str,
    ) -> Result<lib_blockchain::Hash> {
        info!(" Creating blockchain transaction for wallet payment: {} ZHTP for '{}'", amount, purpose);
        
        // Step 1: Get blockchain and scan for UTXOs matching wallet_pubkey
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
                blockchain_comp.get_initialized_blockchain().await?
            } else {
                return Err(anyhow::anyhow!("Blockchain component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Blockchain component not found"));
        };
        
        let blockchain = blockchain_arc.read().await;
        
        // Scan UTXO set for outputs owned by this wallet
        let mut wallet_utxos: Vec<(lib_blockchain::Hash, u32, u64)> = Vec::new();
        
        info!(" Scanning {} UTXOs for wallet pubkey: {}", 
              blockchain.utxo_set.len(), 
              hex::encode(&wallet_pubkey[..8.min(wallet_pubkey.len())]));
        
        for (utxo_hash, output) in &blockchain.utxo_set {
            // Check if this UTXO belongs to our wallet
            // Compare recipient public key bytes with wallet pubkey
            if output.recipient.as_bytes() == wallet_pubkey {
                // NOTE: Amount is hidden in Pedersen commitment, so we need to get it from wallet_registry
                // For genesis UTXOs, we know the amount from wallet_registry initial_balance
                // In production, we'd need to decrypt the note or track amounts separately
                
                // For now, use a placeholder amount - this would come from wallet's UTXO tracking
                let utxo_amount = 5000u64; // Genesis wallet funding amount
                
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
        let fee = 100u64; // 100 micro-ZHTP fee
        let required_amount = amount + fee;
        
        let mut selected_utxos = Vec::new();
        let mut total_selected = 0u64;
        
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
        
        info!(" Selected {} UTXOs totaling {} ZHTP", selected_utxos.len(), total_selected);
        
        drop(blockchain); // Release read lock
        
        // Step 3: Get IdentityManager to create signed transaction
        let identity_mgr_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Identity) {
            if let Some(identity_comp) = component.as_any().downcast_ref::<IdentityComponent>() {
                identity_comp.get_identity_manager_arc()
            } else {
                return Err(anyhow::anyhow!("Identity component type mismatch"));
            }
        } else {
            return Err(anyhow::anyhow!("Identity component not found"));
        };
        
        let identity_mgr_opt = identity_mgr_arc.read().await;
        let identity_mgr: &lib_identity::IdentityManager = identity_mgr_opt.as_ref()
            .ok_or_else(|| anyhow::anyhow!("IdentityManager not initialized"))?;
        
        // Convert lib_blockchain::Hash to lib_crypto::Hash for IdentityManager
        let selected_utxos_crypto: Vec<(lib_crypto::Hash, u32, u64)> = selected_utxos
            .iter()
            .map(|(hash, idx, amt)| {
                (lib_crypto::Hash::from_bytes(hash.as_bytes()), *idx, *amt)
            })
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
        info!("💳 Building payment transaction: {} ZHTP to recipient, {} ZHTP change", amount, change_amount);
        
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
        let network_component = if let Some(component) = self.components.read().await.get(&ComponentId::Network) {
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
        let blockchain_arc = if let Some(component) = self.components.read().await.get(&ComponentId::Blockchain) {
            if let Some(blockchain_comp) = component.as_any().downcast_ref::<BlockchainComponent>() {
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
        let blockchain_with_option = Arc::new(RwLock::new(Some(
            (*blockchain_arc.read().await).clone()
        )));

        // Convert rewards config to orchestrator config
        let orchestrator_config = reward_orchestrator::RewardOrchestratorConfig::from(&self.config.rewards_config);

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
    pub async fn get_shared_blockchain(&self) -> Result<Option<Arc<RwLock<Option<lib_blockchain::Blockchain>>>>> {
        // Create a channel for the response
        let (response_tx, mut response_rx) = tokio::sync::mpsc::unbounded_channel();
        
        // Store response sender for potential cleanup
        let _response_sender = response_tx.clone();
        
        // Send a request to the blockchain component
        let blockchain_request = ComponentMessage::Custom(
            "get_blockchain_instance".to_string(),
            vec![], // Empty data since we can't serialize channels
        );
        
        if let Err(e) = self.send_message(ComponentId::Blockchain, blockchain_request).await {
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
        orchestrator.start_network_components_for_discovery().await?;
        
        // Wait for network stack initialization
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // PHASE 2: Discover existing network
        info!("🔍 Phase 2: Discovering ZHTP network...");
        let network_info = orchestrator.discover_network_with_retry(is_edge_node).await?;
        
        // PHASE 3: Setup identity and blockchain
        info!("🔑 Phase 3: Setting up identity and blockchain...");
        if let Some(ref net_info) = network_info {
            // Joining existing network
            orchestrator.set_joined_existing_network(true).await?;
            orchestrator.start_blockchain_sync(net_info).await?;
            
            // Wait for initial sync
            info!("⏳ Waiting for initial blockchain sync...");
            match orchestrator.wait_for_initial_sync(Duration::from_secs(30)).await {
                Ok(()) => {
                    let height = orchestrator.get_blockchain_height().await?;
                    info!("✓ Sync started: height {}", height);
                }
                Err(e) => {
                    warn!("⚠ Initial sync timeout: {} - will continue in background", e);
                }
            }
        } else {
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
        self.register_component(Arc::new(CryptoComponent::new())).await?;
        info!("   → Starting CryptoComponent...");
        self.start_component(ComponentId::Crypto).await?;
        
        info!("   → Registering NetworkComponent...");
        self.register_component(Arc::new(NetworkComponent::new())).await?;
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
        ).await {
            warn!("      Failed to start local discovery: {}", e);
        } else {
            let signed = lib_network::protocols::quic_mesh::get_tls_spki_hash_from_default_cert().is_some();
            info!("      ✓ Multicast broadcasting started (224.0.1.75:37775, TLS pinning: {})", signed);
        }
        
        Ok(())
    }
    
    /// Discover network with retry logic for edge nodes
    pub async fn discover_network_with_retry(&self, is_edge_node: bool) -> Result<Option<ExistingNetworkInfo>> {
        use crate::discovery_coordinator::DiscoveryCoordinator;

        let mut discovery_protocols = Self::discovery_protocols_from_config(
            &self.config.network_config.protocols,
        );
        if discovery_protocols.is_empty() {
            discovery_protocols = vec![crate::discovery_coordinator::DiscoveryProtocol::UdpMulticast];
        }

        let config = crate::discovery_coordinator::DiscoveryConfig::new(
            self.config.network_config.bootstrap_peers.clone(),
            self.config.protocols_config.api_port,
            discovery_protocols,
        );
        let discovery = DiscoveryCoordinator::new(config);
        discovery.start_event_listener().await;
        
        if is_edge_node {
            info!("🔍 Edge node: Continuously searching for ZHTP network...");
            info!("   Will retry every 35 seconds until a full node is found");
            
            let mut attempt = 1;
            loop {
                info!("📡 Discovery attempt #{}", attempt);
                match discovery.discover_network(&self.config.environment).await {
                    Ok(network_info) => {
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
                    info!("✓ Connected to existing ZHTP network!");
                    info!("   Network peers: {}", network_info.peer_count);
                    info!("   Blockchain height: {}", network_info.blockchain_height);
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
    pub async fn get_genesis_private_data(&self) -> Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)> {
        self.genesis_private_data.read().await.clone()
    }

    /// Get a read-only clone of user wallet
    pub async fn get_user_wallet(&self) -> Option<crate::runtime::did_startup::WalletStartupResult> {
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

/// Create or load persistent node identity
///
/// Uses the standard keystore path (~/.zhtp/keystore/) for identity persistence.
/// This ensures consistency with WalletStartupManager and prevents identity loss.
pub async fn create_or_load_node_identity(
    _environment: &crate::config::Environment,
) -> Result<lib_identity::ZhtpIdentity> {
    // Use the standard keystore path for ALL environments
    // This matches WalletStartupManager and ensures identity persistence
    let keystore_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
        .join(".zhtp")
        .join("keystore");

    // SECURITY REVIEW: ZHTP_DEVICE_NAME env var is checked inside resolve_device_name()
    // to allow operators to configure deterministic NodeId across restarts and cluster
    // deployments. The value is validated by normalize_device_name() which enforces:
    // alphanumeric + .-_ only, max 64 chars, lowercased. Changing this value changes
    // the node's network identity (NodeId), which affects peer discovery and mesh routing.
    // An attacker with env var access could cause identity instability but cannot
    // impersonate other nodes (requires private key for DID). This is a configuration
    // integrity concern, not data exposure. See resolve_device_name_with_host() for
    // audit logging when the env var is set.
    let device_name = resolve_device_name(Some("zhtp-node"))
        .context("Failed to resolve node device name")?;
    info!("Using node device name: {}", device_name);

    // Try to load an existing identity (with private key) from the keystore
    if let Some(identity) = crate::runtime::did_startup::load_node_identity_from_keystore(&keystore_path)
        .await
        .context("Failed to load node identity from keystore")?
    {
        info!("Loaded existing node identity from keystore: {}", identity.did);
        return Ok(identity);
    }

    // Create new identity using P1-7 architecture
    info!("Creating new node identity (no existing keystore found)... device={}", device_name);
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
    info!("Created and saved node identity to keystore at {:?}", keystore_path);
    Ok(node_identity)
}
