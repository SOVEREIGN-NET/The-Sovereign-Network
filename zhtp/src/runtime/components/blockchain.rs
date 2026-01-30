// Blockchain component - thin wrapper that delegates to services
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug, error};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use crate::runtime::services::{GenesisFundingService, TransactionBuilder, GenesisValidator};
use crate::runtime::dht_indexing::index_block_in_dht;
use crate::runtime::node_runtime::NodeRole;
use crate::config::aggregation::BootstrapValidator;
use lib_blockchain::{Blockchain, Transaction};
use lib_consensus::ValidatorManager;
use lib_identity::IdentityId;

/// Blockchain component - manages blockchain lifecycle and delegates business logic to services
#[derive(Debug)]
pub struct BlockchainComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    blockchain: Arc<RwLock<Option<Blockchain>>>,
    edge_state: Arc<RwLock<Option<Arc<RwLock<lib_blockchain::edge_node_state::EdgeNodeState>>>>>,
    mining_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    user_wallet: Arc<RwLock<Option<crate::runtime::did_startup::WalletStartupResult>>>,
    environment: crate::config::Environment,
    bootstrap_validators: Arc<RwLock<Vec<BootstrapValidator>>>,
    joined_existing_network: bool,
    validator_manager: Arc<RwLock<Option<Arc<RwLock<ValidatorManager>>>>>,
    node_identity: Arc<RwLock<Option<IdentityId>>>,
    is_edge_node: bool,
    /// Node role determines what operations this node can perform
    /// This is IMMUTABLE and set at construction time based on configuration
    /// The role cannot change after the component is created
    node_role: Arc<NodeRole>,
}

impl BlockchainComponent {
    /// Create a new BlockchainComponent with the specified node role
    /// CRITICAL: node_role must be derived from configuration before calling this
    pub fn new(node_role: NodeRole) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            edge_state: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(None)),
            environment: crate::config::Environment::Development,
            bootstrap_validators: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: false,
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
            is_edge_node: false,
            node_role: Arc::new(node_role),
        }
    }

    #[deprecated = "Use new(node_role) instead to properly initialize node role from config"]
    pub fn new_deprecated() -> Self {
        Self::new(NodeRole::Observer)
    }

    pub fn new_with_wallet(
        node_role: NodeRole,
        user_wallet: Option<crate::runtime::did_startup::WalletStartupResult>,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            edge_state: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(user_wallet)),
            environment: crate::config::Environment::Development,
            bootstrap_validators: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: false,
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
            is_edge_node: false,
            node_role: Arc::new(node_role),
        }
    }

    pub fn new_with_wallet_and_environment(
        node_role: NodeRole,
        user_wallet: Option<crate::runtime::did_startup::WalletStartupResult>,
        environment: crate::config::Environment,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            edge_state: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(user_wallet)),
            environment,
            bootstrap_validators: Arc::new(RwLock::new(Vec::new())),
            joined_existing_network: false,
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
            is_edge_node: false,
            node_role: Arc::new(node_role),
        }
    }

    pub fn new_with_full_config(
        node_role: NodeRole,
        user_wallet: Option<crate::runtime::did_startup::WalletStartupResult>,
        environment: crate::config::Environment,
        bootstrap_validators: Vec<BootstrapValidator>,
        joined_existing_network: bool,
    ) -> Self {
        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            blockchain: Arc::new(RwLock::new(None)),
            edge_state: Arc::new(RwLock::new(None)),
            mining_handle: Arc::new(RwLock::new(None)),
            user_wallet: Arc::new(RwLock::new(user_wallet)),
            environment,
            bootstrap_validators: Arc::new(RwLock::new(bootstrap_validators)),
            joined_existing_network,
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
            is_edge_node: false,
            node_role: Arc::new(node_role),
        }
    }

    /// Get the current node role (immutable)
    pub fn get_node_role(&self) -> NodeRole {
        (*self.node_role).clone()
    }
    
    pub async fn set_validator_manager(&self, validator_manager: Arc<RwLock<ValidatorManager>>) {
        *self.validator_manager.write().await = Some(validator_manager);
    }
    
    pub async fn set_node_identity(&self, node_identity: IdentityId) {
        *self.node_identity.write().await = Some(node_identity);
    }
    
    pub fn set_edge_mode(&mut self, is_edge: bool) {
        self.is_edge_node = is_edge;
    }
    
    pub async fn set_user_wallet(&self, wallet: crate::runtime::did_startup::WalletStartupResult) {
        let mut user_wallet_guard = self.user_wallet.write().await;
        *user_wallet_guard = Some(wallet.clone());
        drop(user_wallet_guard);
        
        let node_id_hex = hex::encode(&wallet.node_identity_id.0);
        let user_did = format!("did:zhtp:{}", hex::encode(&wallet.user_identity.id.0));
        
        info!(" Updating controlled_nodes for user {} with node {}", 
              &user_did[..40], &node_id_hex[..32]);
        
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let mut blockchain = blockchain_arc.write().await;
                if let Some(identity_data) = blockchain.identity_registry.get_mut(&user_did) {
                    if !identity_data.controlled_nodes.contains(&node_id_hex) {
                        identity_data.controlled_nodes.push(node_id_hex.clone());
                        info!(" Added node {} to user's controlled_nodes list", &node_id_hex[..32]);
                    }
                }
            },
            Err(e) => {
                warn!("  Failed to get global blockchain: {}", e);
            }
        }
    }
    
    pub fn get_blockchain_arc(&self) -> Arc<RwLock<Option<Blockchain>>> {
        self.blockchain.clone()
    }
    
    pub fn get_edge_state_arc(&self) -> Arc<RwLock<Option<Arc<RwLock<lib_blockchain::edge_node_state::EdgeNodeState>>>>> {
        self.edge_state.clone()
    }
    
    pub fn is_edge_mode(&self) -> bool {
        self.is_edge_node
    }
    
    pub async fn get_initialized_blockchain(&self) -> Result<Arc<RwLock<Blockchain>>> {
        // Try global provider first - this is the source of truth
        if let Ok(global) = crate::runtime::blockchain_provider::get_global_blockchain().await {
            return Ok(global);
        }

        // Fallback to local state (might be stale)
        let blockchain_guard = self.blockchain.read().await;
        if let Some(ref blockchain) = *blockchain_guard {
            Ok(Arc::new(RwLock::new(blockchain.clone())))
        } else {
            Err(anyhow::anyhow!("Blockchain not yet initialized"))
        }
    }

    // Delegate to GenesisFundingService
    pub async fn create_genesis_funding(
        blockchain: &mut Blockchain,
        genesis_validators: Vec<GenesisValidator>,
        environment: &crate::config::Environment,
        user_primary_wallet_id: Option<(lib_identity::wallets::WalletId, Vec<u8>)>,
        user_identity_id: Option<lib_identity::IdentityId>,
        genesis_private_data: Vec<(lib_identity::IdentityId, lib_identity::identity::PrivateIdentityData)>,
    ) -> Result<()> {
        GenesisFundingService::create_genesis_funding(
            blockchain,
            genesis_validators,
            environment,
            user_primary_wallet_id,
            user_identity_id,
            genesis_private_data,
        ).await
    }
    
    /// Create UBI distribution transaction - delegates to TransactionBuilder
    async fn create_ubi_transaction(environment: &crate::config::Environment) -> Result<Transaction> {
        TransactionBuilder::create_ubi_transaction(environment).await
    }

    /// Create reward transaction - delegates to TransactionBuilder
    pub async fn create_reward_transaction(
        node_id: [u8; 32],
        reward_amount: u64,
        environment: &crate::config::Environment
    ) -> Result<Transaction> {
        TransactionBuilder::create_reward_transaction(node_id, reward_amount, environment).await
    }
    
    /// Mine a block using actual blockchain methods
    async fn mine_real_block(blockchain: &mut Blockchain) -> Result<()> {
        if blockchain.pending_transactions.is_empty() {
            return Err(anyhow::anyhow!("No pending transactions to mine"));
        }

        info!("Mining block with {} transactions", blockchain.pending_transactions.len());

        let transactions_for_block = blockchain.pending_transactions
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>();

        if transactions_for_block.is_empty() {
            return Err(anyhow::anyhow!("No valid transactions for block"));
        }

        let has_system_transactions = transactions_for_block
            .iter()
            .any(|tx| tx.inputs.is_empty());

        let previous_hash = blockchain.latest_block()
            .map(|b| b.hash())
            .unwrap_or_default();

        // Get mining config from environment - this determines the difficulty to use
        let mining_config = lib_blockchain::types::get_mining_config_from_env();
        let block_difficulty = mining_config.difficulty.clone();

        if has_system_transactions {
            info!("Mining system transaction block with difficulty: {:#x}", block_difficulty.bits());
        } else {
            info!("Mining normal transaction block with difficulty: {:#x}", block_difficulty.bits());
        }

        let block = lib_blockchain::block::creation::create_block(
            transactions_for_block,
            previous_hash,
            blockchain.height + 1,
            block_difficulty,
        )?;

        info!("⛏️ Mining block with {} profile (difficulty: {:#x}, max_iter: {})...",
              if mining_config.allow_instant_mining { "Bootstrap" } else { "Standard" },
              block_difficulty.bits(),
              mining_config.max_iterations);
        let new_block = lib_blockchain::block::creation::mine_block_with_config(block, &mining_config)?;
        info!("✓ Block mined with nonce: {}", new_block.header.nonce);

        match blockchain.add_block_with_proof(new_block.clone()).await {
            Ok(()) => {
                info!("BLOCK MINED SUCCESSFULLY!");
                info!("Block Hash: {:?}", new_block.hash());
                info!("Block Height: {}", blockchain.height);
                info!("Transactions in Block: {}", new_block.transactions.len());
                info!("Total UTXOs: {}", blockchain.utxo_set.len());
                info!("Identity Registry: {} entries", blockchain.identity_registry.len());
                
                if !blockchain.economics_transactions.is_empty() {
                    info!("Economics Transactions: {}", blockchain.economics_transactions.len());
                }
                if let Err(e) = index_block_in_dht(&new_block).await {
                    warn!("DHT indexing failed (mining): {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to add block to blockchain: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }
    
    /// Minimum validators required for BFT consensus mode
    /// With fewer validators, direct mining is allowed (bootstrap mode)
    /// With 4+ validators, all block production must go through BFT consensus
    const MIN_BFT_VALIDATORS: usize = 4;

    /// Real mining loop with consensus coordination
    ///
    /// Operating Modes:
    /// - Bootstrap Mode (< 4 validators): Direct mining allowed for network bootstrapping
    /// - BFT Mode (>= 4 validators): Mining loop is disabled, BFT consensus drives blocks
    ///
    /// When BFT mode is active, the mining loop only checks for pending transactions
    /// and logs status - actual block production is handled by the BFT consensus engine.
    async fn real_mining_loop(
        blockchain: Arc<RwLock<Option<Blockchain>>>,
        validator_manager_arc: Arc<RwLock<Option<Arc<RwLock<ValidatorManager>>>>>,
        node_identity_arc: Arc<RwLock<Option<IdentityId>>>,
        env_for_persist: crate::config::Environment,
        node_role: Arc<NodeRole>,
    ) {
        // CRITICAL: Enforce runtime guard - only FullValidator nodes should run mining loop
        // This replaces debug_assert to catch issues in release builds
        if !node_role.can_mine() {
            error!(
                "CRITICAL BUG: Non-mining node {:?} entered mining loop - config/component initialization bug",
                *node_role
            );
            return;
        }

        info!("⛏️ Mining loop started - waiting 2 seconds for consensus to wire...");
        tokio::time::sleep(Duration::from_secs(2)).await;
        info!("⛏️ Starting mining checks every 30 seconds");

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut block_counter = 1u64;
        let mut consensus_round = 0u32;
        let mut last_bft_mode_log = std::time::Instant::now();

        loop {
            debug!("⏰ Mining loop tick #{}", block_counter);
            interval.tick().await;

            match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(shared_blockchain) => {
                    let blockchain_guard = shared_blockchain.read().await;
                    let pending_count = blockchain_guard.pending_transactions.len();
                    let current_height = blockchain_guard.height;

                    // Check validator count for mode switching
                    let validator_count = blockchain_guard.get_active_validators().len();
                    let bft_mode_active = validator_count >= Self::MIN_BFT_VALIDATORS;

                    if bft_mode_active {
                        // BFT MODE: Mining loop is disabled, BFT consensus drives blocks
                        // Only log periodically to avoid spam
                        if last_bft_mode_log.elapsed() >= Duration::from_secs(120) {
                            info!(
                                "🛡️ BFT MODE ACTIVE: {} validators registered (min: {})",
                                validator_count,
                                Self::MIN_BFT_VALIDATORS
                            );
                            info!(
                                "   Mining loop disabled - block production driven by BFT consensus"
                            );
                            info!(
                                "   Height: {}, Pending: {}, UTXOs: {}",
                                current_height,
                                pending_count,
                                blockchain_guard.utxo_set.len()
                            );
                            last_bft_mode_log = std::time::Instant::now();
                        }

                        // Don't mine - BFT consensus engine handles block production
                        // The ConsensusBlockCommitter callback commits finalized blocks
                        drop(blockchain_guard);
                        continue;
                    }

                    // BOOTSTRAP MODE: Direct mining allowed
                    info!("⛏️ BOOTSTRAP MODE: {} validators (need ≥{} for BFT)",
                        validator_count, Self::MIN_BFT_VALIDATORS);
                    info!("Mining check #{} - Height: {}, Pending: {}, UTXOs: {}, Identities: {}",
                        block_counter, current_height, pending_count,
                        blockchain_guard.utxo_set.len(),
                        blockchain_guard.identity_registry.len()
                    );

                    if pending_count > 0 {
                        let validator_manager_opt = validator_manager_arc.read().await.clone();
                        let node_identity_opt = node_identity_arc.read().await.clone();

                        let should_mine = if let (Some(vm), Some(node_id)) = (validator_manager_opt, node_identity_opt) {
                            let vm_guard = vm.read().await;
                            let active_validators = vm_guard.get_active_validators();

                            if active_validators.is_empty() {
                                warn!("⛏️ No validators in ValidatorManager");
                                true
                            } else {
                                let next_height = current_height + 1;
                                if let Some(proposer) = vm_guard.select_proposer(next_height, consensus_round) {
                                    let node_id_hex = hex::encode(node_id.as_bytes());
                                    let mut is_proposer = false;

                                    for (did_string, identity_data) in blockchain_guard.identity_registry.iter() {
                                        if identity_data.controlled_nodes.contains(&node_id_hex) {
                                            if let Some(identity_hex) = did_string.strip_prefix("did:zhtp:") {
                                                if let Ok(identity_bytes) = hex::decode(identity_hex) {
                                                    let user_identity_hash = lib_crypto::Hash::from_bytes(&identity_bytes[..32]);
                                                    if user_identity_hash == proposer.identity {
                                                        is_proposer = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if is_proposer {
                                        info!("⛏️ BOOTSTRAP: This node selected as proposer");
                                    } else {
                                        info!("⛏️ BOOTSTRAP: Waiting for our turn");
                                    }
                                    is_proposer
                                } else {
                                    true
                                }
                            }
                        } else {
                            warn!("⛏️ Mining without consensus coordination");
                            true
                        };

                        if should_mine {
                            drop(blockchain_guard);
                            let mut blockchain_guard = shared_blockchain.write().await;
                            match Self::mine_real_block(&mut *blockchain_guard).await {
                                Ok(()) => {
                                    info!("⛏️ Bootstrap block #{} mined successfully!", block_counter);
                                    block_counter += 1;
                                    consensus_round = 0;

                                    // Auto-persist blockchain after mining
                                    blockchain_guard.increment_persist_counter();
                                    const PERSIST_INTERVAL: u64 = 1; // Save every block
                                    if blockchain_guard.should_auto_persist(PERSIST_INTERVAL) {
                                        // Use environment-specific path
                                        let persist_path_str = env_for_persist.blockchain_data_path();
                                        let persist_path = std::path::Path::new(&persist_path_str);
                                        match blockchain_guard.save_to_file(persist_path) {
                                            Ok(()) => {
                                                blockchain_guard.mark_persisted();
                                                info!("💾 Blockchain auto-persisted to disk");
                                            }
                                            Err(e) => {
                                                warn!("⚠️ Failed to auto-persist blockchain: {}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to mine block #{}: {}", block_counter, e);
                                    consensus_round += 1;
                                }
                            }
                        } else {
                            consensus_round = (consensus_round + 1) % 10;
                        }
                    } else {
                        debug!("No pending transactions");
                        consensus_round = 0;
                    }
                }
                Err(_) => {
                    // CRITICAL GUARD: Check node role again before using fallback path
                    // This prevents edge nodes or observers from mining even if global provider fails
                    if !node_role.can_mine() {
                        error!(
                            "CRITICAL BUG: Non-mining node {:?} tried to use fallback mining path - config/component initialization bug",
                            *node_role
                        );
                        // Skip mining on this iteration to avoid producing invalid blocks
                    } else if let Some(ref mut local_blockchain) = blockchain.write().await.as_mut() {
                        let pending_count = local_blockchain.pending_transactions.len();
                        if pending_count > 0 {
                            match Self::mine_real_block(local_blockchain).await {
                                Ok(()) => {
                                    info!("Block mined (local fallback)!");
                                    block_counter += 1;
                                }
                                Err(e) => debug!("Mining failed: {}", e),
                            }
                        }
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Component for BlockchainComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Blockchain
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting blockchain component with shared blockchain service...");
        info!(" Network Environment: {}", self.environment);
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Edge node initialization
        if self.is_edge_node {
            info!("🔷 Edge node mode: Initializing EdgeNodeState (header-only sync)");
            const EDGE_MAX_HEADERS: usize = 500;
            let edge_state = lib_blockchain::edge_node_state::EdgeNodeState::new(EDGE_MAX_HEADERS);
            let edge_state_arc = Arc::new(RwLock::new(edge_state));
            *self.edge_state.write().await = Some(edge_state_arc.clone());
            
            crate::runtime::edge_state_provider::initialize_global_edge_state_provider();
            crate::runtime::edge_state_provider::set_global_edge_state(edge_state_arc).await?;
            
            info!("✓ EdgeNodeState initialized");
            *self.start_time.write().await = Some(Instant::now());
            *self.status.write().await = ComponentStatus::Running;
            return Ok(());
        }
        
        // Full node initialization
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(shared_blockchain) => {
                info!("✓ Using existing global blockchain instance");
                // CRITICAL FIX: Don't clone the blockchain data, just store the reference
                // Cloning creates a snapshot that disconnects from the global state
                // Instead, we'll use the global provider directly in mining loop
                
                // For local access via self.blockchain, we can clone the data once for initialization
                // but the mining loop MUST use the global provider to see updates
                let blockchain_clone = shared_blockchain.read().await.clone();
                *self.blockchain.write().await = Some(blockchain_clone);
            }
            Err(_) => {
                if self.joined_existing_network {
                    info!("✓ Joining existing network - blockchain already initialized for sync");
                } else {
                    info!("ℹ Creating new genesis network...");
                }
            }
        }
        
        // Check if this node can mine before starting the mining loop
        // Only FullValidator nodes should participate in block mining
        if !self.node_role.can_mine() {
            let role_desc = match &*self.node_role {
                crate::runtime::node_runtime::NodeRole::Observer => "observer (full blockchain, no mining)",
                crate::runtime::node_runtime::NodeRole::LightNode => "light (headers only)",
                _ => "non-validator",
            };
            info!(
                "ℹ️ Node type {:?} does not mine blocks - running as {} node",
                *self.node_role,
                role_desc
            );
            // Node starts successfully but skips mining service
            *self.status.write().await = ComponentStatus::Running;
            return Ok(());
        }

        info!("✓ Node role {:?} can mine - starting mining service", *self.node_role);

        // Start mining loop
        // CRITICAL FIX: Pass None for local blockchain to force using global provider
        // This ensures the mining loop always sees the latest state from Genesis/Sync
        let validator_manager_arc = self.validator_manager.clone();
        let node_identity_arc = self.node_identity.clone();
        let env_for_persist = self.environment.clone();
        let node_role_for_loop = self.node_role.clone();

        // We pass a new empty Arc for the local fallback, effectively disabling it
        // The mining loop prefers the global provider anyway
        let dummy_local_blockchain = Arc::new(RwLock::new(None));

        let mining_handle = tokio::spawn(async move {
            info!("⛏️ Mining task spawned, starting mining loop...");
            Self::real_mining_loop(dummy_local_blockchain, validator_manager_arc, node_identity_arc, env_for_persist, node_role_for_loop).await;
        });
        
        *self.mining_handle.write().await = Some(mining_handle);
        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;
        
        info!("✓ Blockchain component started with mining enabled");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping blockchain component...");
        *self.status.write().await = ComponentStatus::Stopping;

        // Persist blockchain before shutdown
        if let Ok(shared_blockchain) = crate::runtime::blockchain_provider::get_global_blockchain().await {
            let blockchain_guard = shared_blockchain.read().await;
            let persist_path_str = self.environment.blockchain_data_path();
            let persist_path = std::path::Path::new(&persist_path_str);
            match blockchain_guard.save_to_file(persist_path) {
                Ok(()) => info!("💾 Blockchain persisted to {} before shutdown", persist_path_str),
                Err(e) => warn!("⚠️ Failed to persist blockchain on shutdown: {}", e),
            }
        }

        if let Some(handle) = self.mining_handle.write().await.take() {
            handle.abort();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        *self.blockchain.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        Ok(())
    }

    async fn force_stop(&self) -> Result<()> {
        warn!(" Force stopping blockchain component...");
        *self.status.write().await = ComponentStatus::Stopping;
        
        if let Some(handle) = self.mining_handle.write().await.take() {
            handle.abort();
        }
        
        *self.blockchain.write().await = None;
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
            ComponentMessage::Custom(msg, _data) if msg == "add_test_transaction" => {
                // Try global provider first
                let global_blockchain = crate::runtime::blockchain_provider::get_global_blockchain().await;
                
                // We need to hold the lock for the duration of the operation
                // This is a bit tricky with the different types, so we'll use a closure or just duplicate logic
                // Duplicating logic is safer to avoid lifetime issues with locks
                
                if let Ok(global) = global_blockchain {
                    info!("Creating economic transactions on GLOBAL blockchain...");
                    let mut blockchain = global.write().await;
                    
                    match Self::create_ubi_transaction(&self.environment).await {
                        Ok(ubi_tx) => {
                            match blockchain.add_pending_transaction(ubi_tx.clone()) {
                                Ok(()) => info!("UBI distribution transaction added! Hash: {:?}", ubi_tx.hash()),
                                Err(e) => warn!("Failed to add UBI transaction: {}", e),
                            }
                        }
                        Err(e) => warn!("Failed to create UBI transaction: {}", e),
                    }
                    
                    let example_node_id = [2u8; 32];
                    let reward_amount = 500;
                    match Self::create_reward_transaction(example_node_id, reward_amount, &self.environment).await {
                        Ok(reward_tx) => {
                            match blockchain.add_pending_transaction(reward_tx.clone()) {
                                Ok(()) => info!("Network reward transaction added! Hash: {:?}", reward_tx.hash()),
                                Err(e) => warn!("Failed to add reward transaction: {}", e),
                            }
                        }
                        Err(e) => warn!("Failed to create reward transaction: {}", e),
                    }
                    info!("Transactions queued for mining on global chain");
                    
                } else if let Some(ref mut blockchain) = self.blockchain.write().await.as_mut() {
                    info!("Creating economic transactions on LOCAL blockchain (fallback)...");
                    
                    match Self::create_ubi_transaction(&self.environment).await {
                        Ok(ubi_tx) => {
                            match blockchain.add_pending_transaction(ubi_tx.clone()) {
                                Ok(()) => {
                                    info!("UBI distribution transaction added! Hash: {:?}", ubi_tx.hash());
                                }
                                Err(e) => {
                                    warn!("Failed to add UBI transaction: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create UBI transaction: {}", e);
                        }
                    }
                    
                    let example_node_id = [2u8; 32];
                    let reward_amount = 500;
                    match Self::create_reward_transaction(example_node_id, reward_amount, &self.environment).await {
                        Ok(reward_tx) => {
                            match blockchain.add_pending_transaction(reward_tx.clone()) {
                                Ok(()) => {
                                    info!("Network reward transaction added! Hash: {:?}", reward_tx.hash());
                                }
                                Err(e) => {
                                    warn!("Failed to add reward transaction: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create reward transaction: {}", e);
                        }
                    }
                    
                    info!("Transactions queued for mining");
                }
                Ok(())
            }
            ComponentMessage::HealthCheck => {
                debug!("Blockchain component health check");
                Ok(())
            }
            _ => {
                debug!("Blockchain component received message: {:?}", message);
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
        
        // Try global provider first
        let global_blockchain = crate::runtime::blockchain_provider::get_global_blockchain().await;
        
        if let Ok(global) = global_blockchain {
            let blockchain = global.read().await;
            metrics.insert("chain_height".to_string(), blockchain.height as f64);
            metrics.insert("total_blocks".to_string(), blockchain.blocks.len() as f64);
            metrics.insert("pending_transactions".to_string(), blockchain.pending_transactions.len() as f64);
            metrics.insert("utxo_count".to_string(), blockchain.utxo_set.len() as f64);
            metrics.insert("identity_count".to_string(), blockchain.identity_registry.len() as f64);
            metrics.insert("total_work".to_string(), blockchain.total_work as f64);
            
            let avg_block_size = if blockchain.blocks.len() > 0 {
                blockchain.blocks.iter().map(|b| b.transactions.len()).sum::<usize>() as f64 / blockchain.blocks.len() as f64
            } else {
                0.0
            };
            metrics.insert("avg_transactions_per_block".to_string(), avg_block_size);
        } else if let Some(ref blockchain) = *self.blockchain.read().await {
            metrics.insert("chain_height".to_string(), blockchain.height as f64);
            metrics.insert("total_blocks".to_string(), blockchain.blocks.len() as f64);
            metrics.insert("pending_transactions".to_string(), blockchain.pending_transactions.len() as f64);
            metrics.insert("utxo_count".to_string(), blockchain.utxo_set.len() as f64);
            metrics.insert("identity_count".to_string(), blockchain.identity_registry.len() as f64);
            metrics.insert("total_work".to_string(), blockchain.total_work as f64);
            
            let avg_block_size = if blockchain.blocks.len() > 0 {
                blockchain.blocks.iter().map(|b| b.transactions.len()).sum::<usize>() as f64 / blockchain.blocks.len() as f64
            } else {
                0.0
            };
            metrics.insert("avg_transactions_per_block".to_string(), avg_block_size);
        } else {
            metrics.insert("chain_height".to_string(), 0.0);
            metrics.insert("total_blocks".to_string(), 0.0);
            metrics.insert("pending_transactions".to_string(), 0.0);
            metrics.insert("utxo_count".to_string(), 0.0);
            metrics.insert("identity_count".to_string(), 0.0);
            metrics.insert("total_work".to_string(), 0.0);
            metrics.insert("avg_transactions_per_block".to_string(), 0.0);
        }
        
        Ok(metrics)
    }
}

// Export helper type
pub use crate::runtime::components::consensus::BlockchainValidatorAdapter;
