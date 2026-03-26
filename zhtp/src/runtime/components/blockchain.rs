// Blockchain component - thin wrapper that delegates to services
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::runtime::node_runtime::NodeRole;
use crate::runtime::services::{GenesisFundingService, GenesisValidator, TransactionBuilder};
use crate::runtime::{Component, ComponentHealth, ComponentId, ComponentMessage, ComponentStatus};
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
    /// QUIC peer addresses (e.g. "77.42.37.161:9334") used by observer sync loop
    bootstrap_peers: Vec<String>,
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
            bootstrap_peers: Vec::new(),
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
            bootstrap_peers: Vec::new(),
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
            bootstrap_peers: Vec::new(),
            joined_existing_network: false,
            validator_manager: Arc::new(RwLock::new(None)),
            node_identity: Arc::new(RwLock::new(None)),
            is_edge_node: false,
            node_role: Arc::new(node_role),
        }
    }

    /// Invariant BFT-A-1954: Validator set is loaded exclusively from genesis/canonical state.
    /// The `bootstrap_validators` config list is accepted here for API compatibility but is
    /// NOT used for live validator-set resolution. Genesis block data is the sole source of truth.
    pub fn new_with_full_config(
        node_role: NodeRole,
        user_wallet: Option<crate::runtime::did_startup::WalletStartupResult>,
        environment: crate::config::Environment,
        _bootstrap_validators: Vec<crate::config::aggregation::BootstrapValidator>,
        bootstrap_peers: Vec<String>,
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
            bootstrap_peers,
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

        info!(
            " Updating controlled_nodes for user {} with node {}",
            &user_did[..40],
            &node_id_hex[..32]
        );

        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(blockchain_arc) => {
                let mut blockchain = blockchain_arc.write().await;
                if let Some(identity_data) = blockchain.identity_registry.get_mut(&user_did) {
                    if !identity_data.controlled_nodes.contains(&node_id_hex) {
                        identity_data.controlled_nodes.push(node_id_hex.clone());
                        info!(
                            " Added node {} to user's controlled_nodes list",
                            &node_id_hex[..32]
                        );
                    }
                }
            }
            Err(e) => {
                warn!("  Failed to get global blockchain: {}", e);
            }
        }
    }

    pub fn get_blockchain_arc(&self) -> Arc<RwLock<Option<Blockchain>>> {
        self.blockchain.clone()
    }

    pub fn get_edge_state_arc(
        &self,
    ) -> Arc<RwLock<Option<Arc<RwLock<lib_blockchain::edge_node_state::EdgeNodeState>>>>> {
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
        genesis_private_data: Vec<(
            lib_identity::IdentityId,
            lib_identity::identity::PrivateIdentityData,
        )>,
    ) -> Result<()> {
        GenesisFundingService::create_genesis_funding(
            blockchain,
            genesis_validators,
            environment,
            user_primary_wallet_id,
            user_identity_id,
            genesis_private_data,
        )
        .await
    }

    /// Create UBI distribution transaction - delegates to TransactionBuilder
    async fn create_ubi_transaction(
        environment: &crate::config::Environment,
    ) -> Result<Transaction> {
        TransactionBuilder::create_ubi_transaction(environment).await
    }

    /// Create reward transaction - delegates to TransactionBuilder
    pub async fn create_reward_transaction(
        node_id: [u8; 32],
        reward_amount: u64,
        environment: &crate::config::Environment,
    ) -> Result<Transaction> {
        TransactionBuilder::create_reward_transaction(node_id, reward_amount, environment).await
    }

    fn sync_peers_for_round(
        configured_bootstrap_peers: &[String],
        discovered_peers: &[String],
    ) -> Vec<String> {
        let mut peers = Vec::new();

        for peer in configured_bootstrap_peers
            .iter()
            .chain(discovered_peers.iter())
        {
            if !peer.trim().is_empty() && !peers.contains(peer) {
                peers.push(peer.clone());
            }
        }

        peers
    }

    fn peer_is_ahead(local_height: u64, peer_tip_height: u64) -> bool {
        peer_tip_height > local_height
    }

    /// Periodic catch-up loop for Observer nodes.
    ///
    /// Runs every 30 seconds. For each bootstrap peer, opens a QUIC connection,
    /// checks the peer's chain tip, and if the peer is ahead fetches missing blocks
    /// in batches and applies them via `add_block_from_network_with_persistence`.
    async fn observer_sync_loop(bootstrap_peers: Vec<String>) {
        use lib_network::client::{ZhtpClient, ZhtpClientConfig};
        use serde::Deserialize;

        // Brief initial delay so the rest of the runtime finishes wiring up.
        tokio::time::sleep(Duration::from_secs(15)).await;

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            let bc_arc = match crate::runtime::blockchain_provider::get_global_blockchain().await {
                Ok(a) => a,
                Err(_) => continue,
            };

            let local_height = bc_arc.read().await.height;

            let discovered_peers = crate::runtime::bootstrap_peers_provider::get_bootstrap_peers()
                .await
                .unwrap_or_default();
            let sync_peers = Self::sync_peers_for_round(&bootstrap_peers, &discovered_peers);

            if sync_peers.is_empty() {
                debug!("observer_sync: no bootstrap peers available for this round");
                continue;
            }

            // Try each bootstrap peer until one succeeds.
            'peers: for peer_quic_addr in &sync_peers {
                // Create a throwaway identity for the QUIC handshake.
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let temp_id = match lib_identity::ZhtpIdentity::new_unified(
                    lib_identity::IdentityType::Device,
                    None,
                    None,
                    &format!("observer-sync-{}", ts),
                    None,
                ) {
                    Ok(id) => id,
                    Err(e) => {
                        warn!("observer_sync: failed to create temp identity: {}", e);
                        continue;
                    }
                };

                let cfg = ZhtpClientConfig {
                    allow_bootstrap: true,
                };
                let mut client = match ZhtpClient::new_bootstrap_with_config(temp_id, cfg).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("observer_sync: failed to create QUIC client: {}", e);
                        continue;
                    }
                };

                if let Err(e) = client.connect(peer_quic_addr).await {
                    debug!(
                        "observer_sync: could not connect to {}: {}",
                        peer_quic_addr, e
                    );
                    continue;
                }

                // Fetch peer's chain tip.
                #[derive(Deserialize)]
                struct ChainTip {
                    height: u64,
                }

                let tip_resp = match tokio::time::timeout(
                    Duration::from_secs(10),
                    client.get("/api/v1/blockchain/tip"),
                )
                .await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        warn!(
                            "observer_sync: tip request failed for {}: {}",
                            peer_quic_addr, e
                        );
                        continue;
                    }
                    Err(_) => {
                        warn!(
                            "observer_sync: tip request timed out for {}",
                            peer_quic_addr
                        );
                        continue;
                    }
                };

                if !tip_resp.is_success() {
                    warn!(
                        "observer_sync: peer {} returned non-success for /tip",
                        peer_quic_addr
                    );
                    continue;
                }

                let peer_tip: ChainTip = match serde_json::from_slice(&tip_resp.body) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("observer_sync: failed to parse tip JSON: {}", e);
                        continue;
                    }
                };

                if !Self::peer_is_ahead(local_height, peer_tip.height) {
                    debug!(
                        "observer_sync: peer {} at height {}, local={}, no gap",
                        peer_quic_addr, peer_tip.height, local_height
                    );
                    continue;
                }

                info!(
                    "📥 Observer gap-fill: peer {} height={}, local={}, fetching {} block(s)",
                    peer_quic_addr,
                    peer_tip.height,
                    local_height,
                    peer_tip.height - local_height
                );

                // Fetch and apply missing blocks in batches of 100.
                let mut current = local_height;
                let target = peer_tip.height;

                'batches: loop {
                    if current >= target {
                        break;
                    }

                    let from = current + 1;
                    let to = std::cmp::min(from + 99, target);

                    let path = format!("/api/v1/blockchain/blocks/{}/{}", from, to);
                    let blocks_resp = match tokio::time::timeout(
                        Duration::from_secs(30),
                        client.get(&path),
                    )
                    .await
                    {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            warn!("observer_sync: blocks request failed: {}", e);
                            break 'batches;
                        }
                        Err(_) => {
                            warn!("observer_sync: blocks request timed out");
                            break 'batches;
                        }
                    };

                    if !blocks_resp.is_success() {
                        warn!(
                            "observer_sync: peer returned error for blocks {}-{}",
                            from, to
                        );
                        break 'batches;
                    }

                    let blocks: Vec<lib_blockchain::Block> =
                        match bincode::deserialize(&blocks_resp.body) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("observer_sync: failed to deserialize blocks: {}", e);
                                break 'batches;
                            }
                        };

                    if blocks.is_empty() {
                        warn!(
                            "observer_sync: peer returned empty block list for {}-{}",
                            from, to
                        );
                        break 'batches;
                    }

                    info!(
                        "📥 Applying {} block(s) ({}-{}) from {}",
                        blocks.len(),
                        from,
                        to,
                        peer_quic_addr
                    );

                    let mut bc = bc_arc.write().await;
                    let mut applied: u64 = 0;
                    for block in blocks {
                        let h = block.header.height;
                        match bc.add_block_from_network_with_persistence(block).await {
                            Ok(()) => {
                                applied += 1;
                                current = h;
                            }
                            Err(e) => {
                                warn!("observer_sync: failed to apply block {}: {}", h, e);
                                break 'batches;
                            }
                        }
                    }
                    drop(bc);

                    info!(
                        "✅ observer_sync: applied {} block(s), local height now {}",
                        applied, current
                    );
                    if applied == 0 {
                        break 'batches;
                    }
                }

                // Successfully synced (or gap is filled); stop trying other peers.
                break 'peers;
            }
        }
    }

    fn should_run_peer_sync_loop(
        bootstrap_peers_count: usize,
        joined_existing_network: bool,
        can_mine: bool,
    ) -> bool {
        bootstrap_peers_count > 0 && (joined_existing_network || !can_mine)
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

        // Run periodic gap-fill sync for joiners and non-mining nodes.
        // The bootstrap leader with local chain data should not run this loop.
        let should_run_peer_sync_loop = Self::should_run_peer_sync_loop(
            self.bootstrap_peers.len(),
            self.joined_existing_network,
            self.node_role.can_mine(),
        );
        if should_run_peer_sync_loop {
            let peers = self.bootstrap_peers.clone();
            tokio::spawn(Self::observer_sync_loop(peers));
            info!(
                "✓ Peer sync loop started ({} bootstrap peer(s))",
                self.bootstrap_peers.len()
            );
        } else {
            info!(
                "ℹ️ Peer sync loop disabled (bootstrap_peers={}, joined_existing_network={}, can_mine={})",
                self.bootstrap_peers.len(),
                self.joined_existing_network,
                self.node_role.can_mine(),
            );
        }

        // Check if this node can mine before starting the mining loop
        // Only FullValidator nodes should participate in block mining
        if !self.node_role.can_mine() {
            let role_desc = match &*self.node_role {
                crate::runtime::node_runtime::NodeRole::Observer => {
                    "observer (full blockchain, no mining)"
                }
                crate::runtime::node_runtime::NodeRole::LightNode => "light (headers only)",
                _ => "non-validator",
            };
            info!(
                "ℹ️ Node type {:?} does not mine blocks - running as {} node",
                *self.node_role, role_desc
            );

            *self.status.write().await = ComponentStatus::Running;
            return Ok(());
        }

        // Invariant BFT-A-1955: Validator block production is driven exclusively by BFT
        // finalization. There is no local mining loop — block proposals are created by
        // the consensus engine (ConsensusComponent) and committed only after 2f+1 votes.
        info!(
            "✓ Validator node {:?} started — block production via BFT only",
            *self.node_role
        );

        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping blockchain component...");
        *self.status.write().await = ComponentStatus::Stopping;

        // Persist blockchain before shutdown (legacy mode only)
        if let Ok(shared_blockchain) =
            crate::runtime::blockchain_provider::get_global_blockchain().await
        {
            let blockchain_guard = shared_blockchain.read().await;
            if blockchain_guard.get_store().is_none() {
                let persist_path_str = self.environment.blockchain_data_path();
                let persist_path = std::path::Path::new(&persist_path_str);
                #[allow(deprecated)]
                match blockchain_guard.save_to_file(persist_path) {
                    Ok(()) => info!(
                        "💾 Blockchain persisted to {} before shutdown",
                        persist_path_str
                    ),
                    Err(e) => warn!("⚠️ Failed to persist blockchain on shutdown: {}", e),
                }
            } else {
                info!("💾 Blockchain store handles persistence on shutdown");
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
                let global_blockchain =
                    crate::runtime::blockchain_provider::get_global_blockchain().await;

                // We need to hold the lock for the duration of the operation
                // This is a bit tricky with the different types, so we'll use a closure or just duplicate logic
                // Duplicating logic is safer to avoid lifetime issues with locks

                if let Ok(global) = global_blockchain {
                    info!("Creating economic transactions on GLOBAL blockchain...");
                    let mut blockchain = global.write().await;

                    match Self::create_ubi_transaction(&self.environment).await {
                        Ok(ubi_tx) => match blockchain.add_pending_transaction(ubi_tx.clone()) {
                            Ok(()) => info!(
                                "UBI distribution transaction added! Hash: {:?}",
                                ubi_tx.hash()
                            ),
                            Err(e) => warn!("Failed to add UBI transaction: {}", e),
                        },
                        Err(e) => warn!("Failed to create UBI transaction: {}", e),
                    }

                    let example_node_id = [2u8; 32];
                    let reward_amount = 500;
                    match Self::create_reward_transaction(
                        example_node_id,
                        reward_amount,
                        &self.environment,
                    )
                    .await
                    {
                        Ok(reward_tx) => {
                            match blockchain.add_pending_transaction(reward_tx.clone()) {
                                Ok(()) => info!(
                                    "Network reward transaction added! Hash: {:?}",
                                    reward_tx.hash()
                                ),
                                Err(e) => warn!("Failed to add reward transaction: {}", e),
                            }
                        }
                        Err(e) => warn!("Failed to create reward transaction: {}", e),
                    }
                    info!("Transactions queued for mining on global chain");
                } else if let Some(ref mut blockchain) = self.blockchain.write().await.as_mut() {
                    info!("Creating economic transactions on LOCAL blockchain (fallback)...");

                    match Self::create_ubi_transaction(&self.environment).await {
                        Ok(ubi_tx) => match blockchain.add_pending_transaction(ubi_tx.clone()) {
                            Ok(()) => {
                                info!(
                                    "UBI distribution transaction added! Hash: {:?}",
                                    ubi_tx.hash()
                                );
                            }
                            Err(e) => {
                                warn!("Failed to add UBI transaction: {}", e);
                            }
                        },
                        Err(e) => {
                            warn!("Failed to create UBI transaction: {}", e);
                        }
                    }

                    let example_node_id = [2u8; 32];
                    let reward_amount = 500;
                    match Self::create_reward_transaction(
                        example_node_id,
                        reward_amount,
                        &self.environment,
                    )
                    .await
                    {
                        Ok(reward_tx) => {
                            match blockchain.add_pending_transaction(reward_tx.clone()) {
                                Ok(()) => {
                                    info!(
                                        "Network reward transaction added! Hash: {:?}",
                                        reward_tx.hash()
                                    );
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
        let uptime_secs = start_time
            .map(|t| t.elapsed().as_secs() as f64)
            .unwrap_or(0.0);

        metrics.insert("uptime_seconds".to_string(), uptime_secs);
        metrics.insert(
            "is_running".to_string(),
            if matches!(*self.status.read().await, ComponentStatus::Running) {
                1.0
            } else {
                0.0
            },
        );

        // Try global provider first
        let global_blockchain = crate::runtime::blockchain_provider::get_global_blockchain().await;

        if let Ok(global) = global_blockchain {
            let blockchain = global.read().await;
            metrics.insert("chain_height".to_string(), blockchain.height as f64);
            metrics.insert("total_blocks".to_string(), blockchain.blocks.len() as f64);
            metrics.insert(
                "pending_transactions".to_string(),
                blockchain.pending_transactions.len() as f64,
            );
            metrics.insert("utxo_count".to_string(), blockchain.utxo_set.len() as f64);
            metrics.insert(
                "identity_count".to_string(),
                blockchain.identity_registry.len() as f64,
            );
            metrics.insert("total_work".to_string(), blockchain.total_work as f64);

            let avg_block_size = if blockchain.blocks.len() > 0 {
                blockchain
                    .blocks
                    .iter()
                    .map(|b| b.transactions.len())
                    .sum::<usize>() as f64
                    / blockchain.blocks.len() as f64
            } else {
                0.0
            };
            metrics.insert("avg_transactions_per_block".to_string(), avg_block_size);
        } else if let Some(ref blockchain) = *self.blockchain.read().await {
            metrics.insert("chain_height".to_string(), blockchain.height as f64);
            metrics.insert("total_blocks".to_string(), blockchain.blocks.len() as f64);
            metrics.insert(
                "pending_transactions".to_string(),
                blockchain.pending_transactions.len() as f64,
            );
            metrics.insert("utxo_count".to_string(), blockchain.utxo_set.len() as f64);
            metrics.insert(
                "identity_count".to_string(),
                blockchain.identity_registry.len() as f64,
            );
            metrics.insert("total_work".to_string(), blockchain.total_work as f64);

            let avg_block_size = if blockchain.blocks.len() > 0 {
                blockchain
                    .blocks
                    .iter()
                    .map(|b| b.transactions.len())
                    .sum::<usize>() as f64
                    / blockchain.blocks.len() as f64
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

#[cfg(test)]
mod tests {
    use super::BlockchainComponent;

    #[test]
    fn should_run_peer_sync_loop_for_joining_validator() {
        assert!(BlockchainComponent::should_run_peer_sync_loop(
            1, true, true
        ));
    }

    #[test]
    fn should_not_run_peer_sync_loop_for_bootstrap_leader_validator() {
        assert!(!BlockchainComponent::should_run_peer_sync_loop(
            1, false, true
        ));
    }

    #[test]
    fn should_run_peer_sync_loop_for_non_mining_nodes() {
        assert!(BlockchainComponent::should_run_peer_sync_loop(
            1, false, false
        ));
    }

    #[test]
    fn sync_peers_for_round_merges_and_deduplicates_sources() {
        let peers = BlockchainComponent::sync_peers_for_round(
            &["127.0.0.1:9334".to_string(), "127.0.0.1:9335".to_string()],
            &[
                "127.0.0.1:9335".to_string(),
                "127.0.0.1:9336".to_string(),
                "".to_string(),
            ],
        );

        assert_eq!(
            peers,
            vec![
                "127.0.0.1:9334".to_string(),
                "127.0.0.1:9335".to_string(),
                "127.0.0.1:9336".to_string()
            ]
        );
    }

    #[test]
    fn peer_is_ahead_requires_strictly_higher_tip() {
        assert!(!BlockchainComponent::peer_is_ahead(10, 10));
        assert!(!BlockchainComponent::peer_is_ahead(10, 9));
        assert!(BlockchainComponent::peer_is_ahead(10, 11));
    }
}
