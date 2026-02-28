use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug, error};

use crate::runtime::{Component, ComponentId, ComponentStatus, ComponentHealth, ComponentMessage};
use crate::runtime::node_runtime::NodeRole;
use lib_consensus::{ConsensusEngine, ConsensusConfig, ConsensusEvent, ValidatorManager, NoOpBroadcaster};
use lib_consensus::types::{MessageBroadcaster as ConsensusMessageBroadcaster, ValidatorMessage};
use lib_consensus::validators::{ValidatorNetworkTransport, ValidatorProtocol, ValidatorDiscoveryProtocol};
use lib_identity::IdentityId;
use crate::monitoring::{Alert, AlertLevel, AlertManager};
use crate::runtime::mesh_router_provider::get_global_mesh_router;
use crate::server::mesh::core::MeshRouter;
use lib_blockchain::Blockchain;

/// Adapter that implements lib-consensus MessageBroadcaster using zhtp's MeshRouter
///
/// This bridges the consensus layer (which uses IdentityId) to the network layer
/// (which uses QUIC mesh routing) for multi-node BFT consensus.
pub struct ConsensusMeshBroadcaster {
    mesh_router: Arc<MeshRouter>,
}

impl ConsensusMeshBroadcaster {
    pub fn new(mesh_router: Arc<MeshRouter>) -> Self {
        Self { mesh_router }
    }
}

#[async_trait::async_trait]
impl ConsensusMessageBroadcaster for ConsensusMeshBroadcaster {
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        _validator_ids: &[IdentityId],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get QUIC protocol for sending
        let quic_protocol_guard = self.mesh_router.quic_protocol.read().await;
        let quic_protocol = match quic_protocol_guard.as_ref() {
            Some(qp) => qp.clone(),
            None => {
                debug!("QUIC protocol not available for consensus broadcast");
                return Ok(()); // Best-effort, don't fail
            }
        };
        drop(quic_protocol_guard);

        // Convert types::ValidatorMessage to validators::ValidatorMessage for mesh transport
        let network_message = convert_to_network_message(&message);
        let mesh_message = lib_network::types::mesh_message::ZhtpMeshMessage::ValidatorMessage(network_message);
        let message_bytes = bincode::serialize(&mesh_message)?;

        // Broadcast to all connected peers
        //
        // NOTE: Currently broadcasts to ALL connected peers rather than filtering to
        // the specific validator_ids passed in. This is acceptable because:
        // 1. Non-validators ignore consensus messages they can't verify
        // 2. Validators validate signatures before processing
        // 3. The mesh network is permissioned (authenticated peers only)
        //
        // TODO: For production optimization, filter to validator_ids by:
        // - Maintaining a validator pubkey -> peer_id mapping
        // - Using targeted send_to_peer instead of broadcast_message
        match quic_protocol.broadcast_message(&message_bytes).await {
            Ok(count) => {
                info!("Consensus broadcast sent to {} peers", count);
                Ok(())
            }
            Err(e) => {
                // Propagate error for observability at call sites
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Consensus broadcast failed: {}", e),
                )))
            }
        }
    }
}

/// Adapter that implements `ValidatorNetworkTransport` using zhtp's QUIC mesh.
///
/// Used by `ValidatorProtocol` to broadcast signed validator messages to peers.
struct QuicValidatorTransport {
    mesh_router: Arc<MeshRouter>,
}

impl QuicValidatorTransport {
    fn new(mesh_router: Arc<MeshRouter>) -> Self {
        Self { mesh_router }
    }
}

#[async_trait::async_trait]
impl ValidatorNetworkTransport for QuicValidatorTransport {
    async fn broadcast_to_validators(
        &self,
        message: lib_consensus::validators::ValidatorMessage,
        _recipients: &[IdentityId],
    ) -> anyhow::Result<()> {
        let quic_protocol_guard = self.mesh_router.quic_protocol.read().await;
        let quic_protocol = match quic_protocol_guard.as_ref() {
            Some(qp) => qp.clone(),
            None => {
                debug!("QUIC protocol not available for ValidatorProtocol broadcast");
                return Ok(()); // Best-effort
            }
        };
        drop(quic_protocol_guard);

        let mesh_message = lib_network::types::mesh_message::ZhtpMeshMessage::ValidatorMessage(message);
        let message_bytes = bincode::serialize(&mesh_message)
            .map_err(|e| anyhow::anyhow!("Failed to serialize validator message: {}", e))?;

        match quic_protocol.broadcast_message(&message_bytes).await {
            Ok(count) => {
                debug!("ValidatorProtocol broadcast sent to {} peers", count);
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("ValidatorProtocol broadcast failed: {}", e)),
        }
    }
}

/// Convert from lib_consensus::types::ValidatorMessage to lib_consensus::validators::ValidatorMessage
fn convert_to_network_message(msg: &ValidatorMessage) -> lib_consensus::validators::ValidatorMessage {
    use lib_consensus::validators::{
        ValidatorMessage as NetworkValidatorMessage,
        ProposeMessage, VoteMessage, ConsensusStateView,
    };
    use lib_consensus::types::HeartbeatMessage;
    use std::collections::BTreeMap;

    match msg {
        ValidatorMessage::Propose { proposal } => {
            NetworkValidatorMessage::Propose(ProposeMessage {
                message_id: proposal.id.clone(),
                proposer: proposal.proposer.clone(),
                proposal: proposal.clone(),
                justification: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                signature: proposal.signature.clone(),
            })
        }
        ValidatorMessage::Vote { vote } => {
            // Derive step from vote_type to ensure consistency
            let step = match vote.vote_type {
                lib_consensus::types::VoteType::PreVote => {
                    lib_consensus::types::ConsensusStep::PreVote
                }
                lib_consensus::types::VoteType::PreCommit => {
                    lib_consensus::types::ConsensusStep::PreCommit
                }
                lib_consensus::types::VoteType::Commit => {
                    lib_consensus::types::ConsensusStep::Commit
                }
                lib_consensus::types::VoteType::Against => {
                    // Against votes can occur during any voting step, default to PreVote
                    lib_consensus::types::ConsensusStep::PreVote
                }
            };
            let state_view = ConsensusStateView {
                height: vote.height,
                round: vote.round,
                step,
                known_proposals: vec![vote.proposal_id.clone()],
                vote_counts: BTreeMap::new(),
            };
            NetworkValidatorMessage::Vote(VoteMessage {
                message_id: vote.id.clone(),
                voter: vote.voter.clone(),
                vote: vote.clone(),
                consensus_state: state_view,
                timestamp: vote.timestamp,
                signature: vote.signature.clone(),
            })
        }
        ValidatorMessage::Heartbeat { message } => {
            // HeartbeatMessage is the same type, just re-exported
            NetworkValidatorMessage::Heartbeat(message.clone())
        }
    }
}

/// Adapter to make blockchain ValidatorInfo compatible with consensus ValidatorInfo trait
pub struct BlockchainValidatorAdapter(pub lib_blockchain::ValidatorInfo);

impl lib_consensus::validators::ValidatorInfo for BlockchainValidatorAdapter {
    fn identity_id(&self) -> lib_crypto::Hash {
        let identity_hex = self.0.identity_id
            .strip_prefix("did:zhtp:")
            .unwrap_or(&self.0.identity_id);
        
        if let Ok(bytes) = hex::decode(identity_hex) {
            if bytes.len() >= 32 {
                lib_crypto::Hash::from_bytes(&bytes[..32])
            } else {
                lib_crypto::Hash(lib_crypto::hash_blake3(self.0.identity_id.as_bytes()))
            }
        } else {
            lib_crypto::Hash(lib_crypto::hash_blake3(self.0.identity_id.as_bytes()))
        }
    }
    
    fn stake(&self) -> u64 {
        self.0.stake
    }
    
    fn storage_provided(&self) -> u64 {
        self.0.storage_provided
    }
    
    fn consensus_key(&self) -> Vec<u8> {
        self.0.consensus_key.clone()
    }

    fn networking_key(&self) -> Vec<u8> {
        self.0.networking_key.clone()
    }

    fn rewards_key(&self) -> Vec<u8> {
        self.0.rewards_key.clone()
    }

    fn commission_rate(&self) -> u8 {
        self.0.commission_rate
    }
}

/// Shared blockchain slot that can be populated after consensus engine starts
///
/// This allows the consensus engine to start before the blockchain is wired,
/// and access it once it becomes available.
pub type SharedBlockchainSlot = Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>;

/// Adapter that provides blockchain data to the consensus engine for block production
///
/// This bridges the consensus layer to the actual blockchain, providing:
/// - Latest block hash for chain continuity
/// - Pending transactions for new blocks
/// - Current blockchain height for validation
///
/// Uses a shared slot pattern to handle the case where consensus starts
/// before the blockchain is fully wired.
pub struct ConsensusBlockchainAdapter {
    blockchain_slot: SharedBlockchainSlot,
}

impl ConsensusBlockchainAdapter {
    pub fn new(blockchain_slot: SharedBlockchainSlot) -> Self {
        Self { blockchain_slot }
    }
}

/// Callback for committing BFT-finalized blocks to the blockchain
///
/// When BFT consensus achieves 2/3+1 commit votes, this callback is invoked
/// to actually commit the block to the blockchain storage layer.
///
/// This separates the "when" (BFT consensus decides) from the "how"
/// (blockchain layer stores), maintaining clean architectural boundaries.
pub struct ConsensusBlockCommitter {
    blockchain_slot: SharedBlockchainSlot,
    environment: crate::config::Environment,
}

impl ConsensusBlockCommitter {
    pub fn new(blockchain_slot: SharedBlockchainSlot, environment: crate::config::Environment) -> Self {
        Self {
            blockchain_slot,
            environment,
        }
    }
}

#[async_trait::async_trait]
impl lib_consensus::types::BlockCommitCallback for ConsensusBlockCommitter {
    async fn commit_finalized_block(
        &self,
        proposal: &lib_consensus::types::ConsensusProposal,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get blockchain from slot
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Err("Blockchain not yet available for commit".into()),
        };
        drop(slot);

        let mut blockchain = blockchain_arc.write().await;

        // Check if block at this height already exists (idempotent)
        if blockchain.height >= proposal.height && proposal.height > 0 {
            info!(
                "Block at height {} already exists (current height: {}), skipping commit",
                proposal.height,
                blockchain.height
            );
            return Ok(());
        }

        // Deserialize transactions from proposal block_data
        let transactions: Vec<lib_blockchain::Transaction> = if proposal.block_data.is_empty() {
            Vec::new()
        } else {
            // Try to deserialize as Vec<Transaction>
            match bincode::deserialize(&proposal.block_data) {
                Ok(txs) => txs,
                Err(e) => {
                    warn!(
                        "Failed to deserialize block_data as transactions: {} - treating as empty block",
                        e
                    );
                    Vec::new()
                }
            }
        };

        info!(
            "🔨 BFT consensus committing block at height {} with {} transactions",
            proposal.height,
            transactions.len()
        );

        // Get previous block hash
        let previous_hash = blockchain.latest_block()
            .map(|b| b.hash())
            .unwrap_or_default();

        // Get mining config for difficulty
        let mining_config = lib_blockchain::types::get_mining_config_from_env();
        let block_difficulty = mining_config.difficulty.clone();

        // Create block from the transactions
        let block = lib_blockchain::block::creation::create_block(
            transactions,
            previous_hash,
            proposal.height,
            block_difficulty,
        )?;

        // Mine the block (quick in dev mode due to low difficulty)
        info!(
            "⛏️ Mining BFT-finalized block at height {} with {} profile...",
            proposal.height,
            if mining_config.allow_instant_mining { "Bootstrap" } else { "Standard" }
        );
        let mined_block = lib_blockchain::block::creation::mine_block_with_config(block, &mining_config)?;
        info!("✓ BFT block mined with nonce: {}", mined_block.header.nonce);

        // Add block to blockchain
        match blockchain.add_block_with_proof(mined_block.clone()).await {
            Ok(()) => {
                info!(
                    "✅ BFT BLOCK COMMITTED! Height: {}, Hash: {:?}, Transactions: {}",
                    blockchain.height,
                    mined_block.hash(),
                    mined_block.transactions.len()
                );

                // Store consensus checkpoint for this committed block
                let block_hash = lib_blockchain::types::Hash::new(mined_block.hash().as_array());
                let proposer_id = proposal.proposer.to_string();
                // Convert lib_crypto::Hash to lib_blockchain::Hash
                let prev_hash_bytes: [u8; 32] = match proposal.previous_hash.as_bytes().try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        let actual_len = proposal.previous_hash.as_bytes().len();
                        tracing::error!(
                            "Unexpected previous_hash length: expected 32 bytes, got {}",
                            actual_len
                        );
                        return Err(anyhow::anyhow!(
                            "failed to convert previous_hash to 32-byte array: length {}",
                            actual_len
                        ).into());
                    }
                };
                let prev_hash = lib_blockchain::types::Hash::new(prev_hash_bytes);

                blockchain.store_consensus_checkpoint(
                    proposal.height,
                    block_hash,
                    proposer_id,
                    prev_hash,
                    0, // 0 = unknown; replace with actual count from consensus when available
                );
                info!("📍 Stored consensus checkpoint for height {}", proposal.height);

                // Auto-persist blockchain after BFT commit
                blockchain.increment_persist_counter();
                let persist_path_str = self.environment.blockchain_data_path();
                let persist_path = std::path::Path::new(&persist_path_str);
                match blockchain.save_to_file(persist_path) {
                    Ok(()) => {
                        blockchain.mark_persisted();
                        info!("💾 Blockchain auto-persisted after BFT commit");
                    }
                    Err(e) => {
                        warn!("⚠️ Failed to auto-persist blockchain after BFT commit: {}", e);
                    }
                }

                // Index in DHT
                if let Err(e) = crate::runtime::dht_indexing::index_block_in_dht(&mined_block).await {
                    warn!("DHT indexing failed for BFT block: {}", e);
                }

                Ok(())
            }
            Err(e) => {
                error!("Failed to add BFT-finalized block to blockchain: {}", e);
                Err(e.into())
            }
        }
    }

    async fn get_active_validator_count(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        // Get blockchain from slot
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Ok(0), // No blockchain = no validators
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        let validators = blockchain.get_active_validators();
        Ok(validators.len())
    }
}

#[async_trait::async_trait]
impl lib_consensus::types::ConsensusBlockchainProvider for ConsensusBlockchainAdapter {
    async fn get_latest_block_hash(&self) -> Result<lib_crypto::Hash, Box<dyn std::error::Error + Send + Sync>> {
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Err("Blockchain not yet available".into()),
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        if blockchain.blocks.is_empty() {
            // No blocks yet - genesis
            Ok(lib_crypto::Hash([0u8; 32]))
        } else {
            let latest_block = blockchain.blocks.last().unwrap();
            // Convert lib_blockchain::Hash to lib_crypto::Hash
            let block_hash = latest_block.header.hash();
            let hash_bytes = block_hash.as_array();
            Ok(lib_crypto::Hash(hash_bytes))
        }
    }

    async fn get_pending_transactions(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Ok(Vec::new()), // No blockchain = no transactions
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        let pending = &blockchain.pending_transactions;

        if pending.is_empty() {
            return Ok(Vec::new());
        }

        // Serialize pending transactions
        let tx_data = bincode::serialize(pending)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        info!("📦 Providing {} pending transactions ({} bytes) to consensus",
            pending.len(), tx_data.len());

        Ok(tx_data)
    }

    async fn get_blockchain_height(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let slot = self.blockchain_slot.read().await;
        let blockchain_arc = match slot.as_ref() {
            Some(bc) => bc.clone(),
            None => return Ok(0),
        };
        drop(slot);

        let blockchain = blockchain_arc.read().await;
        Ok(blockchain.height)
    }

    async fn is_ready(&self) -> bool {
        let slot = self.blockchain_slot.read().await;
        if let Some(blockchain_arc) = slot.as_ref() {
            // Blockchain is wired and ready
            if let Ok(blockchain) = blockchain_arc.try_read() {
                return !blockchain.blocks.is_empty() || blockchain.height == 0;
            }
        }
        false
    }
}

/// Consensus component implementation using lib-consensus package
pub struct ConsensusComponent {
    status: Arc<RwLock<ComponentStatus>>,
    start_time: Arc<RwLock<Option<Instant>>>,
    consensus_engine: Arc<RwLock<Option<ConsensusEngine>>>,
    validator_manager: Arc<RwLock<ValidatorManager>>,
    blockchain: Arc<RwLock<Option<Arc<RwLock<Blockchain>>>>>,
    environment: crate::config::Environment,
    // Consensus safety parameters are config-driven; keep them immutable once constructed.
    min_stake: u64,
    // Local validator identity and signing keypair (loaded from keystore when validator-enabled).
    local_validator_identity: Arc<RwLock<Option<IdentityId>>>,
    local_validator_keypair: Arc<RwLock<Option<lib_crypto::KeyPair>>>,
    /// Node role determines whether this node participates in consensus validation
    /// This is IMMUTABLE and set at construction time based on configuration
    /// The role cannot change after the component is created
    node_role: Arc<NodeRole>,
    /// Bootstrap validators pre-seeded from config for initial proposer rotation.
    /// These are replaced by on-chain ValidatorInfo once blocks are mined.
    bootstrap_validators: Vec<crate::config::aggregation::BootstrapValidator>,
}

// Manual Debug implementation because ConsensusEngine doesn't derive Debug
impl std::fmt::Debug for ConsensusComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusComponent")
            .field("status", &self.status)
            .field("start_time", &self.start_time)
            .field("consensus_engine", &"<ConsensusEngine>")
            .field("validator_manager", &"<ValidatorManager>")
            .field("blockchain", &"<Blockchain>")
            .field("environment", &self.environment)
            .field("node_role", &*self.node_role)
            .finish()
    }
}

/// Derive a deterministic 32-byte key from a validator identity ID and a domain tag.
/// Used to pre-seed ValidatorManager before on-chain ValidatorRegistration txs are mined.
fn derive_key_from_identity(identity_id: &str, domain: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(identity_id.len() + domain.len());
    input.extend_from_slice(identity_id.as_bytes());
    input.extend_from_slice(domain);
    lib_crypto::hash_blake3(&input).to_vec()
}

/// Adapter that implements lib-consensus ValidatorInfo for bootstrap config entries.
/// Uses deterministic key derivation so no keys need to be stored in config files.
struct BootstrapValidatorAdapter {
    identity_id: String,
    stake: u64,
    storage_provided: u64,
    commission_rate: u8,
}

impl lib_consensus::validators::ValidatorInfo for BootstrapValidatorAdapter {
    fn identity_id(&self) -> lib_crypto::Hash {
        let identity_hex = self.identity_id
            .strip_prefix("did:zhtp:")
            .unwrap_or(&self.identity_id);
        if let Ok(bytes) = hex::decode(identity_hex) {
            if bytes.len() >= 32 {
                return lib_crypto::Hash::from_bytes(&bytes[..32]);
            }
        }
        lib_crypto::Hash(lib_crypto::hash_blake3(self.identity_id.as_bytes()))
    }

    fn stake(&self) -> u64 { self.stake }
    fn storage_provided(&self) -> u64 { self.storage_provided }

    fn consensus_key(&self) -> Vec<u8> {
        derive_key_from_identity(&self.identity_id, b"consensus")
    }
    fn networking_key(&self) -> Vec<u8> {
        derive_key_from_identity(&self.identity_id, b"networking")
    }
    fn rewards_key(&self) -> Vec<u8> {
        derive_key_from_identity(&self.identity_id, b"rewards")
    }
    fn commission_rate(&self) -> u8 { self.commission_rate }
}

impl ConsensusComponent {
    /// Create a new ConsensusComponent with the specified node role
    /// CRITICAL: node_role must be derived from configuration before calling this
    pub fn new(environment: crate::config::Environment, node_role: NodeRole, min_stake: u64) -> Self {
        Self::new_with_bootstrap_validators(environment, node_role, min_stake, Vec::new())
    }

    /// Create a new ConsensusComponent with bootstrap validators pre-seeded.
    pub fn new_with_bootstrap_validators(
        environment: crate::config::Environment,
        node_role: NodeRole,
        min_stake: u64,
        bootstrap_validators: Vec<crate::config::aggregation::BootstrapValidator>,
    ) -> Self {
        let development_mode = matches!(environment, crate::config::Environment::Development);

        let validator_manager = ValidatorManager::new_with_development_mode(
            100,
            min_stake,
            development_mode,
        );

        Self {
            status: Arc::new(RwLock::new(ComponentStatus::Stopped)),
            start_time: Arc::new(RwLock::new(None)),
            consensus_engine: Arc::new(RwLock::new(None)),
            validator_manager: Arc::new(RwLock::new(validator_manager)),
            blockchain: Arc::new(RwLock::new(None)),
            environment,
            min_stake,
            local_validator_identity: Arc::new(RwLock::new(None)),
            local_validator_keypair: Arc::new(RwLock::new(None)),
            node_role: Arc::new(node_role),
            bootstrap_validators,
        }
    }

    #[deprecated = "Use new_with_bootstrap_validators(environment, node_role, min_stake, validators) instead"]
    pub fn new_deprecated(environment: crate::config::Environment) -> Self {
        Self::new(environment, NodeRole::Observer, 0)
    }

    /// Get the current node role (immutable)
    pub fn get_node_role(&self) -> NodeRole {
        (*self.node_role).clone()
    }
    
    pub async fn set_blockchain(&self, blockchain: Arc<RwLock<Blockchain>>) {
        *self.blockchain.write().await = Some(blockchain);
    }
    
    pub async fn sync_validators_from_blockchain(&self) -> Result<()> {
        let blockchain_opt = self.blockchain.read().await;
        let blockchain = match blockchain_opt.as_ref() {
            Some(bc) => bc,
            None => {
                warn!("Cannot sync validators: blockchain not set");
                return Ok(());
            }
        };
        
        let bc = blockchain.read().await;
        let active_validators = bc.get_active_validators();
        
        if active_validators.is_empty() {
            debug!("No active validators found in blockchain registry");
            return Ok(());
        }
        
        let validator_adapters: Vec<BlockchainValidatorAdapter> = active_validators
            .into_iter()
            .map(|v| BlockchainValidatorAdapter(v.clone()))
            .collect();

        let mut validator_manager = self.validator_manager.write().await;
        let (synced_count, skipped_count) = validator_manager
            .sync_from_validator_list(validator_adapters)
            .context("Failed to sync validators from blockchain")?;
        
        info!(
            "Validator sync complete: {} new validators registered, {} already registered",
            synced_count, skipped_count
        );

        // Also sync into the running consensus engine so remote votes/proposals verify against
        // the real on-chain validator set.
        {
            let mut engine_guard = self.consensus_engine.write().await;
            if let Some(engine) = engine_guard.as_mut() {
                let active_validators = bc.get_active_validators();
                let adapters_for_engine: Vec<BlockchainValidatorAdapter> = active_validators
                    .into_iter()
                    .map(|v| BlockchainValidatorAdapter(v.clone()))
                    .collect();
                let _ = engine
                    .sync_validators_from_list(adapters_for_engine)
                    .map_err(|e| anyhow::anyhow!("Consensus engine validator sync failed: {}", e))?;

                // If this node is a validator, set local identity and keypair so it can propose/vote.
                // Both must be set AFTER sync_validators_from_list because the engine checks
                // that the identity/keypair is registered in the validator set.
                if self.node_role.can_validate() {
                    let local_id = self.local_validator_identity.read().await.clone();
                    if let Some(id) = local_id {
                        engine
                            .set_local_validator_identity(id)
                            .map_err(|e| anyhow::anyhow!("Failed to set local validator identity: {}", e))?;

                        // Set keypair after identity — set_validator_keypair requires identity first.
                        let local_kp = self.local_validator_keypair.read().await.clone();
                        if let Some(kp) = local_kp {
                            if let Err(e) = engine.set_validator_keypair(kp) {
                                warn!("Could not set validator keypair (node will not propose/vote): {}", e);
                            }
                        }
                    } else {
                        warn!("Local validator identity not loaded; consensus will not propose/vote");
                    }
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn get_validator_manager(&self) -> Arc<RwLock<ValidatorManager>> {
        self.validator_manager.clone()
    }

    /// Pre-seed the ValidatorManager from `bootstrap_validators` config entries.
    ///
    /// This runs before on-chain ValidatorRegistration transactions are mined, giving
    /// each node knowledge of all expected validators so proposer rotation can begin
    /// immediately (preventing forks from simultaneous mining).
    ///
    /// Keys are derived deterministically from identity_id — no keys stored in config.
    /// When `sync_validators_from_blockchain()` runs after blocks are mined, real on-chain
    /// keys will replace these bootstrap entries.
    async fn seed_from_bootstrap_validators(&self) {
        if self.bootstrap_validators.is_empty() {
            return;
        }

        let adapters: Vec<BootstrapValidatorAdapter> = self.bootstrap_validators
            .iter()
            .map(|bv| BootstrapValidatorAdapter {
                identity_id: bv.identity_id.clone(),
                stake: bv.stake.max(1), // ensure non-zero for admission
                storage_provided: bv.storage_provided,
                commission_rate: (bv.commission_rate.min(100)) as u8,
            })
            .collect();

        let count = adapters.len();
        let mut vm = self.validator_manager.write().await;
        match vm.sync_from_validator_list(adapters) {
            Ok((added, skipped)) => {
                info!(
                    "🌱 Pre-seeded ValidatorManager with {} bootstrap validator(s) ({} added, {} already present)",
                    count, added, skipped
                );
            }
            Err(e) => {
                warn!("Failed to seed ValidatorManager from bootstrap config: {}", e);
            }
        }
    }
}

async fn load_local_validator_from_keystore() -> Result<(IdentityId, lib_crypto::KeyPair)> {
    use crate::keystore_names::{KeystorePrivateKey, NODE_IDENTITY_FILENAME, NODE_PRIVATE_KEY_FILENAME};
    use std::path::PathBuf;

    let keystore_dir = std::env::var("ZHTP_KEYSTORE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".zhtp").join("keystore")))
        .ok_or_else(|| anyhow::anyhow!("Could not determine keystore directory"))?;

    let node_identity_path = keystore_dir.join(NODE_IDENTITY_FILENAME);
    let node_key_path = keystore_dir.join(NODE_PRIVATE_KEY_FILENAME);

    let node_identity_json = tokio::fs::read_to_string(&node_identity_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", node_identity_path, e))?;
    let node_identity_val: serde_json::Value = serde_json::from_str(&node_identity_json)
        .map_err(|e| anyhow::anyhow!("Invalid JSON {:?}: {}", node_identity_path, e))?;
    let did = node_identity_val
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing .did in {:?}", node_identity_path))?;

    let identity_id = lib_identity::did::parse_did_to_identity_id(did)
        .map_err(|e| anyhow::anyhow!("Invalid DID in {:?}: {}", node_identity_path, e))?;

    let key_json = tokio::fs::read_to_string(&node_key_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read {:?}: {}", node_key_path, e))?;
    let ks: KeystorePrivateKey = serde_json::from_str(&key_json)
        .map_err(|e| anyhow::anyhow!("Invalid JSON {:?}: {}", node_key_path, e))?;

    if ks.dilithium_sk.is_empty() || ks.dilithium_pk.is_empty() {
        return Err(anyhow::anyhow!(
            "Keystore key {:?} missing dilithium_sk/dilithium_pk",
            node_key_path
        ));
    }

    // Consensus identity uses Dilithium public key bytes for signature verification.
    let public_key = lib_crypto::PublicKey::new(ks.dilithium_pk.clone());
    let private_key = lib_crypto::PrivateKey {
        dilithium_sk: ks.dilithium_sk,
        dilithium_pk: ks.dilithium_pk,
        kyber_sk: ks.kyber_sk,
        master_seed: ks.master_seed,
    };

    Ok((identity_id, lib_crypto::KeyPair { public_key, private_key }))
}

async fn handle_liveness_event(alert_manager: &AlertManager, event: ConsensusEvent) {
    match event {
        ConsensusEvent::ConsensusStalled {
            height,
            round,
            timed_out_validators,
            total_validators,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("round".to_string(), round.to_string());
            metadata.insert(
                "timed_out_validators".to_string(),
                timed_out_validators.len().to_string(),
            );
            metadata.insert("total_validators".to_string(), total_validators.to_string());

            let alert = Alert {
                id: format!("consensus-stalled-{}-{}", height, round),
                level: AlertLevel::Critical,
                title: "Consensus stalled".to_string(),
                message: format!(
                    "Consensus stalled at height {} round {} ({} of {} validators timed out)",
                    height,
                    round,
                    timed_out_validators.len(),
                    total_validators
                ),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        ConsensusEvent::ConsensusRecovered { height, round, timestamp } => {
            let mut metadata = HashMap::new();
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("round".to_string(), round.to_string());

            let alert = Alert {
                id: format!("consensus-recovered-{}-{}", height, round),
                level: AlertLevel::Info,
                title: "Consensus recovered".to_string(),
                message: format!("Consensus recovered at height {} round {}", height, round),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        ConsensusEvent::ModeTransitionToBft {
            validator_count,
            height,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("validator_count".to_string(), validator_count.to_string());
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("mode".to_string(), "BFT".to_string());

            let alert = Alert {
                id: format!("consensus-mode-bft-{}", height),
                level: AlertLevel::Info,
                title: "BFT consensus activated".to_string(),
                message: format!(
                    "Network transitioned to BFT consensus mode with {} validators at height {}",
                    validator_count, height
                ),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        ConsensusEvent::ModeTransitionToBootstrap {
            validator_count,
            min_required,
            height,
            timestamp,
        } => {
            let mut metadata = HashMap::new();
            metadata.insert("validator_count".to_string(), validator_count.to_string());
            metadata.insert("min_required".to_string(), min_required.to_string());
            metadata.insert("height".to_string(), height.to_string());
            metadata.insert("mode".to_string(), "Bootstrap".to_string());

            let alert = Alert {
                id: format!("consensus-mode-bootstrap-{}", height),
                level: AlertLevel::Warning,
                title: "Network degraded to bootstrap mode".to_string(),
                message: format!(
                    "Network degraded to bootstrap mode at height {} ({} validators, need ≥{} for BFT)",
                    height, validator_count, min_required
                ),
                source: "consensus".to_string(),
                timestamp,
                metadata,
            };

            let _ = alert_manager.trigger_alert(alert).await;
        }
        _ => {}
    }
}

#[async_trait::async_trait]
impl Component for ConsensusComponent {
    fn id(&self) -> ComponentId {
        ComponentId::Consensus
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn start(&self) -> Result<()> {
        info!("Starting consensus component with lib-consensus implementation...");
        
        *self.status.write().await = ComponentStatus::Starting;
        
        // Check if this node can participate in consensus validation
        // Only FullValidator nodes should run the consensus engine
        if !self.node_role.can_validate() {
            let role_desc = match &*self.node_role {
                crate::runtime::node_runtime::NodeRole::Observer => "observer (verifies blocks, no voting)",
                crate::runtime::node_runtime::NodeRole::LightNode => "light (trusts validators)",
                _ => "non-validator",
            };
            info!(
                "ℹ️ Node type {:?} does not participate in consensus - running as {} node",
                *self.node_role,
                role_desc
            );
            // Node starts successfully but skips consensus engine
            *self.status.write().await = ComponentStatus::Running;
            return Ok(());
        }

        info!("✓ Node role {:?} can validate - starting consensus engine", *self.node_role);

        // Pre-seed ValidatorManager from bootstrap_validators config.
        // This enables proposer rotation before on-chain ValidatorRegistration txs are mined,
        // preventing simultaneous mining / fork races on startup.
        self.seed_from_bootstrap_validators().await;

        let mut config = ConsensusConfig::default();

        // Keep this node's consensus parameters aligned with zhtp configuration.
        // Determinism requirement: all validators on the same chain must share these values.
        config.min_stake = self.min_stake;
        // Storage is optional for validators in zhtp; do not block consensus on storage capacity.
        config.min_storage = 0;
        // Allow non-mainnet to run with <4 validators while still enforcing real signatures.
        config.development_mode = !matches!(self.environment, crate::config::Environment::Mainnet);
        if config.development_mode {
            info!("🔧 Development mode enabled - single validator consensus allowed for testing");
            info!("   Production deployment requires minimum 4 validators for BFT");
        } else {
            info!("🛡️ Production mode: Full consensus validation required (minimum 4 validators for BFT)");
        }

        // Create broadcaster - use ConsensusMeshBroadcaster if mesh router is available,
        // otherwise fall back to NoOpBroadcaster (single-node mode)
        let broadcaster: Arc<dyn ConsensusMessageBroadcaster> =
            match get_global_mesh_router().await {
                Ok(mesh_router) => {
                    info!("🌐 Mesh router available - enabling multi-node consensus broadcasting");
                    Arc::new(ConsensusMeshBroadcaster::new(mesh_router))
                }
                Err(e) => {
                    warn!(
                        "⚠️ Mesh router not available: {} - consensus will run in single-node mode",
                        e
                    );
                    Arc::new(NoOpBroadcaster)
                }
            };

        let mut consensus_engine = lib_consensus::init_consensus(config, broadcaster)?;
        let (liveness_tx, mut liveness_rx) = tokio::sync::mpsc::unbounded_channel();
        consensus_engine.set_liveness_event_sender(liveness_tx);

        // Create consensus message channel for receiving ValidatorMessages from the network
        // Channel size of 256 provides buffer for burst message handling
        let (consensus_msg_tx, consensus_msg_rx) = tokio::sync::mpsc::channel::<ValidatorMessage>(256);
        consensus_engine.set_message_receiver(consensus_msg_rx);

        // Load the persistent local validator signing keypair from the keystore.
        // The keypair is stored on self; it will be passed to the consensus engine later in
        // sync_validators_from_blockchain(), after the validator set is populated, because
        // set_validator_keypair() requires the identity to be registered in the validator set.
        let (local_validator_id, local_validator_keypair) = load_local_validator_from_keystore().await?;

        // Clone for ValidatorProtocol middleware before moving into self
        let vp_keypair = local_validator_keypair.clone();
        let vp_identity = local_validator_id.clone();

        *self.local_validator_identity.write().await = Some(local_validator_id);
        *self.local_validator_keypair.write().await = Some(local_validator_keypair);

        // Wire ValidatorProtocol as security middleware between network and consensus engine
        //
        // Message flow:
        //   Network (QUIC) → raw_validator_msg channel → ValidatorProtocol.handle_message()
        //     → verify signature → consensus_msg_tx → ConsensusEngine
        //
        // Outgoing (via ValidatorProtocol.broadcast_*):
        //   ValidatorProtocol → sign → QuicValidatorTransport → QUIC mesh
        if let Ok(mesh_router) = get_global_mesh_router().await {
            // Create discovery protocol for signature verification lookups
            let discovery = Arc::new(ValidatorDiscoveryProtocol::new(3600));

            // Create ValidatorProtocol and wire it
            let mut validator_protocol = ValidatorProtocol::new(discovery, None);
            validator_protocol.set_validator_keypair(vp_keypair);
            validator_protocol.set_validator_identity(vp_identity).await;
            validator_protocol.set_consensus_forwarder(consensus_msg_tx.clone());
            validator_protocol.set_network_transport(Arc::new(QuicValidatorTransport::new(mesh_router.clone())));

            // Create raw validator message channel
            let (raw_msg_tx, mut raw_msg_rx) =
                tokio::sync::mpsc::channel::<lib_consensus::validators::ValidatorMessage>(256);

            // Wire raw message sender into the mesh message handler
            if let Some(quic_protocol) = mesh_router.quic_protocol.read().await.as_ref() {
                if let Some(handler) = quic_protocol.message_handler.as_ref() {
                    let mut h = handler.write().await;
                    h.set_raw_validator_message_sender(raw_msg_tx);
                    // Also keep direct consensus sender as fallback
                    h.set_consensus_message_sender(consensus_msg_tx.clone());
                    info!("🔗 ValidatorProtocol middleware wired to mesh message handler");
                } else {
                    warn!("QUIC message handler not available - consensus messages won't be received from network");
                }
            } else {
                warn!("QUIC protocol not available - consensus messages won't be received from network");
            }

            // Spawn middleware task: reads raw messages, verifies via ValidatorProtocol, forwards to consensus
            tokio::spawn(async move {
                info!("🛡️ ValidatorProtocol middleware task started");
                while let Some(msg) = raw_msg_rx.recv().await {
                    if let Err(e) = validator_protocol.handle_message(msg).await {
                        // Verification failure: log but don't crash the middleware
                        warn!("ValidatorProtocol rejected message: {}", e);
                    }
                }
                info!("ValidatorProtocol middleware task exited (channel closed)");
            });
        } else {
            warn!("Mesh router not available - consensus messages won't be received from network");
            // No mesh router, but still wire direct consensus sender if available
        }

        // **Start-order independent alert wiring**
        //
        // CRITICAL: Always spawn the alert receiver task, even if monitoring is not running yet.
        // This prevents the problem where:
        // 1. Consensus starts before monitoring
        // 2. No global manager exists → receiver task is not spawned
        // 3. Monitoring starts later
        // 4. Liveness events are dropped silently (no receiver to deliver them)
        //
        // Solution: Always create the receiver. At each event, resolve the manager:
        // - If monitoring is running: emit alert
        // - If not: drop alert and log at ERROR level (not WARN - these are critical events)
        //
        // This makes alert delivery robust to start order and monitoring restarts.
        tokio::spawn(async move {
            let mut dropped_events = Vec::new();
            let mut drop_warning_emitted = false;

            while let Some(event) = liveness_rx.recv().await {
                if let Some(alert_manager) = crate::monitoring::get_global_alert_manager() {
                    // Manager exists now - emit alert (works even if monitoring restarted)
                    // Also catch up on any previously dropped events
                    if !dropped_events.is_empty() {
                        error!(
                            "Consensus recovery: {} liveness events were dropped while monitoring was unavailable",
                            dropped_events.len()
                        );
                        dropped_events.clear();
                        drop_warning_emitted = false;
                    }

                    handle_liveness_event(&alert_manager, event).await;
                } else {
                    // CRITICAL: No manager - this is a Byzantine fault event that cannot be delivered
                    // Log at ERROR level because this is a consensus-critical failure
                    dropped_events.push(event.clone());

                    if !drop_warning_emitted {
                        error!(
                            "CRITICAL: Consensus liveness alert cannot be delivered - monitoring system not started. \
                             Byzantine faults occurring now will not be reported to operators."
                        );
                        drop_warning_emitted = true;
                    }
                }
            }
        });
        
        info!("Consensus engine initialized with hybrid PoS");
        info!("Validator management ready");
        info!("Byzantine fault tolerance active");

        // Wire blockchain provider for real block data in proposals
        // Uses the same slot that set_blockchain() populates
        let blockchain_adapter = ConsensusBlockchainAdapter::new(self.blockchain.clone());
        consensus_engine.set_blockchain_provider(Arc::new(blockchain_adapter));
        info!("📦 Blockchain provider wired to consensus engine");

        // Wire block commit callback for BFT-finalized blocks
        // This is the critical bridge that commits blocks when BFT achieves 2/3+1 votes
        let block_committer = ConsensusBlockCommitter::new(
            self.blockchain.clone(),
            self.environment.clone(),
        );
        consensus_engine.set_block_commit_callback(Arc::new(block_committer));
        info!("🔗 Block commit callback wired to consensus engine");

        // Store reference to engine (for validator manager access)
        // Note: The engine is moved into the consensus loop task
        *self.consensus_engine.write().await = None; // Engine is now owned by the loop task

        // Spawn the consensus loop as a background task
        // This is the main BFT state machine driver
        tokio::spawn(async move {
            info!("🚀 Starting BFT consensus loop...");
            match consensus_engine.run_consensus_loop().await {
                Ok(()) => {
                    info!("Consensus loop exited normally");
                }
                Err(e) => {
                    error!("Consensus loop exited with error: {}", e);
                }
            }
        });

        // Spawn periodic validator re-sync background task.
        // Every 10 s, refresh ValidatorManager from blockchain.validator_registry so
        // newly-mined ValidatorRegistration transactions are picked up without restart.
        {
            let blockchain_slot = self.blockchain.clone();
            let validator_manager = self.validator_manager.clone();
            let consensus_engine = self.consensus_engine.clone();
            let local_id = self.local_validator_identity.clone();
            let local_kp = self.local_validator_keypair.clone();
            let can_validate = self.node_role.can_validate();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                interval.tick().await; // skip first immediate tick
                loop {
                    interval.tick().await;
                    let slot = blockchain_slot.read().await;
                    let blockchain_arc = match slot.as_ref() {
                        Some(bc) => bc.clone(),
                        None => continue,
                    };
                    drop(slot);

                    // Clone validators out of the read guard so the guard can be dropped
                    let active_validators: Vec<lib_blockchain::ValidatorInfo> = {
                        let bc = blockchain_arc.read().await;
                        bc.get_active_validators()
                            .into_iter()
                            .map(|v| v.clone())
                            .collect()
                    };

                    if active_validators.is_empty() {
                        continue;
                    }

                    let adapters: Vec<BlockchainValidatorAdapter> = active_validators
                        .iter()
                        .map(|v| BlockchainValidatorAdapter(v.clone()))
                        .collect();

                    let result = {
                        let mut vm = validator_manager.write().await;
                        vm.sync_from_validator_list(adapters)
                    };
                    match result {
                        Ok((added, _)) if added > 0 => {
                            info!("🔄 Periodic validator sync: {} new validator(s) added from blockchain", added);
                            // Also sync into running consensus engine
                            let mut engine_guard = consensus_engine.write().await;
                            if let Some(engine) = engine_guard.as_mut() {
                                let adapters2: Vec<BlockchainValidatorAdapter> = active_validators
                                    .iter()
                                    .map(|v| BlockchainValidatorAdapter(v.clone()))
                                    .collect();
                                if let Err(e) = engine.sync_validators_from_list(adapters2) {
                                    warn!("Periodic consensus engine validator sync failed: {}", e);
                                } else if can_validate {
                                    if let Some(id) = local_id.read().await.clone() {
                                        let _ = engine.set_local_validator_identity(id);
                                        if let Some(kp) = local_kp.read().await.clone() {
                                            let _ = engine.set_validator_keypair(kp);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            });
        }

        *self.start_time.write().await = Some(Instant::now());
        *self.status.write().await = ComponentStatus::Running;

        info!("🗳️ BFT consensus loop started - listening for validator messages");
        info!("Consensus component started with consensus mechanisms");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping consensus component...");
        *self.status.write().await = ComponentStatus::Stopping;
        *self.consensus_engine.write().await = None;
        *self.start_time.write().await = None;
        *self.status.write().await = ComponentStatus::Stopped;
        info!("Consensus component stopped");
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
                debug!("Consensus component health check");
                Ok(())
            }
            _ => {
                debug!("Consensus component received message: {:?}", message);
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

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[tokio::test]
    async fn test_liveness_alert_bridge_stalled() {
        let alert_manager = AlertManager::new()
            .await
            .expect("Failed to create alert manager");
        alert_manager.start().await.expect("Failed to start alert manager");

        let event = ConsensusEvent::ConsensusStalled {
            height: 42,
            round: 7,
            timed_out_validators: vec![Hash::from_bytes(&[1u8; 32])],
            total_validators: 4,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        handle_liveness_event(&alert_manager, event).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let alerts = alert_manager
            .get_recent_alerts(1)
            .await
            .expect("Failed to fetch alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "Consensus stalled");
        assert_eq!(alerts[0].level, AlertLevel::Critical);
    }
}
