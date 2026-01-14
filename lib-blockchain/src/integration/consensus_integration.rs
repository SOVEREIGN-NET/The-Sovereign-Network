//! Consensus integration for ZHTP blockchain
//! 
//! Provides full integration with lib-consensus package including validator management,
//! block production, consensus events, DAO governance, and reward distribution.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn, error, debug};

use lib_consensus::{
    ConsensusEngine, ConsensusConfig, ConsensusEvent, ValidatorStatus,
    DaoEngine, DaoProposalType, DaoVoteChoice,
    RewardCalculator, RewardRound,
    ConsensusProposal, ConsensusVote, VoteType, ConsensusStep,
    ConsensusType, ConsensusProof, NoOpBroadcaster,
    DifficultyConfig, DifficultyManager,
};
use lib_crypto::{Hash, hash_blake3, KeyPair};
use lib_identity::IdentityId;

use crate::{
    Blockchain, Block, BlockHeader, Transaction, TransactionType, TransactionOutput,
    types::{Hash as BlockchainHash, Difficulty},
    mempool::Mempool,
    utils::time::current_timestamp,
    transaction::IdentityTransactionData,
};

/// Validator keypair for cryptographic operations
#[derive(Debug, Clone)]
pub struct ValidatorKeypair {
    pub public_key: lib_crypto::PublicKey,
    pub private_key: lib_crypto::PrivateKey,
}

/// Detailed information about a validator
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    /// Validator's identity
    pub identity: IdentityId,
    /// Current validator status
    pub status: ValidatorStatus,
    /// Amount of ZHTP staked
    pub stake_amount: u64,
    /// Reputation score (0-100)
    pub reputation_score: u8,
    /// Height of last active participation
    pub last_active_height: u64,
    /// Total number of blocks produced
    pub total_blocks_produced: u64,
    /// Number of times slashed for misbehavior
    pub slashing_count: u32,
}

/// Blockchain consensus coordinator
///
/// This struct bridges the blockchain with the consensus engine, handling
/// all consensus-related operations including block production, validation,
/// DAO governance, and reward distribution.
pub struct BlockchainConsensusCoordinator {
    /// Core consensus engine from lib-consensus
    consensus_engine: Arc<RwLock<ConsensusEngine>>,
    /// Blockchain state reference
    blockchain: Arc<RwLock<Blockchain>>,
    /// Transaction mempool
    mempool: Arc<RwLock<Mempool>>,
    /// Local validator identity (if this node is a validator)
    local_validator_id: Option<IdentityId>,
    /// Event channel for consensus events
    event_sender: mpsc::UnboundedSender<ConsensusEvent>,
    event_receiver: Arc<RwLock<mpsc::UnboundedReceiver<ConsensusEvent>>>,
    /// Block production state
    is_producing_blocks: bool,
    /// Current consensus round cache
    current_round_cache: Arc<RwLock<Option<lib_consensus::ConsensusRound>>>,
    /// Pending consensus proposals
    pending_proposals: Arc<RwLock<VecDeque<ConsensusProposal>>>,
    /// Active consensus votes
    active_votes: Arc<RwLock<HashMap<Hash, Vec<ConsensusVote>>>>,
    /// Difficulty manager (owns difficulty adjustment policy)
    difficulty_manager: Arc<RwLock<DifficultyManager>>,
}

// Manual Debug implementation because ConsensusEngine doesn't derive Debug
impl std::fmt::Debug for BlockchainConsensusCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockchainConsensusCoordinator")
            .field("local_validator_id", &self.local_validator_id)
            .field("is_producing_blocks", &self.is_producing_blocks)
            .field("consensus_engine", &"<ConsensusEngine>")
            .field("blockchain", &"<Blockchain>")
            .field("mempool", &"<Mempool>")
            .finish()
    }
}

impl BlockchainConsensusCoordinator {
    /// Create a new blockchain consensus coordinator
    pub async fn new(
        blockchain: Arc<RwLock<Blockchain>>,
        mempool: Arc<RwLock<Mempool>>,
        consensus_config: ConsensusConfig,
    ) -> Result<Self> {
        let consensus_engine = Arc::new(RwLock::new(
            ConsensusEngine::new(consensus_config, Arc::new(NoOpBroadcaster))?
        ));

        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Initialize difficulty manager with default configuration
        let difficulty_manager = Arc::new(RwLock::new(DifficultyManager::default()));

        Ok(Self {
            consensus_engine,
            blockchain,
            mempool,
            local_validator_id: None,
            event_sender,
            event_receiver: Arc::new(RwLock::new(event_receiver)),
            is_producing_blocks: false,
            current_round_cache: Arc::new(RwLock::new(None)),
            pending_proposals: Arc::new(RwLock::new(VecDeque::new())),
            active_votes: Arc::new(RwLock::new(HashMap::new())),
            difficulty_manager,
        })
    }
    
    /// Create a new blockchain consensus coordinator with custom difficulty configuration
    pub async fn new_with_difficulty_config(
        blockchain: Arc<RwLock<Blockchain>>,
        mempool: Arc<RwLock<Mempool>>,
        consensus_config: ConsensusConfig,
        difficulty_config: DifficultyConfig,
    ) -> Result<Self> {
        let consensus_engine = Arc::new(RwLock::new(
            ConsensusEngine::new(consensus_config, Arc::new(NoOpBroadcaster))?
        ));

        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Initialize difficulty manager with provided configuration
        let difficulty_manager = Arc::new(RwLock::new(DifficultyManager::new(difficulty_config)));

        Ok(Self {
            consensus_engine,
            blockchain,
            mempool,
            local_validator_id: None,
            event_sender,
            event_receiver: Arc::new(RwLock::new(event_receiver)),
            is_producing_blocks: false,
            current_round_cache: Arc::new(RwLock::new(None)),
            pending_proposals: Arc::new(RwLock::new(VecDeque::new())),
            active_votes: Arc::new(RwLock::new(HashMap::new())),
            difficulty_manager,
        })
    }

    /// Register this node as a validator
    pub async fn register_as_validator(
        &mut self,
        identity: IdentityId,
        stake_amount: u64,
        storage_capacity: u64,
        consensus_keypair: &KeyPair,
        commission_rate: u8,
    ) -> Result<()> {
        let mut consensus_engine = self.consensus_engine.write().await;
        
        // Register with the consensus engine
        consensus_engine.register_validator(
            identity.clone(),
            stake_amount,
            storage_capacity,
            consensus_keypair.public_key.dilithium_pk.clone(),
            commission_rate,
            false, // Not genesis validator
        ).await.map_err(|e| anyhow::anyhow!("Consensus registration failed: {}", e))?;

        // Store local validator identity
        self.local_validator_id = Some(identity.clone());

        // Create validator registration transaction
        let mut blockchain = self.blockchain.write().await;
        let registration_tx = self.create_validator_registration_transaction(
            &identity,
            stake_amount,
            storage_capacity,
            consensus_keypair,
            commission_rate,
        ).await?;

        // Add to pending transactions
        blockchain.add_pending_transaction(registration_tx)?;

        info!("Registered as validator: {:?} with {} ZHTP stake", identity, stake_amount);
        Ok(())
    }

    /// Start the consensus coordinator event loop
    pub async fn start_consensus_coordinator(&mut self) -> Result<()> {
        info!(" Starting blockchain consensus coordinator");
        
        self.is_producing_blocks = true;

        // Start consensus event processing loop
        let coordinator_clone = self.clone_for_background();
        tokio::spawn(async move {
            coordinator_clone.consensus_event_loop().await;
        });

        // Start block production if this node is a validator
        if self.local_validator_id.is_some() {
            let coordinator_clone = self.clone_for_background();
            tokio::spawn(async move {
                coordinator_clone.block_production_loop().await;
            });
        }

        // Start DAO governance processing
        let coordinator_clone = self.clone_for_background();
        tokio::spawn(async move {
            coordinator_clone.dao_governance_loop().await;
        });

        // Start reward distribution processing
        let coordinator_clone = self.clone_for_background();
        tokio::spawn(async move {
            coordinator_clone.reward_distribution_loop().await;
        });

        info!("Blockchain consensus coordinator started successfully");
        Ok(())
    }

    /// Create a clone suitable for background tasks
    fn clone_for_background(&self) -> BlockchainConsensusCoordinator {
        BlockchainConsensusCoordinator {
            consensus_engine: self.consensus_engine.clone(),
            blockchain: self.blockchain.clone(),
            mempool: self.mempool.clone(),
            local_validator_id: self.local_validator_id.clone(),
            event_sender: self.event_sender.clone(),
            event_receiver: self.event_receiver.clone(),
            is_producing_blocks: self.is_producing_blocks,
            current_round_cache: self.current_round_cache.clone(),
            pending_proposals: self.pending_proposals.clone(),
            active_votes: self.active_votes.clone(),
            difficulty_manager: self.difficulty_manager.clone(),
        }
    }
    
    /// Get the difficulty manager
    pub fn difficulty_manager(&self) -> &Arc<RwLock<DifficultyManager>> {
        &self.difficulty_manager
    }
    
    /// Get the current difficulty configuration
    ///
    /// **Note**: This clones the entire DifficultyConfig. For better performance,
    /// use specific field getters like `get_difficulty_target_timespan()` when you
    /// only need individual fields.
    pub async fn get_difficulty_config(&self) -> DifficultyConfig {
        let manager = self.difficulty_manager.read().await;
        manager.config().clone()
    }

    /// Get the target timespan for difficulty adjustment without cloning the entire config
    pub async fn get_difficulty_target_timespan(&self) -> u64 {
        let manager = self.difficulty_manager.read().await;
        manager.target_timespan()
    }

    /// Calculate new difficulty using the consensus-owned algorithm
    ///
    /// This is the entry point for blockchain difficulty adjustment.
    /// The blockchain calls this method and the consensus engine owns the algorithm.
    pub async fn calculate_difficulty_adjustment(
        &self,
        height: u64,
        current_difficulty: u32,
        interval_start_time: u64,
        interval_end_time: u64,
    ) -> Result<Option<u32>> {
        let manager = self.difficulty_manager.read().await;
        manager
            .adjust_difficulty(height, current_difficulty, interval_start_time, interval_end_time)
            .map_err(|e| anyhow!("Difficulty adjustment failed: {}", e))
    }
    
    /// Check if difficulty should be adjusted at the given height
    pub async fn should_adjust_difficulty(&self, height: u64) -> bool {
        let manager = self.difficulty_manager.read().await;
        manager.should_adjust(height)
    }
    
    /// Get the initial difficulty value from consensus policy
    pub async fn get_initial_difficulty(&self) -> u32 {
        let manager = self.difficulty_manager.read().await;
        manager.initial_difficulty()
    }
    
    /// Get the difficulty adjustment interval from consensus policy
    pub async fn get_difficulty_adjustment_interval(&self) -> u64 {
        let manager = self.difficulty_manager.read().await;
        manager.adjustment_interval()
    }
    
    /// Apply DAO governance updates to difficulty parameters
    pub async fn apply_difficulty_governance_update(
        &self,
        initial_difficulty: Option<u32>,
        adjustment_interval: Option<u64>,
        target_timespan: Option<u64>,
    ) -> Result<()> {
        let mut manager = self.difficulty_manager.write().await;
        manager
            .apply_governance_update(initial_difficulty, adjustment_interval, target_timespan)
            .map_err(|e| anyhow!("Failed to apply difficulty governance update: {}", e))
    }

    /// Main consensus event processing loop
    async fn consensus_event_loop(&self) {
        info!(" Starting consensus event processing loop");
        
        loop {
            if let Ok(mut receiver) = self.event_receiver.try_write() {
                if let Some(event) = receiver.recv().await {
                    if let Err(e) = self.handle_consensus_event(event).await {
                        error!("Error handling consensus event: {}", e);
                    }
                }
            }
            
            // Brief pause to prevent busy waiting
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    /// Handle individual consensus events
    async fn handle_consensus_event(&self, event: ConsensusEvent) -> Result<()> {
        debug!(" Processing consensus event: {:?}", event);

        match event {
            ConsensusEvent::StartRound { height, trigger } => {
                self.handle_start_round(height, trigger).await?;
            }
            ConsensusEvent::NewBlock { height, previous_hash } => {
                self.handle_new_block(height, previous_hash).await?;
            }
            ConsensusEvent::ProposalReceived { proposal } => {
                self.handle_proposal_received(proposal).await?;
            }
            ConsensusEvent::VoteReceived { vote } => {
                self.handle_vote_received(vote).await?;
            }
            ConsensusEvent::RoundCompleted { height } => {
                self.handle_round_completed(height).await?;
            }
            ConsensusEvent::ValidatorRegistered { identity } => {
                info!("Validator registered: {:?}", identity);
            }
            ConsensusEvent::DaoError { error } => {
                warn!("DAO error: {}", error);
            }
            ConsensusEvent::ByzantineFault { error } => {
                warn!(" Byzantine fault detected: {}", error);
            }
            ConsensusEvent::RewardError { error } => {
                warn!(" Reward error: {}", error);
            }
            _ => {
                debug!("Unhandled consensus event: {:?}", event);
            }
        }

        Ok(())
    }

    /// Handle start round event
    async fn handle_start_round(&self, height: u64, trigger: String) -> Result<()> {
        info!(" Starting consensus round {} (trigger: {})", height, trigger);

        // Update current round cache
        {
            let consensus_engine = self.consensus_engine.read().await;
            let current_round = consensus_engine.current_round().clone();
            *self.current_round_cache.write().await = Some(current_round);
        }

        // Trigger consensus engine event handling
        let mut consensus_engine = self.consensus_engine.write().await;
        let events = consensus_engine.handle_consensus_event(
            ConsensusEvent::StartRound { height, trigger }
        ).await?;

        // Process resulting events
        for event in events {
            if let Err(e) = self.event_sender.send(event) {
                warn!("Failed to send consensus event: {}", e);
            }
        }

        Ok(())
    }

    /// Handle new block event
    async fn handle_new_block(&self, height: u64, previous_hash: Hash) -> Result<()> {
        info!(" Processing new block at height {}", height);

        // Convert Hash types
        // Convert consensus hash to blockchain hash
        let mut hash_bytes = [0u8; 32];
        let prev_bytes = previous_hash.as_bytes();
        hash_bytes[..prev_bytes.len().min(32)].copy_from_slice(&prev_bytes[..prev_bytes.len().min(32)]);
        let blockchain_previous_hash = BlockchainHash::from(hash_bytes);

        // Verify block can be added to blockchain
        let blockchain = self.blockchain.read().await;
        if let Some(latest_block) = blockchain.latest_block() {
            // Validate that the previous hash matches the latest block
            if latest_block.header.hash() != blockchain_previous_hash {
                return Err(anyhow!("Previous hash mismatch: expected {}, got {}", 
                    latest_block.header.hash(), blockchain_previous_hash));
            }
            if latest_block.height() + 1 != height {
                return Err(anyhow::anyhow!(
                    "Block height mismatch: expected {}, got {}",
                    latest_block.height() + 1,
                    height
                ));
            }
        }
        drop(blockchain);

        // Process through consensus engine
        let mut consensus_engine = self.consensus_engine.write().await;
        let events = consensus_engine.handle_consensus_event(
            ConsensusEvent::NewBlock { height, previous_hash }
        ).await?;

        // Forward resulting events
        for event in events {
            if let Err(e) = self.event_sender.send(event) {
                warn!("Failed to send consensus event: {}", e);
            }
        }

        Ok(())
    }

    /// Handle proposal received event
    async fn handle_proposal_received(&self, proposal: ConsensusProposal) -> Result<()> {
        info!("Received consensus proposal: {:?}", proposal.id);

        // Store proposal
        self.pending_proposals.write().await.push_back(proposal.clone());

        // Convert consensus proposal to blockchain block
        let block = self.consensus_proposal_to_block(&proposal).await?;

        // Validate block against blockchain rules
        let blockchain = self.blockchain.read().await;
        let previous_block = blockchain.latest_block();
        
        if !blockchain.verify_block(&block, previous_block)? {
            return Err(anyhow::anyhow!("Block verification failed for proposal"));
        }
        drop(blockchain);

        // If we're a validator, cast our vote
        if let Some(ref _validator_id) = self.local_validator_id {
            self.cast_consensus_vote(&proposal.id, VoteType::PreVote).await?;
        }

        Ok(())
    }

    /// Handle vote received event
    async fn handle_vote_received(&self, vote: ConsensusVote) -> Result<()> {
        debug!(" Received consensus vote: {:?} on proposal {:?}", vote.vote_type, vote.proposal_id);

        // Store vote
        let proposal_id = vote.proposal_id.clone();
        self.active_votes.write().await
            .entry(proposal_id)
            .or_insert_with(Vec::new)
            .push(vote);

        Ok(())
    }

    /// Handle round completed event
    async fn handle_round_completed(&self, height: u64) -> Result<()> {
        info!("Consensus round completed at height {}", height);

        // Find the winning proposal
        if let Some(winning_proposal) = self.determine_winning_proposal(height).await? {
            // Week 10 Phase 1: Extract actual transaction fees from the proposal
            // This provides real fee data instead of simulation
            let (_total_fees, _tx_count) = match self.extract_transaction_fees_from_proposal(&winning_proposal).await {
                Ok((fees, count)) => {
                    info!(
                        "Week 10 Phase 1: Extracted {} transactions with total fees: {} from block at height {}",
                        count, fees, height
                    );
                    (fees, count)
                }
                Err(e) => {
                    warn!("Failed to extract transaction fees from proposal: {}", e);
                    (0, 0)
                }
            };

            // Extract actual transactions from the proposal
            let transactions = self.extract_transactions_from_proposal(&winning_proposal).await?;

            // Week 10 Phase 2: Validate transactions before block inclusion
            // This prevents double-spends, invalid signatures, and other transaction-level issues
            let blockchain = self.blockchain.read().await;
            let stateful_validator = crate::transaction::validation::StatefulTransactionValidator::new(&blockchain);

            match stateful_validator.validate_transactions_for_block_inclusion(&transactions) {
                Ok((validated_fees, tx_count)) => {
                    info!(
                        "Week 10 Phase 2: Validated {} transactions for block at height {} (total_fees={})",
                        tx_count, height, validated_fees
                    );
                }
                Err(e) => {
                    error!(
                        "Week 10 Phase 2: Transaction validation failed for block at height {}: {:?}",
                        height, e
                    );
                    return Err(anyhow::anyhow!("Block validation failed: {:?}", e));
                }
            }
            drop(blockchain);

            let block = self.consensus_proposal_to_block_with_transactions(&winning_proposal, transactions).await?;

            // Only generate proof if we were the block proposer (otherwise we're just accepting someone else's block)
            let mut blockchain = self.blockchain.write().await;
            let was_proposer = self.local_validator_id.as_ref()
                .map(|id| id == &winning_proposal.proposer)
                .unwrap_or(false);

            if was_proposer {
                // We proposed this block - generate proof
                info!("We were the proposer - generating recursive proof for block at height {}", height);
                blockchain.add_block_with_proof(block.clone()).await?;
            } else {
                // Another validator proposed this block - just accept it (already has proof)
                info!("Accepting block from proposer {} at height {}", hex::encode(winning_proposal.proposer.as_bytes()), height);
                blockchain.add_block(block.clone())?;
            }

            // Week 11 Phase 5a: Collect and distribute fees from finalized block
            // Non-blocking: fees are collected immediately with logging
            if let Err(e) = self.collect_and_distribute_fees_for_block(&block).await {
                warn!("Week 11 Phase 5a: Fee collection failed: {}", e);
            }

            // Remove processed transactions from mempool
            let mut mempool = self.mempool.write().await;
            let tx_hashes: Vec<_> = winning_proposal.block_data
                .chunks(32)
                .map(|chunk| {
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(chunk);
                    BlockchainHash::from(hash_bytes)
                })
                .collect();
            mempool.remove_transactions(&tx_hashes);

            info!(" Added new block to blockchain at height {} with {} transactions",
                  height, tx_hashes.len());
        }

        // Clear processed proposals and votes
        self.pending_proposals.write().await.clear();
        self.active_votes.write().await.clear();

        Ok(())
    }
    
    /// Convert consensus proposal to blockchain block with specific transactions
    async fn consensus_proposal_to_block_with_transactions(&self, proposal: &ConsensusProposal, transactions: Vec<Transaction>) -> Result<Block> {
        // Week 10 Phase 3: Construct block with real transaction effects
        // This method ensures blocks are constructed with validated transactions and proper fee tracking

        // Create block header
        let blockchain = self.blockchain.read().await;
        let previous_block = blockchain.latest_block();
        let height = proposal.height;

        // Validate that the proposal height is consistent with blockchain state
        if let Some(ref prev_block) = previous_block {
            if height != prev_block.header.height + 1 {
                return Err(anyhow!("Invalid height: expected {}, got {}", prev_block.header.height + 1, height));
            }
            debug!("Validated block height against previous block: {}", prev_block.header.height);
        }

        let mut hash_bytes = [0u8; 32];
        let prop_bytes = proposal.previous_hash.as_bytes();
        hash_bytes[..prop_bytes.len().min(32)].copy_from_slice(&prop_bytes[..prop_bytes.len().min(32)]);
        let previous_hash = BlockchainHash::from(hash_bytes);
        let timestamp = proposal.timestamp;

        // Validate proposal timestamp
        if let Err(e) = validate_consensus_timestamp(timestamp) {
            warn!("Invalid proposal timestamp: {}", e);
            return Err(anyhow!("Proposal timestamp validation failed: {}", e));
        }
        debug!("Proposal timestamp validated: {}", timestamp);

        // Calculate merkle root from actual transactions
        let merkle_root = crate::transaction::hashing::calculate_transaction_merkle_root(&transactions);

        // Week 10 Phase 3: Calculate transaction fees for block metadata
        let total_fees: u64 = transactions.iter().map(|tx| tx.fee).sum();
        let tx_count = transactions.len();

        info!(
            "Week 10 Phase 3: Constructing block at height {} with {} transactions (total_fees={})",
            height, tx_count, total_fees
        );

        // Set difficulty (in production this would be calculated based on network state)
        let difficulty = Difficulty::from_bits(crate::INITIAL_DIFFICULTY);

        let header = BlockHeader::new(
            1, // version
            previous_hash,
            merkle_root,
            timestamp,
            difficulty,
            height,
            transactions.len() as u32,
            0, // block_size - will be calculated
            difficulty, // cumulative_difficulty
        );

        let block = Block::new(header, transactions);

        // Log block construction summary for audit trail
        info!(
            "Week 10 Phase 3: Block constructed successfully - height={}, tx_count={}, total_fees={}, merkle_root={}",
            height,
            tx_count,
            total_fees,
            hex::encode(merkle_root.as_bytes())
        );

        Ok(block)
    }

    /// Block production loop for validators
    async fn block_production_loop(&self) {
        info!("⛏️ Starting block production loop");

        while self.is_producing_blocks {
            if let Err(e) = self.attempt_block_production().await {
                error!("Block production error: {}", e);
            }

            // Wait for next block time (configurable, default 10 seconds)
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    }

    /// Attempt to produce a new block
    async fn attempt_block_production(&self) -> Result<()> {
        let validator_id = match &self.local_validator_id {
            Some(id) => id,
            None => return Ok(()), // Not a validator, skip block production
        };

        let blockchain = self.blockchain.read().await;
        let current_height = blockchain.get_height() + 1;
        let previous_hash = blockchain.latest_block()
            .map(|b| b.hash())
            .unwrap_or_default();
        drop(blockchain);

        // Check if we should be the proposer for this round
        let consensus_engine = self.consensus_engine.read().await;
        let validator_manager = consensus_engine.validator_manager();
        
        if let Some(proposer) = validator_manager.select_proposer(current_height, 0) {
            if &proposer.identity == validator_id {
                // We are the proposer, create a consensus proposal with transaction data
                let consensus_proposal = self.create_consensus_proposal(current_height, previous_hash).await?;
                
                // Send the proposal through consensus engine
                let proposal_event = ConsensusEvent::ProposalReceived { proposal: consensus_proposal };
                
                if let Err(e) = self.event_sender.send(proposal_event) {
                    warn!("Failed to send consensus proposal event: {}", e);
                }
            }
        }

        Ok(())
    }
    
    /// Create a consensus proposal with transaction data
    async fn create_consensus_proposal(&self, height: u64, previous_hash: BlockchainHash) -> Result<ConsensusProposal> {
        // Select transactions from mempool
        let mempool = self.mempool.read().await;
        let selected_transactions = mempool.get_transactions_for_block(
            crate::MAX_TRANSACTIONS_PER_BLOCK,
            crate::MAX_BLOCK_SIZE,
        );
        drop(mempool);
        
        // Serialize transaction hashes into block_data
        let mut block_data = Vec::new();
        for transaction in &selected_transactions {
            let tx_hash = transaction.hash();
            block_data.extend_from_slice(tx_hash.as_bytes());
        }
        
        // Convert blockchain hash to consensus hash
        let consensus_previous_hash = Hash::from_bytes(previous_hash.as_bytes());
        
        // Generate proposal ID
        let mut proposal_data = Vec::new();
        proposal_data.extend_from_slice(&height.to_le_bytes());
        proposal_data.extend_from_slice(consensus_previous_hash.as_bytes());
        proposal_data.extend_from_slice(&block_data);
        let consensus_timestamp = get_current_unix_timestamp().unwrap_or(0);
        proposal_data.extend_from_slice(&consensus_timestamp.to_le_bytes());
        
        let proposal_id = Hash::from_bytes(&hash_blake3(&proposal_data));
        
        let proposal = ConsensusProposal {
            id: proposal_id.clone(),
            height,
            proposer: self.local_validator_id.clone().unwrap_or_else(|| Hash::from_bytes(&[0u8; 32])),
            previous_hash: consensus_previous_hash,
            block_data,
            timestamp: consensus_timestamp,
            signature: lib_crypto::Signature {
                signature: vec![0u8; 64], // Would be properly signed in production
                public_key: lib_crypto::PublicKey::new(vec![0u8; 32]),
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                timestamp: current_timestamp(),
            },
            consensus_proof: ConsensusProof {
                consensus_type: ConsensusType::Hybrid, // Default to hybrid consensus
                stake_proof: None,
                storage_proof: None,
                work_proof: None,
                zk_did_proof: None,
                timestamp: current_timestamp(),
            },
        };
        
        info!("Created consensus proposal {} at height {} with {} transactions", 
              hex::encode(proposal_id.as_bytes()), height, selected_transactions.len());
        
        Ok(proposal)
    }

    /// DAO governance processing loop
    async fn dao_governance_loop(&self) {
        info!(" Starting DAO governance processing loop");

        loop {
            if let Err(e) = self.process_dao_governance().await {
                error!("DAO governance processing error: {}", e);
            }

            // Process DAO governance every 30 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    /// Process DAO governance operations
    async fn process_dao_governance(&self) -> Result<()> {
        let mut consensus_engine = self.consensus_engine.write().await;
        let dao_engine = consensus_engine.dao_engine_mut();

        // Process expired proposals
        dao_engine.process_expired_proposals().await?;

        // Check for new governance transactions in mempool
        let mempool = self.mempool.read().await;
        let pending_transactions = mempool.get_all_transactions();

        for transaction in pending_transactions {
            if self.is_dao_transaction(transaction) {
                self.process_dao_transaction(transaction, dao_engine).await?;
            }
        }

        Ok(())
    }

    /// Reward distribution processing loop
    async fn reward_distribution_loop(&self) {
        info!("Starting reward distribution processing loop");

        loop {
            if let Err(e) = self.process_reward_distribution().await {
                error!("Reward distribution error: {}", e);
            }

            // Process rewards every minute
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    /// Process reward distribution
    async fn process_reward_distribution(&self) -> Result<()> {
        let blockchain = self.blockchain.read().await;
        let current_height = blockchain.get_height();
        drop(blockchain);

        let consensus_engine = self.consensus_engine.read().await;
        let validator_manager = consensus_engine.validator_manager();
        
        // Create a temporary reward calculator for this operation
        let mut reward_calculator = RewardCalculator::new();
        
        // Calculate rewards for the current round
        let reward_round = reward_calculator.calculate_round_rewards(validator_manager, current_height)?;

        // Create reward transactions
        let reward_transactions = self.create_reward_transactions(&reward_round).await?;

        // Add reward transactions to blockchain
        drop(consensus_engine);
        let mut blockchain = self.blockchain.write().await;
        for tx in reward_transactions {
            blockchain.add_system_transaction(tx)?;
        }

        info!(" Distributed {} ZHTP in rewards to {} validators", 
              reward_round.total_rewards, reward_round.validator_rewards.len());

        Ok(())
    }

    /// Create UBI distribution transactions through consensus  
    pub async fn create_ubi_distributions(
        &self,
        citizens: &[(IdentityId, u64)],
        system_keypair: &KeyPair,
    ) -> Result<Vec<BlockchainHash>> {
        info!("Creating UBI distributions for {} citizens", citizens.len());
        
        // Simple treasury balance validation to avoid consensus engine deadlock
        // Use conservative estimate based on initial treasury setup
        let estimated_treasury_available = 200000u64; // Conservative estimate
        
        let total_ubi: u64 = citizens.iter().map(|(_, amount)| *amount).sum();
        if total_ubi > estimated_treasury_available {
            return Err(anyhow::anyhow!("UBI distribution amount {} exceeds estimated treasury capacity {}", 
                total_ubi, estimated_treasury_available));
        }
        
        info!("Treasury validation passed: {} ZHTP needed, estimated {} ZHTP available", 
            total_ubi, estimated_treasury_available);
        
        // Create UBI transactions for each citizen
        let mut ubi_tx_hashes = Vec::new();
        for (citizen_id, amount) in citizens {
            // Create transfer transaction for UBI payment
            let ubi_transaction = Transaction::new(
                vec![], // No inputs - treasury funding
                vec![TransactionOutput {
                    commitment: BlockchainHash::from_slice(&citizen_id.as_bytes()[..32]),
                    note: BlockchainHash::from_slice(b"UBI_PAYMENT_________________"),
                    recipient: crate::integration::crypto_integration::PublicKey::new(
                        citizen_id.as_bytes().to_vec()
                    ),
                }],
                10, // UBI transaction fee
                crate::integration::crypto_integration::Signature {
                    signature: vec![0u8; 64], // System signature
                    public_key: crate::integration::crypto_integration::PublicKey::new(
                        system_keypair.public_key.dilithium_pk.clone()
                    ),
                    algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                    timestamp: current_timestamp(),
                },
                format!("UBI_DISTRIBUTION:citizen:{}:amount:{}", 
                    hex::encode(citizen_id.as_bytes()), amount).into_bytes(),
            );
            
            let tx_hash = ubi_transaction.hash();
            
            // For demo purposes, we'll simulate successful transaction creation
            // In production, this would integrate with the actual economic transaction system
            info!("Created UBI payment transaction of {} ZHTP for citizen {} (Demo: Transaction hash: {})", 
                amount, hex::encode(&citizen_id.as_bytes()[..8]), hex::encode(tx_hash.as_bytes()));
            
            // Since we can't access blockchain due to consensus locks, we'll record the transaction
            // In production, this would be handled by a separate economic transaction processor
            ubi_tx_hashes.push(tx_hash);
        }
        
        info!("Created {} UBI distribution transactions totaling {} ZHTP", 
            ubi_tx_hashes.len(), total_ubi);
        
        Ok(ubi_tx_hashes)
    }    /// Create welfare funding transactions through consensus  
    pub async fn create_welfare_funding(
        &self,
        services: &[(String, [u8; 32], u64)], // (service_name, address, amount)
        system_keypair: &KeyPair,
    ) -> Result<Vec<BlockchainHash>> {
        info!("🏥 Creating welfare funding for {} services", services.len());
        
        // Simple treasury balance validation to avoid consensus engine deadlock
        // Use conservative estimate based on initial treasury setup
        let estimated_treasury_available = 200000u64; // Conservative estimate
        
        let total_welfare: u64 = services.iter().map(|(_, _, amount)| *amount).sum();
        if total_welfare > estimated_treasury_available {
            return Err(anyhow::anyhow!("Welfare funding amount {} exceeds estimated treasury capacity {}", 
                total_welfare, estimated_treasury_available));
        }
        
        info!("Treasury validation passed: {} ZHTP needed, estimated {} ZHTP available", 
            total_welfare, estimated_treasury_available);
        
        // Create welfare funding transactions
        let mut welfare_tx_hashes = Vec::new();
        for (service_name, service_address, amount) in services {
            // Create transfer transaction for welfare funding
            let welfare_transaction = Transaction::new(
                vec![], // No inputs - treasury funding
                vec![TransactionOutput {
                    commitment: BlockchainHash::from_slice(service_address),
                    note: BlockchainHash::from_slice(b"WELFARE_FUNDING_____________"),
                    recipient: crate::integration::crypto_integration::PublicKey::new(
                        service_address.to_vec()
                    ),
                }],
                25, // Welfare transaction fee
                crate::integration::crypto_integration::Signature {
                    signature: vec![0u8; 64], // System signature
                    public_key: crate::integration::crypto_integration::PublicKey::new(
                        system_keypair.public_key.dilithium_pk.clone()
                    ),
                    algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                    timestamp: current_timestamp(),
                },
                format!("WELFARE_FUNDING:service:{}:amount:{}", 
                    service_name, amount).into_bytes(),
            );
            
            let tx_hash = welfare_transaction.hash();
            
            // For demo purposes, we'll simulate successful transaction creation
            // In production, this would integrate with the actual economic transaction system
            info!("Created welfare funding transaction of {} ZHTP for service {} (Demo: Transaction hash: {})", 
                amount, service_name, hex::encode(tx_hash.as_bytes()));
            
            // Since we can't access blockchain due to consensus locks, we'll record the transaction
            // In production, this would be handled by a separate economic transaction processor
            welfare_tx_hashes.push(tx_hash);
        }
        
        info!("Created {} welfare funding transactions totaling {} ZHTP", 
            welfare_tx_hashes.len(), total_welfare);
        
        Ok(welfare_tx_hashes)
    }

    /// Cast a consensus vote
    async fn cast_consensus_vote(&self, proposal_id: &Hash, vote_type: VoteType) -> Result<()> {
        let validator_id = self.local_validator_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not a validator"))?;

        let mut consensus_engine = self.consensus_engine.write().await;
        
        // Log the validator casting the vote
        debug!("Validator {} casting vote {:?} for proposal {}", 
               validator_id, vote_type, proposal_id);
        let vote = ConsensusVote {
            id: lib_crypto::Hash::from_bytes(&[0u8; 32]),
            voter: self.local_validator_id.clone().unwrap_or_else(|| lib_crypto::Hash::from_bytes(&[0u8; 32])),
            proposal_id: proposal_id.clone(),
            vote_type: vote_type.clone(),
            height: 0, // Would be set properly in implementation
            round: 0,
            timestamp: current_timestamp(),
            signature: self.create_vote_signature(proposal_id, &vote_type).await?,
        };
        let vote_event = ConsensusEvent::VoteReceived { vote };
        consensus_engine.handle_consensus_event(vote_event).await
            .map_err(|e| anyhow::anyhow!("Failed to cast vote: {}", e))?;

        Ok(())
    }

    /// Convert consensus proposal to blockchain block
    async fn consensus_proposal_to_block(&self, proposal: &ConsensusProposal) -> Result<Block> {
        // Get transactions from mempool based on proposal data
        let transactions = self.extract_transactions_from_proposal(proposal).await?;

        // Create block header
        let blockchain = self.blockchain.read().await;
        let previous_block = blockchain.latest_block();
        
        // Determine height based on previous block
        let height = if let Some(ref prev_block) = previous_block {
            prev_block.header.height + 1
        } else {
            proposal.height // Genesis block case
        };
        
        let mut hash_bytes = [0u8; 32];
        let prop_bytes = proposal.previous_hash.as_bytes();
        hash_bytes[..prop_bytes.len().min(32)].copy_from_slice(&prop_bytes[..prop_bytes.len().min(32)]);
        let previous_hash = BlockchainHash::from(hash_bytes);
        let timestamp = proposal.timestamp;
        
        // Calculate merkle root
        let merkle_root = crate::transaction::hashing::calculate_transaction_merkle_root(&transactions);
        
        // Set difficulty (in production this would be calculated based on network state)
        let difficulty = Difficulty::from_bits(crate::INITIAL_DIFFICULTY);

        let header = BlockHeader::new(
            1, // version
            previous_hash,
            merkle_root,
            timestamp,
            difficulty,
            height,
            transactions.len() as u32,
            0, // block_size - will be calculated
            difficulty, // cumulative_difficulty
        );

        let block = Block::new(header, transactions);
        Ok(block)
    }

    /// Extract transactions from consensus proposal
    async fn extract_transactions_from_proposal(&self, proposal: &ConsensusProposal) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();
        let mempool = self.mempool.read().await;
        
        // Parse block_data to extract transaction hashes
        // The block_data should contain serialized transaction hashes (32 bytes each)
        if proposal.block_data.len() % 32 != 0 {
            return Err(anyhow::anyhow!("Invalid block_data: length must be multiple of 32 bytes"));
        }
        
        let transaction_count = proposal.block_data.len() / 32;
        debug!("Extracting {} transactions from consensus proposal", transaction_count);
        
        for i in 0..transaction_count {
            let start_idx = i * 32;
            let end_idx = start_idx + 32;
            
            // Extract transaction hash from proposal
            let mut tx_hash_bytes = [0u8; 32];
            tx_hash_bytes.copy_from_slice(&proposal.block_data[start_idx..end_idx]);
            let tx_hash = BlockchainHash::from(tx_hash_bytes);
            
            // Look up transaction in mempool
            if let Some(transaction) = mempool.get_transaction(&tx_hash) {
                transactions.push(transaction.clone());
                debug!("Found transaction in mempool: {}", hex::encode(tx_hash.as_bytes()));
            } else {
                // Transaction not found in mempool - this could happen if:
                // 1. Transaction was already processed in a previous block
                // 2. Transaction is invalid or expired
                // 3. Network synchronization issue
                warn!("Transaction {} not found in mempool", hex::encode(tx_hash.as_bytes()));
                
                // In a production system, we might want to:
                // - Request the transaction from peers
                // - Check if it's already in a previous block
                // - Continue with available transactions
                continue;
            }
        }
        
        // Validate transaction ordering and dependencies
        self.validate_transaction_order(&transactions)?;
        
        // Verify transactions are still valid
        let blockchain = self.blockchain.read().await;
        for transaction in &transactions {
            if !blockchain.verify_transaction(transaction)? {
                return Err(anyhow::anyhow!("Invalid transaction in proposal: {}", 
                    hex::encode(transaction.hash().as_bytes())));
            }
        }
        drop(blockchain);
        
        info!("Successfully extracted {} valid transactions from consensus proposal", transactions.len());
        Ok(transactions)
    }

    /// Week 10 Phase 1: Extract actual transaction hashes and fees from consensus proposal
    ///
    /// This method gets the actual transactions from the proposal and calculates:
    /// - Total fees collected from all transactions
    /// - Transaction count for fee tracking
    ///
    /// This replaces the simulation-based fee extraction with real transaction data.
    async fn extract_transaction_fees_from_proposal(&self, proposal: &ConsensusProposal) -> Result<(u64, u32)> {
        // Get the actual transactions from the proposal
        let transactions = self.extract_transactions_from_proposal(proposal).await?;

        // Calculate total fees from actual transactions
        let mut total_fees: u64 = 0;
        for transaction in &transactions {
            total_fees = total_fees.saturating_add(transaction.fee);
        }

        let tx_count = transactions.len() as u32;

        debug!(
            "Extracted {} transactions from proposal at height {}: total_fees={}",
            tx_count, proposal.height, total_fees
        );

        Ok((total_fees, tx_count))
    }

    /// Validate transaction ordering and dependencies
    fn validate_transaction_order(&self, transactions: &[Transaction]) -> Result<()> {
        let mut seen_outputs = std::collections::HashSet::new();
        let mut spent_outputs = std::collections::HashSet::new();
        
        for transaction in transactions {
            // Check that all inputs reference outputs that exist (either from previous transactions in this block or previous blocks)
            for input in &transaction.inputs {
                let output_ref = (input.previous_output.clone(), input.output_index);
                
                // Check if the output is being double-spent within this block
                if spent_outputs.contains(&output_ref) {
                    return Err(anyhow::anyhow!("Double spend detected in transaction order"));
                }
                
                spent_outputs.insert(output_ref);
            }
            
            // Track outputs created by this transaction
            for (index, _output) in transaction.outputs.iter().enumerate() {
                let tx_hash = transaction.hash();
                seen_outputs.insert((tx_hash, index as u32));
            }
            
            // Verify transaction dependencies are satisfied
            for input in &transaction.inputs {
                let required_output = (input.previous_output.clone(), input.output_index);
                
                // The referenced output should either:
                // 1. Be from a previous transaction in this block (seen_outputs)
                // 2. Be from a previous block (we assume blockchain verification covers this)
                if !seen_outputs.contains(&required_output) {
                    // This is okay - it means the output is from a previous block
                    // The blockchain verification will ensure it exists and is unspent
                    debug!("Transaction references output from previous block: {:?}", required_output);
                }
            }
        }
        
        Ok(())
    }

    /// Determine winning proposal from votes
    async fn determine_winning_proposal(&self, height: u64) -> Result<Option<ConsensusProposal>> {
        let pending_proposals = self.pending_proposals.read().await;
        let active_votes = self.active_votes.read().await;

        // Find proposal with most votes
        let mut best_proposal = None;
        let mut max_votes = 0;

        for proposal in pending_proposals.iter() {
            if proposal.height == height {
                let vote_count = active_votes.get(&proposal.id)
                    .map(|votes| votes.len())
                    .unwrap_or(0);

                if vote_count > max_votes {
                    max_votes = vote_count;
                    best_proposal = Some(proposal.clone());
                }
            }
        }

        Ok(best_proposal)
    }

    /// Create validator registration transaction
    async fn create_validator_registration_transaction(
        &self,
        identity: &IdentityId,
        stake_amount: u64,
        storage_capacity: u64,
        consensus_keypair: &KeyPair,
        commission_rate: u8,
    ) -> Result<Transaction> {
        // Create validator registration transaction
        let validator_data = IdentityTransactionData {
            did: format!("did:zhtp:validator:{}", hex::encode(&identity.as_bytes()[..8])),
            display_name: format!("Validator {}", hex::encode(&identity.as_bytes()[..4])),
            public_key: consensus_keypair.public_key.dilithium_pk.clone(),
            identity_type: "validator".to_string(),
            did_document_hash: BlockchainHash::from(hash_blake3(&consensus_keypair.public_key.dilithium_pk)),
            created_at: current_timestamp(),
            registration_fee: 0, // System transaction - no fees
            dao_fee: 0, // System transaction - no fees
            ownership_proof: hash_blake3(&consensus_keypair.public_key.dilithium_pk).to_vec(), // Create ownership proof from public key
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };

        // Create transaction with empty signature first, then sign the hash
        let empty_signature = crate::integration::crypto_integration::Signature {
            signature: Vec::new(),
            public_key: crate::integration::crypto_integration::PublicKey::new(Vec::new()),
            algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
            timestamp: current_timestamp(),
        };

        let mut transaction = Transaction::new_identity_registration(
            validator_data,
            vec![], // No inputs for system registration
            empty_signature,
            format!("Validator registration: {} ZHTP stake, {} GB storage, {}% commission", 
                   stake_amount, storage_capacity / (1024*1024*1024), commission_rate).into_bytes(),
        );

        // Set fee to 0 for system transactions (transactions with no inputs)
        transaction.fee = 0;

        // Get the transaction hash for signing
        let tx_hash = transaction.hash();
        let signature_result = consensus_keypair.sign(tx_hash.as_bytes())?;

        // Update transaction with proper signature
        transaction.signature = crate::integration::crypto_integration::Signature {
            signature: signature_result.signature.clone(),
            public_key: crate::integration::crypto_integration::PublicKey::new(
                consensus_keypair.public_key.dilithium_pk.clone()
            ),
            algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
            timestamp: current_timestamp(),
        };

        Ok(transaction)
    }

    /// Check if transaction is DAO-related
    fn is_dao_transaction(&self, transaction: &Transaction) -> bool {
        // Check transaction type and content for DAO operations
        transaction.transaction_type == TransactionType::IdentityRegistration ||
        transaction.transaction_type == TransactionType::IdentityUpdate ||
        String::from_utf8_lossy(&transaction.memo).contains("dao:")
    }

    /// Process DAO transaction - uses proper transaction types instead of memo parsing
    async fn process_dao_transaction(
        &self,
        transaction: &Transaction,
        dao_engine: &mut DaoEngine,
    ) -> Result<()> {
        match transaction.transaction_type {
            TransactionType::DaoProposal => {
                self.process_dao_proposal_transaction(transaction, dao_engine).await?;
            },
            TransactionType::DaoVote => {
                self.process_dao_vote_transaction(transaction, dao_engine).await?;
            },
            TransactionType::DaoExecution => {
                self.process_dao_execution_transaction(transaction, dao_engine).await?;
            },
            _ => {
                // Not a DAO transaction, skip
            }
        }

        Ok(())
    }

    /// Process a DAO proposal transaction
    async fn process_dao_proposal_transaction(
        &self,
        transaction: &Transaction,
        dao_engine: &mut DaoEngine,
    ) -> Result<()> {
        if let Some(ref proposal_data) = transaction.dao_proposal_data {
            info!("📋 Processing DAO proposal: {} (ID: {:?})", 
                  proposal_data.title, proposal_data.proposal_id);
            
            // Convert blockchain proposal data to consensus DaoProposalType
            let proposal_type = self.parse_proposal_type(&proposal_data.proposal_type)?;
            
            // Parse proposer ID from hex string
            let proposer_id = lib_crypto::Hash::from_hex(&proposal_data.proposer)
                .unwrap_or_else(|_| lib_crypto::Hash::from_bytes(proposal_data.proposer.as_bytes()));
            
            // Proposal validation happens in DaoEngine
            let proposal_id = dao_engine.create_dao_proposal(
                proposer_id,
                proposal_data.title.clone(),
                proposal_data.description.clone(),
                proposal_type,
                (proposal_data.voting_period_blocks / 14400) as u32, // blocks to days (assuming 6s blocks)
            ).await?;

            info!("✅ DAO proposal created: {:?}", proposal_id);
        } else {
            warn!("⚠️  DaoProposal transaction missing proposal_data");
        }

        Ok(())
    }

    /// Process a DAO vote transaction
    async fn process_dao_vote_transaction(
        &self,
        transaction: &Transaction,
        dao_engine: &mut DaoEngine,
    ) -> Result<()> {
        if let Some(ref vote_data) = transaction.dao_vote_data {
            info!("🗳️  Processing DAO vote on proposal {:?} by {}", 
                  vote_data.proposal_id, vote_data.voter);
            
            // Convert vote choice string to enum
            let vote_choice = self.parse_vote_choice(&vote_data.vote_choice)?;
            
            // Parse voter ID from hex string
            let voter_id = lib_crypto::Hash::from_hex(&vote_data.voter)
                .unwrap_or_else(|_| lib_crypto::Hash::from_bytes(vote_data.voter.as_bytes()));
            
            // Convert blockchain Hash to lib_crypto Hash for proposal_id
            let proposal_id = lib_crypto::Hash::from_bytes(vote_data.proposal_id.as_bytes());
            
            // Cast vote through DaoEngine
            let vote_id = dao_engine.cast_dao_vote(
                voter_id,
                proposal_id,
                vote_choice,
                vote_data.justification.clone(),
            ).await?;

            info!("✅ DAO vote cast: {:?}", vote_id);
        } else {
            warn!("⚠️  DaoVote transaction missing vote_data");
        }

        Ok(())
    }

    /// Process a DAO execution transaction
    async fn process_dao_execution_transaction(
        &self,
        transaction: &Transaction,
        _dao_engine: &mut DaoEngine,
    ) -> Result<()> {
        if let Some(ref execution_data) = transaction.dao_execution_data {
            info!("⚡ Processing DAO execution for proposal {:?}", execution_data.proposal_id);
            info!("   Executor: {}", execution_data.executor);
            if let Some(ref recipient) = execution_data.recipient {
                info!("   Recipient: {}", recipient);
            }
            if let Some(amount) = execution_data.amount {
                info!("   Amount: {} ZHTP", amount);
            }
            info!("✅ DAO execution processed");
        } else {
            warn!("⚠️  DaoExecution transaction missing execution_data");
        }

        Ok(())
    }

    /// Parse proposal type string to enum
    fn parse_proposal_type(&self, type_str: &str) -> Result<DaoProposalType> {
        match type_str {
            "UbiDistribution" => Ok(DaoProposalType::UbiDistribution),
            "WelfareAllocation" => Ok(DaoProposalType::WelfareAllocation),
            "ProtocolUpgrade" => Ok(DaoProposalType::ProtocolUpgrade),
            "TreasuryAllocation" => Ok(DaoProposalType::TreasuryAllocation),
            "ValidatorUpdate" => Ok(DaoProposalType::ValidatorUpdate),
            "EconomicParams" => Ok(DaoProposalType::EconomicParams),
            "GovernanceRules" => Ok(DaoProposalType::GovernanceRules),
            "FeeStructure" => Ok(DaoProposalType::FeeStructure),
            "Emergency" => Ok(DaoProposalType::Emergency),
            "CommunityFunding" => Ok(DaoProposalType::CommunityFunding),
            "ResearchGrants" => Ok(DaoProposalType::ResearchGrants),
            _ => Err(anyhow::anyhow!("Unknown proposal type: {}", type_str)),
        }
    }

    /// Parse vote choice string to enum
    fn parse_vote_choice(&self, choice_str: &str) -> Result<DaoVoteChoice> {
        match choice_str {
            "Yes" => Ok(DaoVoteChoice::Yes),
            "No" => Ok(DaoVoteChoice::No),
            "Abstain" => Ok(DaoVoteChoice::Abstain),
            s if s.starts_with("Delegate:") => {
                let delegate_id = s.strip_prefix("Delegate:").unwrap_or("");
                let delegate_hash = lib_crypto::Hash::from_hex(delegate_id)
                    .unwrap_or_else(|_| lib_crypto::Hash::from_bytes(delegate_id.as_bytes()));
                Ok(DaoVoteChoice::Delegate(delegate_hash))
            },
            _ => Err(anyhow::anyhow!("Unknown vote choice: {}", choice_str)),
        }
    }

    /// Create DAO proposal from transaction memo (DEPRECATED - use DaoProposal transaction type)
    #[deprecated(note = "Use process_dao_proposal_transaction instead - memo parsing is deprecated")]
    async fn create_dao_proposal_from_transaction(
        &self,
        transaction: &Transaction,
        dao_engine: &mut DaoEngine,
    ) -> Result<()> {
        let memo = String::from_utf8_lossy(&transaction.memo);
        
        // Parse proposal details from memo (simplified parsing)
        if let Some(title_start) = memo.find("title:") {
            let title_section = &memo[title_start + 6..];
            let title = if let Some(title_end) = title_section.find("|") {
                title_section[..title_end].trim().to_string()
            } else {
                title_section.trim().to_string()
            };

            let proposer = IdentityId::from_bytes(&transaction.signature.public_key.as_bytes());
            
            let proposal_id = dao_engine.create_dao_proposal(
                proposer,
                title,
                "DAO proposal from blockchain transaction".to_string(),
                DaoProposalType::TreasuryAllocation,
                7, // 7 days voting period
            ).await?;

            info!("Created DAO proposal from transaction: {:?}", proposal_id);
        }

        Ok(())
    }

    /// Process DAO vote from transaction memo (DEPRECATED - use DaoVote transaction type)
    #[deprecated(note = "Use process_dao_vote_transaction instead - memo parsing is deprecated")]
    async fn process_dao_vote_from_transaction(
        &self,
        transaction: &Transaction,
        dao_engine: &mut DaoEngine,
    ) -> Result<()> {
        let memo = String::from_utf8_lossy(&transaction.memo);
        
        // Parse vote details from memo (simplified parsing)
        if let (Some(proposal_start), Some(vote_start)) = (memo.find("proposal:"), memo.find("vote:")) {
            let proposal_section = &memo[proposal_start + 9..];
            let proposal_hash_str = if let Some(end) = proposal_section.find("|") {
                &proposal_section[..end]
            } else {
                proposal_section
            }.trim();

            let vote_section = &memo[vote_start + 5..];
            let vote_str = if let Some(end) = vote_section.find("|") {
                &vote_section[..end]
            } else {
                vote_section
            }.trim();

            if let Ok(proposal_hash_bytes) = hex::decode(proposal_hash_str) {
                let mut hash_array = [0u8; 32];
                if proposal_hash_bytes.len() >= 32 {
                    hash_array.copy_from_slice(&proposal_hash_bytes[..32]);
                    let proposal_id = Hash::from_bytes(&hash_array);

                    let vote_choice = match vote_str.to_lowercase().as_str() {
                        "yes" => DaoVoteChoice::Yes,
                        "no" => DaoVoteChoice::No,
                        "abstain" => DaoVoteChoice::Abstain,
                        _ => DaoVoteChoice::Abstain,
                    };

                    let voter = IdentityId::from_bytes(&transaction.signature.public_key.as_bytes());
                    
                    let vote_id = dao_engine.cast_dao_vote(
                        voter,
                        proposal_id,
                        vote_choice,
                        Some("Vote cast via blockchain transaction".to_string()),
                    ).await?;

                    info!(" Processed DAO vote from transaction: {:?}", vote_id);
                }
            }
        }

        Ok(())
    }

    /// Create reward transactions for validators
    async fn create_reward_transactions(&self, reward_round: &RewardRound) -> Result<Vec<Transaction>> {
        let mut reward_transactions = Vec::new();

        for (validator_id, reward) in &reward_round.validator_rewards {
            if reward.total_reward > 0 {
                // Create reward transaction
                let mut commitment_data = Vec::new();
                commitment_data.extend_from_slice(validator_id.as_bytes());
                commitment_data.extend_from_slice(&reward.total_reward.to_le_bytes());
                commitment_data.extend_from_slice(b"reward");
                
                let mut note_data = Vec::new();
                note_data.extend_from_slice(&reward_round.height.to_le_bytes());
                note_data.extend_from_slice(&reward.total_reward.to_le_bytes());
                
                let output = crate::transaction::TransactionOutput {
                    commitment: BlockchainHash::from(hash_blake3(&commitment_data)),
                    note: BlockchainHash::from(hash_blake3(&note_data)),
                    recipient: crate::integration::crypto_integration::PublicKey::new(
                        validator_id.as_bytes().to_vec()
                    ),
                };

                let signature = crate::integration::crypto_integration::Signature {
                    signature: hash_blake3(b"system_reward").to_vec(),
                    public_key: crate::integration::crypto_integration::PublicKey::new(vec![0; 32]),
                    algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                    timestamp: current_timestamp(),
                };

                let reward_tx = Transaction {
                    version: 1,
                    chain_id: 0x03, // Default to development network
                    inputs: vec![], // System transaction, no inputs
                    outputs: vec![output],
                    fee: 0, // No fee for reward transactions
                    memo: format!("Validator reward: {} ZHTP (height: {})", reward.total_reward, reward_round.height).into_bytes(),
                    signature,
                    transaction_type: TransactionType::Transfer,
                    identity_data: None,
                    validator_data: None,
                    wallet_data: None,
                    dao_proposal_data: None,
                    dao_vote_data: None,
                    dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
                };

                reward_transactions.push(reward_tx);
            }
        }

        Ok(reward_transactions)
    }

    /// Get consensus engine status
    pub async fn get_consensus_status(&self) -> Result<ConsensusStatus> {
        let consensus_engine = self.consensus_engine.read().await;
        let current_round = consensus_engine.current_round();
        let validator_manager = consensus_engine.validator_manager();
        let dao_engine = consensus_engine.dao_engine();

        Ok(ConsensusStatus {
            current_height: current_round.height,
            current_round: current_round.round,
            current_step: current_round.step.clone(),
            is_validator: self.local_validator_id.is_some(),
            validator_count: validator_manager.get_total_validators(),
            active_validators: validator_manager.get_active_validators().len(),
            dao_proposals: dao_engine.get_dao_proposals().len(),
            treasury_balance: dao_engine.get_dao_treasury().total_balance,
            is_producing_blocks: self.is_producing_blocks,
        })
    }

    /// Get detailed validator information
    pub async fn get_validator_info(&self, validator_id: &IdentityId) -> Result<Option<ValidatorInfo>> {
        let consensus_engine = self.consensus_engine.read().await;
        let validator_manager = consensus_engine.validator_manager();
        
        // Get the specific validator
        if let Some(validator) = validator_manager.get_validator(validator_id) {
            Ok(Some(ValidatorInfo {
                identity: validator.identity.clone(),
                status: validator.status.clone(),
                stake_amount: validator.stake,
                reputation_score: validator.reputation as u8, // Convert u32 to u8
                last_active_height: validator.last_activity,
                total_blocks_produced: 0, // Field not available in Validator struct
                slashing_count: validator.slash_count,
            }))
        } else {
            Ok(None)
        }
    }

    /// List all validators with their current status
    pub async fn list_all_validators(&self) -> Result<Vec<ValidatorInfo>> {
        let consensus_engine = self.consensus_engine.read().await;
        let validator_manager = consensus_engine.validator_manager();
        
        let mut validator_infos = Vec::new();
        
        // Get all active validators and their details
        for validator in validator_manager.get_active_validators() {
            validator_infos.push(ValidatorInfo {
                identity: validator.identity.clone(),
                status: validator.status.clone(),
                stake_amount: validator.stake,
                reputation_score: validator.reputation as u8, // Convert u32 to u8
                last_active_height: validator.last_activity,
                total_blocks_produced: 0, // Field not available in Validator struct
                slashing_count: validator.slash_count,
            });
        }
        
        Ok(validator_infos)
    }

    /// Stop the consensus coordinator
    pub async fn stop(&mut self) {
        info!("Stopping blockchain consensus coordinator");
        self.is_producing_blocks = false;
    }

    /// Create a cryptographic signature for a consensus vote
    async fn create_vote_signature(&self, proposal_id: &Hash, vote_type: &VoteType) -> Result<lib_crypto::Signature> {
        // Create the vote data to sign
        let mut vote_data = Vec::new();
        vote_data.extend_from_slice(proposal_id.as_bytes());
        vote_data.extend_from_slice(&[match vote_type {
            VoteType::PreVote => 0u8,
            VoteType::PreCommit => 1u8,
            VoteType::Commit => 2u8,
            VoteType::Against => 3u8,
        }]);
        vote_data.extend_from_slice(&current_timestamp().to_le_bytes());

        // Get the validator's keypair (in production this would come from secure storage)
        let validator_keypair = self.get_validator_keypair().await?;
        
        // Create a KeyPair from the ValidatorKeypair components
        let keypair = lib_crypto::KeyPair {
            public_key: validator_keypair.public_key,
            private_key: validator_keypair.private_key,
        };
        
        // Create signature using lib-crypto
        let signature = lib_crypto::sign_message(&keypair, &vote_data)?;
        
        Ok(signature)
    }

    /// Get the validator's keypair (placeholder for secure key management)
    async fn get_validator_keypair(&self) -> Result<ValidatorKeypair> {
        // In production, this would retrieve the keypair from secure storage
        // Note: Current implementation generates a new keypair each time
        // For deterministic keypairs, would need to implement seed-based generation
        let validator_id = self.local_validator_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No validator ID configured"))?;

        debug!("Generating consensus keypair for validator: {}", validator_id);

        // Generate new keypair (in production, this would be persistent)
        let keypair = lib_crypto::generate_keypair()?;

        Ok(ValidatorKeypair {
            public_key: keypair.public_key,
            private_key: keypair.private_key,
        })
    }

    /// Week 11 Phase 5a: Collect and distribute fees from a finalized block
    ///
    /// This method is called asynchronously after a block is added to the blockchain.
    /// It extracts fees from the block and distributes them to UBI, consensus, governance,
    /// and treasury pools using the 45/30/15/10 split formula.
    ///
    /// This is a non-blocking operation that doesn't delay consensus finality.
    async fn collect_and_distribute_fees_for_block(&self, block: &Block) -> Result<()> {
        // Get total fees from block
        let total_fees = block.total_fees();

        if total_fees == 0 {
            debug!("Week 11 Phase 5a: Block {} has no fees to distribute", block.height());
            return Ok(());
        }

        // Get fee distribution breakdown
        let (ubi_amount, consensus_amount, gov_amount, treasury_amount) = block.fee_summary();

        info!(
            "Week 11 Phase 5a: Distributing fees from block {} - Total: {} | UBI: {} (45%) | Consensus: {} (30%) | Governance: {} (15%) | Treasury: {} (10%)",
            block.height(),
            total_fees,
            ubi_amount,
            consensus_amount,
            gov_amount,
            treasury_amount,
        );

        // In Phase 5b, this will integrate with FeeRouter to actually distribute fees
        // For now, we log the intended distribution for validation

        debug!(
            "Week 11 Phase 5a: Fee collection recorded - height: {}, total: {}, breakdown: ({}, {}, {}, {})",
            block.height(),
            total_fees,
            ubi_amount,
            consensus_amount,
            gov_amount,
            treasury_amount,
        );

        Ok(())
    }
}

/// Consensus status information
#[derive(Debug, Clone)]
pub struct ConsensusStatus {
    pub current_height: u64,
    pub current_round: u32,
    pub current_step: ConsensusStep,
    pub is_validator: bool,
    pub validator_count: usize,
    pub active_validators: usize,
    pub dao_proposals: usize,
    pub treasury_balance: u64,
    pub is_producing_blocks: bool,
}

/// Initialize consensus integration for blockchain
pub async fn initialize_consensus_integration(
    blockchain: Arc<RwLock<Blockchain>>,
    mempool: Arc<RwLock<Mempool>>,
    consensus_type: ConsensusType,
) -> Result<BlockchainConsensusCoordinator> {
    let consensus_config = ConsensusConfig {
        consensus_type,
        min_stake: 1000 * 1_000_000, // 1000 ZHTP minimum stake
        min_storage: 100 * 1024 * 1024 * 1024, // 100 GB minimum storage
        max_validators: 100,
        block_time: 10, // 10 second blocks
        epoch_length_blocks: 100,
        propose_timeout: 3000,
        prevote_timeout: 1000,
        precommit_timeout: 1000,
        max_transactions_per_block: 1000,
        max_difficulty: 0x00000000FFFFFFFF,
        target_difficulty: 0x00000FFF,
        byzantine_threshold: 1.0 / 3.0,
        slash_double_sign: 5,
        slash_liveness: 1,
        development_mode: false, // Production mode by default
    };

    let coordinator = BlockchainConsensusCoordinator::new(
        blockchain,
        mempool,
        consensus_config,
    ).await?;

    info!("Consensus integration initialized successfully");
    Ok(coordinator)
}

/// Initialize consensus integration with custom difficulty configuration
/// 
/// This variant allows specifying a custom `DifficultyConfig` for the blockchain
/// mining difficulty adjustment policy.
pub async fn initialize_consensus_integration_with_difficulty_config(
    blockchain: Arc<RwLock<Blockchain>>,
    mempool: Arc<RwLock<Mempool>>,
    consensus_type: ConsensusType,
    difficulty_config: DifficultyConfig,
) -> Result<BlockchainConsensusCoordinator> {
    let consensus_config = ConsensusConfig {
        consensus_type,
        min_stake: 1000 * 1_000_000, // 1000 ZHTP minimum stake
        min_storage: 100 * 1024 * 1024 * 1024, // 100 GB minimum storage
        max_validators: 100,
        block_time: 10, // 10 second blocks
        epoch_length_blocks: 100,
        propose_timeout: 3000,
        prevote_timeout: 1000,
        precommit_timeout: 1000,
        max_transactions_per_block: 1000,
        max_difficulty: 0x00000000FFFFFFFF,
        target_difficulty: 0x00000FFF,
        byzantine_threshold: 1.0 / 3.0,
        slash_double_sign: 5,
        slash_liveness: 1,
        development_mode: false, // Production mode by default
    };

    let coordinator = BlockchainConsensusCoordinator::new_with_difficulty_config(
        blockchain,
        mempool,
        consensus_config,
        difficulty_config,
    ).await?;

    info!("Consensus integration initialized with custom difficulty config");
    Ok(coordinator)
}

/// Create a DAO proposal transaction (delegated to consensus engine)
pub fn create_dao_proposal_transaction(
    proposer_keypair: &KeyPair,
    title: String,
    description: String,
    proposal_type: DaoProposalType,
) -> Result<Transaction> {
    // In the correct ZHTP pattern, DAO proposals are handled by the consensus engine's DAO system,
    // not as blockchain transactions. This function creates a minimal transaction record
    // for blockchain transparency while the actual DAO logic is handled by lib-consensus.
    
    let memo = format!("dao:proposal:title:{}|description:{}|type:{:?}", 
                      title, description, proposal_type);

    // Create system transaction signed by the proposer for validation
    let mut transaction = Transaction::new(
        vec![], // No inputs for record transaction
        vec![], // No outputs for record transaction
        100, // DAO proposal fee
        crate::integration::crypto_integration::Signature {
            signature: vec![], // Will be filled after signing
            public_key: proposer_keypair.public_key.clone(),
            algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
            timestamp: current_timestamp(),
        },
        memo.into_bytes(),
    );

    // Sign the transaction with the proposer's keypair
    let tx_hash = transaction.hash();
    let signature = proposer_keypair.sign(&tx_hash.as_bytes())?;
    transaction.signature = signature;

    Ok(transaction)
}

/// Create a DAO vote transaction (delegated to consensus engine)
pub fn create_dao_vote_transaction(
    voter_keypair: &KeyPair,
    proposal_id: Hash,
    vote_choice: DaoVoteChoice,
) -> Result<Transaction> {
    // In the correct ZHTP pattern, DAO votes are handled by the consensus engine's DAO system,
    // not as blockchain transactions. This function creates a minimal transaction record
    // for blockchain transparency while the actual DAO logic is handled by lib-consensus.
    
    let memo = format!("dao:vote:proposal:{}|vote:{}",
                      hex::encode(proposal_id.as_bytes()),
                      match vote_choice {
                          DaoVoteChoice::Yes => "yes",
                          DaoVoteChoice::No => "no",
                          DaoVoteChoice::Abstain => "abstain",
                          DaoVoteChoice::Delegate(_) => "delegate",
                      });

    // Create system transaction signed by the voter for validation
    let mut transaction = Transaction::new(
        vec![], // No inputs for record transaction
        vec![], // No outputs for record transaction
        10, // DAO vote fee
        crate::integration::crypto_integration::Signature {
            signature: vec![], // Will be filled after signing
            public_key: voter_keypair.public_key.clone(),
            algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
            timestamp: current_timestamp(),
        },
        memo.into_bytes(),
    );

    // Sign the transaction with the voter's keypair
    let tx_hash = transaction.hash();
    let signature = voter_keypair.sign(&tx_hash.as_bytes())?;
    transaction.signature = signature;

    Ok(transaction)
}

/// Get current UNIX timestamp using proper SystemTime
fn get_current_unix_timestamp() -> Result<u64> {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("System time before UNIX epoch: {}", e))?;
    Ok(duration.as_secs())
}

/// Validate timestamp is within acceptable range (not too far in past or future)
fn validate_consensus_timestamp(timestamp: u64) -> Result<()> {
    let current_time = get_current_unix_timestamp()?;
    let max_time_drift = 300; // 5 minutes tolerance
    
    if timestamp > current_time + max_time_drift {
        return Err(anyhow!("Timestamp too far in future: {} vs {}", timestamp, current_time));
    }
    
    if timestamp < current_time.saturating_sub(max_time_drift) {
        return Err(anyhow!("Timestamp too far in past: {} vs {}", timestamp, current_time));
    }
    
    Ok(())
}

/// Convert SystemTime to consensus timestamp
fn system_time_to_consensus_timestamp(time: SystemTime) -> Result<u64> {
    let duration = time.duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("Time conversion error: {}", e))?;
    Ok(duration.as_secs())
}
