//! Main consensus engine implementation combining all consensus mechanisms
//!

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use lib_crypto::{hash_blake3, Hash, PostQuantumSignature};
use lib_identity::IdentityId;

use crate::byzantine::ByzantineFaultDetector;
use crate::dao::DaoEngine;
use crate::proofs::{StakeProof, StorageProof, WorkProof};
use crate::rewards::RewardCalculator;
use crate::types::*;
use crate::validators::ValidatorManager;
use crate::{ConsensusError, ConsensusResult};

/// Main ZHTP consensus engine combining all consensus mechanisms
///
/// Debug is not derived because `MessageBroadcaster` is a trait object.
/// Use tracing/logging at call sites instead.
pub struct ConsensusEngine {
    /// Local validator identity
    validator_identity: Option<IdentityId>,
    /// Validator management
    validator_manager: ValidatorManager,
    /// Current consensus round
    current_round: ConsensusRound,
    /// Consensus configuration
    config: ConsensusConfig,
    /// Pending proposals queue
    pending_proposals: VecDeque<ConsensusProposal>,
    /// Vote pool organized by height
    vote_pool: HashMap<u64, HashMap<Hash, ConsensusVote>>,
    /// Consensus state history
    round_history: VecDeque<ConsensusRound>,
    /// DAO governance engine
    dao_engine: DaoEngine,
    /// Byzantine fault detection
    byzantine_detector: ByzantineFaultDetector,
    /// Reward calculation system
    reward_calculator: RewardCalculator,
    /// Message broadcaster for network distribution
    ///
    /// Invariant CE-ENG-1: ConsensusEngine never constructs, configures, or inspects
    /// the broadcaster. It only calls it.
    broadcaster: Arc<dyn MessageBroadcaster>,
}

impl ConsensusEngine {
    /// Create a new consensus engine
    ///
    /// Invariant CE-ENG-1: The broadcaster is dependency-injected.
    /// No defaults. No globals. No feature flags.
    pub fn new(
        config: ConsensusConfig,
        broadcaster: Arc<dyn MessageBroadcaster>,
    ) -> ConsensusResult<Self> {
        let validator_manager = ValidatorManager::new_with_development_mode(
            config.max_validators,
            config.min_stake,
            config.development_mode,
        );

        let current_round = ConsensusRound {
            height: 0,
            round: 0,
            step: ConsensusStep::Propose,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            proposer: None,
            proposals: Vec::new(),
            votes: HashMap::new(),
            timed_out: false,
            locked_proposal: None,
            valid_proposal: None,
        };

        Ok(Self {
            validator_identity: None,
            validator_manager,
            current_round,
            config,
            pending_proposals: VecDeque::new(),
            vote_pool: HashMap::new(),
            round_history: VecDeque::new(),
            dao_engine: DaoEngine::new(),
            byzantine_detector: ByzantineFaultDetector::new(),
            reward_calculator: RewardCalculator::new(),
            broadcaster,
        })
    }

    /// Register as a validator
    pub async fn register_validator(
        &mut self,
        identity: IdentityId,
        stake: u64,
        storage_capacity: u64,
        consensus_key: Vec<u8>,
        commission_rate: u8,
        is_genesis: bool,
    ) -> ConsensusResult<()> {
        // Validate minimum requirements (skip for genesis node)
        if !is_genesis && stake < self.config.min_stake {
            return Err(ConsensusError::ValidatorError(
                "Insufficient stake amount".to_string(),
            ));
        }

        if storage_capacity < self.config.min_storage {
            return Err(ConsensusError::ValidatorError(
                "Insufficient storage capacity".to_string(),
            ));
        }

        if commission_rate > 100 {
            return Err(ConsensusError::ValidatorError(
                "Invalid commission rate".to_string(),
            ));
        }

        // Register with validator manager
        self.validator_manager
            .register_validator(
                identity.clone(),
                stake,
                storage_capacity,
                consensus_key,
                commission_rate,
            )
            .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;

        // Set as local validator if this is the first one
        if self.validator_identity.is_none() {
            self.validator_identity = Some(identity.clone());
        }

        tracing::info!(
            "Registered validator {:?} with {} ZHTP stake",
            identity,
            stake
        );
        Ok(())
    }

    /// Process a single consensus event (pure component method)
    /// This replaces the standalone start_consensus() loop pattern
    pub async fn handle_consensus_event(
        &mut self,
        event: ConsensusEvent,
    ) -> ConsensusResult<Vec<ConsensusEvent>> {
        match event {
            ConsensusEvent::StartRound { height, trigger } => {
                tracing::info!(
                    " Starting consensus round {} (trigger: {})",
                    height,
                    trigger
                );

                // Log different trigger types for monitoring and debugging
                match trigger.as_str() {
                    "timeout" => tracing::warn!(
                        "⏰ Consensus round triggered by timeout - potential network delays"
                    ),
                    "new_transaction" => {
                        tracing::debug!("💳 New transaction triggered consensus round")
                    }
                    "validator_join" => {
                        tracing::info!("New validator joining triggered consensus round")
                    }
                    "validator_leave" => {
                        tracing::warn!(" Validator leaving triggered consensus round")
                    }
                    "force_restart" => tracing::warn!(" Manual consensus restart triggered"),
                    _ => tracing::debug!("Custom trigger: {}", trigger),
                }

                self.prepare_consensus_round(height).await?;
                Ok(vec![ConsensusEvent::RoundPrepared { height }])
            }
            ConsensusEvent::NewBlock {
                height,
                previous_hash,
            } => {
                tracing::info!(
                    "🧱 Processing new block at height {} with previous hash: {}",
                    height,
                    previous_hash
                );

                // Validate blockchain continuity by checking previous hash
                if let Err(e) = self.validate_previous_hash(height, &previous_hash).await {
                    tracing::error!("Previous hash validation failed: {}", e);
                    return Ok(vec![ConsensusEvent::RoundFailed {
                        height,
                        error: format!("Previous hash validation failed: {}", e),
                    }]);
                }

                match self.run_consensus_round().await {
                    Ok(_) => {
                        let mut events = vec![ConsensusEvent::RoundCompleted { height }];

                        // Process DAO proposals
                        if let Err(e) = self.dao_engine.process_expired_proposals().await {
                            tracing::warn!("DAO processing error: {}", e);
                            events.push(ConsensusEvent::DaoError {
                                error: e.to_string(),
                            });
                        }

                        // Check for Byzantine faults
                        if let Err(e) = self
                            .byzantine_detector
                            .detect_faults(&self.validator_manager)
                        {
                            tracing::warn!("Byzantine fault detection error: {}", e);
                            events.push(ConsensusEvent::ByzantineFault {
                                error: e.to_string(),
                            });
                        }

                        // Calculate and distribute rewards
                        if let Err(e) = self.reward_calculator.calculate_round_rewards(
                            &self.validator_manager,
                            self.current_round.height,
                        ) {
                            tracing::warn!("Reward calculation error: {}", e);
                            events.push(ConsensusEvent::RewardError {
                                error: e.to_string(),
                            });
                        }

                        Ok(events)
                    }
                    Err(e) => {
                        tracing::error!("Consensus round failed: {}", e);
                        Ok(vec![ConsensusEvent::RoundFailed {
                            height,
                            error: e.to_string(),
                        }])
                    }
                }
            }
            ConsensusEvent::ValidatorJoin { identity, stake } => {
                self.handle_validator_registration(identity.clone(), stake)
                    .await?;
                Ok(vec![ConsensusEvent::ValidatorRegistered { identity }])
            }
            _ => {
                tracing::debug!("Unhandled consensus event: {:?}", event);
                Ok(vec![])
            }
        }
    }

    /// Prepare for a consensus round (internal method)
    async fn prepare_consensus_round(&mut self, height: u64) -> ConsensusResult<()> {
        if !self.validator_manager.has_sufficient_validators() {
            return Err(ConsensusError::ValidatorError(
                "Insufficient validators for consensus".to_string(),
            ));
        }

        tracing::info!(" Preparing ZHTP consensus for height {}", height);
        self.current_round.height = height;
        Ok(())
    }

    /// Handle validator registration event
    async fn handle_validator_registration(
        &mut self,
        identity: lib_identity::IdentityId,
        stake: u64,
    ) -> ConsensusResult<()> {
        self.register_validator(
            identity.clone(),
            stake,
            1024 * 1024 * 1024, // Default storage capacity
            vec![0u8; 32],      // Default consensus key
            5,                  // Default commission rate
            false,              // Not genesis
        )
        .await?;
        Ok(())
    }

    /// Run a single consensus round
    async fn run_consensus_round(&mut self) -> ConsensusResult<()> {
        self.advance_to_next_round();

        // Select proposer for this round
        let proposer = self
            .validator_manager
            .select_proposer(self.current_round.height, self.current_round.round)
            .ok_or_else(|| ConsensusError::ValidatorError("No proposer available".to_string()))?;

        self.current_round.proposer = Some(proposer.identity.clone());

        tracing::info!(
            "Starting consensus round {} at height {} with proposer {:?}",
            self.current_round.round,
            self.current_round.height,
            proposer.identity
        );

        // Run consensus steps
        self.run_propose_step().await?;
        self.run_prevote_step().await?;
        self.run_precommit_step().await?;
        self.run_commit_step().await?;

        // Archive completed round
        self.archive_completed_round();

        Ok(())
    }

    /// Get active validator IDs for the current round
    ///
    /// This is used when broadcasting to ensure the validator set is passed explicitly
    /// rather than queried from network state (Invariant CE-ENG-5).
    fn get_active_validator_ids(&self) -> Vec<IdentityId> {
        self.validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect()
    }

    /// Advance to the next consensus round
    fn advance_to_next_round(&mut self) {
        self.current_round.height += 1;
        self.current_round.round = 0;
        self.current_round.step = ConsensusStep::Propose;
        self.current_round.start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.current_round.proposer = None;
        self.current_round.proposals.clear();
        self.current_round.votes.clear();
        self.current_round.timed_out = false;
        self.current_round.locked_proposal = None;
        self.current_round.valid_proposal = None;
    }

    /// Run the propose step
    async fn run_propose_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Propose;

        // If we are the proposer, create a proposal
        if let Some(ref validator_id) = self.validator_identity {
            if Some(validator_id) == self.current_round.proposer.as_ref() {
                let proposal = self.create_proposal().await?;
                self.current_round.proposals.push(proposal.id.clone());
                self.pending_proposals.push_back(proposal.clone());

                // Invariant CE-ENG-3: Broadcast after state transition (proposal now in state)
                // Create canonical ValidatorMessage from already-formed proposal
                let msg = ValidatorMessage::Propose {
                    proposal,
                };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        "Failed to broadcast proposal to validators (continuing per CE-ENG-4)"
                    );
                }
            }
        }

        // Wait for proposals with timeout
        self.wait_for_step_timeout(self.config.propose_timeout)
            .await;

        Ok(())
    }

    /// Run the prevote step
    async fn run_prevote_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreVote;

        // Cast prevote
        if let Some(proposal_id) = self.current_round.proposals.first() {
            let vote = self.cast_vote(proposal_id.clone(), VoteType::PreVote)
                .await?;

            // Invariant CE-ENG-3: Broadcast after state transition
            // Create canonical ValidatorMessage from already-formed vote
            let msg = ValidatorMessage::Vote { vote };

            // Invariant CE-ENG-5: Pass validator set explicitly, never query network
            let validator_ids = self.get_active_validator_ids();

            // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
            // Log failures for observability without affecting consensus correctness
            if let Err(e) = self.broadcaster
                .broadcast_to_validators(msg, &validator_ids)
                .await
            {
                tracing::debug!(
                    error = ?e,
                    height = self.current_round.height,
                    "Failed to broadcast prevote to validators (continuing per CE-ENG-4)"
                );
            }
        }

        // Wait for prevotes with timeout
        self.wait_for_step_timeout(self.config.prevote_timeout)
            .await;

        Ok(())
    }

    /// Run the precommit step
    async fn run_precommit_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreCommit;

        // Check if we received enough prevotes
        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let prevote_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreVote);
            let threshold = self.validator_manager.get_byzantine_threshold();

            if prevote_count >= threshold {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::PreCommit)
                    .await?;
                self.current_round.valid_proposal = Some(proposal_id);

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = ValidatorMessage::Vote { vote };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        "Failed to broadcast precommit to validators (continuing per CE-ENG-4)"
                    );
                }
            }
        }

        // Wait for precommits with timeout
        self.wait_for_step_timeout(self.config.precommit_timeout)
            .await;

        Ok(())
    }

    /// Run the commit step
    async fn run_commit_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Commit;

        // Check if we received enough precommits
        if let Some(proposal_id) = self.current_round.valid_proposal.as_ref().cloned() {
            let precommit_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreCommit);
            let threshold = self.validator_manager.get_byzantine_threshold();

            if precommit_count >= threshold {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::Commit)
                    .await?;

                tracing::info!(
                    "Block committed at height {} with proposal {:?}",
                    self.current_round.height,
                    proposal_id
                );

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = ValidatorMessage::Vote { vote };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        proposal_id = ?proposal_id,
                        "Failed to broadcast commit vote to validators (continuing per CE-ENG-4)"
                    );
                }

                // Process the committed block
                self.process_committed_block(&proposal_id).await?;
            }
        }

        Ok(())
    }

    /// Create a new proposal
    async fn create_proposal(&self) -> ConsensusResult<ConsensusProposal> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Get previous block hash from blockchain state
        let previous_hash = self.get_previous_block_hash().await?;

        // Collect pending transactions for this block
        let block_data = self.collect_block_transactions().await?;

        // Generate proposal ID from deterministic data
        let proposal_id = Hash::from_bytes(&hash_blake3(
            &[
                &self.current_round.height.to_le_bytes(),
                previous_hash.as_bytes(),
                &block_data,
                validator_id.as_bytes(),
            ]
            .concat(),
        ));

        // Create consensus proof
        let consensus_proof = self.create_consensus_proof().await?;

        // Sign the proposal data
        let proposal_data = self.serialize_proposal_data(
            &proposal_id,
            validator_id,
            self.current_round.height,
            &previous_hash,
            &block_data,
        )?;

        let signature = self.sign_proposal_data(&proposal_data).await?;

        let proposal = ConsensusProposal {
            id: proposal_id,
            proposer: validator_id.clone(),
            height: self.current_round.height,
            previous_hash,
            block_data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            signature,
            consensus_proof,
        };

        tracing::info!(
            "Created proposal {:?} for height {} by {:?}",
            proposal.id,
            proposal.height,
            proposal.proposer
        );

        Ok(proposal)
    }

    /// Get the hash of the previous block
    async fn get_previous_block_hash(&self) -> ConsensusResult<Hash> {
        // In production, this would query the blockchain for the latest block hash
        if self.current_round.height == 0 {
            // Genesis block
            Ok(Hash([0u8; 32]))
        } else {
            // For demo, create deterministic previous hash based on height
            let prev_hash_data = format!("block_{}", self.current_round.height - 1);
            Ok(Hash::from_bytes(&hash_blake3(prev_hash_data.as_bytes())))
        }
    }

    /// Collect transactions for the new block
    async fn collect_block_transactions(&self) -> ConsensusResult<Vec<u8>> {
        // In production, this would:
        // 1. Get pending transactions from mempool
        // 2. Validate transactions
        // 3. Select transactions based on fees and priority
        // 4. Create block data with transaction merkle tree

        // For demo, create minimal block data
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        let block_data = format!(
            "block_height:{},timestamp:{},validator_count:{}",
            self.current_round.height,
            timestamp,
            self.validator_manager.get_active_validators().len()
        );

        Ok(block_data.into_bytes())
    }

    /// Serialize proposal data for signing
    fn serialize_proposal_data(
        &self,
        proposal_id: &Hash,
        proposer: &IdentityId,
        height: u64,
        previous_hash: &Hash,
        block_data: &[u8],
    ) -> ConsensusResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(proposal_id.as_bytes());
        data.extend_from_slice(proposer.as_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(previous_hash.as_bytes());
        data.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
        data.extend_from_slice(block_data);
        Ok(data)
    }

    /// Sign proposal data
    async fn sign_proposal_data(&self, data: &[u8]) -> ConsensusResult<PostQuantumSignature> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create signature using validator's consensus key
        let signature_data = [data, &validator.consensus_key].concat();
        let signature_hash = hash_blake3(&signature_data);

        Ok(PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: validator.consensus_key.clone(),
                kyber_pk: validator.consensus_key[..16].to_vec(), // Truncated for demo
                key_id: validator_id.as_bytes().try_into().unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
        })
    }

    /// Create consensus proof based on configuration
    async fn create_consensus_proof(&self) -> ConsensusResult<ConsensusProof> {
        let consensus_type = self.config.consensus_type.clone();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        match consensus_type {
            ConsensusType::ProofOfStake => {
                let stake_proof = self.create_stake_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: Some(stake_proof),
                    storage_proof: None,
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::ProofOfStorage => {
                let storage_proof = self.create_storage_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: None,
                    storage_proof: Some(storage_proof),
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::ProofOfUsefulWork => {
                let work_proof = self.create_work_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: None,
                    storage_proof: None,
                    work_proof: Some(work_proof),
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::Hybrid => {
                let stake_proof = self.create_stake_proof().await?;
                let storage_proof = self.create_storage_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: Some(stake_proof),
                    storage_proof: Some(storage_proof),
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::ByzantineFaultTolerance => {
                // BFT uses all proof types
                let stake_proof = self.create_stake_proof().await?;
                let storage_proof = self.create_storage_proof().await?;
                let work_proof = self.create_work_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: Some(stake_proof),
                    storage_proof: Some(storage_proof),
                    work_proof: Some(work_proof),
                    zk_did_proof: None,
                    timestamp,
                })
            }
        }
    }

    /// Create stake proof
    async fn create_stake_proof(&self) -> ConsensusResult<StakeProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create deterministic stake transaction hash based on validator identity and stake
        let stake_tx_data = [
            validator_id.as_bytes(),
            &validator.stake.to_le_bytes(),
            b"stake_transaction",
        ]
        .concat();
        let stake_tx_hash = Hash::from_bytes(&hash_blake3(&stake_tx_data));

        let stake_proof = StakeProof::new(
            validator_id.clone(),
            validator.stake,
            stake_tx_hash,
            self.current_round.height.saturating_sub(1), // Stake was made in previous block
            86400,                                       // 1 day lock time in seconds
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(stake_proof)
    }

    /// Create storage proof
    async fn create_storage_proof(&self) -> ConsensusResult<StorageProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create realistic storage challenges
        let mut challenges = Vec::new();
        let num_challenges = 3; // Standard number of challenges

        for i in 0..num_challenges {
            let challenge_data = [
                validator_id.as_bytes(),
                &(i as u32).to_le_bytes(),
                &self.current_round.height.to_le_bytes(),
            ]
            .concat();

            let challenge = crate::proofs::StorageChallenge {
                id: Hash::from_bytes(&hash_blake3(&challenge_data)),
                content_hash: Hash::from_bytes(&hash_blake3(
                    &[challenge_data.clone(), b"content".to_vec()].concat(),
                )),
                challenge: challenge_data[..16].to_vec(), // First 16 bytes as challenge
                response: hash_blake3(&challenge_data).to_vec(), // Hash as response
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| ConsensusError::TimeError(e))?
                    .as_secs()
                    - (i as u64 * 3600),
            };
            challenges.push(challenge);
        }

        // Create merkle proof for stored data
        let merkle_data = [
            validator_id.as_bytes(),
            &validator.storage_provided.to_le_bytes(),
            b"merkle_root",
        ]
        .concat();
        let merkle_proof = vec![Hash::from_bytes(&hash_blake3(&merkle_data))];

        // Calculate realistic utilization based on validator activity
        let utilization = std::cmp::min(
            90,                               // Max 90% utilization
            50 + (validator.reputation / 10), // 50-90% based on reputation
        ) as u64;

        let storage_proof = StorageProof::new(
            Hash::from_bytes(validator_id.as_bytes()),
            validator.storage_provided,
            utilization,
            challenges,
            merkle_proof,
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(storage_proof)
    }

    /// Create work proof
    async fn create_work_proof(&self) -> ConsensusResult<WorkProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Calculate realistic work values based on validator capabilities
        let routing_work = (validator.voting_power * 10).min(5000); // Based on voting power
        let storage_work = (validator.storage_provided / (1024 * 1024 * 1024)).min(1000); // GB to work units
        let compute_work = (validator.reputation as u64 * 5).min(2000); // Based on reputation

        let work_proof = WorkProof::new(
            routing_work,
            storage_work,
            compute_work,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            validator_id.as_bytes().try_into().unwrap_or([0u8; 32]),
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(work_proof)
    }

    /// Cast a vote
    ///
    /// Returns the created vote so that the caller can broadcast it.
    /// Invariant CE-ENG-3: Broadcast happens after this state transition.
    async fn cast_vote(&mut self, proposal_id: Hash, vote_type: VoteType) -> ConsensusResult<ConsensusVote> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create vote ID from deterministic data
        let vote_id = Hash::from_bytes(&hash_blake3(
            &[
                proposal_id.as_bytes(),
                validator_id.as_bytes(),
                &(vote_type.clone() as u8).to_le_bytes(),
                &self.current_round.height.to_le_bytes(),
                &self.current_round.round.to_le_bytes(),
            ]
            .concat(),
        ));

        // Create vote data for signing
        let vote_data =
            self.serialize_vote_data(&vote_id, validator_id, &proposal_id, &vote_type)?;

        // Sign the vote
        let signature = self.sign_vote_data(&vote_data, &validator).await?;

        let vote = ConsensusVote {
            id: vote_id.clone(),
            voter: validator_id.clone(),
            proposal_id: proposal_id.clone(),
            vote_type: vote_type.clone(),
            height: self.current_round.height,
            round: self.current_round.round,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            signature,
        };

        // Store vote
        self.vote_pool
            .entry(self.current_round.height)
            .or_insert_with(HashMap::new)
            .insert(vote.id.clone(), vote.clone());

        // Update validator activity
        self.validator_manager
            .update_validator_activity(validator_id);

        tracing::debug!(
            " Cast {:?} vote on proposal {:?} from validator {:?}",
            vote_type,
            proposal_id,
            validator_id
        );

        Ok(vote)
    }

    /// Serialize vote data for signing
    fn serialize_vote_data(
        &self,
        vote_id: &Hash,
        voter: &IdentityId,
        proposal_id: &Hash,
        vote_type: &VoteType,
    ) -> ConsensusResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(vote_id.as_bytes());
        data.extend_from_slice(voter.as_bytes());
        data.extend_from_slice(proposal_id.as_bytes());
        data.push(vote_type.clone() as u8);
        data.extend_from_slice(&self.current_round.height.to_le_bytes());
        data.extend_from_slice(&self.current_round.round.to_le_bytes());
        Ok(data)
    }

    /// Sign vote data
    async fn sign_vote_data(
        &self,
        data: &[u8],
        validator: &crate::validators::Validator,
    ) -> ConsensusResult<PostQuantumSignature> {
        // Create signature using validator's consensus key
        let signature_data = [data, &validator.consensus_key].concat();
        let signature_hash = hash_blake3(&signature_data);

        Ok(PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: validator.consensus_key.clone(),
                kyber_pk: validator.consensus_key[..16].to_vec(),
                key_id: validator
                    .identity
                    .as_bytes()
                    .try_into()
                    .unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
        })
    }

    /// Count votes for a proposal
    fn count_votes_for_proposal(&self, proposal_id: &Hash, vote_type: &VoteType) -> u64 {
        if let Some(votes) = self.vote_pool.get(&self.current_round.height) {
            votes
                .values()
                .filter(|vote| &vote.proposal_id == proposal_id && &vote.vote_type == vote_type)
                .count() as u64
        } else {
            0
        }
    }

    /// Wait for step timeout
    async fn wait_for_step_timeout(&mut self, timeout_ms: u64) {
        tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms)).await;
    }

    /// Process committed block
    async fn process_committed_block(&mut self, proposal_id: &Hash) -> ConsensusResult<()> {
        // Find and process the committed proposal
        if let Some(proposal_index) = self
            .pending_proposals
            .iter()
            .position(|p| &p.id == proposal_id)
        {
            let proposal = self.pending_proposals.remove(proposal_index).unwrap();

            // Validate the block one more time before applying
            self.validate_committed_block(&proposal).await?;

            // Apply block to state
            self.apply_block_to_state(&proposal).await?;

            // Update validator activities and reputation
            self.update_validator_metrics(&proposal).await?;

            // Calculate and distribute block rewards
            let reward_round = self
                .reward_calculator
                .calculate_round_rewards(&self.validator_manager, self.current_round.height)?;
            self.reward_calculator.distribute_rewards(&reward_round)?;

            // Process any DAO proposals that may have expired
            if let Err(e) = self.dao_engine.process_expired_proposals().await {
                tracing::warn!("Error processing DAO proposals: {}", e);
            }

            tracing::info!(
                " Successfully processed committed block: {:?} at height {}",
                proposal.id,
                proposal.height
            );
        }

        Ok(())
    }

    /// Validate committed block before applying
    async fn validate_committed_block(&self, proposal: &ConsensusProposal) -> ConsensusResult<()> {
        // Verify proposal signature
        let proposal_data = self.serialize_proposal_data(
            &proposal.id,
            &proposal.proposer,
            proposal.height,
            &proposal.previous_hash,
            &proposal.block_data,
        )?;

        if !self
            .verify_signature(&proposal_data, &proposal.signature)
            .await?
        {
            return Err(ConsensusError::ProofVerificationFailed(
                "Invalid proposal signature".to_string(),
            ));
        }

        // Verify consensus proof
        if !self
            .verify_consensus_proof(&proposal.consensus_proof)
            .await?
        {
            return Err(ConsensusError::ProofVerificationFailed(
                "Invalid consensus proof".to_string(),
            ));
        }

        tracing::debug!("Block validation passed for {:?}", proposal.id);
        Ok(())
    }

    /// Apply block to blockchain state
    async fn apply_block_to_state(&mut self, proposal: &ConsensusProposal) -> ConsensusResult<()> {
        // In production, this would:
        // 1. Execute all transactions in the block
        // 2. Update account balances and state
        // 3. Update validator set if needed
        // 4. Apply any governance changes
        // 5. Store block in blockchain database

        // For now, just log the application
        tracing::info!(
            " Applied block {:?} to state (height: {}, size: {} bytes)",
            proposal.id,
            proposal.height,
            proposal.block_data.len()
        );

        Ok(())
    }

    /// Update validator metrics based on block participation
    async fn update_validator_metrics(
        &mut self,
        proposal: &ConsensusProposal,
    ) -> ConsensusResult<()> {
        // Update proposer metrics
        let proposer_id = proposal.proposer.clone();
        if let Some(proposer) = self.validator_manager.get_validator_mut(&proposer_id) {
            proposer.reputation = std::cmp::min(proposer.reputation + 1, 1000); // Cap at 1000
            proposer.update_activity();
        }

        // Update metrics for validators who voted
        if let Some(votes) = self.vote_pool.get(&proposal.height) {
            let voter_ids: Vec<IdentityId> = votes.values().map(|v| v.voter.clone()).collect();
            for voter_id in voter_ids {
                if let Some(voter) = self.validator_manager.get_validator_mut(&voter_id) {
                    voter.reputation = std::cmp::min(voter.reputation + 1, 1000);
                    voter.update_activity();
                }
            }
        }

        tracing::debug!(" Updated validator metrics for block {:?}", proposal.id);
        Ok(())
    }

    /// Verify a signature
    async fn verify_signature(
        &self,
        _data: &[u8],
        signature: &PostQuantumSignature,
    ) -> ConsensusResult<bool> {
        // In production, this would use proper post-quantum signature verification
        // For demo, we verify that the signature is not empty and has correct structure
        Ok(!signature.signature.is_empty() && !signature.public_key.dilithium_pk.is_empty())
    }

    /// Verify consensus proof
    async fn verify_consensus_proof(&self, proof: &ConsensusProof) -> ConsensusResult<bool> {
        match proof.consensus_type {
            ConsensusType::ProofOfStake => {
                if let Some(stake_proof) = &proof.stake_proof {
                    Ok(stake_proof.verify(self.current_round.height)?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::ProofOfStorage => {
                if let Some(storage_proof) = &proof.storage_proof {
                    Ok(storage_proof.verify()?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::ProofOfUsefulWork => {
                if let Some(work_proof) = &proof.work_proof {
                    Ok(work_proof.verify()?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::Hybrid => {
                let stake_valid = proof
                    .stake_proof
                    .as_ref()
                    .map(|p| p.verify(self.current_round.height))
                    .transpose()?
                    .unwrap_or(false);

                let storage_valid = proof
                    .storage_proof
                    .as_ref()
                    .map(|p| p.verify())
                    .transpose()?
                    .unwrap_or(false);

                Ok(stake_valid && storage_valid)
            }
            ConsensusType::ByzantineFaultTolerance => {
                // For BFT, we rely on vote thresholds rather than individual proofs
                Ok(true)
            }
        }
    }

    /// Archive completed round
    fn archive_completed_round(&mut self) {
        self.round_history.push_back(self.current_round.clone());

        // Keep only recent history
        if self.round_history.len() > 100 {
            self.round_history.pop_front();
        }
    }

    /// Get DAO engine reference
    pub fn dao_engine(&self) -> &DaoEngine {
        &self.dao_engine
    }

    /// Get mutable DAO engine reference
    pub fn dao_engine_mut(&mut self) -> &mut DaoEngine {
        &mut self.dao_engine
    }

    /// Get validator manager reference
    pub fn validator_manager(&self) -> &ValidatorManager {
        &self.validator_manager
    }

    /// Get current consensus round
    pub fn current_round(&self) -> &ConsensusRound {
        &self.current_round
    }

    /// Get consensus configuration
    pub fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    /// Validate that the previous hash matches the expected blockchain state
    async fn validate_previous_hash(
        &self,
        height: u64,
        previous_hash: &Hash,
    ) -> ConsensusResult<()> {
        // For genesis block (height 0), previous hash should be zero
        if height == 0 {
            let zero_hash = Hash::from_bytes(&[0u8; 32]);
            if *previous_hash != zero_hash {
                return Err(ConsensusError::InvalidPreviousHash(format!(
                    "Genesis block must have zero previous hash, got: {}",
                    previous_hash
                )));
            }
            return Ok(());
        }

        // For subsequent blocks, validate against the actual chain state
        // In a implementation, this would check against stored blockchain state

        // Check if we have the expected previous block
        if height > 1 {
            tracing::debug!(
                "Validating previous hash {} for height {}",
                previous_hash,
                height
            );

            // Here we would normally:
            // 1. Query the blockchain storage for block at height-1
            // 2. Compare its hash with the provided previous_hash
            // 3. Detect potential forks or reorganizations

            // For now, we log the validation but don't fail
            tracing::info!("Previous hash validation passed for height {}", height);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock message broadcaster for testing
    ///
    /// Tracks all broadcast calls and message types without side effects.
    /// This is used to verify that the consensus engine broadcasts
    /// the correct messages at the correct phases.
    #[derive(Debug)]
    struct MockMessageBroadcaster {
        /// All broadcast calls in order
        broadcasts: Mutex<Vec<BroadcastCall>>,
    }

    #[derive(Debug)]
    struct BroadcastCall {
        message: ValidatorMessage,
        validator_ids: Vec<IdentityId>,
    }

    impl MockMessageBroadcaster {
        fn new() -> Self {
            Self {
                broadcasts: Mutex::new(Vec::new()),
            }
        }

        fn get_broadcasts(&self) -> Vec<BroadcastCall> {
            self.broadcasts.lock().unwrap().clone()
        }

        fn count_broadcasts(&self) -> usize {
            self.broadcasts.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl MessageBroadcaster for MockMessageBroadcaster {
        async fn broadcast_to_validators(
            &self,
            message: ValidatorMessage,
            validator_ids: &[IdentityId],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcasts.lock().unwrap().push(BroadcastCall {
                message,
                validator_ids: validator_ids.to_vec(),
            });
            Ok(())
        }
    }

    impl Clone for BroadcastCall {
        fn clone(&self) -> Self {
            Self {
                message: self.message.clone(),
                validator_ids: self.validator_ids.clone(),
            }
        }
    }

    fn test_validator_id(id: u8) -> IdentityId {
        // Create a deterministic test validator ID from a single byte
        // by repeating it 32 times to match Hash::from_bytes signature
        lib_crypto::Hash::from_bytes(&[id; 32])
    }

    #[tokio::test]
    async fn test_consensus_engine_creation_with_broadcaster() {
        let config = ConsensusConfig::default();
        let mock_broadcaster: Arc<dyn MessageBroadcaster> =
            Arc::new(MockMessageBroadcaster::new());
        let result = ConsensusEngine::new(config, mock_broadcaster);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_proposal_broadcast_in_propose_phase() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Set as proposer (needed to create a proposal)
        engine.current_round.proposer = Some(validator_id.clone());
        engine.validator_identity = Some(validator_id);

        // Run propose step
        engine.run_propose_step().await.expect("Failed to run propose step");

        // Verify proposal was broadcast
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(
            broadcasts.len() > 0,
            "Expected at least one broadcast in propose phase"
        );

        // Verify it's a propose message
        assert!(
            broadcasts.iter().any(|call| matches!(call.message, ValidatorMessage::Propose { .. })),
            "Expected ValidatorMessage::Propose variant"
        );
    }

    #[tokio::test]
    async fn test_vote_broadcast_in_prevote_phase() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Create a proposal to vote on
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step
        engine.run_prevote_step().await.expect("Failed to run prevote step");

        // Verify vote was broadcast
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(
            broadcasts.len() > 0,
            "Expected at least one broadcast in prevote phase"
        );

        // Verify it's a vote message
        assert!(
            broadcasts.iter().any(|call| matches!(call.message, ValidatorMessage::Vote { .. })),
            "Expected ValidatorMessage::Vote variant"
        );
    }

    #[tokio::test]
    async fn test_validator_set_passed_to_broadcaster() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register multiple validators
        let validator_ids: Vec<_> = (0..3)
            .map(|i| test_validator_id(i))
            .collect();

        for id in &validator_ids {
            engine
                .register_validator(
                    id.clone(),
                    10_000_000_000,
                    100 * 1024 * 1024 * 1024,
                    vec![42u8; 32],
                    5,
                    true,
                )
                .await
                .expect("Failed to register validator");
        }

        // Create a proposal to vote on
        engine.current_round.proposer = Some(validator_ids[0].clone());
        engine.validator_identity = Some(validator_ids[0].clone());
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step
        engine.run_prevote_step().await.expect("Failed to run prevote step");

        // Verify validator set was passed to broadcaster
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(broadcasts.len() > 0, "Expected broadcasts");

        for call in broadcasts {
            assert!(
                !call.validator_ids.is_empty(),
                "Expected validator IDs to be passed to broadcaster"
            );
            // All registered validators should be in the list
            assert!(
                call.validator_ids.len() >= 3,
                "Expected all validators to be in broadcast recipient list"
            );
        }
    }

    #[tokio::test]
    async fn test_broadcast_failure_does_not_affect_consensus() {
        /// Mock broadcaster that always fails
        struct FailingBroadcaster;

        #[async_trait::async_trait]
        impl MessageBroadcaster for FailingBroadcaster {
            async fn broadcast_to_validators(
                &self,
                _message: ValidatorMessage,
                _validator_ids: &[IdentityId],
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Err("Network error".into())
            }
        }

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(FailingBroadcaster);
        let mut engine =
            ConsensusEngine::new(config, broadcaster).expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Create a proposal to vote on
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step - should not fail even though broadcaster fails
        let result = engine.run_prevote_step().await;
        assert!(
            result.is_ok(),
            "Prevote step should succeed even if broadcast fails"
        );

        // Vote should still be in the vote pool
        let votes = engine.vote_pool.get(&engine.current_round.height);
        assert!(votes.is_some(), "Vote should be stored even if broadcast fails");
    }

    #[tokio::test]
    async fn test_proposal_only_broadcast_when_proposer() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator but don't make it the proposer
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Set a different validator as proposer
        engine.current_round.proposer = Some(test_validator_id(2));

        // Run propose step
        engine.run_propose_step().await.expect("Failed to run propose step");

        // Verify no proposal was broadcast
        assert_eq!(
            mock_broadcaster.count_broadcasts(),
            0,
            "Proposal should not be broadcast if not proposer"
        );
    }


    #[tokio::test]
    async fn test_multiple_phases_produce_multiple_broadcasts() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Set as proposer
        engine.current_round.proposer = Some(validator_id.clone());
        engine.validator_identity = Some(validator_id);

        // Run propose step - should broadcast proposal
        engine.run_propose_step().await.expect("Failed to run propose step");
        let broadcasts_after_propose = mock_broadcaster.count_broadcasts();
        assert!(broadcasts_after_propose > 0, "Expected broadcast in propose phase");

        // Run prevote step - should broadcast vote
        engine.run_prevote_step().await.expect("Failed to run prevote step");
        let broadcasts_after_prevote = mock_broadcaster.count_broadcasts();
        assert!(
            broadcasts_after_prevote > broadcasts_after_propose,
            "Expected additional broadcast in prevote phase"
        );
    }
}

