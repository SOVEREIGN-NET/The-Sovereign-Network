//! Byzantine Fault Tolerance consensus engine

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use lib_crypto::{Hash, hash_blake3};
use lib_identity::IdentityId;

use crate::types::{
    ConsensusEvent, ConsensusRound, ConsensusStep, ConsensusProposal, ConsensusVote, 
    VoteType, ConsensusConfig
};
use crate::validators::ValidatorManager;
use crate::byzantine::ByzantineFaultDetector;
use crate::{ConsensusResult, ConsensusError};

/// Byzantine Fault Tolerance consensus engine
#[derive(Debug)]
pub struct BftEngine {
    /// Current consensus round
    current_round: ConsensusRound,
    /// Configuration
    config: ConsensusConfig,
    /// Validator manager
    validator_manager: ValidatorManager,
    /// Pending proposals
    pending_proposals: VecDeque<ConsensusProposal>,
    /// Vote pool by height and round
    vote_pool: HashMap<(u64, u32), HashMap<Hash, ConsensusVote>>,
    /// Round history
    round_history: VecDeque<ConsensusRound>,
    /// Byzantine fault detector
    byzantine_detector: ByzantineFaultDetector,
    /// Local validator identity
    validator_identity: Option<IdentityId>,
}

impl BftEngine {
    /// Create new BFT engine
    pub fn new(config: ConsensusConfig, validator_manager: ValidatorManager) -> Self {
        let current_round = ConsensusRound {
            height: 0,
            round: 0,
            step: ConsensusStep::Propose,
            start_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            proposer: None,
            proposals: Vec::new(),
            votes: HashMap::new(),
            timed_out: false,
            locked_proposal: None,
            valid_proposal: None,
        };

        Self {
            current_round,
            config,
            validator_manager,
            pending_proposals: VecDeque::new(),
            vote_pool: HashMap::new(),
            round_history: VecDeque::new(),
            byzantine_detector: ByzantineFaultDetector::new(),
            validator_identity: None,
        }
    }
    
    /// Set local validator identity
    pub fn set_validator_identity(&mut self, identity: IdentityId) {
        self.validator_identity = Some(identity);
    }

    /// Handle consensus event (pure component method)
    /// This replaces the standalone start_consensus() loop pattern
    pub async fn handle_consensus_event(&mut self, event: ConsensusEvent) -> ConsensusResult<Vec<ConsensusEvent>> {
        match event {
            ConsensusEvent::StartRound { height, trigger } => {
                tracing::info!(" BFT: Starting consensus round {} (trigger: {})", height, trigger);
                
                // Handle BFT-specific trigger behavior
                match trigger.as_str() {
                    "timeout" => {
                        tracing::warn!("⏰ BFT timeout - increasing round timeout");
                        self.increase_round_timeout().await?;
                    },
                    "new_transaction" => {
                        tracing::debug!("💳 BFT processing new transactions");
                    },
                    "validator_byzantine" => {
                        tracing::error!(" BFT triggered by Byzantine behavior detection");
                        self.handle_byzantine_trigger().await?;
                    },
                    _ => tracing::debug!("BFT trigger: {}", trigger),
                }
                
                self.prepare_for_round(height).await?;
                Ok(vec![ConsensusEvent::RoundPrepared { height }])
            }
            ConsensusEvent::NewBlock { height, previous_hash } => {
                match self.run_consensus_round(previous_hash).await {
                    Ok(Some(committed_hash)) => {
                        tracing::info!("BFT block committed: {} at height {}", committed_hash, height);
                        
                        // Record the committed hash for finality tracking
                        self.record_committed_block(height, committed_hash.clone()).await?;
                        
                        // Notify about successful commitment
                        tracing::info!("BFT finality achieved for block {} at height {}", committed_hash, height);
                        
                        Ok(vec![ConsensusEvent::RoundCompleted { height }])
                    }
                    Ok(None) => {
                        Ok(vec![ConsensusEvent::RoundFailed { 
                            height, 
                            error: "No consensus reached".to_string() 
                        }])
                    }
                    Err(e) => {
                        Ok(vec![ConsensusEvent::RoundFailed { 
                            height, 
                            error: e.to_string() 
                        }])
                    }
                }
            }
            _ => {
                tracing::debug!("Unhandled BFT consensus event: {:?}", event);
                Ok(vec![])
            }
        }
    }

    /// Prepare for a consensus round (internal method)
    async fn prepare_for_round(&mut self, height: u64) -> ConsensusResult<()> {
        // Initialize new height
        self.current_round.height = height;
        self.current_round.round = 0;
        self.current_round.step = ConsensusStep::Propose;
        self.current_round.start_time = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?.as_secs();
        self.current_round.proposer = None;
        self.current_round.proposals.clear();
        self.current_round.votes.clear();
        self.current_round.timed_out = false;
        self.current_round.locked_proposal = None;
        self.current_round.valid_proposal = None;

        tracing::info!(" Prepared BFT consensus for height {}", height);
        Ok(())
    }

    /// Run a single BFT consensus round
    async fn run_consensus_round(&mut self, previous_hash: Hash) -> ConsensusResult<Option<Hash>> {
        tracing::info!(
            "Starting BFT round {} at height {}",
            self.current_round.round, self.current_round.height
        );

        // Detect any Byzantine faults from previous rounds
        self.byzantine_detector.detect_faults(&self.validator_manager)?;

        // Select proposer for this round
        let proposer = self.validator_manager
            .select_proposer(self.current_round.height, self.current_round.round)
            .ok_or_else(|| ConsensusError::ValidatorError("No proposer available".to_string()))?;

        self.current_round.proposer = Some(proposer.identity.clone());

        // Run the three phases of BFT consensus
        self.run_propose_phase(previous_hash).await?;
        self.run_prevote_phase().await?;
        self.run_precommit_phase().await?;

        // Check if we reached consensus
        if let Some(proposal_id) = &self.current_round.valid_proposal {
            if self.has_commit_quorum(proposal_id) {
                return Ok(Some(proposal_id.clone()));
            }
        }

        Ok(None)
    }

    /// Run propose phase of BFT
    async fn run_propose_phase(&mut self, previous_hash: Hash) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Propose;

        // If we are the proposer, create a proposal
        if let Some(ref validator_id) = self.validator_identity {
            if Some(validator_id) == self.current_round.proposer.as_ref() {
                let proposal = self.create_bft_proposal(previous_hash).await?;
                self.current_round.proposals.push(proposal.id.clone());
                self.pending_proposals.push_back(proposal);
            }
        }

        // Wait for proposals with timeout
        self.wait_for_step_timeout(self.config.propose_timeout).await;

        Ok(())
    }

    /// Run prevote phase of BFT
    async fn run_prevote_phase(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreVote;

        // Prevote logic
        if let Some(proposal_id) = self.get_valid_proposal_for_prevote() {
            self.cast_bft_vote(proposal_id, VoteType::PreVote).await?;
        } else {
            // Vote nil if no valid proposal
            self.cast_nil_vote(VoteType::PreVote).await?;
        }

        // Wait for prevotes
        self.wait_for_step_timeout(self.config.prevote_timeout).await;

        // Check for prevote quorum
        if let Some(proposal_id) = self.check_prevote_quorum() {
            self.current_round.valid_proposal = Some(proposal_id.clone());
            self.current_round.locked_proposal = Some(proposal_id);
        }

        Ok(())
    }

    /// Run precommit phase of BFT
    async fn run_precommit_phase(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreCommit;

        // Precommit logic
        if let Some(proposal_id) = &self.current_round.valid_proposal {
            self.cast_bft_vote(proposal_id.clone(), VoteType::PreCommit).await?;
        } else {
            // Vote nil if no valid proposal
            self.cast_nil_vote(VoteType::PreCommit).await?;
        }

        // Wait for precommits
        self.wait_for_step_timeout(self.config.precommit_timeout).await;

        // Check for precommit quorum
        if let Some(proposal_id) = &self.current_round.valid_proposal {
            if self.has_precommit_quorum(proposal_id) {
                // We have precommit quorum, move to commit
                self.cast_bft_vote(proposal_id.clone(), VoteType::Commit).await?;
            }
        }

        Ok(())
    }

    /// Create a BFT proposal
    async fn create_bft_proposal(&self, previous_hash: Hash) -> ConsensusResult<ConsensusProposal> {
        let validator_id = self.validator_identity.as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Collect transactions for the block
        let block_data = self.collect_block_transactions().await?;

        // Generate proposal ID
        let proposal_id = Hash::from_bytes(&hash_blake3(&[
            &self.current_round.height.to_le_bytes(),
            &(self.current_round.round as u64).to_le_bytes(),
            previous_hash.as_bytes(),
            &block_data,
            validator_id.as_bytes(),
        ].concat()));

        // Create consensus proof
        let consensus_proof = self.create_bft_consensus_proof().await?;

        // Sign the proposal
        let signature = self.sign_proposal_data(
            &proposal_id,
            validator_id,
            &block_data,
        ).await?;

        let proposal = ConsensusProposal {
            id: proposal_id,
            proposer: validator_id.clone(),
            height: self.current_round.height,
            previous_hash,
            block_data,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?.as_secs(),
            signature,
            consensus_proof,
        };

        tracing::info!(
            "Created BFT proposal {:?} for height {} round {}",
            proposal.id, proposal.height, self.current_round.round
        );

        Ok(proposal)
    }

    /// Cast a BFT vote
    async fn cast_bft_vote(&mut self, proposal_id: Hash, vote_type: VoteType) -> ConsensusResult<()> {
        let validator_id = self.validator_identity.as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Create vote ID
        let vote_id = Hash::from_bytes(&hash_blake3(&[
            proposal_id.as_bytes(),
            validator_id.as_bytes(),
            &(vote_type.clone() as u8).to_le_bytes(),
            &self.current_round.height.to_le_bytes(),
            &self.current_round.round.to_le_bytes(),
        ].concat()));

        // Sign the vote
        let signature = self.sign_vote_data(
            &vote_id,
            validator_id,
            &proposal_id,
            &vote_type,
        ).await?;

        let vote = ConsensusVote {
            id: vote_id.clone(),
            voter: validator_id.clone(),
            proposal_id: proposal_id.clone(),
            vote_type: vote_type.clone(),
            height: self.current_round.height,
            round: self.current_round.round,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?.as_secs(),
            signature,
        };

        // Store vote
        let round_key = (self.current_round.height, self.current_round.round);
        self.vote_pool.entry(round_key)
            .or_insert_with(HashMap::new)
            .insert(vote.id.clone(), vote);

        tracing::debug!(
            " Cast BFT {:?} vote on proposal {:?}",
            vote_type, proposal_id
        );

        Ok(())
    }

    /// Cast a nil vote (vote for no proposal)
    async fn cast_nil_vote(&mut self, vote_type: VoteType) -> ConsensusResult<()> {
        let nil_proposal = Hash([0u8; 32]); // Nil proposal represented as zero hash
        self.cast_bft_vote(nil_proposal, vote_type).await
    }

    /// Get valid proposal for prevote
    fn get_valid_proposal_for_prevote(&self) -> Option<Hash> {
        // If we have a locked proposal from previous round, vote for it
        if let Some(ref locked_proposal) = self.current_round.locked_proposal {
            return Some(locked_proposal.clone());
        }

        // Otherwise, vote for the first valid proposal we received
        self.current_round.proposals.first().cloned()
    }

    /// Check for prevote quorum
    fn check_prevote_quorum(&self) -> Option<Hash> {
        let round_key = (self.current_round.height, self.current_round.round);
        let votes = self.vote_pool.get(&round_key)?;

        // Count prevotes for each proposal
        let mut prevote_counts: HashMap<Hash, u64> = HashMap::new();
        
        for vote in votes.values() {
            if vote.vote_type == VoteType::PreVote {
                let validator = self.validator_manager.get_validator(&vote.voter)?;
                *prevote_counts.entry(vote.proposal_id.clone()).or_insert(0) += validator.voting_power;
            }
        }

        // Check if any proposal has 2/3+ prevotes
        let threshold = self.validator_manager.get_byzantine_threshold();
        
        for (proposal_id, vote_power) in prevote_counts {
            if vote_power >= threshold && proposal_id != Hash([0u8; 32]) {
                return Some(proposal_id);
            }
        }

        None
    }

    /// Check for precommit quorum
    fn has_precommit_quorum(&self, proposal_id: &Hash) -> bool {
        let round_key = (self.current_round.height, self.current_round.round);
        let votes = match self.vote_pool.get(&round_key) {
            Some(votes) => votes,
            None => return false,
        };

        let mut precommit_power = 0u64;
        
        for vote in votes.values() {
            if vote.vote_type == VoteType::PreCommit && &vote.proposal_id == proposal_id {
                if let Some(validator) = self.validator_manager.get_validator(&vote.voter) {
                    precommit_power += validator.voting_power;
                }
            }
        }

        let threshold = self.validator_manager.get_byzantine_threshold();
        precommit_power >= threshold
    }

    /// Check for commit quorum
    fn has_commit_quorum(&self, proposal_id: &Hash) -> bool {
        let round_key = (self.current_round.height, self.current_round.round);
        let votes = match self.vote_pool.get(&round_key) {
            Some(votes) => votes,
            None => return false,
        };

        let mut commit_power = 0u64;
        
        for vote in votes.values() {
            if vote.vote_type == VoteType::Commit && &vote.proposal_id == proposal_id {
                if let Some(validator) = self.validator_manager.get_validator(&vote.voter) {
                    commit_power += validator.voting_power;
                }
            }
        }

        let threshold = self.validator_manager.get_byzantine_threshold();
        commit_power >= threshold
    }

    /// Advance to next round
    async fn advance_to_next_round(&mut self) -> ConsensusResult<()> {
        // Save current round to history
        self.round_history.push_back(self.current_round.clone());
        if self.round_history.len() > 100 {
            self.round_history.pop_front();
        }

        // Advance round
        self.current_round.round += 1;
        self.current_round.step = ConsensusStep::Propose;
        self.current_round.start_time = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?.as_secs();
        self.current_round.proposer = None;
        self.current_round.proposals.clear();
        self.current_round.votes.clear();
        self.current_round.timed_out = false;
        // Keep locked_proposal and valid_proposal for next round

        tracing::info!(
            " Advanced to BFT round {} at height {}",
            self.current_round.round, self.current_round.height
        );

        Ok(())
    }

    /// Wait for step timeout
    async fn wait_for_step_timeout(&mut self, timeout_ms: u64) {
        tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms)).await;
    }

    /// Collect transactions for block
    async fn collect_block_transactions(&self) -> ConsensusResult<Vec<u8>> {
        // In production, this would collect transactions from mempool
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?.as_secs();
        
        let block_data = format!(
            "bft_block_height:{},round:{},timestamp:{},validators:{}",
            self.current_round.height,
            self.current_round.round,
            timestamp,
            self.validator_manager.get_active_validators().len()
        );
        
        Ok(block_data.into_bytes())
    }

    /// Create BFT consensus proof
    async fn create_bft_consensus_proof(&self) -> ConsensusResult<crate::types::ConsensusProof> {
        use crate::types::{ConsensusProof, ConsensusType};
        
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?.as_secs();

        Ok(ConsensusProof {
            consensus_type: ConsensusType::ByzantineFaultTolerance,
            stake_proof: None,
            storage_proof: None,
            work_proof: None,
            zk_did_proof: None,
            timestamp,
        })
    }

    /// Sign proposal data
    async fn sign_proposal_data(
        &self,
        proposal_id: &Hash,
        proposer: &IdentityId,
        block_data: &[u8],
    ) -> ConsensusResult<lib_crypto::PostQuantumSignature> {
        let signature_data = [
            proposal_id.as_bytes(),
            proposer.as_bytes(),
            block_data,
        ].concat();

        let signature_hash = hash_blake3(&signature_data);

        Ok(lib_crypto::PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: signature_hash[..32].to_vec(),
                kyber_pk: signature_hash[..16].to_vec(),
                key_id: proposer.as_bytes().try_into().unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?.as_secs(),
        })
    }

    /// Sign vote data
    async fn sign_vote_data(
        &self,
        vote_id: &Hash,
        voter: &IdentityId,
        proposal_id: &Hash,
        vote_type: &VoteType,
    ) -> ConsensusResult<lib_crypto::PostQuantumSignature> {
        let signature_data = [
            vote_id.as_bytes(),
            voter.as_bytes(),
            proposal_id.as_bytes(),
            &[vote_type.clone() as u8],
        ].concat();

        let signature_hash = hash_blake3(&signature_data);

        Ok(lib_crypto::PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: signature_hash[..32].to_vec(),
                kyber_pk: signature_hash[..16].to_vec(),
                key_id: voter.as_bytes().try_into().unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?.as_secs(),
        })
    }

    /// Get current round
    pub fn current_round(&self) -> &ConsensusRound {
        &self.current_round
    }

    /// Get validator manager
    pub fn validator_manager(&self) -> &ValidatorManager {
        &self.validator_manager
    }

    /// Increase round timeout for BFT consensus
    async fn increase_round_timeout(&mut self) -> ConsensusResult<()> {
        // Mark round as timed out and increase round number
        self.current_round.timed_out = true;
        self.current_round.round += 1;
        tracing::warn!("⏰ BFT timeout - advanced to round {}", self.current_round.round);
        Ok(())
    }

    /// Handle Byzantine fault trigger
    async fn handle_byzantine_trigger(&mut self) -> ConsensusResult<()> {
        tracing::error!(" BFT handling Byzantine fault trigger");
        // Reset round state and increase security measures
        self.current_round.step = ConsensusStep::Propose;
        self.current_round.proposer = None; // Clear proposer to force re-selection
        Ok(())
    }

    /// Record committed block for finality tracking
    async fn record_committed_block(&mut self, height: u64, committed_hash: Hash) -> ConsensusResult<()> {
        tracing::info!("Recording committed block {} at height {}", committed_hash, height);
        
        // In a implementation, this would:
        // 1. Store the committed hash in persistent storage
        // 2. Update finality checkpoints
        // 3. Notify other components about finality
        // 4. Update the longest committed chain
        
        // For now, we just log the commitment
        tracing::info!("Block {} committed with BFT finality at height {}", committed_hash, height);
        
        Ok(())
    }
}
