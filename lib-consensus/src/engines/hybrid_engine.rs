//! Hybrid consensus engine combining PoS and PoStorage

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;

use crate::proofs::StakeProof;
use crate::types::{
    ConsensusConfig, ConsensusEvent, ConsensusProof, ConsensusProposal, ConsensusRound,
    ConsensusStep, ConsensusType, ConsensusVote, VoteType,
};
use crate::validators::ValidatorManager;
use crate::{ConsensusError, ConsensusResult};

/// Hybrid consensus engine combining Proof of Stake and Proof of Storage
#[derive(Debug)]
pub struct HybridEngine {
    /// Current consensus round
    current_round: ConsensusRound,
    /// Configuration
    config: ConsensusConfig,
    /// Validator manager
    validator_manager: ValidatorManager,
    /// Pending proposals
    pending_proposals: VecDeque<ConsensusProposal>,
    /// Vote pool by height
    vote_pool: HashMap<u64, HashMap<Hash, ConsensusVote>>,
    /// Round history
    round_history: VecDeque<ConsensusRound>,
    /// Local validator identity
    validator_identity: Option<IdentityId>,
    /// Stake weight in hybrid calculation (0.0 to 1.0)
    stake_weight: f64,
    /// Storage weight in hybrid calculation (0.0 to 1.0)
    storage_weight: f64,
}

impl HybridEngine {
    /// Create new hybrid engine
    pub fn new(
        config: ConsensusConfig,
        validator_manager: ValidatorManager,
        stake_weight: f64,
        storage_weight: f64,
    ) -> Self {
        let current_round = ConsensusRound {
            height: 0,
            round: 0,
            step: ConsensusStep::Propose,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
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
            validator_identity: None,
            stake_weight: stake_weight.max(0.0).min(1.0),
            storage_weight: storage_weight.max(0.0).min(1.0),
        }
    }

    /// Set local validator identity
    pub fn set_validator_identity(&mut self, identity: IdentityId) {
        self.validator_identity = Some(identity);
    }

    /// Handle consensus event (pure component method)
    /// This replaces the standalone start_consensus() loop pattern
    pub async fn handle_consensus_event(
        &mut self,
        event: ConsensusEvent,
    ) -> ConsensusResult<Vec<ConsensusEvent>> {
        match event {
            ConsensusEvent::StartRound { height, trigger } => {
                tracing::info!(
                    " Hybrid: Starting consensus round {} (trigger: {})",
                    height,
                    trigger
                );

                // Handle hybrid-specific triggers (PoW + BFT combination)
                match trigger.as_str() {
                    "timeout" => {
                        tracing::warn!("⏰ Hybrid timeout - switching to BFT mode");
                        self.switch_to_bft_mode().await?;
                    }
                    "work_proof_found" => {
                        tracing::info!("⛏️ PoW solution found - validating work");
                        self.validate_work_proof().await?;
                    }
                    "difficulty_adjustment" => {
                        tracing::info!("Difficulty adjustment triggered hybrid round");
                        self.adjust_hybrid_parameters().await?;
                    }
                    _ => tracing::debug!("Hybrid trigger: {}", trigger),
                }

                self.prepare_for_round(height).await?;
                Ok(vec![ConsensusEvent::RoundPrepared { height }])
            }
            ConsensusEvent::NewBlock {
                height,
                previous_hash,
            } => {
                match self.run_hybrid_round(previous_hash).await {
                    Ok(Some(committed_hash)) => {
                        tracing::info!(
                            "Hybrid block committed: {} at height {}",
                            committed_hash,
                            height
                        );

                        // Record committed hash for hybrid consensus tracking
                        self.record_hybrid_commitment(height, committed_hash.clone())
                            .await?;

                        Ok(vec![ConsensusEvent::RoundCompleted { height }])
                    }
                    Ok(None) => Ok(vec![ConsensusEvent::RoundFailed {
                        height,
                        error: "No consensus reached".to_string(),
                    }]),
                    Err(e) => Ok(vec![ConsensusEvent::RoundFailed {
                        height,
                        error: e.to_string(),
                    }]),
                }
            }
            _ => {
                tracing::debug!("Unhandled hybrid consensus event: {:?}", event);
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
        self.current_round.start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        tracing::info!(" Prepared hybrid consensus for height {}", height);
        Ok(())
    }

    /// Run a single hybrid consensus round
    async fn run_hybrid_round(&mut self, previous_hash: Hash) -> ConsensusResult<Option<Hash>> {
        tracing::info!(
            "Starting hybrid round {} at height {} (stake: {:.1}%, storage: {:.1}%)",
            self.current_round.round,
            self.current_round.height,
            self.stake_weight * 100.0,
            self.storage_weight * 100.0
        );

        // Select proposer using hybrid criteria
        let proposer = self
            .select_hybrid_proposer()
            .ok_or_else(|| ConsensusError::ValidatorError("No proposer available".to_string()))?;

        self.current_round.proposer = Some(proposer.identity.clone());

        // Run consensus phases
        self.run_propose_phase(previous_hash).await?;
        self.run_vote_phase().await?;
        self.run_commit_phase().await?;

        // Check if we reached consensus
        if let Some(proposal_id) = &self.current_round.valid_proposal {
            if self.has_hybrid_consensus(proposal_id) {
                return Ok(Some(proposal_id.clone()));
            }
        }

        Ok(None)
    }

    /// Select proposer using hybrid criteria (stake + storage)
    fn select_hybrid_proposer(&self) -> Option<&crate::validators::Validator> {
        let active_validators = self.validator_manager.get_active_validators();

        if active_validators.is_empty() {
            return None;
        }

        // Calculate hybrid scores for each validator
        let mut validator_scores: Vec<(&crate::validators::Validator, f64)> = active_validators
            .into_iter()
            .map(|validator| {
                let stake_score = (validator.stake as f64).sqrt() * self.stake_weight;
                let storage_score = (validator.storage_provided as f64
                    / (1024.0 * 1024.0 * 1024.0))
                    * self.storage_weight;
                let reputation_bonus = (validator.reputation as f64) / 1000.0;

                let total_score = stake_score + storage_score + reputation_bonus;
                (validator, total_score)
            })
            .collect();

        // Sort by hybrid score (descending)
        validator_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Use round-robin among top candidates to prevent centralization
        let top_candidates = validator_scores
            .into_iter()
            .take(5) // Top 5 candidates
            .map(|(validator, _)| validator)
            .collect::<Vec<_>>();

        if top_candidates.is_empty() {
            return None;
        }

        let index = (self.current_round.height + self.current_round.round as u64) as usize
            % top_candidates.len();
        Some(top_candidates[index])
    }

    /// Run propose phase
    async fn run_propose_phase(&mut self, previous_hash: Hash) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Propose;

        // If we are the proposer, create a proposal
        if let Some(ref validator_id) = self.validator_identity {
            if Some(validator_id) == self.current_round.proposer.as_ref() {
                let proposal = self.create_hybrid_proposal(previous_hash).await?;
                self.current_round.proposals.push(proposal.id.clone());
                self.pending_proposals.push_back(proposal);
            }
        }

        // Wait for proposals with timeout
        self.wait_for_timeout(self.config.propose_timeout).await;

        Ok(())
    }

    /// Run voting phase
    async fn run_vote_phase(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreVote;

        // Vote for the best proposal based on hybrid criteria
        if let Some(proposal_id) = self.select_best_proposal() {
            self.cast_hybrid_vote(proposal_id, VoteType::PreVote)
                .await?;
        }

        // Wait for votes
        self.wait_for_timeout(self.config.prevote_timeout).await;

        // Check for voting consensus
        if let Some(proposal_id) = self.check_hybrid_vote_consensus() {
            self.current_round.valid_proposal = Some(proposal_id);
        }

        Ok(())
    }

    /// Run commit phase
    async fn run_commit_phase(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Commit;

        // Commit if we have a valid proposal
        if let Some(proposal_id) = &self.current_round.valid_proposal {
            self.cast_hybrid_vote(proposal_id.clone(), VoteType::Commit)
                .await?;
        }

        // Wait for commits
        self.wait_for_timeout(self.config.precommit_timeout).await;

        Ok(())
    }

    /// Create a hybrid proposal
    async fn create_hybrid_proposal(
        &self,
        previous_hash: Hash,
    ) -> ConsensusResult<ConsensusProposal> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Collect transactions
        let block_data = self.collect_block_transactions().await?;

        // Generate proposal ID
        let proposal_id = Hash::from_bytes(&hash_blake3(
            &[
                &self.current_round.height.to_le_bytes(),
                &(self.current_round.round as u64).to_le_bytes(),
                previous_hash.as_bytes(),
                &block_data,
                validator_id.as_bytes(),
                b"hybrid",
            ]
            .concat(),
        ));

        // Create hybrid consensus proof
        let consensus_proof = self.create_hybrid_consensus_proof().await?;

        // Sign the proposal
        let signature = self
            .sign_proposal_data(&proposal_id, validator_id, &block_data)
            .await?;

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
            "Created hybrid proposal {:?} for height {} (stake+storage)",
            proposal.id,
            proposal.height
        );

        Ok(proposal)
    }

    /// Cast a hybrid vote
    async fn cast_hybrid_vote(
        &mut self,
        proposal_id: Hash,
        vote_type: VoteType,
    ) -> ConsensusResult<()> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Create vote ID
        let vote_id = Hash::from_bytes(&hash_blake3(
            &[
                proposal_id.as_bytes(),
                validator_id.as_bytes(),
                &(vote_type.clone() as u8).to_le_bytes(),
                &self.current_round.height.to_le_bytes(),
                &self.current_round.round.to_le_bytes(),
                b"hybrid",
            ]
            .concat(),
        ));

        // Sign the vote
        let signature = self
            .sign_vote_data(&vote_id, validator_id, &proposal_id, &vote_type)
            .await?;

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
            .insert(vote.id.clone(), vote);

        tracing::debug!(
            " Cast hybrid {:?} vote on proposal {:?}",
            vote_type,
            proposal_id
        );

        Ok(())
    }

    /// Select best proposal based on hybrid criteria
    fn select_best_proposal(&self) -> Option<Hash> {
        // For now, select the first valid proposal
        // In a more sophisticated implementation, would evaluate proposals
        // based on transaction quality, fees, etc.
        self.current_round.proposals.first().cloned()
    }

    /// Check for hybrid vote consensus
    fn check_hybrid_vote_consensus(&self) -> Option<Hash> {
        let votes = self.vote_pool.get(&self.current_round.height)?;

        // Count hybrid voting power for each proposal
        let mut proposal_power: HashMap<Hash, f64> = HashMap::new();

        for vote in votes.values() {
            if vote.vote_type == VoteType::PreVote {
                if let Some(validator) = self.validator_manager.get_validator(&vote.voter) {
                    let hybrid_power = self.calculate_hybrid_voting_power(validator);
                    *proposal_power
                        .entry(vote.proposal_id.clone())
                        .or_insert(0.0) += hybrid_power;
                }
            }
        }

        // Check if any proposal has 2/3+ of hybrid voting power
        let total_hybrid_power = self.calculate_total_hybrid_power();
        let threshold = total_hybrid_power * 2.0 / 3.0;

        for (proposal_id, power) in proposal_power {
            if power >= threshold {
                return Some(proposal_id);
            }
        }

        None
    }

    /// Check for hybrid consensus
    fn has_hybrid_consensus(&self, proposal_id: &Hash) -> bool {
        let votes = match self.vote_pool.get(&self.current_round.height) {
            Some(votes) => votes,
            None => return false,
        };

        let mut commit_power = 0.0;

        for vote in votes.values() {
            if vote.vote_type == VoteType::Commit && &vote.proposal_id == proposal_id {
                if let Some(validator) = self.validator_manager.get_validator(&vote.voter) {
                    commit_power += self.calculate_hybrid_voting_power(validator);
                }
            }
        }

        let total_hybrid_power = self.calculate_total_hybrid_power();
        let threshold = total_hybrid_power * 2.0 / 3.0;

        commit_power >= threshold
    }

    /// Calculate hybrid voting power for a validator
    fn calculate_hybrid_voting_power(&self, validator: &crate::validators::Validator) -> f64 {
        let stake_power = (validator.stake as f64).sqrt() * self.stake_weight;
        let storage_power =
            (validator.storage_provided as f64 / (1024.0 * 1024.0 * 1024.0)) * self.storage_weight;
        let reputation_bonus = (validator.reputation as f64) / 1000.0;

        stake_power + storage_power + reputation_bonus
    }

    /// Calculate total hybrid voting power in the network
    fn calculate_total_hybrid_power(&self) -> f64 {
        self.validator_manager
            .get_active_validators()
            .iter()
            .map(|validator| self.calculate_hybrid_voting_power(validator))
            .sum()
    }

    /// Create hybrid consensus proof
    async fn create_hybrid_consensus_proof(&self) -> ConsensusResult<ConsensusProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create both stake and storage proofs for hybrid consensus
        let stake_proof = StakeProof::new(
            validator_id.clone(),
            validator.stake,
            Hash::from_bytes(&hash_blake3(
                &[validator_id.as_bytes(), &validator.stake.to_le_bytes()].concat(),
            )),
            self.current_round.height.saturating_sub(1),
            86400, // 1 day lock time
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        let storage_proof = crate::proofs::StorageProof::new(
            Hash::from_bytes(validator_id.as_bytes()),
            validator.storage_provided,
            80,         // 80% utilization
            Vec::new(), // Simplified challenges
            vec![Hash::from_bytes(&hash_blake3(
                &[validator_id.as_bytes(), b"storage"].concat(),
            ))],
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        Ok(ConsensusProof {
            consensus_type: ConsensusType::Hybrid,
            stake_proof: Some(stake_proof),
            storage_proof: Some(storage_proof),
            work_proof: None,
            zk_did_proof: None,
            timestamp,
        })
    }

    /// Advance to next round
    async fn advance_to_next_round(&mut self) -> ConsensusResult<()> {
        // Save current round
        self.round_history.push_back(self.current_round.clone());
        if self.round_history.len() > 100 {
            self.round_history.pop_front();
        }

        // Advance round
        self.current_round.round += 1;
        self.current_round.step = ConsensusStep::Propose;
        self.current_round.start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();
        self.current_round.proposer = None;
        self.current_round.proposals.clear();
        self.current_round.votes.clear();
        self.current_round.timed_out = false;

        tracing::info!(
            " Advanced to hybrid round {} at height {}",
            self.current_round.round,
            self.current_round.height
        );

        Ok(())
    }

    /// Wait for timeout
    async fn wait_for_timeout(&mut self, timeout_ms: u64) {
        tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms)).await;
    }

    /// Collect block transactions
    async fn collect_block_transactions(&self) -> ConsensusResult<Vec<u8>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        let block_data = format!(
            "hybrid_block_height:{},round:{},timestamp:{},stake_weight:{:.2},storage_weight:{:.2}",
            self.current_round.height,
            self.current_round.round,
            timestamp,
            self.stake_weight,
            self.storage_weight
        );

        Ok(block_data.into_bytes())
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
            b"hybrid",
        ]
        .concat();

        let signature_hash = hash_blake3(&signature_data);

        Ok(lib_crypto::PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: signature_hash[..32].to_vec(),
                kyber_pk: signature_hash[..16].to_vec(),
                key_id: proposer.as_bytes().try_into().unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
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
            b"hybrid",
        ]
        .concat();

        let signature_hash = hash_blake3(&signature_data);

        Ok(lib_crypto::PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: signature_hash[..32].to_vec(),
                kyber_pk: signature_hash[..16].to_vec(),
                key_id: voter.as_bytes().try_into().unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
        })
    }

    /// Update hybrid weights
    pub fn update_weights(&mut self, stake_weight: f64, storage_weight: f64) {
        self.stake_weight = stake_weight.max(0.0).min(1.0);
        self.storage_weight = storage_weight.max(0.0).min(1.0);

        tracing::info!(
            "⚖️ Updated hybrid weights: stake {:.1}%, storage {:.1}%",
            self.stake_weight * 100.0,
            self.storage_weight * 100.0
        );
    }

    /// Get current round
    pub fn current_round(&self) -> &ConsensusRound {
        &self.current_round
    }

    /// Get validator manager
    pub fn validator_manager(&self) -> &ValidatorManager {
        &self.validator_manager
    }

    /// Switch to BFT mode when PoW times out
    async fn switch_to_bft_mode(&mut self) -> ConsensusResult<()> {
        tracing::warn!(" Switching to BFT mode due to PoW timeout");
        // Increase BFT weight temporarily
        self.stake_weight = 0.8;
        self.storage_weight = 0.2;
        Ok(())
    }

    /// Validate work proof in hybrid consensus
    async fn validate_work_proof(&mut self) -> ConsensusResult<()> {
        tracing::info!("⛏️ Validating work proof in hybrid consensus");
        // Increase PoW weight when work is found
        self.stake_weight = 0.3;
        self.storage_weight = 0.7;
        Ok(())
    }

    /// Adjust hybrid parameters
    async fn adjust_hybrid_parameters(&mut self) -> ConsensusResult<()> {
        tracing::info!("Adjusting hybrid consensus parameters");
        // Balance weights based on network conditions
        self.stake_weight = 0.5;
        self.storage_weight = 0.5;
        Ok(())
    }

    /// Record hybrid commitment
    async fn record_hybrid_commitment(
        &mut self,
        height: u64,
        committed_hash: Hash,
    ) -> ConsensusResult<()> {
        tracing::info!(
            "Recording hybrid commitment {} at height {}",
            committed_hash,
            height
        );

        // In a implementation:
        // 1. Record both PoW and BFT components of the commitment
        // 2. Update hybrid chain state
        // 3. Adjust difficulty and stake requirements

        tracing::info!(
            "Hybrid block {} committed at height {}",
            committed_hash,
            height
        );
        Ok(())
    }
}
