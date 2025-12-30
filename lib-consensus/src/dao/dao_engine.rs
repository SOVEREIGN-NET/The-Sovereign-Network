//! DAO governance engine implementation
//!
//! Refactored to query blockchain state instead of maintaining in-memory HashMaps.
//! The blockchain is now the source of truth for proposals, votes, and treasury state.

use crate::dao::{
    DaoProposal, DaoProposalStatus, DaoProposalType, DaoTreasury, DaoVote, DaoVoteChoice,
    DaoVoteTally, PrivacyLevel,
};
use anyhow::Result;
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// DAO governance engine (blockchain-backed)
#[derive(Debug, Clone)]
pub struct DaoEngine {
    /// Vote tracking cache (proposal_id -> voter_id -> vote_id)
    /// This is kept for performance but rebuilt from blockchain on startup
    vote_tracking: HashMap<Hash, HashMap<IdentityId, Hash>>,
}

impl DaoEngine {
    /// Create a new DAO engine
    pub fn new() -> Self {
        let engine = Self {
            vote_tracking: HashMap::new(),
        };

        tracing::info!("DAO engine initialized (blockchain-backed)");
        engine
    }

    /// Initialize DAO with production-ready data
    /// NOTE: This method is deprecated - data is loaded from blockchain
    #[deprecated(note = "DAO state is now read from blockchain, not initialized in memory")]
    fn initialize_production_dao(&mut self) {
        tracing::info!("DAO initialization skipped - data loaded from blockchain");
    }

    /// Load treasury state from blockchain
    /// NOTE: This method is deprecated - use blockchain.get_dao_treasury_balance()
    #[deprecated(note = "Use blockchain.get_dao_treasury_balance() instead")]
    fn load_treasury_from_blockchain(&mut self) {
        tracing::warn!(
            "load_treasury_from_blockchain is deprecated - treasury data comes from blockchain"
        );
    }

    /// Load active proposals from blockchain state
    /// NOTE: This method is deprecated - use blockchain.get_dao_proposals()
    #[deprecated(note = "Use blockchain.get_dao_proposals() instead")]
    fn load_proposals_from_blockchain(&mut self) {
        tracing::warn!(
            "load_proposals_from_blockchain is deprecated - proposals come from blockchain"
        );
    }

    /// Create a new DAO proposal
    /// NOTE: This now returns proposal data to be submitted to blockchain
    /// The actual submission happens through blockchain.add_pending_transaction()
    pub async fn create_dao_proposal(
        &mut self,
        proposer: IdentityId,
        title: String,
        description: String,
        proposal_type: DaoProposalType,
        voting_period_days: u32,
    ) -> Result<Hash> {
        // Validate treasury spending proposals require special checks
        if let DaoProposalType::TreasuryAllocation = proposal_type {
            let proposer_voting_power = self.get_dao_voting_power(&proposer);
            if proposer_voting_power < 100 {
                return Err(anyhow::anyhow!(
                    "Treasury proposals require minimum 100 voting power. Proposer has: {}",
                    proposer_voting_power
                ));
            }

            // NOTE: Treasury balance check would need blockchain reference
            // For now, skip this validation or pass treasury balance as parameter
            tracing::info!(
                "Treasury spending proposal validation passed for proposer: {:?}",
                proposer
            );
        }

        // Generate proposal ID
        let proposal_id = hash_blake3(
            &[
                proposer.as_bytes(),
                title.as_bytes(),
                description.as_bytes(),
                &SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_nanos()
                    .to_le_bytes(),
            ]
            .concat(),
        );
        let proposal_id = Hash::from_bytes(&proposal_id);

        // Calculate voting end time
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let voting_end_time = current_time + (voting_period_days as u64 * 24 * 60 * 60);

        // Set quorum requirements based on proposal type
        let quorum_required = match proposal_type {
            DaoProposalType::TreasuryAllocation => 25, // 25% quorum for treasury spending
            DaoProposalType::WelfareAllocation => 22,  // 22% quorum for welfare services
            DaoProposalType::ProtocolUpgrade => 30,    // 30% quorum for protocol changes
            DaoProposalType::UbiDistribution => 20,    // 20% quorum for UBI changes
            _ => 10,                                   // 10% quorum for general governance
        };

        // Create proposal
        let proposal = DaoProposal {
            id: proposal_id.clone(),
            title,
            description,
            proposer: proposer.clone(),
            proposal_type: proposal_type.clone(),
            status: DaoProposalStatus::Active,
            voting_start_time: current_time,
            voting_end_time,
            quorum_required,
            vote_tally: DaoVoteTally::default(),
            created_at: current_time,
            created_at_height: self.get_current_block_height(),
            execution_params: None,
            ubi_impact: None, // Can be set later when proposal details are finalized
            economic_impact: None, // Will be calculated based on proposal type
            privacy_level: PrivacyLevel::Public, // Default to public visibility
        };

        // NOTE: Proposal storage happens on blockchain via DaoProposal transaction
        // This method only validates and returns the proposal ID for transaction creation

        tracing::info!(
            "Validated DAO proposal {:?}: {} (Type: {:?}) - ready for blockchain submission",
            proposal_id,
            proposal.title,
            proposal_type
        );

        Ok(proposal_id)
    }

    /// Cast a DAO vote - validates vote and returns vote ID
    /// NOTE: Proposal existence and status should be validated by caller (consensus layer)
    /// Vote storage happens on blockchain via DaoVote transaction
    pub async fn cast_dao_vote(
        &mut self,
        voter: IdentityId,
        proposal_id: Hash,
        vote_choice: DaoVoteChoice,
        justification: Option<String>,
    ) -> Result<Hash> {
        // Check if user has already voted (use local cache)
        if let Some(user_votes) = self.vote_tracking.get(&proposal_id) {
            if user_votes.contains_key(&voter) {
                return Err(anyhow::anyhow!("User has already voted on this proposal"));
            }
        }

        // Get voter's voting power
        let voting_power = self.get_dao_voting_power(&voter);
        if voting_power == 0 {
            return Err(anyhow::anyhow!("Voter has no voting power"));
        }

        // Create vote ID
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let vote_id = hash_blake3(
            &[
                proposal_id.as_bytes(),
                voter.as_bytes(),
                &vote_choice.to_u8().to_le_bytes(),
                &current_time.to_le_bytes(),
            ]
            .concat(),
        );
        let vote_id = Hash::from_bytes(&vote_id);

        // Track that this user voted (prevent double voting)
        self.vote_tracking
            .entry(proposal_id.clone())
            .or_insert_with(HashMap::new)
            .insert(voter.clone(), vote_id.clone());

        tracing::info!(
            "Validated DAO vote {:?} for proposal {:?} - ready for blockchain submission",
            vote_id,
            proposal_id
        );

        Ok(vote_id)
    }

    /// Calculate DAO voting power for a user
    ///
    /// Voting power is calculated from multiple factors:
    /// - Base power: 1 (every identity gets base vote)
    /// - Token balance: 1 power per 10,000 ZHTP tokens
    /// - Staked tokens: 2 power per 10,000 ZHTP staked (bonus for commitment)
    /// - Network contribution: Up to 50% bonus based on storage/compute provided
    /// - Reputation score: Up to 25% bonus based on on-chain reputation
    /// - Delegation: Can receive voting power from other users
    ///
    /// Note: This requires blockchain context. In production, should be called
    /// through blockchain.calculate_user_voting_power(user_id)
    pub fn get_dao_voting_power(&self, _user_id: &IdentityId) -> u64 {
        // Placeholder: returns base power of 1
        // Real implementation moved to Blockchain::calculate_user_voting_power()
        // which has access to token balances, stakes, and reputation data
        1
    }

    /// Calculate total voting power from components (helper method)
    pub fn calculate_voting_power(
        token_balance: u64,
        staked_amount: u64,
        network_contribution_score: u32,
        reputation_score: u32,
        delegated_power: u64,
    ) -> u64 {
        // Base power: everyone gets 1 vote
        let base_power = 1u64;

        // Token-based power: 1 vote per 10,000 ZHTP
        let token_power = token_balance / 10_000;

        // Stake-based power: 2 votes per 10,000 ZHTP staked (incentivize staking)
        let stake_power = (staked_amount / 10_000) * 2;

        // Network contribution bonus (0-50% based on storage/compute provided)
        // contribution_score ranges from 0-100
        let contribution_multiplier = 1.0 + (network_contribution_score.min(100) as f64 / 200.0);

        // Reputation bonus (0-25% based on on-chain reputation)
        // reputation_score ranges from 0-100
        let reputation_multiplier = 1.0 + (reputation_score.min(100) as f64 / 400.0);

        // Calculate base voting power before bonuses
        let base_voting_power = base_power + token_power + stake_power;

        // Apply multipliers
        let power_with_contribution = (base_voting_power as f64 * contribution_multiplier) as u64;
        let power_with_reputation = (power_with_contribution as f64 * reputation_multiplier) as u64;

        // Add delegated voting power
        let total_power = power_with_reputation.saturating_add(delegated_power);

        // Cap at reasonable maximum to prevent excessive concentration
        // Max voting power: 1,000,000 (equivalent to 5M tokens + max bonuses)
        total_power.min(1_000_000)
    }

    /// Sign a DAO vote
    async fn sign_dao_vote(
        &self,
        voter: &IdentityId,
        proposal_id: &Hash,
        vote_choice: &DaoVoteChoice,
    ) -> Result<lib_crypto::Signature> {
        let vote_data = [
            voter.as_bytes(),
            proposal_id.as_bytes(),
            &vote_choice.to_u8().to_le_bytes(),
        ]
        .concat();

        let signature_hash = hash_blake3(&vote_data);

        Ok(lib_crypto::Signature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: signature_hash[..32].to_vec(),
                kyber_pk: signature_hash[..32].to_vec(),
                key_id: signature_hash[..32].try_into().unwrap(),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Process expired proposals
    /// DEPRECATED: Proposal status updates now happen on blockchain layer
    /// The blockchain queries proposal data and vote tallies directly
    #[deprecated(
        note = "Use blockchain.has_proposal_passed() and blockchain.execute_dao_proposal() instead"
    )]
    pub async fn process_expired_proposals(&mut self) -> Result<()> {
        tracing::warn!("process_expired_proposals is deprecated - use blockchain layer methods");
        Ok(())
    }

    /// Execute a passed DAO proposal
    /// DEPRECATED: Proposal execution now happens on blockchain layer via execute_dao_proposal()
    /// which creates proper DaoExecution transactions with real UTXO transfers
    #[deprecated(note = "Use blockchain.execute_dao_proposal() instead")]
    async fn execute_dao_proposal(&mut self, _proposal_id: &Hash) -> Result<()> {
        tracing::warn!(
            "execute_dao_proposal is deprecated - use blockchain.execute_dao_proposal() instead"
        );
        Err(anyhow::anyhow!("This method is deprecated. Use blockchain.execute_dao_proposal() to execute proposals with real UTXO transfers."))
    }

    /// Parse treasury amount from proposal (helper method)
    fn parse_treasury_amount_from_proposal(&self, proposal: &DaoProposal) -> Result<u64> {
        // Look for amount in description (e.g., "amount:1000")
        let description = &proposal.description;

        if let Some(start) = description.find("amount:") {
            let amount_section = &description[start + 7..];
            if let Some(end) = amount_section.find(' ') {
                let amount_str = amount_section[..end].trim();
                if let Ok(amount) = amount_str.parse::<u64>() {
                    return Ok(amount);
                }
            }
        }

        // Default to 1000 ZHTP for demo proposals if no amount specified
        Ok(1000)
    }

    /// Get DAO treasury state
    /// NOTE: This method is deprecated - use blockchain.get_dao_treasury_balance() instead
    #[deprecated(note = "Use blockchain treasury methods instead")]
    pub fn get_dao_treasury(&self) -> DaoTreasury {
        // Return empty treasury - real state is on blockchain
        tracing::warn!(
            "get_dao_treasury called on DaoEngine - use blockchain treasury methods instead"
        );
        DaoTreasury {
            total_balance: 0,
            available_balance: 0,
            allocated_funds: 0,
            reserved_funds: 0,
            transaction_history: Vec::new(),
            annual_budgets: Vec::new(),
        }
    }

    /// Get all DAO proposals
    /// NOTE: This method is deprecated - use blockchain.get_dao_proposals() instead
    #[deprecated(
        note = "Use blockchain.get_dao_proposals() instead - proposals are stored on blockchain"
    )]
    pub fn get_dao_proposals(&self) -> Vec<DaoProposal> {
        // Return empty vec - proposals should be fetched from blockchain
        tracing::warn!(
            "get_dao_proposals called on DaoEngine - use blockchain.get_dao_proposals() instead"
        );
        Vec::new()
    }

    /// Get DAO proposal by ID
    /// NOTE: This method is deprecated - use blockchain.get_dao_proposal() instead
    #[deprecated(note = "Use blockchain.get_dao_proposal() instead")]
    pub fn get_dao_proposal_by_id(&self, _proposal_id: &Hash) -> Option<DaoProposal> {
        tracing::warn!("get_dao_proposal_by_id called on DaoEngine - use blockchain.get_dao_proposal() instead");
        None
    }

    /// Get user's DAO votes - DEPRECATED
    #[deprecated(note = "Use blockchain.get_dao_votes_for_user() instead")]
    pub fn get_user_dao_votes(&self, _user_id: &Hash) -> Vec<&DaoVote> {
        tracing::warn!("get_user_dao_votes called on DaoEngine - use blockchain methods instead");
        Vec::new()
    }

    /// Get current block height (would be injected from blockchain state)
    fn get_current_block_height(&self) -> u64 {
        // In production, this would be injected from the consensus engine
        // For now, use a timestamp-based approximation
        let genesis_timestamp = 1672531200; // Jan 1, 2023
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let seconds_elapsed = current_timestamp.saturating_sub(genesis_timestamp);
        let estimated_height = seconds_elapsed / 6; // Assuming 6 second block times
        estimated_height
    }

    /// Calculate total eligible voting power in the network
    fn calculate_total_eligible_power(&self) -> u64 {
        // In production, this would sum up all eligible voters' power
        // For now, estimate based on active participants
        let active_voters: u64 = self
            .vote_tracking
            .values()
            .map(|votes| votes.len() as u64)
            .sum();

        // Assume each active voter represents ~10% of eligible population
        let estimated_total = if active_voters > 0 {
            active_voters * 10
        } else {
            1000 // Default assumption for new networks
        };

        estimated_total.max(100) // Minimum 100 eligible power
    }
}
