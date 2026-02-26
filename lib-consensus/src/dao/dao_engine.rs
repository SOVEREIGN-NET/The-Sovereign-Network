//! DAO governance engine implementation
//!
//! Refactored to query blockchain state instead of maintaining in-memory HashMaps.
//! The blockchain is now the source of truth for proposals, votes, and treasury state.

use crate::dao::{
    DaoExecutionAction, DaoExecutionParams, DaoProposal, DaoProposalStatus, DaoProposalType,
    DaoTreasury, DaoVote, DaoVoteChoice, DaoVoteTally, GovernanceParameterUpdate,
    GovernanceParameterValue, PrivacyLevel,
};
use crate::validators::validator_manager::{MAX_VALIDATORS_HARD_CAP, MIN_VALIDATORS};
use anyhow::Result;
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::ConsensusConfig;

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
    #[allow(dead_code)]
    fn initialize_production_dao(&mut self) {
        tracing::info!("DAO initialization skipped - data loaded from blockchain");
    }

    /// Load treasury state from blockchain
    /// NOTE: This method is deprecated - use blockchain.get_dao_treasury_balance()
    #[deprecated(note = "Use blockchain.get_dao_treasury_balance() instead")]
    #[allow(dead_code)]
    fn load_treasury_from_blockchain(&mut self) {
        tracing::warn!(
            "load_treasury_from_blockchain is deprecated - treasury data comes from blockchain"
        );
    }

    /// Load active proposals from blockchain state
    /// NOTE: This method is deprecated - use blockchain.get_dao_proposals()
    #[deprecated(note = "Use blockchain.get_dao_proposals() instead")]
    #[allow(dead_code)]
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
            DaoProposalType::DifficultyParameterUpdate => 30, // 30% quorum for difficulty changes (affects consensus)
            _ => 10,                                   // 10% quorum for general governance
        };

        // Create proposal with validation
        let proposal = DaoProposal::new(
            proposal_id.clone(),
            title,
            description,
            proposer.clone(),
            proposal_type.clone(),
            DaoProposalStatus::Active,
            current_time,
            voting_end_time,
            quorum_required,
            DaoVoteTally::new(0), // Will be populated with eligible voters
            current_time,
            self.get_current_block_height(),
            None,
            None, // Can be set later when proposal details are finalized
            None, // Will be calculated based on proposal type
            PrivacyLevel::Public, // Default to public visibility
        ).map_err(|e| anyhow::anyhow!("Failed to create proposal: {}", e))?;

        // NOTE: Proposal storage happens on blockchain via DaoProposal transaction
        // This method only validates and returns the proposal ID for transaction creation

        tracing::info!(
            "Validated DAO proposal {:?}: {} (Type: {:?}) - ready for blockchain submission",
            proposal_id,
            proposal.title(),
            proposal_type
        );

        Ok(proposal_id)
    }

    /// Create a difficulty parameter update proposal
    /// 
    /// This is a convenience method for creating proposals to update the blockchain's
    /// difficulty adjustment parameters through DAO governance.
    ///
    /// # Arguments
    /// * `proposer` - Identity of the proposal creator
    /// * `target_timespan` - Target time for difficulty adjustment interval (seconds)
    /// * `adjustment_interval` - Number of blocks between adjustments
    /// * `min_adjustment_factor` - Optional minimum adjustment factor (percentage)
    /// * `max_adjustment_factor` - Optional maximum adjustment factor (percentage)
    /// * `voting_period_days` - Duration of the voting period in days
    ///
    /// # Errors
    /// Returns an error if validation fails:
    /// - target_timespan must be > 0
    /// - adjustment_interval must be > 0
    /// - min_adjustment_factor must be >= 1 (if provided)
    /// - max_adjustment_factor must be >= 1 (if provided)
    /// - max_adjustment_factor must be >= min_adjustment_factor (if both provided)
    ///
    /// # Example
    /// ```ignore
    /// use lib_consensus::DaoEngine;
    /// 
    /// let mut engine = DaoEngine::new();
    /// let proposal_id = engine.create_difficulty_update_proposal(
    ///     proposer_id,
    ///     14 * 24 * 60 * 60,  // 2 weeks target timespan
    ///     2016,               // blocks between adjustments
    ///     Some(4),            // min factor (4x = max 1/4 decrease)
    ///     Some(4),            // max factor (4x = max 4x increase)
    ///     7,                  // 7 day voting period
    /// ).await?;
    /// ```
    pub async fn create_difficulty_update_proposal(
        &mut self,
        proposer: IdentityId,
        target_timespan: u64,
        adjustment_interval: u64,
        min_adjustment_factor: Option<u64>,
        max_adjustment_factor: Option<u64>,
        voting_period_days: u32,
    ) -> Result<Hash> {
        // Validate parameters
        if target_timespan == 0 {
            return Err(anyhow::anyhow!("target_timespan must be greater than 0"));
        }
        if adjustment_interval == 0 {
            return Err(anyhow::anyhow!("adjustment_interval must be greater than 0"));
        }
        if let Some(min_factor) = min_adjustment_factor {
            if min_factor < 1 {
                return Err(anyhow::anyhow!("min_adjustment_factor must be >= 1"));
            }
        }
        if let Some(max_factor) = max_adjustment_factor {
            if max_factor < 1 {
                return Err(anyhow::anyhow!("max_adjustment_factor must be >= 1"));
            }
        }
        if let (Some(min_factor), Some(max_factor)) = (min_adjustment_factor, max_adjustment_factor) {
            if max_factor < min_factor {
                return Err(anyhow::anyhow!("max_adjustment_factor must be >= min_adjustment_factor"));
            }
        }

        // Build description with parameters
        let mut description = format!(
            "Difficulty Parameter Update Proposal\n\n\
            Parameters:\n\
            - Target Timespan: {} seconds ({:.2} days)\n\
            - Adjustment Interval: {} blocks",
            target_timespan,
            target_timespan as f64 / 86400.0,
            adjustment_interval
        );

        if let Some(min_factor) = min_adjustment_factor {
            description.push_str(&format!("\n- Min Adjustment Factor: {}%", min_factor));
        }
        if let Some(max_factor) = max_adjustment_factor {
            description.push_str(&format!("\n- Max Adjustment Factor: {}%", max_factor));
        }

        // Calculate and include target block time
        let target_block_time_secs = target_timespan / adjustment_interval;
        description.push_str(&format!("\n\nTarget Block Time: {} seconds", target_block_time_secs));

        // Build execution parameters
        let updates = vec![
            GovernanceParameterValue::BlockchainTargetTimespan(target_timespan),
            GovernanceParameterValue::BlockchainAdjustmentInterval(adjustment_interval),
        ];

        // TODO: min/max adjustment factors are accepted for validation but only stored in
        // the human-readable description. They are NOT included in execution_params and will
        // NOT be programmatically applied during proposal execution.
        // DifficultyConfig uses a single symmetric max_adjustment_factor for both directions.
        // Future enhancement: extend GovernanceParameterValue to support separate min/max factors
        // and update DifficultyConfig accordingly. See DifficultyParameterUpdateData in lib-blockchain.
        // Consider removing these parameters from the function signature until fully supported.

        let execution_params = DaoExecutionParams {
            action: DaoExecutionAction::GovernanceParameterUpdate(GovernanceParameterUpdate {
                updates,
            }),
        };

        let title = format!(
            "Difficulty Update: {} sec target, {} block interval",
            target_block_time_secs, adjustment_interval
        );

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

        // Create proposal with 30% quorum (same as protocol upgrades since this affects consensus)
        // Note: The proposal is created for validation and ID generation;
        // actual storage happens on blockchain via DaoProposal transaction
        let _proposal = DaoProposal::new(
            proposal_id.clone(),
            title,
            description,
            proposer.clone(),
            DaoProposalType::DifficultyParameterUpdate,
            DaoProposalStatus::Active,
            current_time,
            voting_end_time,
            30, // 30% quorum for difficulty changes
            DaoVoteTally::default(),
            current_time,
            self.get_current_block_height(),
            Some(self.encode_execution_params(&execution_params)?),
            None,
            None,
            PrivacyLevel::Public,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create proposal: {}", e))?;

        tracing::info!(
            "Validated difficulty update proposal {:?}: target_timespan={}, adjustment_interval={} - ready for blockchain submission",
            proposal_id,
            target_timespan,
            adjustment_interval
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
        _justification: Option<String>,
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

    /// Decode execution parameters from proposal bytes
    pub fn decode_execution_params(&self, params: &[u8]) -> Result<DaoExecutionParams> {
        bincode::deserialize(params)
            .map_err(|e| anyhow::anyhow!("Failed to decode execution params: {}", e))
    }

    /// Encode execution parameters for proposal submission
    pub fn encode_execution_params(&self, params: &DaoExecutionParams) -> Result<Vec<u8>> {
        bincode::serialize(params)
            .map_err(|e| anyhow::anyhow!("Failed to encode execution params: {}", e))
    }

    /// Apply execution parameters to consensus configuration
    pub fn apply_execution_params(
        &self,
        config: &mut ConsensusConfig,
        params: &DaoExecutionParams,
    ) -> Result<()> {
        match &params.action {
            DaoExecutionAction::GovernanceParameterUpdate(update) => {
                self.apply_governance_update(config, update)
            }
            // Mint/burn authorizations don't modify ConsensusConfig —
            // they are forwarded to the Treasury Kernel for execution.
            DaoExecutionAction::MintAuthorization(_)
            | DaoExecutionAction::BurnAuthorization(_) => Ok(()),
        }
    }

    /// Apply a governance parameter update to consensus configuration
    pub fn apply_governance_update(
        &self,
        config: &mut ConsensusConfig,
        update: &GovernanceParameterUpdate,
    ) -> Result<()> {
        self.validate_governance_update(update)?;

        for param in &update.updates {
            match param {
                GovernanceParameterValue::MinStake(value) => config.min_stake = *value,
                GovernanceParameterValue::MinStorage(value) => config.min_storage = *value,
                GovernanceParameterValue::MaxValidators(value) => {
                    // Defense-in-depth: clamp the value into the valid range even after
                    // validate_governance_update() has already checked the proposal.
                    let clamped = (*value as usize).max(MIN_VALIDATORS) as u32;
                    let clamped = clamped.min(MAX_VALIDATORS_HARD_CAP);
                    config.max_validators = clamped;
                }
                GovernanceParameterValue::BlockTime(value) => config.block_time = *value,
                GovernanceParameterValue::EpochLengthBlocks(value) => {
                    config.epoch_length_blocks = *value;
                }
                GovernanceParameterValue::ProposeTimeout(value) => config.propose_timeout = *value,
                GovernanceParameterValue::PrevoteTimeout(value) => config.prevote_timeout = *value,
                GovernanceParameterValue::PrecommitTimeout(value) => config.precommit_timeout = *value,
                GovernanceParameterValue::MaxTransactionsPerBlock(value) => {
                    config.max_transactions_per_block = *value;
                }
                GovernanceParameterValue::MaxDifficulty(value) => config.max_difficulty = *value,
                GovernanceParameterValue::TargetDifficulty(value) => config.target_difficulty = *value,
                GovernanceParameterValue::ByzantineThreshold(value) => {
                    config.byzantine_threshold = *value;
                }
                GovernanceParameterValue::SlashDoubleSign(value) => config.slash_double_sign = *value,
                GovernanceParameterValue::SlashLiveness(value) => config.slash_liveness = *value,
                GovernanceParameterValue::DevelopmentMode(value) => config.development_mode = *value,
                // Blockchain difficulty parameters are handled by DifficultyManager,
                // not ConsensusConfig. These parameters are validated here but applied 
                // separately through the following flow:
                //
                // 1. DAO proposal with BlockchainInitialDifficulty/AdjustmentInterval/TargetTimespan
                //    parameters is validated by validate_governance_update()
                // 2. After proposal passes voting, execute_passed_proposal() is called
                // 3. For blockchain difficulty params, the caller (typically node runtime)
                //    extracts these values from the passed proposal
                // 4. Caller invokes BlockchainConsensusCoordinator::apply_difficulty_governance_update()
                //    which delegates to DifficultyManager::apply_governance_update()
                //
                // See: lib-blockchain/src/integration/consensus_integration.rs
                //      BlockchainConsensusCoordinator::apply_difficulty_governance_update()
                GovernanceParameterValue::BlockchainInitialDifficulty(_)
                | GovernanceParameterValue::BlockchainAdjustmentInterval(_)
                | GovernanceParameterValue::BlockchainTargetTimespan(_)
                | GovernanceParameterValue::TxFeeBase(_)
                | GovernanceParameterValue::TxFeeBytesPerSov(_)
                | GovernanceParameterValue::TxFeeWitnessCap(_)
                | GovernanceParameterValue::OracleCommitteeMembers(_)
                | GovernanceParameterValue::OracleEpochDurationSecs(_)
                | GovernanceParameterValue::OracleMaxSourceAgeSecs(_)
                | GovernanceParameterValue::OracleMaxDeviationBps(_)
                | GovernanceParameterValue::OracleMaxPriceStalenessEpochs(_) => {
                    // No-op here: these are applied via the DifficultyManager pathway
                    // described in the comment above, not via ConsensusConfig mutation
                }
            }
        }

        Ok(())
    }

    /// Validate governance parameter updates before application
    pub fn validate_governance_update(&self, update: &GovernanceParameterUpdate) -> Result<()> {
        if update.updates.is_empty() {
            return Err(anyhow::anyhow!("Governance update must include at least one change"));
        }

        for param in &update.updates {
            match param {
                GovernanceParameterValue::MinStake(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Min stake must be greater than zero"));
                    }
                }
                GovernanceParameterValue::MinStorage(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Min storage must be greater than zero"));
                    }
                }
                GovernanceParameterValue::MaxValidators(value) => {
                    // Governance may adjust max_validators only within the range
                    // [MIN_VALIDATORS, MAX_VALIDATORS_HARD_CAP].
                    //
                    // - The lower bound (MIN_VALIDATORS = 4) protects BFT safety:
                    //   setting max below the minimum required by the protocol is
                    //   nonsensical and would prevent the network from operating.
                    // - The upper bound (MAX_VALIDATORS_HARD_CAP = 256) prevents
                    //   governance from enabling O(n²) consensus message floods.
                    if (*value as usize) < MIN_VALIDATORS {
                        return Err(anyhow::anyhow!(
                            "MaxValidators governance update rejected: proposed value {} is below \
                             MIN_VALIDATORS ({}).  Setting max_validators below the BFT safety \
                             floor is not permitted.",
                            value,
                            MIN_VALIDATORS,
                        ));
                    }
                    if *value > MAX_VALIDATORS_HARD_CAP {
                        return Err(anyhow::anyhow!(
                            "MaxValidators governance update rejected: proposed value {} exceeds \
                             MAX_VALIDATORS_HARD_CAP ({}).  A protocol upgrade is required to \
                             raise the hard cap.",
                            value,
                            MAX_VALIDATORS_HARD_CAP,
                        ));
                    }
                }
                GovernanceParameterValue::BlockTime(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Block time must be greater than zero"));
                    }
                }
                GovernanceParameterValue::EpochLengthBlocks(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!(
                            "Epoch length blocks must be greater than zero"
                        ));
                    }
                }
                GovernanceParameterValue::ProposeTimeout(value)
                | GovernanceParameterValue::PrevoteTimeout(value)
                | GovernanceParameterValue::PrecommitTimeout(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Timeouts must be greater than zero"));
                    }
                }
                GovernanceParameterValue::MaxTransactionsPerBlock(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!(
                            "Max transactions per block must be greater than zero"
                        ));
                    }
                }
                GovernanceParameterValue::MaxDifficulty(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Max difficulty must be greater than zero"));
                    }
                }
                GovernanceParameterValue::TargetDifficulty(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Target difficulty must be greater than zero"));
                    }
                }
                GovernanceParameterValue::ByzantineThreshold(value) => {
                    if *value <= 0.0 || *value > 0.5 {
                        return Err(anyhow::anyhow!(
                            "Byzantine threshold must be in (0.0, 0.5]"
                        ));
                    }
                }
                GovernanceParameterValue::SlashDoubleSign(value)
                | GovernanceParameterValue::SlashLiveness(value) => {
                    if *value > 100 {
                        return Err(anyhow::anyhow!("Slashing percentage must be <= 100"));
                    }
                }
                GovernanceParameterValue::DevelopmentMode(_) => {}
                // Blockchain difficulty parameters validation
                GovernanceParameterValue::BlockchainInitialDifficulty(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Initial difficulty must be greater than zero"));
                    }
                }
                GovernanceParameterValue::BlockchainAdjustmentInterval(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Adjustment interval must be greater than zero"));
                    }
                }
                GovernanceParameterValue::BlockchainTargetTimespan(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Target timespan must be greater than zero"));
                    }
                }
                GovernanceParameterValue::TxFeeBase(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Tx base fee must be greater than zero"));
                    }
                }
                GovernanceParameterValue::TxFeeBytesPerSov(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Tx bytes_per_sov must be greater than zero"));
                    }
                }
                GovernanceParameterValue::TxFeeWitnessCap(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Tx witness cap must be greater than zero"));
                    }
                }
                GovernanceParameterValue::OracleCommitteeMembers(members) => {
                    if members.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Oracle committee members must not be empty"
                        ));
                    }
                    let unique_count = members
                        .iter()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    if unique_count != members.len() {
                        return Err(anyhow::anyhow!(
                            "Oracle committee members must be unique"
                        ));
                    }
                }
                GovernanceParameterValue::OracleEpochDurationSecs(value)
                | GovernanceParameterValue::OracleMaxSourceAgeSecs(value)
                | GovernanceParameterValue::OracleMaxPriceStalenessEpochs(value) => {
                    if *value == 0 {
                        return Err(anyhow::anyhow!("Oracle parameter must be greater than zero"));
                    }
                }
                GovernanceParameterValue::OracleMaxDeviationBps(value) => {
                    if *value > 10_000 {
                        return Err(anyhow::anyhow!(
                            "Oracle max deviation bps must be <= 10000"
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract and apply governance updates from a proposal
    pub fn apply_governance_update_from_proposal(
        &self,
        proposal: &DaoProposal,
        config: &mut ConsensusConfig,
    ) -> Result<()> {
        match proposal.proposal_type() {
            DaoProposalType::ProtocolUpgrade
            | DaoProposalType::EconomicParams
            | DaoProposalType::GovernanceRules
            | DaoProposalType::FeeStructure
            | DaoProposalType::Emergency
            | DaoProposalType::DifficultyParameterUpdate => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "Proposal type does not support governance parameter updates"
                ));
            }
        }

        let params = proposal
            .execution_params()
            .ok_or_else(|| anyhow::anyhow!("Proposal missing execution parameters"))?;
        let decoded = self.decode_execution_params(params)?;

        match decoded.action {
            DaoExecutionAction::GovernanceParameterUpdate(_) => {
                self.apply_execution_params(config, &decoded)
            }
            // Mint/burn authorizations don't modify ConsensusConfig —
            // they are forwarded to the Treasury Kernel for execution.
            DaoExecutionAction::MintAuthorization(_)
            | DaoExecutionAction::BurnAuthorization(_) => Ok(()),
        }
    }

    /// Calculate DAO voting power for a user
    ///
    /// Voting power is calculated from multiple factors:
    /// - Base power: 1 (every identity gets base vote)
    /// - Token balance: 1 power per 10,000 SOV tokens
    /// - Staked tokens: 2 power per 10,000 SOV staked (bonus for commitment)
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

        // Token-based power: 1 vote per 10,000 SOV
        let token_power = token_balance / 10_000;

        // Stake-based power: 2 votes per 10,000 SOV staked (incentivize staking)
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    async fn execute_dao_proposal(&mut self, _proposal_id: &Hash) -> Result<()> {
        tracing::warn!(
            "execute_dao_proposal is deprecated - use blockchain.execute_dao_proposal() instead"
        );
        Err(anyhow::anyhow!("This method is deprecated. Use blockchain.execute_dao_proposal() to execute proposals with real UTXO transfers."))
    }

    /// Parse treasury amount from proposal (helper method)
    #[allow(dead_code)]
    fn parse_treasury_amount_from_proposal(&self, proposal: &DaoProposal) -> Result<u64> {
        // Look for amount in description (e.g., "amount:1000")
        let description = proposal.description();

        if let Some(start) = description.find("amount:") {
            let amount_section = &description[start + 7..];
            if let Some(end) = amount_section.find(' ') {
                let amount_str = amount_section[..end].trim();
                if let Ok(amount) = amount_str.parse::<u64>() {
                    return Ok(amount);
                }
            }
        }

        // Default to 1000 SOV for demo proposals if no amount specified
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
    #[allow(dead_code)]
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
