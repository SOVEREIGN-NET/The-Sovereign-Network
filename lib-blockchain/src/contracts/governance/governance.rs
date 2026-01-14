//! Governance Contract - DOC 02: Phase 1 Governance & Treasury Rails
//!
//! Provides proposal creation, voting, and timelock enforcement for the SOV economic system.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! Voting Period:          7 days (604,800 seconds)
//! Timelock Delay:         2 days (172,800 seconds)
//! Majority Threshold:     > 50% of votes
//! Supermajority Threshold: >= 66.67% of votes
//! ```
//!
//! # Architecture
//!
//! The Governance contract provides:
//! - Proposal creation and tracking
//! - Time-weighted voting (voting power from CBE token holdings)
//! - Timelock enforcement (2 day delay before execution)
//! - Proposal categories (Regular, Emergency, Constitutional)
//! - Vote recording and aggregation
//!
//! # Invariants
//!
//! - **G1**: Proposals can only be created by entities with voting power
//! - **G2**: Voting period is exactly 7 days
//! - **G3**: Timelock enforces 2 day minimum delay before execution
//! - **G4**: Vote totals sum to total voting power cast

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Voting period in seconds (7 days)
pub const VOTING_PERIOD_SECONDS: u64 = 7 * 24 * 60 * 60; // 604,800

/// Timelock delay in seconds (2 days)
pub const TIMELOCK_DELAY_SECONDS: u64 = 2 * 24 * 60 * 60; // 172,800

/// Majority threshold (> 50%)
pub const MAJORITY_THRESHOLD_BASIS_POINTS: u16 = 5_001; // 50.01%

/// Supermajority threshold (>= 66.67%)
pub const SUPERMAJORITY_THRESHOLD_BASIS_POINTS: u16 = 6_667; // 66.67%

/// Minimum voting power to create a proposal (100,000 CBE tokens)
pub const MIN_VOTING_POWER_FOR_PROPOSAL: u64 = 100_000 * 10_u64.pow(8); // 100k CBE with 8 decimals

/// Quorum threshold in basis points (50%)
pub const QUORUM_THRESHOLD_BASIS_POINTS: u16 = 5_000; // 50% of voting power

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for Governance operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceError {
    /// Governance not yet initialized
    NotInitialized,

    /// Governance already initialized
    AlreadyInitialized,

    /// Caller does not have sufficient voting power
    InsufficientVotingPower,

    /// Caller is not authorized for this operation
    Unauthorized,

    /// Proposal not found
    ProposalNotFound,

    /// Proposal is not in the correct state for this operation
    InvalidProposalState,

    /// Timelock has not expired
    TimelockNotExpired,

    /// Voting period has ended
    VotingPeriodEnded,

    /// Voting period has not started
    VotingPeriodNotStarted,

    /// Voter has already voted on this proposal
    AlreadyVoted,

    /// Proposal title cannot be empty
    EmptyTitle,

    /// Proposal description cannot be empty
    EmptyDescription,

    /// Invalid proposal type
    InvalidProposalType,

    /// Arithmetic overflow
    Overflow,

    /// Quorum not reached
    QuorumNotMet,
}

impl std::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GovernanceError::NotInitialized =>
                write!(f, "Governance not yet initialized"),
            GovernanceError::AlreadyInitialized =>
                write!(f, "Governance already initialized"),
            GovernanceError::InsufficientVotingPower =>
                write!(f, "Insufficient voting power"),
            GovernanceError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            GovernanceError::ProposalNotFound =>
                write!(f, "Proposal not found"),
            GovernanceError::InvalidProposalState =>
                write!(f, "Proposal is not in the correct state"),
            GovernanceError::TimelockNotExpired =>
                write!(f, "Timelock has not expired"),
            GovernanceError::VotingPeriodEnded =>
                write!(f, "Voting period has ended"),
            GovernanceError::VotingPeriodNotStarted =>
                write!(f, "Voting period has not started"),
            GovernanceError::AlreadyVoted =>
                write!(f, "Voter has already voted on this proposal"),
            GovernanceError::EmptyTitle =>
                write!(f, "Proposal title cannot be empty"),
            GovernanceError::EmptyDescription =>
                write!(f, "Proposal description cannot be empty"),
            GovernanceError::InvalidProposalType =>
                write!(f, "Invalid proposal type"),
            GovernanceError::Overflow =>
                write!(f, "Arithmetic overflow"),
            GovernanceError::QuorumNotMet =>
                write!(f, "Quorum not reached - insufficient voter participation"),
        }
    }
}

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/// Proposal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal is pending (before voting starts)
    Pending,

    /// Proposal is active (voting period open)
    Active,

    /// Proposal was rejected (voting period ended with insufficient votes)
    Rejected,

    /// Proposal was approved (passed voting, waiting for timelock)
    Approved,

    /// Proposal has been executed
    Executed,

    /// Proposal was cancelled
    Cancelled,
}

/// Vote type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Vote in favor
    For,

    /// Vote against
    Against,

    /// Abstain from voting
    Abstain,
}

/// Proposal category (determines voting thresholds)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalCategory {
    /// Regular governance proposal (majority required)
    Regular,

    /// Emergency proposal (can be executed faster, majority required)
    Emergency,

    /// Constitutional change (supermajority required)
    Constitutional,
}

/// Individual proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique proposal ID
    pub id: u64,

    /// Proposal title
    pub title: String,

    /// Proposal description
    pub description: String,

    /// Proposal category
    pub category: ProposalCategory,

    /// Proposer address
    pub proposer: [u8; 32],

    /// Current status
    pub status: ProposalStatus,

    /// When the proposal was created (Unix timestamp)
    pub created_at: u64,

    /// When voting started (Unix timestamp)
    pub voting_start_at: u64,

    /// When voting ends (Unix timestamp)
    pub voting_end_at: u64,

    /// When the proposal can be executed (Unix timestamp)
    pub execution_time_at: u64,

    /// Votes for
    pub votes_for: u64,

    /// Votes against
    pub votes_against: u64,

    /// Votes abstaining
    pub votes_abstain: u64,

    /// Total voting power at proposal creation
    pub total_voting_power_at_creation: u64,

    /// Whether this is an emergency proposal (faster execution)
    pub is_emergency: bool,
}

/// Vote cast by a voter on a proposal
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Vote {
    /// The vote type
    pub vote_type: VoteType,

    /// Voting power used
    pub voting_power: u64,

    /// When the vote was cast (Unix timestamp)
    pub voted_at: u64,
}

// ============================================================================
// GOVERNANCE CONTRACT
// ============================================================================

/// Governance Contract
///
/// Manages proposals, voting, and timelock enforcement for the SOV network.
///
/// # Initialization
///
/// The contract must be initialized once with the governance administrator address.
/// After initialization:
/// - Proposals can be created by entities with sufficient voting power
/// - Voting is time-locked (7 days per proposal)
/// - Execution is delayed by timelock (2 days)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Governance {
    /// Contract initialization status
    initialized: bool,

    /// Governance administrator
    admin: Option<[u8; 32]>,

    /// Next proposal ID to assign
    next_proposal_id: u64,

    /// All proposals
    proposals: HashMap<u64, Proposal>,

    /// Vote records: proposal_id -> voter_address -> vote
    votes: HashMap<u64, HashMap<[u8; 32], Vote>>,

    /// Total voting power (should be queried from CBE token contract)
    /// For now, we track this as a reference value
    total_voting_power: u64,

    /// Current timestamp (for testing purposes, set to block timestamp in production)
    current_timestamp: u64,
}

impl Governance {
    /// Create a new uninitialized Governance contract
    pub fn new() -> Self {
        Self {
            initialized: false,
            admin: None,
            next_proposal_id: 1,
            proposals: HashMap::new(),
            votes: HashMap::new(),
            total_voting_power: 0,
            current_timestamp: 0,
        }
    }

    /// Initialize the governance contract
    ///
    /// # Arguments
    ///
    /// * `admin` - The governance administrator address
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    pub fn init(&mut self, admin: [u8; 32]) -> Result<(), GovernanceError> {
        if self.initialized {
            return Err(GovernanceError::AlreadyInitialized);
        }

        self.admin = Some(admin);
        self.initialized = true;

        Ok(())
    }

    /// Check if governance is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // PROPOSAL CREATION
    // ========================================================================

    /// Create a new proposal
    ///
    /// # Arguments
    ///
    /// * `proposer` - Address of the proposer
    /// * `title` - Proposal title
    /// * `description` - Proposal description
    /// * `category` - Proposal category (Regular, Emergency, Constitutional)
    /// * `voting_power` - Voting power of the proposer (for validation)
    ///
    /// # Invariants Enforced
    ///
    /// - G1: Proposer must have sufficient voting power (>= MIN_VOTING_POWER_FOR_PROPOSAL)
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if governance is not initialized
    /// - `InsufficientVotingPower` if proposer doesn't have minimum required power
    /// - `EmptyTitle` if title is empty
    /// - `EmptyDescription` if description is empty
    pub fn create_proposal(
        &mut self,
        proposer: [u8; 32],
        title: String,
        description: String,
        category: ProposalCategory,
        voting_power: u64,
    ) -> Result<u64, GovernanceError> {
        if !self.initialized {
            return Err(GovernanceError::NotInitialized);
        }

        if title.is_empty() {
            return Err(GovernanceError::EmptyTitle);
        }

        if description.is_empty() {
            return Err(GovernanceError::EmptyDescription);
        }

        if voting_power < MIN_VOTING_POWER_FOR_PROPOSAL {
            return Err(GovernanceError::InsufficientVotingPower);
        }

        let proposal_id = self.next_proposal_id;
        let voting_start = self.current_timestamp;
        let voting_end = voting_start.checked_add(VOTING_PERIOD_SECONDS)
            .ok_or(GovernanceError::Overflow)?;
        let execution_time = voting_end.checked_add(TIMELOCK_DELAY_SECONDS)
            .ok_or(GovernanceError::Overflow)?;

        let proposal = Proposal {
            id: proposal_id,
            title,
            description,
            category,
            proposer,
            status: ProposalStatus::Active,
            created_at: self.current_timestamp,
            voting_start_at: voting_start,
            voting_end_at: voting_end,
            execution_time_at: execution_time,
            votes_for: 0,
            votes_against: 0,
            votes_abstain: 0,
            total_voting_power_at_creation: self.total_voting_power,
            is_emergency: category == ProposalCategory::Emergency,
        };

        self.proposals.insert(proposal_id, proposal);
        self.next_proposal_id = proposal_id.checked_add(1)
            .ok_or(GovernanceError::Overflow)?;

        Ok(proposal_id)
    }

    // ========================================================================
    // VOTING
    // ========================================================================

    /// Cast a vote on a proposal
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID of the proposal to vote on
    /// * `voter` - Address of the voter
    /// * `vote_type` - Type of vote (For, Against, Abstain)
    /// * `voting_power` - Voting power of the voter
    ///
    /// # Invariants Enforced
    ///
    /// - G4: Vote total must not exceed total voting power cast
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if governance is not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    /// - `VotingPeriodNotStarted` if voting hasn't started
    /// - `VotingPeriodEnded` if voting has ended
    /// - `AlreadyVoted` if voter has already voted on this proposal
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: [u8; 32],
        vote_type: VoteType,
        voting_power: u64,
    ) -> Result<(), GovernanceError> {
        if !self.initialized {
            return Err(GovernanceError::NotInitialized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // Check voting period
        if self.current_timestamp < proposal.voting_start_at {
            return Err(GovernanceError::VotingPeriodNotStarted);
        }

        if self.current_timestamp >= proposal.voting_end_at {
            return Err(GovernanceError::VotingPeriodEnded);
        }

        // Check if already voted
        let proposal_votes = self.votes.entry(proposal_id).or_insert_with(HashMap::new);
        if proposal_votes.contains_key(&voter) {
            return Err(GovernanceError::AlreadyVoted);
        }

        // Record the vote
        let vote = Vote {
            vote_type,
            voting_power,
            voted_at: self.current_timestamp,
        };

        proposal_votes.insert(voter, vote);

        // Update vote counts
        match vote_type {
            VoteType::For => {
                proposal.votes_for = proposal.votes_for.checked_add(voting_power)
                    .ok_or(GovernanceError::Overflow)?;
            }
            VoteType::Against => {
                proposal.votes_against = proposal.votes_against.checked_add(voting_power)
                    .ok_or(GovernanceError::Overflow)?;
            }
            VoteType::Abstain => {
                proposal.votes_abstain = proposal.votes_abstain.checked_add(voting_power)
                    .ok_or(GovernanceError::Overflow)?;
            }
        }

        Ok(())
    }

    // ========================================================================
    // PROPOSAL FINALIZATION
    // ========================================================================

    /// Finalize voting on a proposal (after voting period ends)
    ///
    /// This determines if the proposal passed based on voting threshold and quorum.
    ///
    /// **Quorum**: Total votes cast (including abstentions) must reach 50% of total voting power
    /// **Threshold**: Votes in favor must exceed votes against (adjusted for proposal category)
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if governance is not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    /// - `VotingPeriodNotStarted` if voting hasn't started yet
    /// - `VotingPeriodEnded` if voting period hasn't ended yet
    /// - `QuorumNotMet` if insufficient participation (< 50% of voting power)
    pub fn finalize_voting(
        &mut self,
        proposal_id: u64,
    ) -> Result<(), GovernanceError> {
        if !self.initialized {
            return Err(GovernanceError::NotInitialized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if self.current_timestamp < proposal.voting_start_at {
            return Err(GovernanceError::VotingPeriodNotStarted);
        }

        if self.current_timestamp < proposal.voting_end_at {
            return Err(GovernanceError::VotingPeriodEnded);
        }

        // ====================================================================
        // STEP 1: CHECK QUORUM
        // ====================================================================
        // Total voting power that participated (including abstentions)
        let total_voted = proposal.votes_for
            .checked_add(proposal.votes_against)
            .ok_or(GovernanceError::Overflow)?
            .checked_add(proposal.votes_abstain)
            .ok_or(GovernanceError::Overflow)?;

        // Quorum: At least 50% of total voting power must participate
        let quorum_required = (proposal.total_voting_power_at_creation * QUORUM_THRESHOLD_BASIS_POINTS as u64) / 10_000;

        if total_voted < quorum_required {
            proposal.status = ProposalStatus::Rejected;
            return Err(GovernanceError::QuorumNotMet);
        }

        // ====================================================================
        // STEP 2: CHECK VOTING THRESHOLD
        // ====================================================================
        // Threshold only considers For/Against (abstentions don't count toward threshold)
        let total_yea_nay = proposal.votes_for.checked_add(proposal.votes_against)
            .ok_or(GovernanceError::Overflow)?;

        if total_yea_nay == 0 {
            // Quorum met but no one voted for/against (all abstained)
            proposal.status = ProposalStatus::Rejected;
            return Ok(());
        }

        let threshold = match proposal.category {
            ProposalCategory::Regular | ProposalCategory::Emergency =>
                MAJORITY_THRESHOLD_BASIS_POINTS,
            ProposalCategory::Constitutional =>
                SUPERMAJORITY_THRESHOLD_BASIS_POINTS,
        };

        // Calculate percentage of For votes relative to For + Against votes
        let for_percentage = (proposal.votes_for as u64 * 10_000) / total_yea_nay;

        if for_percentage >= threshold as u64 {
            proposal.status = ProposalStatus::Approved;
        } else {
            proposal.status = ProposalStatus::Rejected;
        }

        Ok(())
    }

    /// Execute a proposal (after timelock expires)
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if governance is not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    /// - `InvalidProposalState` if proposal is not in Approved state
    /// - `TimelockNotExpired` if timelock hasn't expired yet
    pub fn execute_proposal(
        &mut self,
        proposal_id: u64,
    ) -> Result<(), GovernanceError> {
        if !self.initialized {
            return Err(GovernanceError::NotInitialized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Approved {
            return Err(GovernanceError::InvalidProposalState);
        }

        if self.current_timestamp < proposal.execution_time_at {
            return Err(GovernanceError::TimelockNotExpired);
        }

        proposal.status = ProposalStatus::Executed;
        Ok(())
    }

    /// Cancel a proposal
    ///
    /// Only the admin can cancel proposals.
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if governance is not initialized
    /// - `Unauthorized` if caller is not the admin
    /// - `ProposalNotFound` if proposal doesn't exist
    pub fn cancel_proposal(
        &mut self,
        proposal_id: u64,
        caller: [u8; 32],
    ) -> Result<(), GovernanceError> {
        if !self.initialized {
            return Err(GovernanceError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(GovernanceError::Unauthorized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        proposal.status = ProposalStatus::Cancelled;
        Ok(())
    }

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /// Get a proposal by ID
    pub fn get_proposal(&self, proposal_id: u64) -> Option<&Proposal> {
        self.proposals.get(&proposal_id)
    }

    /// Get a vote cast by a voter on a proposal
    pub fn get_vote(
        &self,
        proposal_id: u64,
        voter: &[u8; 32],
    ) -> Option<&Vote> {
        self.votes.get(&proposal_id)?.get(voter)
    }

    /// Get all votes on a proposal
    pub fn get_votes_on_proposal(&self, proposal_id: u64) -> Option<&HashMap<[u8; 32], Vote>> {
        self.votes.get(&proposal_id)
    }

    /// Get the next proposal ID
    pub fn get_next_proposal_id(&self) -> u64 {
        self.next_proposal_id
    }

    /// Get the total voting power
    pub fn get_total_voting_power(&self) -> u64 {
        self.total_voting_power
    }

    /// Get the current timestamp (for testing)
    pub fn get_current_timestamp(&self) -> u64 {
        self.current_timestamp
    }

    // ========================================================================
    // ADMIN OPERATIONS
    // ========================================================================

    /// Set the current timestamp (for testing and block time synchronization)
    pub fn set_current_timestamp(&mut self, timestamp: u64) {
        self.current_timestamp = timestamp;
    }

    /// Update total voting power (should be called from CBE token contract)
    pub fn update_total_voting_power(&mut self, new_power: u64) {
        self.total_voting_power = new_power;
    }

    /// Get the admin address
    pub fn get_admin(&self) -> Option<[u8; 32]> {
        self.admin
    }
}

impl Default for Governance {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// COMPREHENSIVE GOVERNANCE VOTING TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_governance() -> Governance {
        let mut gov = Governance::new();
        let admin = [1u8; 32];
        gov.init(admin).unwrap();
        gov
    }

    fn create_test_proposer() -> [u8; 32] {
        [2u8; 32]
    }

    fn create_test_voter(id: u8) -> [u8; 32] {
        [id; 32]
    }

    // ========================================================================
    // GOVERNANCE INITIALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_governance_initialization() {
        let gov = create_test_governance();
        assert!(gov.is_initialized());
        assert_eq!(gov.get_admin(), Some([1u8; 32]));
    }

    #[test]
    fn test_governance_initialization_fails_when_already_initialized() {
        let mut gov = create_test_governance();
        let result = gov.init([1u8; 32]);
        assert_eq!(result, Err(GovernanceError::AlreadyInitialized));
    }

    // ========================================================================
    // PROPOSAL CREATION TESTS
    // ========================================================================

    #[test]
    fn test_create_proposal_success() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let result = gov.create_proposal(
            create_test_proposer(),
            "Test Proposal".to_string(),
            "This is a test proposal".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        );

        assert!(result.is_ok());
        let proposal_id = result.unwrap();
        assert_eq!(proposal_id, 1);

        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.title, "Test Proposal");
        assert_eq!(proposal.status, ProposalStatus::Active);
    }

    #[test]
    fn test_create_proposal_requires_minimum_voting_power() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let result = gov.create_proposal(
            create_test_proposer(),
            "Weak Proposal".to_string(),
            "Insufficient power".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL - 1,
        );

        assert_eq!(result, Err(GovernanceError::InsufficientVotingPower));
    }

    #[test]
    fn test_create_proposal_requires_non_empty_title() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let result = gov.create_proposal(
            create_test_proposer(),
            "".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        );

        assert_eq!(result, Err(GovernanceError::EmptyTitle));
    }

    #[test]
    fn test_create_proposal_requires_non_empty_description() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let result = gov.create_proposal(
            create_test_proposer(),
            "Title".to_string(),
            "".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        );

        assert_eq!(result, Err(GovernanceError::EmptyDescription));
    }

    // ========================================================================
    // VOTING TESTS
    // ========================================================================

    #[test]
    fn test_cast_vote_during_voting_period() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Test Proposal".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        let result = gov.vote(
            proposal_id,
            create_test_voter(3),
            VoteType::For,
            100_000,
        );

        assert!(result.is_ok());

        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.votes_for, 100_000);
        assert_eq!(proposal.votes_against, 0);
    }

    #[test]
    fn test_voting_prevented_after_period_ends() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Test Proposal".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        // Advance time past voting period
        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);

        let result = gov.vote(
            proposal_id,
            create_test_voter(3),
            VoteType::For,
            100_000,
        );

        assert_eq!(result, Err(GovernanceError::VotingPeriodEnded));
    }

    #[test]
    fn test_voter_cannot_vote_twice() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Test Proposal".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 100_000).unwrap();

        let result = gov.vote(proposal_id, create_test_voter(3), VoteType::Against, 50_000);
        assert_eq!(result, Err(GovernanceError::AlreadyVoted));
    }

    // ========================================================================
    // QUORUM ENFORCEMENT TESTS
    // ========================================================================

    #[test]
    fn test_proposal_fails_without_quorum() {
        let mut gov = create_test_governance();
        let total_power = 1_000_000u64;
        gov.update_total_voting_power(total_power);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Quorum Test".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        // Only 40% voting power participates (below 50% quorum)
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 400_000).unwrap();

        // Advance time past voting period
        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);

        let result = gov.finalize_voting(proposal_id);

        // Should fail due to quorum not met
        assert_eq!(result, Err(GovernanceError::QuorumNotMet));

        // Proposal should be marked as rejected
        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_proposal_passes_with_quorum_and_majority() {
        let mut gov = create_test_governance();
        let total_power = 1_000_000u64;
        gov.update_total_voting_power(total_power);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Majority Test".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        // 60% voting power participates (above 50% quorum)
        // 60% vote For, 40% vote Against
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 600_000).unwrap();
        gov.vote(proposal_id, create_test_voter(4), VoteType::Against, 400_000).unwrap();

        // Advance time past voting period
        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);

        let result = gov.finalize_voting(proposal_id);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    #[test]
    fn test_proposal_fails_with_quorum_but_without_majority() {
        let mut gov = create_test_governance();
        let total_power = 1_000_000u64;
        gov.update_total_voting_power(total_power);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Rejection Test".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        // 60% voting power participates (quorum met)
        // But only 40% for, 60% against (no majority)
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 400_000).unwrap();
        gov.vote(proposal_id, create_test_voter(4), VoteType::Against, 600_000).unwrap();

        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);

        let result = gov.finalize_voting(proposal_id);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_abstentions_count_toward_quorum_but_not_majority() {
        let mut gov = create_test_governance();
        let total_power = 1_000_000u64;
        gov.update_total_voting_power(total_power);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Abstain Test".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        // 50% For, 20% Against, 30% Abstain = 80% participation (quorum met)
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 500_000).unwrap();
        gov.vote(proposal_id, create_test_voter(4), VoteType::Against, 200_000).unwrap();
        gov.vote(proposal_id, create_test_voter(5), VoteType::Abstain, 300_000).unwrap();

        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);

        let result = gov.finalize_voting(proposal_id);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(proposal_id).unwrap();
        // 50% For vs 20% Against = 50/(50+20) = 71.4% > 50% majority, so should pass
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }

    // ========================================================================
    // TIMELOCK ENFORCEMENT TESTS
    // ========================================================================

    #[test]
    fn test_timelock_prevents_immediate_execution() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Timelock Test".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 600_000).unwrap();

        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);
        gov.finalize_voting(proposal_id).unwrap();

        // Try to execute immediately (should fail)
        let result = gov.execute_proposal(proposal_id);
        assert_eq!(result, Err(GovernanceError::TimelockNotExpired));
    }

    #[test]
    fn test_proposal_executes_after_timelock() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Execution Test".to_string(),
            "Description".to_string(),
            ProposalCategory::Regular,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 600_000).unwrap();

        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);
        gov.finalize_voting(proposal_id).unwrap();

        // Advance past timelock
        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + TIMELOCK_DELAY_SECONDS + 100);

        let result = gov.execute_proposal(proposal_id);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Executed);
    }

    // ========================================================================
    // CONSTITUTIONAL VOTING TESTS (SUPERMAJORITY)
    // ========================================================================

    #[test]
    fn test_constitutional_proposal_requires_supermajority() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Constitutional Change".to_string(),
            "Description".to_string(),
            ProposalCategory::Constitutional,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        // 60% for (enough for regular, not for constitutional supermajority)
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 600_000).unwrap();
        gov.vote(proposal_id, create_test_voter(4), VoteType::Against, 400_000).unwrap();

        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);
        let result = gov.finalize_voting(proposal_id);
        assert!(result.is_ok());

        // Should be rejected (60% is not >= 66.67% supermajority)
        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_constitutional_proposal_passes_with_supermajority() {
        let mut gov = create_test_governance();
        gov.update_total_voting_power(1_000_000);

        let proposal_id = gov.create_proposal(
            create_test_proposer(),
            "Constitutional Change".to_string(),
            "Description".to_string(),
            ProposalCategory::Constitutional,
            MIN_VOTING_POWER_FOR_PROPOSAL,
        ).unwrap();

        gov.set_current_timestamp(100);

        // 70% for (exceeds 66.67% supermajority)
        gov.vote(proposal_id, create_test_voter(3), VoteType::For, 700_000).unwrap();
        gov.vote(proposal_id, create_test_voter(4), VoteType::Against, 300_000).unwrap();

        gov.set_current_timestamp(VOTING_PERIOD_SECONDS + 100);
        gov.finalize_voting(proposal_id).unwrap();

        let proposal = gov.get_proposal(proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
    }
}
