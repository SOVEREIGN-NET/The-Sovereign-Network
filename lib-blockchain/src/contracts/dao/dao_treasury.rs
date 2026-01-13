//! DAO Treasury Contract - DOC 03: DAO Sunset & Value Separation
//!
//! Generic DAO Treasury template for governance-controlled sector DAOs.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! DAO Allocation:         6% of monthly transaction fees
//! Governance Control:     All spending requires DAO governance vote
//! Timelock Withdrawal:    7 days minimum delay after approval
//! Spending Categories:    Research, Operations, Community, Emergency
//! ```
//!
//! # Architecture
//!
//! The DAO Treasury contract:
//! - Receives 6% monthly fee allocation from FeeRouter
//! - Requires governance vote for all spending decisions
//! - Enforces 7-day timelock between approval and execution
//! - Tracks spending by category for accountability
//! - Maintains audit trail of all transactions
//!
//! # Sector DAOs
//!
//! - HealthcareDAOTreasury (medical research and programs)
//! - EducationDAOTreasury (education initiatives)
//! - EnergyDAOTreasury (renewable energy projects)
//! - HousingDAOTreasury (affordable housing solutions)
//! - FoodDAOTreasury (food security and agriculture)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// DAO allocation percentage: 6% of transaction fees
pub const DAO_ALLOCATION_PERCENTAGE: u16 = 6;

/// Number of sector DAOs
pub const NUM_SECTOR_DAOS: u8 = 5;

/// Per-DAO allocation percentage (6% / 5 = 1.2%)
pub const PER_DAO_ALLOCATION_PERCENTAGE: u16 = 120; // basis points (1.2%)

/// Timelock for DAO treasury withdrawals: 7 days
pub const DAO_TIMELOCK_SECONDS: u64 = 7 * 24 * 60 * 60; // 604,800

/// Minimum voting power to create spending proposal (50,000 CBE)
pub const MIN_DAO_VOTING_POWER_FOR_PROPOSAL: u64 = 50_000 * 10_u64.pow(8);

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for DAO Treasury operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaoTreasuryError {
    /// DAO Treasury not yet initialized
    NotInitialized,

    /// DAO Treasury already initialized
    AlreadyInitialized,

    /// Caller is not authorized for this operation
    Unauthorized,

    /// Caller does not have sufficient voting power
    InsufficientVotingPower,

    /// Spending proposal not found
    ProposalNotFound,

    /// Proposal is not in the correct state
    InvalidProposalState,

    /// Timelock has not expired
    TimelockNotExpired,

    /// Insufficient balance for spending
    InsufficientBalance,

    /// Amount is zero
    ZeroAmount,

    /// Arithmetic overflow
    Overflow,

    /// Invalid spending category
    InvalidSpendingCategory,

    /// Treasury is frozen (emergency lock)
    TreasuryFrozen,
}

impl std::fmt::Display for DaoTreasuryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaoTreasuryError::NotInitialized =>
                write!(f, "DAO Treasury not yet initialized"),
            DaoTreasuryError::AlreadyInitialized =>
                write!(f, "DAO Treasury already initialized"),
            DaoTreasuryError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            DaoTreasuryError::InsufficientVotingPower =>
                write!(f, "Insufficient voting power for proposal"),
            DaoTreasuryError::ProposalNotFound =>
                write!(f, "Spending proposal not found"),
            DaoTreasuryError::InvalidProposalState =>
                write!(f, "Proposal is not in the correct state"),
            DaoTreasuryError::TimelockNotExpired =>
                write!(f, "Timelock has not expired"),
            DaoTreasuryError::InsufficientBalance =>
                write!(f, "Insufficient balance for spending"),
            DaoTreasuryError::ZeroAmount =>
                write!(f, "Amount cannot be zero"),
            DaoTreasuryError::Overflow =>
                write!(f, "Arithmetic overflow"),
            DaoTreasuryError::InvalidSpendingCategory =>
                write!(f, "Invalid spending category"),
            DaoTreasuryError::TreasuryFrozen =>
                write!(f, "Treasury is frozen - no spending allowed"),
        }
    }
}

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/// Spending category for DAO treasury
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendingCategory {
    /// Research and development
    Research,

    /// Operational expenses
    Operations,

    /// Community programs
    Community,

    /// Emergency funds
    Emergency,
}

/// Status of a spending proposal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal pending (voting not started)
    Pending,

    /// Proposal active (voting in progress)
    Active,

    /// Proposal approved (waiting for timelock)
    Approved,

    /// Timelock expired (ready to execute)
    Ready,

    /// Proposal executed
    Executed,

    /// Proposal rejected
    Rejected,

    /// Proposal cancelled
    Cancelled,
}

/// Spending proposal for DAO treasury
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingProposal {
    /// Unique proposal ID
    pub proposal_id: u64,

    /// Proposal title
    pub title: String,

    /// Proposal description
    pub description: String,

    /// Spending category
    pub category: SpendingCategory,

    /// Amount to spend
    pub amount: u64,

    /// Recipient address
    pub recipient: [u8; 32],

    /// Proposer address
    pub proposer: [u8; 32],

    /// Current status
    pub status: ProposalStatus,

    /// When the proposal was created (Unix timestamp)
    pub created_at: u64,

    /// When voting started
    pub voting_start_at: u64,

    /// When voting ended
    pub voting_end_at: u64,

    /// When the proposal can be executed (Unix timestamp)
    pub execution_time_at: u64,

    /// Votes in favor
    pub votes_for: u64,

    /// Votes against
    pub votes_against: u64,

    /// Total voting power at proposal creation
    pub total_voting_power_at_creation: u64,
}

/// Spending record for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingRecord {
    /// Unique spending ID
    pub spending_id: u64,

    /// Category of spending
    pub category: SpendingCategory,

    /// Amount spent
    pub amount: u64,

    /// Recipient
    pub recipient: [u8; 32],

    /// Associated proposal ID
    pub proposal_id: u64,

    /// When the spending occurred (Unix timestamp)
    pub timestamp: u64,
}

// ============================================================================
// DAO TREASURY CONTRACT
// ============================================================================

/// DAO Treasury Contract
///
/// Generic governance-controlled treasury for sector DAOs.
///
/// # Initialization
///
/// The treasury must be initialized with:
/// - Treasury name (e.g., "HealthcareDAO Treasury")
/// - Administrator address
/// - Associated governance address
///
/// # Spending Workflow
///
/// 1. DAO member creates spending proposal (requires voting power)
/// 2. Community votes on proposal (7-day voting period)
/// 3. If approved, proposal enters 7-day timelock
/// 4. After timelock, proposal can be executed
/// 5. Funds transferred to recipient
/// 6. Transaction recorded in audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoTreasury {
    /// Initialization status
    initialized: bool,

    /// Treasury name (e.g., "Healthcare DAO")
    name: String,

    /// Treasury administrator
    admin: Option<[u8; 32]>,

    /// Associated governance address
    governance: Option<[u8; 32]>,

    /// Current balance
    balance: u64,

    /// Total received
    total_received: u64,

    /// Total spent
    total_spent: u64,

    /// All spending proposals
    proposals: HashMap<u64, SpendingProposal>,

    /// Next proposal ID
    next_proposal_id: u64,

    /// All spending records (audit trail)
    spending_records: HashMap<u64, SpendingRecord>,

    /// Next spending ID
    next_spending_id: u64,

    /// Total voting power (reference value from governance)
    total_voting_power: u64,

    /// Whether the treasury is frozen
    is_frozen: bool,

    /// Current timestamp (for testing)
    current_timestamp: u64,
}

impl DaoTreasury {
    /// Create a new uninitialized DAO Treasury
    pub fn new() -> Self {
        Self {
            initialized: false,
            name: String::new(),
            admin: None,
            governance: None,
            balance: 0,
            total_received: 0,
            total_spent: 0,
            proposals: HashMap::new(),
            next_proposal_id: 1,
            spending_records: HashMap::new(),
            next_spending_id: 1,
            total_voting_power: 0,
            is_frozen: false,
            current_timestamp: 0,
        }
    }

    /// Initialize the DAO Treasury
    ///
    /// # Arguments
    ///
    /// * `name` - Treasury name (e.g., "HealthcareDAO Treasury")
    /// * `admin` - Treasury administrator
    /// * `governance` - Associated governance address
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    pub fn init(
        &mut self,
        name: String,
        admin: [u8; 32],
        governance: [u8; 32],
    ) -> Result<(), DaoTreasuryError> {
        if self.initialized {
            return Err(DaoTreasuryError::AlreadyInitialized);
        }

        self.name = name;
        self.admin = Some(admin);
        self.governance = Some(governance);
        self.initialized = true;

        Ok(())
    }

    /// Check if treasury is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // FUND RECEIPT
    // ========================================================================

    /// Receive funds from FeeRouter (6% allocation)
    ///
    /// # Arguments
    ///
    /// * `amount` - Amount being received
    /// * `sender` - Address sending funds (should be FeeRouter)
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `ZeroAmount` if amount is zero
    /// - `Overflow` if balance would exceed u64::MAX
    pub fn receive_allocation(&mut self, amount: u64, _sender: [u8; 32]) -> Result<(), DaoTreasuryError> {
        if !self.initialized {
            return Err(DaoTreasuryError::NotInitialized);
        }

        if amount == 0 {
            return Err(DaoTreasuryError::ZeroAmount);
        }

        self.balance = self.balance.checked_add(amount)
            .ok_or(DaoTreasuryError::Overflow)?;

        self.total_received = self.total_received.checked_add(amount)
            .ok_or(DaoTreasuryError::Overflow)?;

        Ok(())
    }

    // ========================================================================
    // SPENDING PROPOSALS
    // ========================================================================

    /// Create a spending proposal (requires voting power)
    ///
    /// # Arguments
    ///
    /// * `proposer` - Address of the proposer
    /// * `title` - Proposal title
    /// * `description` - Proposal description
    /// * `category` - Spending category
    /// * `amount` - Amount to spend
    /// * `recipient` - Recipient address
    /// * `voting_power` - Voting power of proposer
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `InsufficientVotingPower` if proposer lacks minimum power
    /// - `InsufficientBalance` if balance is insufficient
    pub fn create_proposal(
        &mut self,
        proposer: [u8; 32],
        title: String,
        description: String,
        category: SpendingCategory,
        amount: u64,
        recipient: [u8; 32],
        voting_power: u64,
    ) -> Result<u64, DaoTreasuryError> {
        if !self.initialized {
            return Err(DaoTreasuryError::NotInitialized);
        }

        if voting_power < MIN_DAO_VOTING_POWER_FOR_PROPOSAL {
            return Err(DaoTreasuryError::InsufficientVotingPower);
        }

        if amount == 0 {
            return Err(DaoTreasuryError::ZeroAmount);
        }

        if amount > self.balance {
            return Err(DaoTreasuryError::InsufficientBalance);
        }

        let proposal_id = self.next_proposal_id;
        let voting_start = self.current_timestamp;
        let voting_end = voting_start.checked_add(7 * 24 * 60 * 60) // 7 days
            .ok_or(DaoTreasuryError::Overflow)?;
        let execution_time = voting_end.checked_add(DAO_TIMELOCK_SECONDS)
            .ok_or(DaoTreasuryError::Overflow)?;

        let proposal = SpendingProposal {
            proposal_id,
            title,
            description,
            category,
            amount,
            recipient,
            proposer,
            status: ProposalStatus::Active,
            created_at: self.current_timestamp,
            voting_start_at: voting_start,
            voting_end_at: voting_end,
            execution_time_at: execution_time,
            votes_for: 0,
            votes_against: 0,
            total_voting_power_at_creation: self.total_voting_power,
        };

        self.proposals.insert(proposal_id, proposal);
        self.next_proposal_id = self.next_proposal_id.checked_add(1)
            .ok_or(DaoTreasuryError::Overflow)?;

        Ok(proposal_id)
    }

    /// Vote on a spending proposal
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID of the proposal to vote on
    /// * `voter` - Address of the voter
    /// * `vote_for` - True to vote for, false to vote against
    /// * `voting_power` - Voting power of the voter
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    /// - `InvalidProposalState` if proposal not in voting period
    pub fn vote(
        &mut self,
        proposal_id: u64,
        _voter: [u8; 32],
        vote_for: bool,
        voting_power: u64,
    ) -> Result<(), DaoTreasuryError> {
        if !self.initialized {
            return Err(DaoTreasuryError::NotInitialized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(DaoTreasuryError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Active {
            return Err(DaoTreasuryError::InvalidProposalState);
        }

        if self.current_timestamp < proposal.voting_start_at
            || self.current_timestamp >= proposal.voting_end_at {
            return Err(DaoTreasuryError::InvalidProposalState);
        }

        if vote_for {
            proposal.votes_for = proposal.votes_for.checked_add(voting_power)
                .ok_or(DaoTreasuryError::Overflow)?;
        } else {
            proposal.votes_against = proposal.votes_against.checked_add(voting_power)
                .ok_or(DaoTreasuryError::Overflow)?;
        }

        Ok(())
    }

    /// Finalize voting on a proposal
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID of the proposal
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    /// - `InvalidProposalState` if voting period hasn't ended
    pub fn finalize_voting(&mut self, proposal_id: u64) -> Result<(), DaoTreasuryError> {
        if !self.initialized {
            return Err(DaoTreasuryError::NotInitialized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(DaoTreasuryError::ProposalNotFound)?;

        if self.current_timestamp < proposal.voting_end_at {
            return Err(DaoTreasuryError::InvalidProposalState);
        }

        let total_votes = proposal.votes_for.checked_add(proposal.votes_against)
            .ok_or(DaoTreasuryError::Overflow)?;

        if total_votes == 0 {
            proposal.status = ProposalStatus::Rejected;
            return Ok(());
        }

        // Simple majority: > 50%
        let threshold = total_votes / 2 + 1;

        if proposal.votes_for >= threshold {
            proposal.status = ProposalStatus::Approved;
        } else {
            proposal.status = ProposalStatus::Rejected;
        }

        Ok(())
    }

    /// Execute a spending proposal (after timelock expires)
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID of the proposal to execute
    /// * `caller` - Address calling execute (usually admin)
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    /// - `InvalidProposalState` if proposal not approved
    /// - `TimelockNotExpired` if timelock hasn't expired
    /// - `TreasuryFrozen` if treasury is frozen
    /// - `InsufficientBalance` if balance is insufficient
    pub fn execute_proposal(
        &mut self,
        proposal_id: u64,
        caller: [u8; 32],
    ) -> Result<(), DaoTreasuryError> {
        if !self.initialized {
            return Err(DaoTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin && Some(caller) != self.governance {
            return Err(DaoTreasuryError::Unauthorized);
        }

        if self.is_frozen {
            return Err(DaoTreasuryError::TreasuryFrozen);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(DaoTreasuryError::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Approved {
            return Err(DaoTreasuryError::InvalidProposalState);
        }

        if self.current_timestamp < proposal.execution_time_at {
            return Err(DaoTreasuryError::TimelockNotExpired);
        }

        if proposal.amount > self.balance {
            return Err(DaoTreasuryError::InsufficientBalance);
        }

        // Transfer funds
        self.balance = self.balance.checked_sub(proposal.amount)
            .ok_or(DaoTreasuryError::InsufficientBalance)?;

        self.total_spent = self.total_spent.checked_add(proposal.amount)
            .ok_or(DaoTreasuryError::Overflow)?;

        // Record spending
        let spending_record = SpendingRecord {
            spending_id: self.next_spending_id,
            category: proposal.category,
            amount: proposal.amount,
            recipient: proposal.recipient,
            proposal_id,
            timestamp: self.current_timestamp,
        };

        self.spending_records.insert(self.next_spending_id, spending_record);
        self.next_spending_id = self.next_spending_id.checked_add(1)
            .ok_or(DaoTreasuryError::Overflow)?;

        // Mark proposal as executed
        proposal.status = ProposalStatus::Executed;

        Ok(())
    }

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /// Get current balance
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Get total received
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Get total spent
    pub fn total_spent(&self) -> u64 {
        self.total_spent
    }

    /// Get treasury name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get a proposal by ID
    pub fn get_proposal(&self, proposal_id: u64) -> Option<&SpendingProposal> {
        self.proposals.get(&proposal_id)
    }

    /// Get spending records (audit trail)
    pub fn get_spending_records(&self) -> &HashMap<u64, SpendingRecord> {
        &self.spending_records
    }

    /// Get admin address
    pub fn get_admin(&self) -> Option<[u8; 32]> {
        self.admin
    }

    /// Get governance address
    pub fn get_governance(&self) -> Option<[u8; 32]> {
        self.governance
    }

    /// Check if treasury is frozen
    pub fn is_frozen(&self) -> bool {
        self.is_frozen
    }

    // ========================================================================
    // ADMIN OPERATIONS
    // ========================================================================

    /// Freeze/unfreeze the treasury (emergency only)
    pub fn set_frozen(&mut self, frozen: bool, caller: [u8; 32]) -> Result<(), DaoTreasuryError> {
        if !self.initialized {
            return Err(DaoTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(DaoTreasuryError::Unauthorized);
        }

        self.is_frozen = frozen;
        Ok(())
    }

    /// Update total voting power
    pub fn update_total_voting_power(&mut self, new_power: u64) {
        self.total_voting_power = new_power;
    }

    /// Set current timestamp (for testing)
    pub fn set_current_timestamp(&mut self, timestamp: u64) {
        self.current_timestamp = timestamp;
    }

    /// Get current timestamp
    pub fn get_current_timestamp(&self) -> u64 {
        self.current_timestamp
    }
}

impl Default for DaoTreasury {
    fn default() -> Self {
        Self::new()
    }
}
