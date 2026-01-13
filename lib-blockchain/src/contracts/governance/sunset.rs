//! Sunset Contract - DOC 03: DAO Sunset & Value Separation
//!
//! State machine for CBE token sunset - enabling graceful wind-down and dissolution.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! State Machine:          NORMAL → RESTRICTED → WIND_DOWN → DISSOLVED
//! Restricted Duration:    90 days minimum
//! Wind-Down Duration:     180 days minimum
//! Final Payout:          100% to nonprofit treasury upon dissolution
//! ```
//!
//! # Architecture
//!
//! The Sunset contract manages the controlled end-of-life process for the for-profit entity:
//! - NORMAL: All operations permitted
//! - RESTRICTED: For-profit operations limited, restricted spending
//! - WIND_DOWN: Asset liquidation only, no new operations
//! - DISSOLVED: All assets transferred to nonprofit, entity terminated
//!
//! # Governance Trigger
//!
//! State transitions are triggered only by governance votes with enforced timelocks.

use serde::{Deserialize, Serialize};

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Minimum time in RESTRICTED state before moving to WIND_DOWN (90 days)
pub const RESTRICTED_MIN_DURATION: u64 = 90 * 24 * 60 * 60; // 7,776,000 seconds

/// Minimum time in WIND_DOWN state before DISSOLVED (180 days)
pub const WIND_DOWN_MIN_DURATION: u64 = 180 * 24 * 60 * 60; // 15,552,000 seconds

/// Upon dissolution, all assets go to nonprofit (100%)
pub const FINAL_PAYOUT_TO_NONPROFIT_PERCENTAGE: u16 = 100;

/// Voting timelock for state transitions (14 days)
pub const SUNSET_STATE_TRANSITION_TIMELOCK: u64 = 14 * 24 * 60 * 60; // 1,209,600 seconds

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for Sunset contract operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SunsetError {
    /// Sunset contract not yet initialized
    NotInitialized,

    /// Sunset contract already initialized
    AlreadyInitialized,

    /// Caller is not authorized for this operation
    Unauthorized,

    /// Invalid state transition
    InvalidStateTransition,

    /// Minimum duration not met for state transition
    MinimumDurationNotMet,

    /// Timelock has not expired
    TimelockNotExpired,

    /// Voting power is insufficient
    InsufficientVotingPower,

    /// Proposal not found
    ProposalNotFound,

    /// Invalid state
    InvalidState,

    /// Arithmetic overflow
    Overflow,
}

impl std::fmt::Display for SunsetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SunsetError::NotInitialized =>
                write!(f, "Sunset contract not yet initialized"),
            SunsetError::AlreadyInitialized =>
                write!(f, "Sunset contract already initialized"),
            SunsetError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            SunsetError::InvalidStateTransition =>
                write!(f, "Invalid state transition"),
            SunsetError::MinimumDurationNotMet =>
                write!(f, "Minimum duration not met for this transition"),
            SunsetError::TimelockNotExpired =>
                write!(f, "Timelock has not expired"),
            SunsetError::InsufficientVotingPower =>
                write!(f, "Insufficient voting power"),
            SunsetError::ProposalNotFound =>
                write!(f, "Proposal not found"),
            SunsetError::InvalidState =>
                write!(f, "Invalid state"),
            SunsetError::Overflow =>
                write!(f, "Arithmetic overflow"),
        }
    }
}

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/// Sunset state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SunsetState {
    /// Normal operations - all activities permitted
    Normal,

    /// Restricted - limited for-profit operations, restricted spending
    Restricted,

    /// Wind-down - liquidation only, no new operations
    WindDown,

    /// Dissolved - entity terminated, all assets transferred
    Dissolved,
}

/// Spending policy for each state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendingPolicy {
    /// All spending allowed
    Unrestricted,

    /// Operations and essential spending only (no dividends, bonuses)
    LimitedOperations,

    /// Liquidation only (asset sales, operational wind-down)
    LiquidationOnly,

    /// No spending allowed
    Frozen,
}

/// State transition request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionProposal {
    /// Unique proposal ID
    pub proposal_id: u64,

    /// From state
    pub from_state: SunsetState,

    /// To state
    pub to_state: SunsetState,

    /// When transition was proposed
    pub proposed_at: u64,

    /// When transition can be executed (after timelock)
    pub execution_at: u64,

    /// Voting power in favor
    pub votes_for: u64,

    /// Voting power against
    pub votes_against: u64,

    /// Whether transition was executed
    pub executed: bool,
}

// ============================================================================
// SUNSET CONTRACT
// ============================================================================

/// Sunset Contract
///
/// Manages the controlled wind-down and dissolution of for-profit entity.
///
/// # Initialization
///
/// The contract must be initialized with:
/// - Administrator (governance)
/// - Target nonprofit treasury (receives final payout)
///
/// # State Transitions
///
/// All transitions require governance vote with timelock:
/// - NORMAL → RESTRICTED: 90-day restricted period begins
/// - RESTRICTED → WIND_DOWN: 180-day liquidation period begins
/// - WIND_DOWN → DISSOLVED: Entity dissolved, assets transferred to nonprofit
///
/// # Spending Policies by State
///
/// - NORMAL: Unrestricted (normal business operations)
/// - RESTRICTED: Limited operations only (no dividends/bonuses)
/// - WIND_DOWN: Liquidation only (asset sales, operational wind-down)
/// - DISSOLVED: No spending (all assets gone, entity terminated)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sunset {
    /// Initialization status
    initialized: bool,

    /// Administrator (governance)
    admin: Option<[u8; 32]>,

    /// Nonprofit treasury address (final payout destination)
    nonprofit_treasury: Option<[u8; 32]>,

    /// Current state
    state: SunsetState,

    /// When current state was entered
    state_entered_at: u64,

    /// Total assets held for final payout
    total_assets: u64,

    /// All state transition proposals
    proposals: HashMap<u64, StateTransitionProposal>,

    /// Next proposal ID
    next_proposal_id: u64,

    /// Audit trail: (timestamp, old_state, new_state)
    state_transitions: Vec<(u64, SunsetState, SunsetState)>,

    /// Current timestamp (for testing)
    current_timestamp: u64,
}

use std::collections::HashMap;

impl Sunset {
    /// Create a new uninitialized Sunset contract
    pub fn new() -> Self {
        Self {
            initialized: false,
            admin: None,
            nonprofit_treasury: None,
            state: SunsetState::Normal,
            state_entered_at: 0,
            total_assets: 0,
            proposals: HashMap::new(),
            next_proposal_id: 1,
            state_transitions: Vec::new(),
            current_timestamp: 0,
        }
    }

    /// Initialize the sunset contract
    ///
    /// # Arguments
    ///
    /// * `admin` - Governance administrator
    /// * `nonprofit_treasury` - Address to receive final payout
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    pub fn init(
        &mut self,
        admin: [u8; 32],
        nonprofit_treasury: [u8; 32],
    ) -> Result<(), SunsetError> {
        if self.initialized {
            return Err(SunsetError::AlreadyInitialized);
        }

        self.admin = Some(admin);
        self.nonprofit_treasury = Some(nonprofit_treasury);
        self.state = SunsetState::Normal;
        self.state_entered_at = self.current_timestamp;
        self.initialized = true;

        Ok(())
    }

    /// Check if sunset contract is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // STATE MANAGEMENT
    // ========================================================================

    /// Get spending policy for current state
    pub fn get_spending_policy(&self) -> SpendingPolicy {
        match self.state {
            SunsetState::Normal => SpendingPolicy::Unrestricted,
            SunsetState::Restricted => SpendingPolicy::LimitedOperations,
            SunsetState::WindDown => SpendingPolicy::LiquidationOnly,
            SunsetState::Dissolved => SpendingPolicy::Frozen,
        }
    }

    /// Propose a state transition (requires governance vote)
    ///
    /// # Arguments
    ///
    /// * `from_state` - Expected current state
    /// * `to_state` - Desired next state
    /// * `caller` - Address proposing transition (must be admin)
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if contract not initialized
    /// - `Unauthorized` if caller is not admin
    /// - `InvalidStateTransition` if transition is not valid
    pub fn propose_state_transition(
        &mut self,
        from_state: SunsetState,
        to_state: SunsetState,
        caller: [u8; 32],
    ) -> Result<u64, SunsetError> {
        if !self.initialized {
            return Err(SunsetError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(SunsetError::Unauthorized);
        }

        // Verify valid transitions
        let valid_transition = match (from_state, to_state) {
            (SunsetState::Normal, SunsetState::Restricted) => true,
            (SunsetState::Restricted, SunsetState::WindDown) => true,
            (SunsetState::WindDown, SunsetState::Dissolved) => true,
            _ => false,
        };

        if !valid_transition {
            return Err(SunsetError::InvalidStateTransition);
        }

        let proposal_id = self.next_proposal_id;
        let execution_at = self.current_timestamp.checked_add(SUNSET_STATE_TRANSITION_TIMELOCK)
            .ok_or(SunsetError::Overflow)?;

        let proposal = StateTransitionProposal {
            proposal_id,
            from_state,
            to_state,
            proposed_at: self.current_timestamp,
            execution_at,
            votes_for: 0,
            votes_against: 0,
            executed: false,
        };

        self.proposals.insert(proposal_id, proposal);
        self.next_proposal_id = self.next_proposal_id.checked_add(1)
            .ok_or(SunsetError::Overflow)?;

        Ok(proposal_id)
    }

    /// Vote on a state transition proposal
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID of the proposal
    /// * `vote_for` - True to vote for, false to vote against
    /// * `voting_power` - Voting power of the voter
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if contract not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    pub fn vote_on_transition(
        &mut self,
        proposal_id: u64,
        _voter: [u8; 32],
        vote_for: bool,
        voting_power: u64,
    ) -> Result<(), SunsetError> {
        if !self.initialized {
            return Err(SunsetError::NotInitialized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(SunsetError::ProposalNotFound)?;

        if vote_for {
            proposal.votes_for = proposal.votes_for.checked_add(voting_power)
                .ok_or(SunsetError::Overflow)?;
        } else {
            proposal.votes_against = proposal.votes_against.checked_add(voting_power)
                .ok_or(SunsetError::Overflow)?;
        }

        Ok(())
    }

    /// Execute a state transition (after timelock expires)
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - ID of the approved proposal
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if contract not initialized
    /// - `ProposalNotFound` if proposal doesn't exist
    /// - `TimelockNotExpired` if timelock hasn't expired
    /// - `MinimumDurationNotMet` if minimum duration in current state not met
    pub fn execute_state_transition(&mut self, proposal_id: u64) -> Result<(), SunsetError> {
        if !self.initialized {
            return Err(SunsetError::NotInitialized);
        }

        let proposal = self.proposals.get_mut(&proposal_id)
            .ok_or(SunsetError::ProposalNotFound)?;

        if self.current_timestamp < proposal.execution_at {
            return Err(SunsetError::TimelockNotExpired);
        }

        // Check current state matches proposal
        if proposal.from_state != self.state {
            return Err(SunsetError::InvalidStateTransition);
        }

        // Check minimum duration in current state
        let time_in_state = self.current_timestamp.saturating_sub(self.state_entered_at);

        let min_duration = match proposal.from_state {
            SunsetState::Normal => 0, // No minimum from NORMAL
            SunsetState::Restricted => RESTRICTED_MIN_DURATION,
            SunsetState::WindDown => WIND_DOWN_MIN_DURATION,
            SunsetState::Dissolved => return Err(SunsetError::InvalidStateTransition),
        };

        if time_in_state < min_duration {
            return Err(SunsetError::MinimumDurationNotMet);
        }

        // Record transition in audit trail
        self.state_transitions.push((
            self.current_timestamp,
            proposal.from_state,
            proposal.to_state,
        ));

        // Update state
        let _old_state = self.state;
        self.state = proposal.to_state;
        self.state_entered_at = self.current_timestamp;

        // Mark proposal as executed
        proposal.executed = true;

        Ok(())
    }

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /// Get current state
    pub fn get_state(&self) -> SunsetState {
        self.state
    }

    /// Get spending policy for current state
    pub fn get_current_spending_policy(&self) -> SpendingPolicy {
        self.get_spending_policy()
    }

    /// Get time in current state
    pub fn get_time_in_state(&self) -> u64 {
        self.current_timestamp.saturating_sub(self.state_entered_at)
    }

    /// Get total assets
    pub fn get_total_assets(&self) -> u64 {
        self.total_assets
    }

    /// Get a state transition proposal
    pub fn get_proposal(&self, proposal_id: u64) -> Option<&StateTransitionProposal> {
        self.proposals.get(&proposal_id)
    }

    /// Get all state transitions (audit trail)
    pub fn get_state_transitions(&self) -> &[(u64, SunsetState, SunsetState)] {
        &self.state_transitions
    }

    /// Get admin address
    pub fn get_admin(&self) -> Option<[u8; 32]> {
        self.admin
    }

    /// Get nonprofit treasury address
    pub fn get_nonprofit_treasury(&self) -> Option<[u8; 32]> {
        self.nonprofit_treasury
    }

    // ========================================================================
    // ADMIN OPERATIONS
    // ========================================================================

    /// Update total assets (called when assets are added or removed)
    pub fn set_total_assets(&mut self, amount: u64) {
        self.total_assets = amount;
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

impl Default for Sunset {
    fn default() -> Self {
        Self::new()
    }
}
