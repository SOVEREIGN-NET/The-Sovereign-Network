//! Nonprofit Treasury Contract - DOC 02: Phase 1 Governance & Treasury Rails
//!
//! Manages funds reserved for nonprofit purposes within the SOV economic system.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! Funding Source:    20% mandatory tribute from for-profit revenue
//! Purpose:           Nonprofit operations and community welfare
//! Withdrawal:        Governance-controlled via DAO votes
//! ```
//!
//! # Architecture
//!
//! The Nonprofit Treasury contract:
//! - Receives 20% mandatory tribute from ForProfitTreasury via TributeRouter
//! - Holds funds in complete isolation from for-profit operations
//! - No auto-forwarding logic (funds held until governance approves spending)
//! - Tracks balance with high precision (integer math only)
//! - Enforces source validation (only receives from TributeRouter)
//!
//! # Invariants
//!
//! - **T1**: All funds come from TributeRouter (20% tribute enforcement)
//! - **T2**: No forwarding or automated distribution
//! - **T3**: Balance tracking is auditable and precise
//! - **T4**: Only governance can authorize withdrawals

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Nonprofit treasury allocation percentage (20% of profit)
pub const NONPROFIT_ALLOCATION_PERCENTAGE: u16 = 20;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for Nonprofit Treasury operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NonprofitTreasuryError {
    /// Treasury not yet initialized
    NotInitialized,

    /// Treasury already initialized
    AlreadyInitialized,

    /// Caller is not authorized for this operation
    Unauthorized,

    /// Attempted to receive funds from unauthorized source
    UnauthorizedSource,

    /// Insufficient balance for withdrawal
    InsufficientBalance,

    /// Withdrawal amount is zero
    ZeroAmount,

    /// Arithmetic overflow
    Overflow,

    /// Invalid recipient address
    InvalidRecipient,

    /// Treasury is frozen (no withdrawals allowed)
    TreasuryFrozen,
}

impl std::fmt::Display for NonprofitTreasuryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonprofitTreasuryError::NotInitialized =>
                write!(f, "Treasury not yet initialized"),
            NonprofitTreasuryError::AlreadyInitialized =>
                write!(f, "Treasury already initialized"),
            NonprofitTreasuryError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            NonprofitTreasuryError::UnauthorizedSource =>
                write!(f, "Can only receive funds from TributeRouter"),
            NonprofitTreasuryError::InsufficientBalance =>
                write!(f, "Insufficient balance for withdrawal"),
            NonprofitTreasuryError::ZeroAmount =>
                write!(f, "Amount cannot be zero"),
            NonprofitTreasuryError::Overflow =>
                write!(f, "Arithmetic overflow"),
            NonprofitTreasuryError::InvalidRecipient =>
                write!(f, "Invalid recipient address"),
            NonprofitTreasuryError::TreasuryFrozen =>
                write!(f, "Treasury is frozen - no withdrawals allowed"),
        }
    }
}

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/// Transaction record for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryTransaction {
    /// Transaction ID
    pub transaction_id: u64,

    /// Type of transaction (Deposit, Withdrawal)
    pub transaction_type: TransactionType,

    /// Amount transferred
    pub amount: u64,

    /// Source or destination address
    pub counterparty: [u8; 32],

    /// When the transaction occurred (Unix timestamp)
    pub timestamp: u64,

    /// Associated governance proposal (if applicable)
    pub proposal_id: Option<u64>,

    /// Human-readable description
    pub description: String,
}

/// Type of treasury transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Funds received
    Deposit,

    /// Funds withdrawn
    Withdrawal,
}

/// Withdrawal request (pending approval)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// Unique request ID
    pub request_id: u64,

    /// Recipient address
    pub recipient: [u8; 32],

    /// Amount requested
    pub amount: u64,

    /// Associated governance proposal
    pub proposal_id: u64,

    /// Status (Pending, Approved, Executed, Rejected)
    pub status: WithdrawalStatus,

    /// When the request was created
    pub created_at: u64,

    /// When the request was processed (if applicable)
    pub processed_at: Option<u64>,
}

/// Status of a withdrawal request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Waiting for governance approval
    Pending,

    /// Approved by governance
    Approved,

    /// Funds have been transferred
    Executed,

    /// Governance rejected the request
    Rejected,
}

// ============================================================================
// NONPROFIT TREASURY CONTRACT
// ============================================================================

/// Nonprofit Treasury Contract
///
/// Holds and manages nonprofit-designated funds received from for-profit operations.
///
/// # Initialization
///
/// The treasury must be initialized once with:
/// - Treasury administrator (governance DAO address)
/// - TributeRouter address (authorized funding source)
///
/// # Funding
///
/// The treasury only accepts deposits from the TributeRouter, which enforces
/// the 20% mandatory tribute from for-profit revenue.
///
/// # Withdrawals
///
/// All withdrawals require governance approval via the associated Governance contract.
/// Withdrawals are tracked and auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonprofitTreasury {
    /// Initialization status
    initialized: bool,

    /// Treasury administrator (governance DAO)
    admin: Option<[u8; 32]>,

    /// Authorized funding source (TributeRouter)
    funding_source: Option<[u8; 32]>,

    /// Current balance
    balance: u64,

    /// Total received (for audit)
    total_received: u64,

    /// Total withdrawn (for audit)
    total_withdrawn: u64,

    /// All transactions (audit trail)
    transactions: HashMap<u64, TreasuryTransaction>,

    /// Next transaction ID
    next_transaction_id: u64,

    /// Pending withdrawal requests
    withdrawal_requests: HashMap<u64, WithdrawalRequest>,

    /// Next withdrawal request ID
    next_withdrawal_request_id: u64,

    /// Whether the treasury is frozen
    is_frozen: bool,

    /// Current timestamp (for testing)
    current_timestamp: u64,
}

impl NonprofitTreasury {
    /// Create a new uninitialized Nonprofit Treasury
    pub fn new() -> Self {
        Self {
            initialized: false,
            admin: None,
            funding_source: None,
            balance: 0,
            total_received: 0,
            total_withdrawn: 0,
            transactions: HashMap::new(),
            next_transaction_id: 1,
            withdrawal_requests: HashMap::new(),
            next_withdrawal_request_id: 1,
            is_frozen: false,
            current_timestamp: 0,
        }
    }

    /// Initialize the treasury
    ///
    /// # Arguments
    ///
    /// * `admin` - The treasury administrator (governance DAO)
    /// * `funding_source` - The authorized funding source (TributeRouter)
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    pub fn init(
        &mut self,
        admin: [u8; 32],
        funding_source: [u8; 32],
    ) -> Result<(), NonprofitTreasuryError> {
        if self.initialized {
            return Err(NonprofitTreasuryError::AlreadyInitialized);
        }

        self.admin = Some(admin);
        self.funding_source = Some(funding_source);
        self.initialized = true;

        Ok(())
    }

    /// Check if treasury is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // DEPOSIT OPERATIONS
    // ========================================================================

    /// Receive funds from TributeRouter
    ///
    /// # Arguments
    ///
    /// * `sender` - The address sending funds (must be TributeRouter)
    /// * `amount` - Amount being received
    ///
    /// # Invariants Enforced
    ///
    /// - T1: Sender must be the authorized TributeRouter
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `UnauthorizedSource` if sender is not the TributeRouter
    /// - `ZeroAmount` if amount is zero
    /// - `Overflow` if balance would exceed u64::MAX
    pub fn receive(
        &mut self,
        sender: [u8; 32],
        amount: u64,
    ) -> Result<(), NonprofitTreasuryError> {
        if !self.initialized {
            return Err(NonprofitTreasuryError::NotInitialized);
        }

        // Verify sender is authorized funding source
        if Some(sender) != self.funding_source {
            return Err(NonprofitTreasuryError::UnauthorizedSource);
        }

        if amount == 0 {
            return Err(NonprofitTreasuryError::ZeroAmount);
        }

        // Update balances
        self.balance = self.balance.checked_add(amount)
            .ok_or(NonprofitTreasuryError::Overflow)?;

        self.total_received = self.total_received.checked_add(amount)
            .ok_or(NonprofitTreasuryError::Overflow)?;

        // Record transaction
        let transaction = TreasuryTransaction {
            transaction_id: self.next_transaction_id,
            transaction_type: TransactionType::Deposit,
            amount,
            counterparty: sender,
            timestamp: self.current_timestamp,
            proposal_id: None,
            description: "Tribute deposit from TributeRouter".to_string(),
        };

        self.transactions.insert(self.next_transaction_id, transaction);
        self.next_transaction_id = self.next_transaction_id.checked_add(1)
            .ok_or(NonprofitTreasuryError::Overflow)?;

        Ok(())
    }

    // ========================================================================
    // WITHDRAWAL OPERATIONS
    // ========================================================================

    /// Request a withdrawal (governance approval required)
    ///
    /// # Arguments
    ///
    /// * `recipient` - Address to receive funds
    /// * `amount` - Amount to withdraw
    /// * `proposal_id` - Associated governance proposal ID
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `ZeroAmount` if amount is zero
    /// - `InsufficientBalance` if balance is too low
    pub fn request_withdrawal(
        &mut self,
        recipient: [u8; 32],
        amount: u64,
        proposal_id: u64,
    ) -> Result<u64, NonprofitTreasuryError> {
        if !self.initialized {
            return Err(NonprofitTreasuryError::NotInitialized);
        }

        if amount == 0 {
            return Err(NonprofitTreasuryError::ZeroAmount);
        }

        if amount > self.balance {
            return Err(NonprofitTreasuryError::InsufficientBalance);
        }

        let request_id = self.next_withdrawal_request_id;
        let request = WithdrawalRequest {
            request_id,
            recipient,
            amount,
            proposal_id,
            status: WithdrawalStatus::Pending,
            created_at: self.current_timestamp,
            processed_at: None,
        };

        self.withdrawal_requests.insert(request_id, request);
        self.next_withdrawal_request_id = self.next_withdrawal_request_id.checked_add(1)
            .ok_or(NonprofitTreasuryError::Overflow)?;

        Ok(request_id)
    }

    /// Approve a withdrawal request (admin only)
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `Unauthorized` if caller is not admin
    /// - `InvalidRecipient` if the withdrawal request is not found
    pub fn approve_withdrawal(
        &mut self,
        request_id: u64,
        caller: [u8; 32],
    ) -> Result<(), NonprofitTreasuryError> {
        if !self.initialized {
            return Err(NonprofitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(NonprofitTreasuryError::Unauthorized);
        }

        let request = self.withdrawal_requests.get_mut(&request_id)
            .ok_or(NonprofitTreasuryError::InvalidRecipient)?;

        request.status = WithdrawalStatus::Approved;
        request.processed_at = Some(self.current_timestamp);

        Ok(())
    }

    /// Execute an approved withdrawal
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `Unauthorized` if caller is not admin
    /// - `InvalidRecipient` if request not found or not approved
    /// - `TreasuryFrozen` if treasury is frozen
    /// - `InsufficientBalance` if balance is insufficient
    pub fn execute_withdrawal(
        &mut self,
        request_id: u64,
        caller: [u8; 32],
    ) -> Result<(), NonprofitTreasuryError> {
        if !self.initialized {
            return Err(NonprofitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(NonprofitTreasuryError::Unauthorized);
        }

        if self.is_frozen {
            return Err(NonprofitTreasuryError::TreasuryFrozen);
        }

        let request = self.withdrawal_requests.get_mut(&request_id)
            .ok_or(NonprofitTreasuryError::InvalidRecipient)?;

        if request.status != WithdrawalStatus::Approved {
            return Err(NonprofitTreasuryError::InvalidRecipient);
        }

        if request.amount > self.balance {
            return Err(NonprofitTreasuryError::InsufficientBalance);
        }

        // Update balances
        self.balance = self.balance.checked_sub(request.amount)
            .ok_or(NonprofitTreasuryError::InsufficientBalance)?;

        self.total_withdrawn = self.total_withdrawn.checked_add(request.amount)
            .ok_or(NonprofitTreasuryError::Overflow)?;

        // Record transaction
        let transaction = TreasuryTransaction {
            transaction_id: self.next_transaction_id,
            transaction_type: TransactionType::Withdrawal,
            amount: request.amount,
            counterparty: request.recipient,
            timestamp: self.current_timestamp,
            proposal_id: Some(request.proposal_id),
            description: "Governance-approved nonprofit withdrawal".to_string(),
        };

        self.transactions.insert(self.next_transaction_id, transaction);
        self.next_transaction_id = self.next_transaction_id.checked_add(1)
            .ok_or(NonprofitTreasuryError::Overflow)?;

        // Mark request as executed
        request.status = WithdrawalStatus::Executed;

        Ok(())
    }

    /// Reject a withdrawal request
    pub fn reject_withdrawal(
        &mut self,
        request_id: u64,
        caller: [u8; 32],
    ) -> Result<(), NonprofitTreasuryError> {
        if !self.initialized {
            return Err(NonprofitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(NonprofitTreasuryError::Unauthorized);
        }

        let request = self.withdrawal_requests.get_mut(&request_id)
            .ok_or(NonprofitTreasuryError::InvalidRecipient)?;

        request.status = WithdrawalStatus::Rejected;
        request.processed_at = Some(self.current_timestamp);

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

    /// Get total withdrawn
    pub fn total_withdrawn(&self) -> u64 {
        self.total_withdrawn
    }

    /// Get a transaction by ID
    pub fn get_transaction(&self, transaction_id: u64) -> Option<&TreasuryTransaction> {
        self.transactions.get(&transaction_id)
    }

    /// Get all transactions
    pub fn get_transactions(&self) -> &HashMap<u64, TreasuryTransaction> {
        &self.transactions
    }

    /// Get a withdrawal request by ID
    pub fn get_withdrawal_request(&self, request_id: u64) -> Option<&WithdrawalRequest> {
        self.withdrawal_requests.get(&request_id)
    }

    /// Get all withdrawal requests
    pub fn get_withdrawal_requests(&self) -> &HashMap<u64, WithdrawalRequest> {
        &self.withdrawal_requests
    }

    /// Check if treasury is frozen
    pub fn is_frozen(&self) -> bool {
        self.is_frozen
    }

    /// Get admin address
    pub fn get_admin(&self) -> Option<[u8; 32]> {
        self.admin
    }

    /// Get funding source address
    pub fn get_funding_source(&self) -> Option<[u8; 32]> {
        self.funding_source
    }

    // ========================================================================
    // ADMIN OPERATIONS
    // ========================================================================

    /// Freeze/unfreeze the treasury (emergency only)
    pub fn set_frozen(&mut self, frozen: bool, caller: [u8; 32]) -> Result<(), NonprofitTreasuryError> {
        if !self.initialized {
            return Err(NonprofitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(NonprofitTreasuryError::Unauthorized);
        }

        self.is_frozen = frozen;
        Ok(())
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

impl Default for NonprofitTreasury {
    fn default() -> Self {
        Self::new()
    }
}
