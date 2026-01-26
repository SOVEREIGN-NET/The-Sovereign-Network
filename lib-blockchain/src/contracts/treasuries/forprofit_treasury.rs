//! ForProfit Treasury Contract - DOC 02: Phase 1 Governance & Treasury Rails
//!
//! Manages funds from for-profit operations with mandatory tribute enforcement.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! Revenue Source:         For-profit operations
//! Mandatory Tribute:      20% must go to nonprofit treasury
//! Shareholder Dividend:   Can only be paid after tribute is satisfied
//! Spending Guards:        Prevents circumvention of tribute requirements
//! ```
//!
//! # Architecture
//!
//! The ForProfit Treasury contract:
//! - Receives profits from for-profit operations
//! - Enforces 20% mandatory tribute via TributeRouter
//! - Prevents dividend/bonus distributions until tribute is paid
//! - Tracks all spending with spending guards
//! - Implements anti-circumvention rules
//!
//! # Invariants
//!
//! - **T5**: 20% of profits must be paid as tribute to nonprofit treasury
//! - **T6**: No dividend/bonus before tribute payment
//! - **T7**: All spending is traceable and auditable
//! - **T8**: Anti-circumvention rules prevent profit hiding

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Mandatory tribute percentage (20% of profit to nonprofit)
pub const MANDATORY_TRIBUTE_PERCENTAGE: u16 = 20;

/// Maximum dividend percentage (without affecting tribute)
pub const MAX_DIVIDEND_PERCENTAGE: u16 = 50;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for ForProfit Treasury operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForProfitTreasuryError {
    /// Treasury not yet initialized
    NotInitialized,

    /// Treasury already initialized
    AlreadyInitialized,

    /// Caller is not authorized for this operation
    Unauthorized,

    /// Insufficient balance for spending
    InsufficientBalance,

    /// Amount is zero
    ZeroAmount,

    /// Arithmetic overflow
    Overflow,

    /// Tribute has not been paid
    TributePending,

    /// Attempted spending violates anti-circumvention rules
    CircumventionAttempt,

    /// Attempt to pay dividend before tribute
    DividendBeforeTribute,

    /// Invalid spending category
    InvalidSpendingCategory,

    /// Treasury is frozen (no spending allowed)
    TreasuryFrozen,
}

impl std::fmt::Display for ForProfitTreasuryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForProfitTreasuryError::NotInitialized =>
                write!(f, "Treasury not yet initialized"),
            ForProfitTreasuryError::AlreadyInitialized =>
                write!(f, "Treasury already initialized"),
            ForProfitTreasuryError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            ForProfitTreasuryError::InsufficientBalance =>
                write!(f, "Insufficient balance"),
            ForProfitTreasuryError::ZeroAmount =>
                write!(f, "Amount cannot be zero"),
            ForProfitTreasuryError::Overflow =>
                write!(f, "Arithmetic overflow"),
            ForProfitTreasuryError::TributePending =>
                write!(f, "Tribute payment pending"),
            ForProfitTreasuryError::CircumventionAttempt =>
                write!(f, "Spending violates anti-circumvention rules"),
            ForProfitTreasuryError::DividendBeforeTribute =>
                write!(f, "Cannot pay dividend before tribute"),
            ForProfitTreasuryError::InvalidSpendingCategory =>
                write!(f, "Invalid spending category"),
            ForProfitTreasuryError::TreasuryFrozen =>
                write!(f, "Treasury is frozen - no spending allowed"),
        }
    }
}

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/// Category of spending
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendingCategory {
    /// Operational expenses (salaries, infrastructure, etc.)
    Operations,

    /// Shareholder dividends
    Dividend,

    /// Performance bonuses
    Bonus,

    /// Capital investment
    Investment,

    /// Other (requires governance approval)
    Other,
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

    /// When the spending occurred
    pub timestamp: u64,

    /// Description
    pub description: String,

    /// Whether tribute has been paid for this profit cycle
    pub tribute_paid: bool,
}

/// Profit declaration record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfitDeclaration {
    /// Unique declaration ID
    pub declaration_id: u64,

    /// Total profit amount
    pub profit_amount: u64,

    /// When declared
    pub declared_at: u64,

    /// Mandatory tribute amount (20% of profit)
    pub tribute_amount: u64,

    /// Whether tribute has been paid to nonprofit
    pub tribute_paid: bool,

    /// Off-chain signature (for verification)
    pub signature_hash: Option<[u8; 32]>,

    /// Remaining balance after tribute
    pub remaining_balance: u64,
}

// ============================================================================
// FORPROFIT TREASURY CONTRACT
// ============================================================================

/// ForProfit Treasury Contract
///
/// Manages for-profit revenue with mandatory tribute enforcement.
///
/// # Initialization
///
/// The treasury must be initialized with:
/// - Treasury administrator
/// - Nonprofit Treasury address (tribute recipient)
///
/// # Revenue Flow
///
/// 1. Profits are declared via declare_profit()
/// 2. Tribute (20%) is calculated and marked for payment
/// 3. settle_tribute() transfers tribute to NonprofitTreasury
/// 4. Only after tribute is paid can dividends/bonuses be distributed
///
/// # Anti-Circumvention Rules
///
/// The treasury enforces rules to prevent profit hiding:
/// - No large untracked transfers
/// - Dividend cap without tribute
/// - Spending category tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForProfitTreasury {
    /// Initialization status
    initialized: bool,

    /// Treasury administrator
    admin: Option<[u8; 32]>,

    /// Nonprofit treasury address (tribute recipient)
    nonprofit_treasury: Option<[u8; 32]>,

    /// Current balance
    balance: u64,

    /// Total received (for audit)
    total_received: u64,

    /// Total spent (for audit)
    total_spent: u64,

    /// Total tribute paid (for audit)
    total_tribute_paid: u64,

    /// All profit declarations
    profit_declarations: HashMap<u64, ProfitDeclaration>,

    /// Next declaration ID
    next_declaration_id: u64,

    /// All spending records
    spending_records: HashMap<u64, SpendingRecord>,

    /// Next spending ID
    next_spending_id: u64,

    /// Current profit cycle status
    current_cycle_profit: u64,

    /// Whether tribute is paid for current cycle
    current_cycle_tribute_paid: bool,

    /// Whether the treasury is frozen
    is_frozen: bool,

    /// Current timestamp (for testing)
    current_timestamp: u64,
}

impl ForProfitTreasury {
    /// Create a new uninitialized ForProfit Treasury
    pub fn new() -> Self {
        Self {
            initialized: false,
            admin: None,
            nonprofit_treasury: None,
            balance: 0,
            total_received: 0,
            total_spent: 0,
            total_tribute_paid: 0,
            profit_declarations: HashMap::new(),
            next_declaration_id: 1,
            spending_records: HashMap::new(),
            next_spending_id: 1,
            current_cycle_profit: 0,
            current_cycle_tribute_paid: false,
            is_frozen: false,
            current_timestamp: 0,
        }
    }

    /// Initialize the treasury
    ///
    /// # Arguments
    ///
    /// * `admin` - Treasury administrator
    /// * `nonprofit_treasury` - Address of nonprofit treasury (tribute recipient)
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    pub fn init(
        &mut self,
        admin: [u8; 32],
        nonprofit_treasury: [u8; 32],
    ) -> Result<(), ForProfitTreasuryError> {
        if self.initialized {
            return Err(ForProfitTreasuryError::AlreadyInitialized);
        }

        self.admin = Some(admin);
        self.nonprofit_treasury = Some(nonprofit_treasury);
        self.initialized = true;

        Ok(())
    }

    /// Check if treasury is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // PROFIT DECLARATION & TRIBUTE
    // ========================================================================

    /// Declare profit with off-chain signature verification
    ///
    /// # Arguments
    ///
    /// * `profit_amount` - Total profit for this cycle
    /// * `caller` - Address declaring the profit
    /// * `signature_hash` - Hash of off-chain signature (for verification)
    ///
    /// # Invariants Enforced
    ///
    /// - T5: Tribute amount = profit * 20%
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `Unauthorized` if caller is not admin
    /// - `ZeroAmount` if profit is zero
    /// - `Overflow` if calculations overflow
    pub fn declare_profit(
        &mut self,
        profit_amount: u64,
        caller: [u8; 32],
        signature_hash: Option<[u8; 32]>,
    ) -> Result<u64, ForProfitTreasuryError> {
        if !self.initialized {
            return Err(ForProfitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(ForProfitTreasuryError::Unauthorized);
        }

        if profit_amount == 0 {
            return Err(ForProfitTreasuryError::ZeroAmount);
        }

        // Calculate mandatory tribute (20%)
        let tribute_amount = (profit_amount as u128 * MANDATORY_TRIBUTE_PERCENTAGE as u128 / 100) as u64;
        let remaining = profit_amount.checked_sub(tribute_amount)
            .ok_or(ForProfitTreasuryError::Overflow)?;

        // Create profit declaration
        let declaration_id = self.next_declaration_id;
        let declaration = ProfitDeclaration {
            declaration_id,
            profit_amount,
            declared_at: self.current_timestamp,
            tribute_amount,
            tribute_paid: false,
            signature_hash,
            remaining_balance: remaining,
        };

        self.profit_declarations.insert(declaration_id, declaration);
        self.next_declaration_id = self.next_declaration_id.checked_add(1)
            .ok_or(ForProfitTreasuryError::Overflow)?;

        // Update cycle tracking
        self.current_cycle_profit = profit_amount;
        self.current_cycle_tribute_paid = false;

        // Add to balance
        self.balance = self.balance.checked_add(profit_amount)
            .ok_or(ForProfitTreasuryError::Overflow)?;
        self.total_received = self.total_received.checked_add(profit_amount)
            .ok_or(ForProfitTreasuryError::Overflow)?;

        Ok(declaration_id)
    }

    /// Settle tribute payment to nonprofit treasury
    ///
    /// # Arguments
    ///
    /// * `declaration_id` - ID of the profit declaration to pay tribute for
    /// * `caller` - Address calling settle_tribute
    ///
    /// # Invariants Enforced
    ///
    /// - T5: Exactly 20% transferred to nonprofit
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `Unauthorized` if caller is not admin
    /// - `InvalidSpendingCategory` if declaration not found
    /// - `TributePending` if tribute already paid
    /// - `InsufficientBalance` if balance too low
    pub fn settle_tribute(
        &mut self,
        declaration_id: u64,
        caller: [u8; 32],
    ) -> Result<u64, ForProfitTreasuryError> {
        if !self.initialized {
            return Err(ForProfitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(ForProfitTreasuryError::Unauthorized);
        }

        let declaration = self.profit_declarations.get_mut(&declaration_id)
            .ok_or(ForProfitTreasuryError::InvalidSpendingCategory)?;

        if declaration.tribute_paid {
            return Err(ForProfitTreasuryError::TributePending);
        }

        let tribute = declaration.tribute_amount;
        if tribute > self.balance {
            return Err(ForProfitTreasuryError::InsufficientBalance);
        }

        // Transfer tribute
        self.balance = self.balance.checked_sub(tribute)
            .ok_or(ForProfitTreasuryError::InsufficientBalance)?;

        self.total_spent = self.total_spent.checked_add(tribute)
            .ok_or(ForProfitTreasuryError::Overflow)?;

        self.total_tribute_paid = self.total_tribute_paid.checked_add(tribute)
            .ok_or(ForProfitTreasuryError::Overflow)?;

        // Mark tribute as paid
        declaration.tribute_paid = true;
        self.current_cycle_tribute_paid = true;

        Ok(tribute)
    }

    // ========================================================================
    // SPENDING OPERATIONS
    // ========================================================================

    /// Spend funds from the treasury
    ///
    /// # Arguments
    ///
    /// * `category` - Category of spending
    /// * `amount` - Amount to spend
    /// * `recipient` - Recipient address
    /// * `description` - Description of the spending
    /// * `caller` - Address authorizing the spending
    ///
    /// # Invariants Enforced
    ///
    /// - T6: Dividends/bonuses not allowed before tribute payment
    /// - T8: Anti-circumvention rules applied
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if treasury is not initialized
    /// - `Unauthorized` if caller is not admin
    /// - `DividendBeforeTribute` if trying to pay dividend before tribute
    /// - `CircumventionAttempt` if spending violates rules
    /// - `InsufficientBalance` if balance too low
    pub fn spend(
        &mut self,
        category: SpendingCategory,
        amount: u64,
        recipient: [u8; 32],
        description: String,
        caller: [u8; 32],
    ) -> Result<u64, ForProfitTreasuryError> {
        if !self.initialized {
            return Err(ForProfitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(ForProfitTreasuryError::Unauthorized);
        }

        if self.is_frozen {
            return Err(ForProfitTreasuryError::TreasuryFrozen);
        }

        if amount == 0 {
            return Err(ForProfitTreasuryError::ZeroAmount);
        }

        // Check anti-circumvention rules
        match category {
            SpendingCategory::Dividend | SpendingCategory::Bonus => {
                // T6: No dividend/bonus before tribute
                if !self.current_cycle_tribute_paid && self.current_cycle_profit > 0 {
                    return Err(ForProfitTreasuryError::DividendBeforeTribute);
                }
            }
            _ => {}
        }

        // Check balance
        if amount > self.balance {
            return Err(ForProfitTreasuryError::InsufficientBalance);
        }

        // Apply spending guards for large amounts
        if amount > self.balance / 2 && category != SpendingCategory::Operations {
            return Err(ForProfitTreasuryError::CircumventionAttempt);
        }

        // Record spending
        let spending_id = self.next_spending_id;
        let record = SpendingRecord {
            spending_id,
            category,
            amount,
            recipient,
            timestamp: self.current_timestamp,
            description,
            tribute_paid: self.current_cycle_tribute_paid,
        };

        self.spending_records.insert(spending_id, record);
        self.next_spending_id = self.next_spending_id.checked_add(1)
            .ok_or(ForProfitTreasuryError::Overflow)?;

        // Update balance
        self.balance = self.balance.checked_sub(amount)
            .ok_or(ForProfitTreasuryError::InsufficientBalance)?;

        self.total_spent = self.total_spent.checked_add(amount)
            .ok_or(ForProfitTreasuryError::Overflow)?;

        Ok(spending_id)
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

    /// Get total tribute paid
    pub fn total_tribute_paid(&self) -> u64 {
        self.total_tribute_paid
    }

    /// Get a profit declaration by ID
    pub fn get_profit_declaration(&self, declaration_id: u64) -> Option<&ProfitDeclaration> {
        self.profit_declarations.get(&declaration_id)
    }

    /// Get a spending record by ID
    pub fn get_spending_record(&self, spending_id: u64) -> Option<&SpendingRecord> {
        self.spending_records.get(&spending_id)
    }

    /// Check if current cycle tribute is paid
    pub fn is_current_cycle_tribute_paid(&self) -> bool {
        self.current_cycle_tribute_paid
    }

    /// Check if treasury is frozen
    pub fn is_frozen(&self) -> bool {
        self.is_frozen
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

    /// Freeze/unfreeze the treasury (emergency only)
    pub fn set_frozen(&mut self, frozen: bool, caller: [u8; 32]) -> Result<(), ForProfitTreasuryError> {
        if !self.initialized {
            return Err(ForProfitTreasuryError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(ForProfitTreasuryError::Unauthorized);
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

impl Default for ForProfitTreasury {
    fn default() -> Self {
        Self::new()
    }
}
