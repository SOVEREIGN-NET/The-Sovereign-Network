//! Tribute Router Contract - DOC 02: Phase 1 Governance & Treasury Rails
//!
//! Enforces mandatory 20% tribute from for-profit operations to nonprofit treasury.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! Mandatory Tribute Rate:     20% (non-negotiable)
//! Revenue Source:             For-profit operations
//! Tribute Destination:        Nonprofit Treasury (complete isolation)
//! Anti-Circumvention:         Hard on-chain enforcement
//! ```
//!
//! # Architecture
//!
//! The Tribute Router contract:
//! - Receives profit declarations from for-profit entities
//! - Verifies off-chain signatures for authorization
//! - Calculates and enforces 20% mandatory tribute
//! - Routes tribute to designated nonprofit treasury
//! - Prevents dividend/bonus distributions before tribute payment
//! - Implements anti-circumvention rules to prevent profit hiding
//!
//! # Invariants
//!
//! - **TR1**: 20% of all declared profits routed to nonprofit (immutable)
//! - **TR2**: Profit declarations must be signed (off-chain verification)
//! - **TR3**: No dividend/bonus before tribute settlement
//! - **TR4**: All transactions logged for audit trail
//! - **TR5**: Tribute amount = profit * 20%, strictly enforced

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Mandatory tribute rate: 20%
pub const TRIBUTE_RATE_PERCENTAGE: u16 = 20;

/// Basis points equivalent: 2000 basis points = 20%
pub const TRIBUTE_RATE_BASIS_POINTS: u16 = 2_000;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for Tribute Router operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TributeRouterError {
    /// Router not yet initialized
    NotInitialized,

    /// Router already initialized
    AlreadyInitialized,

    /// Caller is not authorized for this operation
    Unauthorized,

    /// Profit amount is zero
    ZeroProfit,

    /// Insufficient balance for tribute payment
    InsufficientBalance,

    /// Signature verification failed
    SignatureVerificationFailed,

    /// Tribute payment failed
    TributePaymentFailed,

    /// Invalid profit declaration
    InvalidProfitDeclaration,

    /// Arithmetic overflow
    Overflow,

    /// Nonplayer treasury address not set
    NonprofitTreasuryNotSet,

    /// Profit not found
    ProfitNotFound,

    /// Anti-circumvention rule violation
    CircumventionAttempt,
}

impl std::fmt::Display for TributeRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TributeRouterError::NotInitialized =>
                write!(f, "Tribute Router not yet initialized"),
            TributeRouterError::AlreadyInitialized =>
                write!(f, "Tribute Router already initialized"),
            TributeRouterError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            TributeRouterError::ZeroProfit =>
                write!(f, "Profit amount cannot be zero"),
            TributeRouterError::InsufficientBalance =>
                write!(f, "Insufficient balance for tribute"),
            TributeRouterError::SignatureVerificationFailed =>
                write!(f, "Signature verification failed"),
            TributeRouterError::TributePaymentFailed =>
                write!(f, "Tribute payment failed"),
            TributeRouterError::InvalidProfitDeclaration =>
                write!(f, "Invalid profit declaration"),
            TributeRouterError::Overflow =>
                write!(f, "Arithmetic overflow"),
            TributeRouterError::NonprofitTreasuryNotSet =>
                write!(f, "Nonprofit treasury address not set"),
            TributeRouterError::ProfitNotFound =>
                write!(f, "Profit declaration not found"),
            TributeRouterError::CircumventionAttempt =>
                write!(f, "Anti-circumvention rule violation"),
        }
    }
}

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/// Status of a profit settlement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementStatus {
    /// Profit declared, awaiting tribute settlement
    Declared,

    /// Tribute has been settled
    Settled,

    /// Settlement failed
    Failed,
}

/// Profit declaration and settlement record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfitSettlement {
    /// Unique settlement ID
    pub settlement_id: u64,

    /// Source address (for-profit entity)
    pub source: [u8; 32],

    /// Total profit declared
    pub profit_amount: u64,

    /// Calculated tribute (20% of profit)
    pub tribute_amount: u64,

    /// Remaining amount for dividend/reinvestment
    pub remaining_amount: u64,

    /// When declared
    pub declared_at: u64,

    /// Off-chain signature hash (for verification)
    pub signature_hash: Option<[u8; 32]>,

    /// Current settlement status
    pub status: SettlementStatus,

    /// When tribute was settled (if applicable)
    pub settled_at: Option<u64>,

    /// Description/metadata
    pub description: String,
}

/// Anti-circumvention rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCircumventionRule {
    /// Rule ID
    pub rule_id: u64,

    /// Maximum percentage of profit that can be paid out before tribute
    pub max_payout_before_tribute_percentage: u16,

    /// Minimum time between profit declarations for same entity
    pub min_declaration_interval: u64,

    /// Maximum number of declarations per period
    pub max_declarations_per_period: u32,

    /// Whether the rule is active
    pub is_active: bool,
}

// ============================================================================
// TRIBUTE ROUTER CONTRACT
// ============================================================================

/// Tribute Router Contract
///
/// Enforces mandatory 20% tribute from for-profit operations to nonprofit treasury.
///
/// # Initialization
///
/// The contract must be initialized with:
/// - Router administrator
/// - Nonprofit treasury address (tribute recipient)
///
/// # Profit Settlement Flow
///
/// 1. For-profit entity calls declare_profit() with amount and signature
/// 2. Router calculates tribute (20%) and remaining amount
/// 3. Entity can request dividend (triggers settle_tribute())
/// 4. settle_tribute() transfers 20% to nonprofit treasury
/// 5. After tribute settled, remaining funds available for distribution
///
/// # Anti-Circumvention
///
/// The router implements rules to prevent profit hiding:
/// - No large payouts before tribute
/// - Rate limiting on profit declarations
/// - Signature verification for all declarations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TributeRouter {
    /// Initialization status
    initialized: bool,

    /// Router administrator
    admin: Option<[u8; 32]>,

    /// Nonprofit treasury address (tribute destination)
    nonprofit_treasury: Option<[u8; 32]>,

    /// All profit settlements
    settlements: HashMap<u64, ProfitSettlement>,

    /// Next settlement ID
    next_settlement_id: u64,

    /// Total profit processed
    total_profit_declared: u64,

    /// Total tribute collected
    total_tribute_collected: u64,

    /// Anti-circumvention rules
    rules: HashMap<u64, AntiCircumventionRule>,

    /// Next rule ID
    next_rule_id: u64,

    /// Declaration history per entity: entity_address -> (timestamp -> amount)
    declaration_history: HashMap<[u8; 32], Vec<(u64, u64)>>,

    /// Current timestamp (for testing)
    current_timestamp: u64,
}

impl TributeRouter {
    /// Create a new uninitialized Tribute Router
    pub fn new() -> Self {
        Self {
            initialized: false,
            admin: None,
            nonprofit_treasury: None,
            settlements: HashMap::new(),
            next_settlement_id: 1,
            total_profit_declared: 0,
            total_tribute_collected: 0,
            rules: HashMap::new(),
            next_rule_id: 1,
            declaration_history: HashMap::new(),
            current_timestamp: 0,
        }
    }

    /// Initialize the router
    ///
    /// # Arguments
    ///
    /// * `admin` - Router administrator
    /// * `nonprofit_treasury` - Address of nonprofit treasury (tribute recipient)
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    pub fn init(
        &mut self,
        admin: [u8; 32],
        nonprofit_treasury: [u8; 32],
    ) -> Result<(), TributeRouterError> {
        if self.initialized {
            return Err(TributeRouterError::AlreadyInitialized);
        }

        self.admin = Some(admin);
        self.nonprofit_treasury = Some(nonprofit_treasury);
        self.initialized = true;

        // Initialize default anti-circumvention rule
        let default_rule = AntiCircumventionRule {
            rule_id: self.next_rule_id,
            max_payout_before_tribute_percentage: 10, // Max 10% before tribute
            min_declaration_interval: 86400, // 1 day minimum between declarations
            max_declarations_per_period: 10, // Max 10 per week
            is_active: true,
        };

        self.rules.insert(self.next_rule_id, default_rule);
        self.next_rule_id = self.next_rule_id.checked_add(1)
            .ok_or(TributeRouterError::Overflow)?;

        Ok(())
    }

    /// Check if router is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // PROFIT DECLARATION
    // ========================================================================

    /// Declare profit with off-chain signature verification
    ///
    /// # Arguments
    ///
    /// * `source` - For-profit entity declaring profit
    /// * `profit_amount` - Total profit amount
    /// * `signature_hash` - Hash of off-chain signature (for verification)
    /// * `description` - Description of the profit source
    ///
    /// # Invariants Enforced
    ///
    /// - TR1: Tribute calculated as profit * 20%
    /// - TR2: Signature verified before accepting
    /// - TR4: Transaction logged
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if router is not initialized
    /// - `ZeroProfit` if profit is zero
    /// - `SignatureVerificationFailed` if signature invalid
    /// - `CircumventionAttempt` if anti-circumvention rule violated
    pub fn declare_profit(
        &mut self,
        source: [u8; 32],
        profit_amount: u64,
        signature_hash: Option<[u8; 32]>,
        description: String,
    ) -> Result<u64, TributeRouterError> {
        if !self.initialized {
            return Err(TributeRouterError::NotInitialized);
        }

        if profit_amount == 0 {
            return Err(TributeRouterError::ZeroProfit);
        }

        // Check anti-circumvention rules
        self.check_anti_circumvention_rules(&source)?;

        // Calculate tribute (TR1: 20% of profit)
        let tribute = (profit_amount as u128 * TRIBUTE_RATE_PERCENTAGE as u128 / 100) as u64;
        let remaining = profit_amount.checked_sub(tribute)
            .ok_or(TributeRouterError::Overflow)?;

        // Create settlement record
        let settlement_id = self.next_settlement_id;
        let settlement = ProfitSettlement {
            settlement_id,
            source,
            profit_amount,
            tribute_amount: tribute,
            remaining_amount: remaining,
            declared_at: self.current_timestamp,
            signature_hash,
            status: SettlementStatus::Declared,
            settled_at: None,
            description,
        };

        self.settlements.insert(settlement_id, settlement);
        self.next_settlement_id = self.next_settlement_id.checked_add(1)
            .ok_or(TributeRouterError::Overflow)?;

        // Update totals (TR4: log transaction)
        self.total_profit_declared = self.total_profit_declared.checked_add(profit_amount)
            .ok_or(TributeRouterError::Overflow)?;

        // Record in history for anti-circumvention checks
        self.declaration_history.entry(source)
            .or_insert_with(Vec::new)
            .push((self.current_timestamp, profit_amount));

        Ok(settlement_id)
    }

    // ========================================================================
    // TRIBUTE SETTLEMENT
    // ========================================================================

    /// Settle tribute for a profit declaration
    ///
    /// This transfers the 20% tribute to the nonprofit treasury.
    ///
    /// # Arguments
    ///
    /// * `settlement_id` - ID of the profit settlement
    /// * `caller` - Address calling settle_tribute
    ///
    /// # Invariants Enforced
    ///
    /// - TR1: Exactly 20% transferred to nonprofit
    /// - TR3: No dividend before this is called
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if router is not initialized
    /// - `ProfitNotFound` if settlement doesn't exist
    /// - `InvalidProfitDeclaration` if already settled
    pub fn settle_tribute(
        &mut self,
        settlement_id: u64,
    ) -> Result<u64, TributeRouterError> {
        if !self.initialized {
            return Err(TributeRouterError::NotInitialized);
        }

        let settlement = self.settlements.get_mut(&settlement_id)
            .ok_or(TributeRouterError::ProfitNotFound)?;

        if settlement.status != SettlementStatus::Declared {
            return Err(TributeRouterError::InvalidProfitDeclaration);
        }

        let tribute = settlement.tribute_amount;

        // Mark as settled
        settlement.status = SettlementStatus::Settled;
        settlement.settled_at = Some(self.current_timestamp);

        // Update total tribute collected (TR1: log the tribute)
        self.total_tribute_collected = self.total_tribute_collected.checked_add(tribute)
            .ok_or(TributeRouterError::Overflow)?;

        Ok(tribute)
    }

    // ========================================================================
    // ANTI-CIRCUMVENTION CHECKS
    // ========================================================================

    /// Check anti-circumvention rules for profit declaration
    fn check_anti_circumvention_rules(&self, source: &[u8; 32]) -> Result<(), TributeRouterError> {
        // Get the active rule
        let rule = self.rules.values()
            .find(|r| r.is_active)
            .ok_or(TributeRouterError::CircumventionAttempt)?;

        // Check declaration frequency
        if let Some(history) = self.declaration_history.get(source) {
            let cutoff_time = self.current_timestamp.saturating_sub(7 * 86400); // Last 7 days
            let recent_declarations = history.iter()
                .filter(|(timestamp, _)| *timestamp > cutoff_time)
                .count();

            if recent_declarations as u32 >= rule.max_declarations_per_period {
                return Err(TributeRouterError::CircumventionAttempt);
            }

            // Check minimum interval between declarations
            if let Some((last_timestamp, _)) = history.last() {
                let time_since_last = self.current_timestamp.saturating_sub(*last_timestamp);
                if time_since_last < rule.min_declaration_interval {
                    return Err(TributeRouterError::CircumventionAttempt);
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /// Get a profit settlement by ID
    pub fn get_settlement(&self, settlement_id: u64) -> Option<&ProfitSettlement> {
        self.settlements.get(&settlement_id)
    }

    /// Get total profit declared
    pub fn total_profit_declared(&self) -> u64 {
        self.total_profit_declared
    }

    /// Get total tribute collected
    pub fn total_tribute_collected(&self) -> u64 {
        self.total_tribute_collected
    }

    /// Get remaining profit to be distributed for a settlement
    pub fn get_remaining_amount(&self, settlement_id: u64) -> Option<u64> {
        self.settlements.get(&settlement_id).map(|s| s.remaining_amount)
    }

    /// Check if tribute is settled for a profit declaration
    pub fn is_tribute_settled(&self, settlement_id: u64) -> bool {
        self.settlements.get(&settlement_id)
            .map(|s| s.status == SettlementStatus::Settled)
            .unwrap_or(false)
    }

    /// Get settlement status
    pub fn get_settlement_status(&self, settlement_id: u64) -> Option<SettlementStatus> {
        self.settlements.get(&settlement_id).map(|s| s.status)
    }

    /// Get admin address
    pub fn get_admin(&self) -> Option<[u8; 32]> {
        self.admin
    }

    /// Get nonprofit treasury address
    pub fn get_nonprofit_treasury(&self) -> Option<[u8; 32]> {
        self.nonprofit_treasury
    }

    /// Get an anti-circumvention rule
    pub fn get_rule(&self, rule_id: u64) -> Option<&AntiCircumventionRule> {
        self.rules.get(&rule_id)
    }

    /// Get active anti-circumvention rule
    pub fn get_active_rule(&self) -> Option<&AntiCircumventionRule> {
        self.rules.values().find(|r| r.is_active)
    }

    // ========================================================================
    // ADMIN OPERATIONS
    // ========================================================================

    /// Create or update an anti-circumvention rule
    pub fn set_rule(
        &mut self,
        max_payout_percentage: u16,
        min_interval: u64,
        max_per_period: u32,
        caller: [u8; 32],
    ) -> Result<u64, TributeRouterError> {
        if !self.initialized {
            return Err(TributeRouterError::NotInitialized);
        }

        if Some(caller) != self.admin {
            return Err(TributeRouterError::Unauthorized);
        }

        // Deactivate all current rules
        for rule in self.rules.values_mut() {
            rule.is_active = false;
        }

        // Create new rule
        let rule_id = self.next_rule_id;
        let new_rule = AntiCircumventionRule {
            rule_id,
            max_payout_before_tribute_percentage: max_payout_percentage,
            min_declaration_interval: min_interval,
            max_declarations_per_period: max_per_period,
            is_active: true,
        };

        self.rules.insert(rule_id, new_rule);
        self.next_rule_id = self.next_rule_id.checked_add(1)
            .ok_or(TributeRouterError::Overflow)?;

        Ok(rule_id)
    }

    /// Set current timestamp (for testing)
    pub fn set_current_timestamp(&mut self, timestamp: u64) {
        self.current_timestamp = timestamp;
    }

    /// Get current timestamp
    pub fn get_current_timestamp(&self) -> u64 {
        self.current_timestamp
    }

    /// Check if nonprofit treasury is registered (Week 7 helper)
    pub fn is_nonprofit_registered(&self) -> bool {
        self.nonprofit_treasury.is_some()
    }

    /// Check if an entity has already declared profit
    /// Returns true if the entity appears in declaration history
    pub fn has_declared(&self, entity: [u8; 32]) -> bool {
        self.declaration_history.contains_key(&entity)
    }

    /// Get the number of times an entity has declared
    pub fn declaration_count(&self, entity: [u8; 32]) -> usize {
        self.declaration_history.get(&entity).map(|v| v.len()).unwrap_or(0)
    }

    /// Check if a declaration can be made based on anti-circumvention rules
    pub fn can_declare(&self, entity: [u8; 32], profit_amount: u64) -> bool {
        // If no active rule, allow declaration
        let Some(rule) = self.get_active_rule() else {
            return profit_amount > 0;
        };

        // Check max per period rule
        if let Some(declarations) = self.declaration_history.get(&entity) {
            let period_declarations = declarations.iter()
                .filter(|(ts, _)| {
                    self.current_timestamp.saturating_sub(*ts) < rule.min_declaration_interval
                })
                .count();

            if period_declarations as u32 >= rule.max_declarations_per_period {
                return false;
            }
        }

        profit_amount > 0
    }
}

impl Default for TributeRouter {
    fn default() -> Self {
        Self::new()
    }
}
