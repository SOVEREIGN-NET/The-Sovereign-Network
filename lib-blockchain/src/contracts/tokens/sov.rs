//! SOV Token Contract - DOC 02: Phase 1 Governance & Treasury Rails
//!
//! The native token of the Sovereign Network with fixed supply.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! Total Supply:           1,000,000,000,000 (1 trillion, fixed, no minting)
//! Transaction Fee Rate:   100 basis points = 1% (not 2%)
//! ```
//!
//! # Architecture
//!
//! SOV is the primary currency token used for:
//! - Transaction fees (1% collected by FeeRouter)
//! - UBI distribution (45% of fees)
//! - DAO funding (30% of fees)
//! - Emergency reserves (15% of fees)
//! - Development grants (10% of fees)
//!
//! # Invariants
//!
//! - **S1**: Total supply is exactly 1 trillion (1,000,000,000,000)
//! - **S2**: No minting after initial distribution
//! - **S3**: No burn mechanism (or DAO-approved only)
//! - **S4**: Mission-bound use only

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::executor::{ExecutionContext, CallOrigin};

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Total supply of SOV tokens: 1 trillion (1,000,000,000,000)
/// This is FIXED and IMMUTABLE after initialization.
pub const SOV_TOTAL_SUPPLY: u64 = 1_000_000_000_000;

/// Number of decimal places for SOV token
pub const SOV_DECIMALS: u8 = 8;

/// Token symbol
pub const SOV_SYMBOL: &str = "SOV";

/// Token name
pub const SOV_NAME: &str = "Sovereign";

/// Transaction fee rate in basis points (100 = 1%)
pub const SOV_FEE_RATE_BASIS_POINTS: u16 = 100;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for SOV token operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SovTokenError {
    /// Token already initialized
    AlreadyInitialized,

    /// Token not yet initialized
    NotInitialized,

    /// Caller is not authorized
    Unauthorized,

    /// Insufficient balance for transfer
    InsufficientBalance,

    /// Insufficient allowance for transfer_from
    InsufficientAllowance,

    /// Attempted to mint after initialization (not allowed)
    MintingDisabled,

    /// Transfer amount is zero
    ZeroAmount,

    /// Arithmetic overflow
    Overflow,

    /// Recipient cannot be zero address
    ZeroRecipient,
}

impl std::fmt::Display for SovTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SovTokenError::AlreadyInitialized =>
                write!(f, "SOV token already initialized"),
            SovTokenError::NotInitialized =>
                write!(f, "SOV token not initialized"),
            SovTokenError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            SovTokenError::InsufficientBalance =>
                write!(f, "Insufficient balance"),
            SovTokenError::InsufficientAllowance =>
                write!(f, "Insufficient allowance"),
            SovTokenError::MintingDisabled =>
                write!(f, "Minting is disabled after initialization"),
            SovTokenError::ZeroAmount =>
                write!(f, "Transfer amount cannot be zero"),
            SovTokenError::Overflow =>
                write!(f, "Arithmetic overflow"),
            SovTokenError::ZeroRecipient =>
                write!(f, "Recipient cannot be zero address"),
        }
    }
}

// ============================================================================
// SOV TOKEN CONTRACT
// ============================================================================

/// SOV Token Contract
///
/// Native token of the Sovereign Network with fixed 1 trillion supply.
///
/// # Initialization
///
/// The token must be initialized exactly once with the initial distribution.
/// After initialization:
/// - Total supply is locked at 1 trillion
/// - No further minting is possible
/// - Transfers and allowances function normally
///
/// # Fee Collection
///
/// SOV collects 1% transaction fees at the consensus layer.
/// Fees are NOT handled by this contract directly - they are routed
/// through the FeeRouter contract which distributes them according
/// to the 45/30/15/10 split.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovToken {
    /// Token identifier
    token_id: [u8; 32],

    /// Account balances
    balances: HashMap<[u8; 32], u64>,

    /// Allowances: owner -> spender -> amount
    allowances: HashMap<[u8; 32], HashMap<[u8; 32], u64>>,

    /// Total supply (should always equal SOV_TOTAL_SUPPLY after init)
    total_supply: u64,

    /// Whether the token has been initialized
    initialized: bool,

    /// The address that performed initial distribution (for audit)
    initializer: Option<[u8; 32]>,
}

impl SovToken {
    /// Create a new uninitialized SOV token contract
    pub fn new() -> Self {
        Self {
            token_id: Self::derive_token_id(),
            balances: HashMap::new(),
            allowances: HashMap::new(),
            total_supply: 0,
            initialized: false,
            initializer: None,
        }
    }

    /// Derive the canonical token ID for SOV
    fn derive_token_id() -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        SOV_NAME.hash(&mut hasher);
        SOV_SYMBOL.hash(&mut hasher);
        let hash = hasher.finish();

        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        // Fill rest with deterministic pattern
        for i in 8..32 {
            id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
        }
        id
    }

    /// Initialize the token with the full supply distributed to specified addresses
    ///
    /// # Arguments
    ///
    /// * `initializer` - The address performing initialization
    /// * `distribution` - Map of addresses to their initial balances
    ///
    /// # Invariants Enforced
    ///
    /// - S1: Sum of distribution must equal exactly SOV_TOTAL_SUPPLY
    /// - S2: Can only be called once
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    /// - `Overflow` if distribution doesn't sum to exactly SOV_TOTAL_SUPPLY
    pub fn init(
        &mut self,
        initializer: &PublicKey,
        distribution: HashMap<PublicKey, u64>,
    ) -> Result<(), SovTokenError> {
        if self.initialized {
            return Err(SovTokenError::AlreadyInitialized);
        }

        // Calculate total of distribution
        let mut total: u64 = 0;
        for amount in distribution.values() {
            total = total.checked_add(*amount)
                .ok_or(SovTokenError::Overflow)?;
        }

        // Invariant S1: Must distribute exactly SOV_TOTAL_SUPPLY
        if total != SOV_TOTAL_SUPPLY {
            return Err(SovTokenError::Overflow);
        }

        // Apply distribution
        for (address, amount) in distribution {
            if amount > 0 {
                self.balances.insert(address.key_id, amount);
            }
        }

        self.total_supply = SOV_TOTAL_SUPPLY;
        self.initialized = true;
        self.initializer = Some(initializer.key_id);

        Ok(())
    }

    /// Simple initialization: all supply to a single address
    ///
    /// Convenience method for testing and simple deployments.
    pub fn init_simple(
        &mut self,
        initializer: &PublicKey,
        recipient: &PublicKey,
    ) -> Result<(), SovTokenError> {
        let mut distribution = HashMap::new();
        distribution.insert(recipient.clone(), SOV_TOTAL_SUPPLY);
        self.init(initializer, distribution)
    }

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /// Check if the token is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the token ID
    pub fn token_id(&self) -> [u8; 32] {
        self.token_id
    }

    /// Get total supply (should always be SOV_TOTAL_SUPPLY after init)
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Get token name
    pub fn name(&self) -> &'static str {
        SOV_NAME
    }

    /// Get token symbol
    pub fn symbol(&self) -> &'static str {
        SOV_SYMBOL
    }

    /// Get decimal places
    pub fn decimals(&self) -> u8 {
        SOV_DECIMALS
    }

    /// Get balance of an account
    pub fn balance_of(&self, account: &PublicKey) -> u64 {
        self.balances.get(&account.key_id).copied().unwrap_or(0)
    }

    /// Get allowance for a spender
    pub fn allowance(&self, owner: &PublicKey, spender: &PublicKey) -> u64 {
        self.allowances
            .get(&owner.key_id)
            .and_then(|spenders| spenders.get(&spender.key_id))
            .copied()
            .unwrap_or(0)
    }

    // ========================================================================
    // TRANSFER OPERATIONS
    // ========================================================================

    /// Transfer tokens from the execution source to a recipient
    ///
    /// Authorization is determined by the execution context:
    /// - User calls: debit from ctx.caller
    /// - Contract calls: debit from ctx.contract
    ///
    /// # Arguments
    ///
    /// * `ctx` - Execution context providing authorization
    /// * `to` - Recipient address
    /// * `amount` - Amount to transfer
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if token not initialized
    /// - `Unauthorized` if call_origin is System
    /// - `ZeroAmount` if amount is zero
    /// - `ZeroRecipient` if recipient is zero address
    /// - `InsufficientBalance` if source has insufficient balance
    pub fn transfer(
        &mut self,
        ctx: &ExecutionContext,
        to: &PublicKey,
        amount: u64,
    ) -> Result<(), SovTokenError> {
        if !self.initialized {
            return Err(SovTokenError::NotInitialized);
        }

        if amount == 0 {
            return Err(SovTokenError::ZeroAmount);
        }

        if to.as_bytes().iter().all(|b| *b == 0) {
            return Err(SovTokenError::ZeroRecipient);
        }

        // Determine source based on execution context
        let source_key_id = match ctx.call_origin {
            CallOrigin::User => ctx.caller.key_id,
            CallOrigin::Contract => ctx.contract.key_id,
            CallOrigin::System => return Err(SovTokenError::Unauthorized),
        };

        // Check source balance
        let source_balance = self.balances.get(&source_key_id).copied().unwrap_or(0);
        if source_balance < amount {
            return Err(SovTokenError::InsufficientBalance);
        }

        // Debit source
        if source_balance == amount {
            self.balances.remove(&source_key_id);
        } else {
            self.balances.insert(source_key_id, source_balance - amount);
        }

        // Credit recipient
        let to_balance = self.balances.get(&to.key_id).copied().unwrap_or(0);
        self.balances.insert(
            to.key_id,
            to_balance.checked_add(amount).ok_or(SovTokenError::Overflow)?,
        );

        Ok(())
    }

    /// Transfer from an allowance
    ///
    /// # Arguments
    ///
    /// * `ctx` - Execution context (spender derived from ctx)
    /// * `owner` - Account to debit from
    /// * `to` - Recipient address
    /// * `amount` - Amount to transfer
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if token not initialized
    /// - `InsufficientAllowance` if spender doesn't have enough allowance
    /// - `InsufficientBalance` if owner doesn't have enough balance
    pub fn transfer_from(
        &mut self,
        ctx: &ExecutionContext,
        owner: &PublicKey,
        to: &PublicKey,
        amount: u64,
    ) -> Result<(), SovTokenError> {
        if !self.initialized {
            return Err(SovTokenError::NotInitialized);
        }

        if amount == 0 {
            return Err(SovTokenError::ZeroAmount);
        }

        // Determine spender from execution context
        let spender_key_id = match ctx.call_origin {
            CallOrigin::User => ctx.caller.key_id,
            CallOrigin::Contract => ctx.contract.key_id,
            CallOrigin::System => return Err(SovTokenError::Unauthorized),
        };

        // Check allowance
        let current_allowance = self.allowances
            .get(&owner.key_id)
            .and_then(|s| s.get(&spender_key_id))
            .copied()
            .unwrap_or(0);

        if current_allowance < amount {
            return Err(SovTokenError::InsufficientAllowance);
        }

        // Check owner balance
        let owner_balance = self.balances.get(&owner.key_id).copied().unwrap_or(0);
        if owner_balance < amount {
            return Err(SovTokenError::InsufficientBalance);
        }

        // Reduce allowance
        let new_allowance = current_allowance - amount;
        if new_allowance == 0 {
            if let Some(spenders) = self.allowances.get_mut(&owner.key_id) {
                spenders.remove(&spender_key_id);
            }
        } else {
            self.allowances
                .entry(owner.key_id)
                .or_default()
                .insert(spender_key_id, new_allowance);
        }

        // Debit owner
        if owner_balance == amount {
            self.balances.remove(&owner.key_id);
        } else {
            self.balances.insert(owner.key_id, owner_balance - amount);
        }

        // Credit recipient
        let to_balance = self.balances.get(&to.key_id).copied().unwrap_or(0);
        self.balances.insert(
            to.key_id,
            to_balance.checked_add(amount).ok_or(SovTokenError::Overflow)?,
        );

        Ok(())
    }

    /// Approve spending allowance
    ///
    /// # Arguments
    ///
    /// * `owner` - Account granting allowance
    /// * `spender` - Account being granted allowance
    /// * `amount` - Amount of allowance
    pub fn approve(&mut self, owner: &PublicKey, spender: &PublicKey, amount: u64) {
        if amount == 0 {
            // Remove allowance if zero
            if let Some(spenders) = self.allowances.get_mut(&owner.key_id) {
                spenders.remove(&spender.key_id);
            }
        } else {
            self.allowances
                .entry(owner.key_id)
                .or_default()
                .insert(spender.key_id, amount);
        }
    }

    // ========================================================================
    // MINTING IS DISABLED
    // ========================================================================

    /// Attempt to mint tokens (always fails after initialization)
    ///
    /// SOV has a fixed supply. Minting is only allowed during initialization.
    /// After init, this will always return an error.
    ///
    /// # Returns
    ///
    /// - `Err(MintingDisabled)` always
    pub fn mint(&self, _to: &PublicKey, _amount: u64) -> Result<(), SovTokenError> {
        Err(SovTokenError::MintingDisabled)
    }

    // ========================================================================
    // FEE CALCULATION HELPERS
    // ========================================================================

    /// Calculate the 1% fee for a given amount
    ///
    /// This is a helper for the consensus layer and FeeRouter.
    /// SOV has a 1% (100 basis points) transaction fee.
    ///
    /// # Arguments
    ///
    /// * `amount` - The transaction amount
    ///
    /// # Returns
    ///
    /// The fee amount (1% of the input)
    pub fn calculate_fee(amount: u64) -> u64 {
        // 1% = amount / 100
        // Use integer division (rounds down)
        amount / 100
    }

    /// Calculate the net amount after fee deduction
    ///
    /// # Arguments
    ///
    /// * `gross_amount` - The gross transaction amount
    ///
    /// # Returns
    ///
    /// (net_amount, fee_amount)
    pub fn calculate_net_and_fee(gross_amount: u64) -> (u64, u64) {
        let fee = Self::calculate_fee(gross_amount);
        (gross_amount - fee, fee)
    }
}

impl Default for SovToken {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id],
            kyber_pk: vec![id],
            key_id: [id; 32],
        }
    }

    fn create_test_execution_context(caller: &PublicKey) -> ExecutionContext {
        ExecutionContext::with_contract(
            caller.clone(),
            caller.clone(),
            1,           // block_number
            1000,        // timestamp
            100000,      // gas_limit
            [1u8; 32],   // tx_hash
        )
    }

    // ========================================================================
    // CONSTANT TESTS
    // ========================================================================

    #[test]
    fn test_sov_total_supply_is_one_trillion() {
        assert_eq!(SOV_TOTAL_SUPPLY, 1_000_000_000_000);
    }

    #[test]
    fn test_sov_fee_rate_is_one_percent() {
        assert_eq!(SOV_FEE_RATE_BASIS_POINTS, 100);
    }

    #[test]
    fn test_sov_decimals_is_8() {
        assert_eq!(SOV_DECIMALS, 8);
    }

    // ========================================================================
    // INITIALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_new_token_not_initialized() {
        let token = SovToken::new();
        assert!(!token.is_initialized());
        assert_eq!(token.total_supply(), 0);
    }

    #[test]
    fn test_init_simple_success() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let recipient = create_test_public_key(2);

        let result = token.init_simple(&initializer, &recipient);

        assert!(result.is_ok());
        assert!(token.is_initialized());
        assert_eq!(token.total_supply(), SOV_TOTAL_SUPPLY);
        assert_eq!(token.balance_of(&recipient), SOV_TOTAL_SUPPLY);
    }

    #[test]
    fn test_init_distribution_success() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let addr1 = create_test_public_key(2);
        let addr2 = create_test_public_key(3);

        let mut distribution = HashMap::new();
        distribution.insert(addr1.clone(), 600_000_000_000); // 60%
        distribution.insert(addr2.clone(), 400_000_000_000); // 40%

        let result = token.init(&initializer, distribution);

        assert!(result.is_ok());
        assert_eq!(token.balance_of(&addr1), 600_000_000_000);
        assert_eq!(token.balance_of(&addr2), 400_000_000_000);
        assert_eq!(token.total_supply(), SOV_TOTAL_SUPPLY);
    }

    #[test]
    fn test_init_rejects_double_init() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let recipient = create_test_public_key(2);

        token.init_simple(&initializer, &recipient).unwrap();
        let result = token.init_simple(&initializer, &recipient);

        assert_eq!(result, Err(SovTokenError::AlreadyInitialized));
    }

    #[test]
    fn test_init_rejects_wrong_total() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let addr1 = create_test_public_key(2);

        let mut distribution = HashMap::new();
        distribution.insert(addr1, 500_000_000_000); // Only 50%

        let result = token.init(&initializer, distribution);

        assert_eq!(result, Err(SovTokenError::Overflow));
    }

    // ========================================================================
    // TRANSFER TESTS
    // ========================================================================

    #[test]
    fn test_transfer_success() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let sender = create_test_public_key(2);
        let recipient = create_test_public_key(3);

        token.init_simple(&initializer, &sender).unwrap();

        let ctx = create_test_execution_context(&sender);
        let result = token.transfer(&ctx, &recipient, 100_000_000_000);

        assert!(result.is_ok());
        assert_eq!(token.balance_of(&sender), SOV_TOTAL_SUPPLY - 100_000_000_000);
        assert_eq!(token.balance_of(&recipient), 100_000_000_000);
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let sender = create_test_public_key(2);
        let recipient = create_test_public_key(3);

        token.init_simple(&initializer, &sender).unwrap();

        let ctx = create_test_execution_context(&sender);
        let result = token.transfer(&ctx, &recipient, SOV_TOTAL_SUPPLY + 1);

        assert_eq!(result, Err(SovTokenError::InsufficientBalance));
    }

    #[test]
    fn test_transfer_zero_amount_fails() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let sender = create_test_public_key(2);
        let recipient = create_test_public_key(3);

        token.init_simple(&initializer, &sender).unwrap();

        let ctx = create_test_execution_context(&sender);
        let result = token.transfer(&ctx, &recipient, 0);

        assert_eq!(result, Err(SovTokenError::ZeroAmount));
    }

    // ========================================================================
    // ALLOWANCE TESTS
    // ========================================================================

    #[test]
    fn test_approve_and_transfer_from() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let owner = create_test_public_key(2);
        let spender = create_test_public_key(3);
        let recipient = create_test_public_key(4);

        token.init_simple(&initializer, &owner).unwrap();
        token.approve(&owner, &spender, 50_000_000_000);

        assert_eq!(token.allowance(&owner, &spender), 50_000_000_000);

        let ctx = create_test_execution_context(&spender);
        let result = token.transfer_from(&ctx, &owner, &recipient, 30_000_000_000);

        assert!(result.is_ok());
        assert_eq!(token.balance_of(&owner), SOV_TOTAL_SUPPLY - 30_000_000_000);
        assert_eq!(token.balance_of(&recipient), 30_000_000_000);
        assert_eq!(token.allowance(&owner, &spender), 20_000_000_000);
    }

    #[test]
    fn test_transfer_from_insufficient_allowance() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let owner = create_test_public_key(2);
        let spender = create_test_public_key(3);
        let recipient = create_test_public_key(4);

        token.init_simple(&initializer, &owner).unwrap();
        token.approve(&owner, &spender, 10_000_000_000);

        let ctx = create_test_execution_context(&spender);
        let result = token.transfer_from(&ctx, &owner, &recipient, 50_000_000_000);

        assert_eq!(result, Err(SovTokenError::InsufficientAllowance));
    }

    // ========================================================================
    // MINTING TESTS
    // ========================================================================

    #[test]
    fn test_mint_disabled() {
        let mut token = SovToken::new();
        let initializer = create_test_public_key(1);
        let recipient = create_test_public_key(2);

        token.init_simple(&initializer, &recipient).unwrap();

        let result = token.mint(&recipient, 1000);

        assert_eq!(result, Err(SovTokenError::MintingDisabled));
        assert_eq!(token.total_supply(), SOV_TOTAL_SUPPLY);
    }

    // ========================================================================
    // FEE CALCULATION TESTS
    // ========================================================================

    #[test]
    fn test_calculate_fee_1_percent() {
        // 1% of 1000 = 10
        assert_eq!(SovToken::calculate_fee(1000), 10);

        // 1% of 100 = 1
        assert_eq!(SovToken::calculate_fee(100), 1);

        // 1% of 1,000,000 = 10,000
        assert_eq!(SovToken::calculate_fee(1_000_000), 10_000);
    }

    #[test]
    fn test_calculate_net_and_fee() {
        let (net, fee) = SovToken::calculate_net_and_fee(1000);
        assert_eq!(net, 990);
        assert_eq!(fee, 10);

        let (net, fee) = SovToken::calculate_net_and_fee(1_000_000_000);
        assert_eq!(fee, 10_000_000);
        assert_eq!(net, 990_000_000);
    }

    #[test]
    fn test_fee_calculation_year_1() {
        // Year 1: $1M/month volume -> $10K fees
        // In token units: 1,000,000,000 (assuming 1 token = $1)
        let monthly_volume = 1_000_000_000u64;
        let fee = SovToken::calculate_fee(monthly_volume);
        assert_eq!(fee, 10_000_000); // $10K = 10,000,000 units
    }

    #[test]
    fn test_fee_calculation_year_3() {
        // Year 3: $500M/month volume -> $5M fees
        let monthly_volume = 500_000_000_000u64;
        let fee = SovToken::calculate_fee(monthly_volume);
        assert_eq!(fee, 5_000_000_000); // $5M
    }

    #[test]
    fn test_fee_calculation_year_5() {
        // Year 5: $5B/month volume -> $50M fees
        let monthly_volume = 5_000_000_000_000u64;
        let fee = SovToken::calculate_fee(monthly_volume);
        assert_eq!(fee, 50_000_000_000); // $50M
    }

    // ========================================================================
    // TOKEN INFO TESTS
    // ========================================================================

    #[test]
    fn test_token_info() {
        let token = SovToken::new();

        assert_eq!(token.name(), "Sovereign");
        assert_eq!(token.symbol(), "SOV");
        assert_eq!(token.decimals(), 8);
    }
}
