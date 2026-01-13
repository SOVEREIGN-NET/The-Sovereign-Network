//! CBE Corporate Token Contract - DOC 02: Phase 1 Governance & Treasury Rails
//!
//! The corporate equity token for the CBE (for-profit) entity.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! Total Supply:          100,000,000,000 (100 billion, fixed)
//! Compensation pool:     40% (40 billion tokens)
//! Operational treasury:  30% (30 billion tokens)
//! Performance incentives: 20% (20 billion tokens)
//! Strategic reserves:    10% (10 billion tokens)
//! ```
//!
//! # Token Price Progression
//!
//! ```text
//! Year 1: $0.10 -> $0.15
//! Year 2: $0.15 -> $0.35
//! Year 3: $0.35 -> $1.00
//! Year 5: $1.00 -> $2.00+
//! ```
//!
//! # Invariants
//!
//! - **C1**: Total supply is exactly 100 billion (100,000,000,000)
//! - **C2**: No minting after initial distribution
//! - **C3**: Vesting-aware transfers (restricted until vested)
//! - **C4**: Distribution locked at 40/30/20/10 split

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::executor::{ExecutionContext, CallOrigin};

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Total supply of CBE tokens: 100 billion (100,000,000,000)
pub const CBE_TOTAL_SUPPLY: u64 = 100_000_000_000;

/// Compensation pool allocation: 40% = 40 billion
pub const CBE_COMPENSATION_POOL: u64 = 40_000_000_000;

/// Operational treasury allocation: 30% = 30 billion
pub const CBE_OPERATIONAL_TREASURY: u64 = 30_000_000_000;

/// Performance incentives allocation: 20% = 20 billion
pub const CBE_PERFORMANCE_INCENTIVES: u64 = 20_000_000_000;

/// Strategic reserves allocation: 10% = 10 billion
pub const CBE_STRATEGIC_RESERVES: u64 = 10_000_000_000;

/// Number of decimal places for CBE token
pub const CBE_DECIMALS: u8 = 8;

/// Token symbol
pub const CBE_SYMBOL: &str = "CBE";

/// Token name
pub const CBE_NAME: &str = "CBE Equity";

// ============================================================================
// DISTRIBUTION ALLOCATION
// ============================================================================

/// Distribution allocation structure
///
/// Represents the 40/30/20/10 split of CBE tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionAllocation {
    /// Compensation pool: 40 billion (40%)
    pub compensation: u64,

    /// Operational treasury: 30 billion (30%)
    pub operational: u64,

    /// Performance incentives: 20 billion (20%)
    pub performance: u64,

    /// Strategic reserves: 10 billion (10%)
    pub strategic: u64,
}

impl Default for DistributionAllocation {
    fn default() -> Self {
        Self {
            compensation: CBE_COMPENSATION_POOL,
            operational: CBE_OPERATIONAL_TREASURY,
            performance: CBE_PERFORMANCE_INCENTIVES,
            strategic: CBE_STRATEGIC_RESERVES,
        }
    }
}

impl DistributionAllocation {
    /// Verify the allocation sums to total supply
    pub fn verify(&self) -> bool {
        self.compensation
            .checked_add(self.operational)
            .and_then(|sum| sum.checked_add(self.performance))
            .and_then(|sum| sum.checked_add(self.strategic))
            == Some(CBE_TOTAL_SUPPLY)
    }
}

// ============================================================================
// VESTING TYPES
// ============================================================================

/// Vesting schedule for CBE tokens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Total tokens in this vesting schedule
    pub total_amount: u64,

    /// Tokens already vested (can be transferred)
    pub vested_amount: u64,

    /// Block height when vesting started
    pub start_block: u64,

    /// Number of blocks until fully vested
    pub vesting_duration_blocks: u64,

    /// Cliff period in blocks (no vesting before cliff)
    pub cliff_blocks: u64,

    /// Pool this vesting belongs to
    pub pool: VestingPool,
}

/// Which pool a vesting schedule belongs to
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VestingPool {
    Compensation,
    Operational,
    Performance,
    Strategic,
}

impl VestingPool {
    pub fn as_str(&self) -> &'static str {
        match self {
            VestingPool::Compensation => "compensation",
            VestingPool::Operational => "operational",
            VestingPool::Performance => "performance",
            VestingPool::Strategic => "strategic",
        }
    }
}

impl VestingSchedule {
    /// Calculate vested amount at a given block height
    pub fn calculate_vested(&self, current_block: u64) -> u64 {
        if current_block < self.start_block + self.cliff_blocks {
            // Before cliff: nothing vested
            return 0;
        }

        let blocks_since_start = current_block.saturating_sub(self.start_block);

        if blocks_since_start >= self.vesting_duration_blocks {
            // Fully vested
            return self.total_amount;
        }

        // Linear vesting after cliff
        // vested = total * (blocks_since_start / vesting_duration)
        let vested = (self.total_amount as u128)
            .checked_mul(blocks_since_start as u128)
            .and_then(|v| v.checked_div(self.vesting_duration_blocks as u128))
            .unwrap_or(0) as u64;

        vested
    }

    /// Get transferable (vested - already released) amount
    pub fn transferable(&self, current_block: u64) -> u64 {
        self.calculate_vested(current_block).saturating_sub(self.vested_amount)
    }
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for CBE token operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbeTokenError {
    /// Token already initialized
    AlreadyInitialized,

    /// Token not yet initialized
    NotInitialized,

    /// Caller is not authorized
    Unauthorized,

    /// Insufficient balance for transfer
    InsufficientBalance,

    /// Insufficient vested balance for transfer
    InsufficientVestedBalance,

    /// Insufficient allowance for transfer_from
    InsufficientAllowance,

    /// Attempted to mint after initialization
    MintingDisabled,

    /// Transfer amount is zero
    ZeroAmount,

    /// Arithmetic overflow
    Overflow,

    /// Recipient cannot be zero address
    ZeroRecipient,

    /// Invalid distribution allocation
    InvalidAllocation,

    /// Vesting schedule not found
    VestingNotFound,

    /// Cannot transfer unvested tokens
    TokensNotVested,
}

impl std::fmt::Display for CbeTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CbeTokenError::AlreadyInitialized =>
                write!(f, "CBE token already initialized"),
            CbeTokenError::NotInitialized =>
                write!(f, "CBE token not initialized"),
            CbeTokenError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            CbeTokenError::InsufficientBalance =>
                write!(f, "Insufficient balance"),
            CbeTokenError::InsufficientVestedBalance =>
                write!(f, "Insufficient vested balance"),
            CbeTokenError::InsufficientAllowance =>
                write!(f, "Insufficient allowance"),
            CbeTokenError::MintingDisabled =>
                write!(f, "Minting is disabled after initialization"),
            CbeTokenError::ZeroAmount =>
                write!(f, "Transfer amount cannot be zero"),
            CbeTokenError::Overflow =>
                write!(f, "Arithmetic overflow"),
            CbeTokenError::ZeroRecipient =>
                write!(f, "Recipient cannot be zero address"),
            CbeTokenError::InvalidAllocation =>
                write!(f, "Distribution allocation must sum to 100 billion"),
            CbeTokenError::VestingNotFound =>
                write!(f, "Vesting schedule not found"),
            CbeTokenError::TokensNotVested =>
                write!(f, "Cannot transfer unvested tokens"),
        }
    }
}

// ============================================================================
// CBE TOKEN CONTRACT
// ============================================================================

/// CBE Corporate Token Contract
///
/// Corporate equity token with vesting support and fixed distribution.
///
/// # Distribution Pools
///
/// - Compensation (40%): Employee and team compensation
/// - Operational (30%): Day-to-day operations funding
/// - Performance (20%): Performance-based incentives
/// - Strategic (10%): Long-term strategic reserves
///
/// # Vesting
///
/// CBE tokens can have vesting schedules attached. Unvested tokens
/// cannot be transferred until they vest according to their schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbeToken {
    /// Token identifier
    token_id: [u8; 32],

    /// Account balances (total including unvested)
    balances: HashMap<[u8; 32], u64>,

    /// Vesting schedules by account
    vesting_schedules: HashMap<[u8; 32], Vec<VestingSchedule>>,

    /// Allowances: owner -> spender -> amount
    allowances: HashMap<[u8; 32], HashMap<[u8; 32], u64>>,

    /// Total supply (should always equal CBE_TOTAL_SUPPLY after init)
    total_supply: u64,

    /// Distribution allocation
    distribution: DistributionAllocation,

    /// Pool addresses
    pool_addresses: PoolAddresses,

    /// Whether the token has been initialized
    initialized: bool,
}

/// Addresses for the four distribution pools
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolAddresses {
    pub compensation: Option<[u8; 32]>,
    pub operational: Option<[u8; 32]>,
    pub performance: Option<[u8; 32]>,
    pub strategic: Option<[u8; 32]>,
}

impl CbeToken {
    /// Create a new uninitialized CBE token contract
    pub fn new() -> Self {
        Self {
            token_id: Self::derive_token_id(),
            balances: HashMap::new(),
            vesting_schedules: HashMap::new(),
            allowances: HashMap::new(),
            total_supply: 0,
            distribution: DistributionAllocation::default(),
            pool_addresses: PoolAddresses::default(),
            initialized: false,
        }
    }

    /// Derive the canonical token ID for CBE
    fn derive_token_id() -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        CBE_NAME.hash(&mut hasher);
        CBE_SYMBOL.hash(&mut hasher);
        let hash = hasher.finish();

        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        for i in 8..32 {
            id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
        }
        id
    }

    /// Initialize the token with the 40/30/20/10 distribution
    ///
    /// # Arguments
    ///
    /// * `compensation_address` - Address for compensation pool (40%)
    /// * `operational_address` - Address for operational treasury (30%)
    /// * `performance_address` - Address for performance incentives (20%)
    /// * `strategic_address` - Address for strategic reserves (10%)
    ///
    /// # Invariants Enforced
    ///
    /// - C1: Total distribution equals exactly CBE_TOTAL_SUPPLY
    /// - C4: Distribution follows 40/30/20/10 split
    pub fn init(
        &mut self,
        compensation_address: &PublicKey,
        operational_address: &PublicKey,
        performance_address: &PublicKey,
        strategic_address: &PublicKey,
    ) -> Result<(), CbeTokenError> {
        if self.initialized {
            return Err(CbeTokenError::AlreadyInitialized);
        }

        // Verify allocation sums correctly
        if !self.distribution.verify() {
            return Err(CbeTokenError::InvalidAllocation);
        }

        // Store pool addresses
        self.pool_addresses = PoolAddresses {
            compensation: Some(compensation_address.key_id),
            operational: Some(operational_address.key_id),
            performance: Some(performance_address.key_id),
            strategic: Some(strategic_address.key_id),
        };

        // Distribute tokens to pools
        self.balances.insert(compensation_address.key_id, CBE_COMPENSATION_POOL);
        self.balances.insert(operational_address.key_id, CBE_OPERATIONAL_TREASURY);
        self.balances.insert(performance_address.key_id, CBE_PERFORMANCE_INCENTIVES);
        self.balances.insert(strategic_address.key_id, CBE_STRATEGIC_RESERVES);

        self.total_supply = CBE_TOTAL_SUPPLY;
        self.initialized = true;

        Ok(())
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

    /// Get total supply
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Get token name
    pub fn name(&self) -> &'static str {
        CBE_NAME
    }

    /// Get token symbol
    pub fn symbol(&self) -> &'static str {
        CBE_SYMBOL
    }

    /// Get decimal places
    pub fn decimals(&self) -> u8 {
        CBE_DECIMALS
    }

    /// Get distribution allocation
    pub fn distribution(&self) -> &DistributionAllocation {
        &self.distribution
    }

    /// Get total balance of an account (including unvested)
    pub fn balance_of(&self, account: &PublicKey) -> u64 {
        self.balances.get(&account.key_id).copied().unwrap_or(0)
    }

    /// Get vested (transferable) balance at a given block
    pub fn vested_balance_of(&self, account: &PublicKey, current_block: u64) -> u64 {
        let total_balance = self.balance_of(account);

        // Calculate total unvested from vesting schedules
        let schedules = self.vesting_schedules.get(&account.key_id);
        if schedules.is_none() {
            // No vesting schedules means all balance is vested
            return total_balance;
        }

        let unvested: u64 = schedules.unwrap().iter()
            .map(|s| {
                let vested = s.calculate_vested(current_block);
                s.total_amount.saturating_sub(vested)
            })
            .sum();

        total_balance.saturating_sub(unvested)
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
    // VESTING OPERATIONS
    // ========================================================================

    /// Create a vesting schedule for tokens
    ///
    /// # Arguments
    ///
    /// * `beneficiary` - Address receiving the vesting tokens
    /// * `amount` - Amount of tokens to vest
    /// * `start_block` - Block when vesting starts
    /// * `duration_blocks` - Total vesting duration in blocks
    /// * `cliff_blocks` - Cliff period in blocks
    /// * `pool` - Which pool this vesting is from
    pub fn create_vesting(
        &mut self,
        beneficiary: &PublicKey,
        amount: u64,
        start_block: u64,
        duration_blocks: u64,
        cliff_blocks: u64,
        pool: VestingPool,
    ) -> Result<(), CbeTokenError> {
        if !self.initialized {
            return Err(CbeTokenError::NotInitialized);
        }

        if amount == 0 {
            return Err(CbeTokenError::ZeroAmount);
        }

        // Create vesting schedule
        let schedule = VestingSchedule {
            total_amount: amount,
            vested_amount: 0,
            start_block,
            vesting_duration_blocks: duration_blocks,
            cliff_blocks,
            pool,
        };

        // Add to beneficiary's schedules
        self.vesting_schedules
            .entry(beneficiary.key_id)
            .or_default()
            .push(schedule);

        Ok(())
    }

    /// Get vesting schedules for an account
    pub fn get_vesting_schedules(&self, account: &PublicKey) -> Vec<VestingSchedule> {
        self.vesting_schedules
            .get(&account.key_id)
            .cloned()
            .unwrap_or_default()
    }

    // ========================================================================
    // TRANSFER OPERATIONS
    // ========================================================================

    /// Transfer tokens (only vested tokens can be transferred)
    ///
    /// # Arguments
    ///
    /// * `ctx` - Execution context
    /// * `to` - Recipient address
    /// * `amount` - Amount to transfer
    /// * `current_block` - Current block height (for vesting calculation)
    pub fn transfer(
        &mut self,
        ctx: &ExecutionContext,
        to: &PublicKey,
        amount: u64,
        current_block: u64,
    ) -> Result<(), CbeTokenError> {
        if !self.initialized {
            return Err(CbeTokenError::NotInitialized);
        }

        if amount == 0 {
            return Err(CbeTokenError::ZeroAmount);
        }

        if to.as_bytes().iter().all(|b| *b == 0) {
            return Err(CbeTokenError::ZeroRecipient);
        }

        // Determine source
        let source_key_id = match ctx.call_origin {
            CallOrigin::User => ctx.caller.key_id,
            CallOrigin::Contract => ctx.contract.key_id,
            CallOrigin::System => return Err(CbeTokenError::Unauthorized),
        };

        // Create a temporary PublicKey for vested_balance_of lookup
        let source_pk = PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: source_key_id,
        };

        // Check vested balance
        let vested = self.vested_balance_of(&source_pk, current_block);
        if vested < amount {
            return Err(CbeTokenError::InsufficientVestedBalance);
        }

        // Check total balance
        let source_balance = self.balances.get(&source_key_id).copied().unwrap_or(0);
        if source_balance < amount {
            return Err(CbeTokenError::InsufficientBalance);
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
            to_balance.checked_add(amount).ok_or(CbeTokenError::Overflow)?,
        );

        Ok(())
    }

    /// Approve spending allowance
    pub fn approve(&mut self, owner: &PublicKey, spender: &PublicKey, amount: u64) {
        if amount == 0 {
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

    /// Attempt to mint tokens (always fails after initialization)
    pub fn mint(&self, _to: &PublicKey, _amount: u64) -> Result<(), CbeTokenError> {
        Err(CbeTokenError::MintingDisabled)
    }
}

impl Default for CbeToken {
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
            1,
            1000,
            100000,
            [1u8; 32],
        )
    }

    // ========================================================================
    // CONSTANT TESTS
    // ========================================================================

    #[test]
    fn test_cbe_total_supply_is_100_billion() {
        assert_eq!(CBE_TOTAL_SUPPLY, 100_000_000_000);
    }

    #[test]
    fn test_cbe_distribution_sums_to_total() {
        let sum = CBE_COMPENSATION_POOL
            + CBE_OPERATIONAL_TREASURY
            + CBE_PERFORMANCE_INCENTIVES
            + CBE_STRATEGIC_RESERVES;
        assert_eq!(sum, CBE_TOTAL_SUPPLY);
    }

    #[test]
    fn test_cbe_compensation_is_40_percent() {
        assert_eq!(CBE_COMPENSATION_POOL, 40_000_000_000);
        assert_eq!(CBE_COMPENSATION_POOL * 100 / CBE_TOTAL_SUPPLY, 40);
    }

    #[test]
    fn test_cbe_operational_is_30_percent() {
        assert_eq!(CBE_OPERATIONAL_TREASURY, 30_000_000_000);
        assert_eq!(CBE_OPERATIONAL_TREASURY * 100 / CBE_TOTAL_SUPPLY, 30);
    }

    #[test]
    fn test_cbe_performance_is_20_percent() {
        assert_eq!(CBE_PERFORMANCE_INCENTIVES, 20_000_000_000);
        assert_eq!(CBE_PERFORMANCE_INCENTIVES * 100 / CBE_TOTAL_SUPPLY, 20);
    }

    #[test]
    fn test_cbe_strategic_is_10_percent() {
        assert_eq!(CBE_STRATEGIC_RESERVES, 10_000_000_000);
        assert_eq!(CBE_STRATEGIC_RESERVES * 100 / CBE_TOTAL_SUPPLY, 10);
    }

    // ========================================================================
    // INITIALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_new_token_not_initialized() {
        let token = CbeToken::new();
        assert!(!token.is_initialized());
        assert_eq!(token.total_supply(), 0);
    }

    #[test]
    fn test_init_success() {
        let mut token = CbeToken::new();
        let compensation = create_test_public_key(1);
        let operational = create_test_public_key(2);
        let performance = create_test_public_key(3);
        let strategic = create_test_public_key(4);

        let result = token.init(&compensation, &operational, &performance, &strategic);

        assert!(result.is_ok());
        assert!(token.is_initialized());
        assert_eq!(token.total_supply(), CBE_TOTAL_SUPPLY);

        // Verify distribution
        assert_eq!(token.balance_of(&compensation), CBE_COMPENSATION_POOL);
        assert_eq!(token.balance_of(&operational), CBE_OPERATIONAL_TREASURY);
        assert_eq!(token.balance_of(&performance), CBE_PERFORMANCE_INCENTIVES);
        assert_eq!(token.balance_of(&strategic), CBE_STRATEGIC_RESERVES);
    }

    #[test]
    fn test_init_rejects_double_init() {
        let mut token = CbeToken::new();
        let compensation = create_test_public_key(1);
        let operational = create_test_public_key(2);
        let performance = create_test_public_key(3);
        let strategic = create_test_public_key(4);

        token.init(&compensation, &operational, &performance, &strategic).unwrap();
        let result = token.init(&compensation, &operational, &performance, &strategic);

        assert_eq!(result, Err(CbeTokenError::AlreadyInitialized));
    }

    // ========================================================================
    // DISTRIBUTION ALLOCATION TESTS
    // ========================================================================

    #[test]
    fn test_distribution_allocation_verify() {
        let allocation = DistributionAllocation::default();
        assert!(allocation.verify());
    }

    #[test]
    fn test_distribution_allocation_invalid() {
        let allocation = DistributionAllocation {
            compensation: 50_000_000_000, // Wrong!
            operational: 30_000_000_000,
            performance: 20_000_000_000,
            strategic: 10_000_000_000,
        };
        assert!(!allocation.verify());
    }

    // ========================================================================
    // VESTING TESTS
    // ========================================================================

    #[test]
    fn test_vesting_before_cliff() {
        let schedule = VestingSchedule {
            total_amount: 1000,
            vested_amount: 0,
            start_block: 100,
            vesting_duration_blocks: 1000,
            cliff_blocks: 200,
            pool: VestingPool::Compensation,
        };

        // Before cliff (100 + 200 = 300)
        assert_eq!(schedule.calculate_vested(150), 0);
        assert_eq!(schedule.calculate_vested(299), 0);
    }

    #[test]
    fn test_vesting_at_cliff() {
        let schedule = VestingSchedule {
            total_amount: 1000,
            vested_amount: 0,
            start_block: 100,
            vesting_duration_blocks: 1000,
            cliff_blocks: 200,
            pool: VestingPool::Compensation,
        };

        // At cliff: 200/1000 = 20%
        let vested = schedule.calculate_vested(300);
        assert_eq!(vested, 200); // 20% of 1000
    }

    #[test]
    fn test_vesting_fully_vested() {
        let schedule = VestingSchedule {
            total_amount: 1000,
            vested_amount: 0,
            start_block: 100,
            vesting_duration_blocks: 1000,
            cliff_blocks: 0,
            pool: VestingPool::Compensation,
        };

        // After full vesting period
        assert_eq!(schedule.calculate_vested(1100), 1000);
        assert_eq!(schedule.calculate_vested(2000), 1000);
    }

    #[test]
    fn test_vesting_linear_progression() {
        let schedule = VestingSchedule {
            total_amount: 1000,
            vested_amount: 0,
            start_block: 0,
            vesting_duration_blocks: 1000,
            cliff_blocks: 0,
            pool: VestingPool::Compensation,
        };

        // Linear vesting
        assert_eq!(schedule.calculate_vested(100), 100);  // 10%
        assert_eq!(schedule.calculate_vested(500), 500);  // 50%
        assert_eq!(schedule.calculate_vested(750), 750);  // 75%
    }

    // ========================================================================
    // TRANSFER TESTS
    // ========================================================================

    #[test]
    fn test_transfer_success() {
        let mut token = CbeToken::new();
        let compensation = create_test_public_key(1);
        let operational = create_test_public_key(2);
        let performance = create_test_public_key(3);
        let strategic = create_test_public_key(4);
        let recipient = create_test_public_key(5);

        token.init(&compensation, &operational, &performance, &strategic).unwrap();

        let ctx = create_test_execution_context(&compensation);
        let result = token.transfer(&ctx, &recipient, 1_000_000_000, 0);

        assert!(result.is_ok());
        assert_eq!(token.balance_of(&compensation), CBE_COMPENSATION_POOL - 1_000_000_000);
        assert_eq!(token.balance_of(&recipient), 1_000_000_000);
    }

    // ========================================================================
    // MINTING TESTS
    // ========================================================================

    #[test]
    fn test_mint_disabled() {
        let mut token = CbeToken::new();
        let compensation = create_test_public_key(1);
        let operational = create_test_public_key(2);
        let performance = create_test_public_key(3);
        let strategic = create_test_public_key(4);

        token.init(&compensation, &operational, &performance, &strategic).unwrap();

        let result = token.mint(&compensation, 1000);
        assert_eq!(result, Err(CbeTokenError::MintingDisabled));
    }

    // ========================================================================
    // TOKEN INFO TESTS
    // ========================================================================

    #[test]
    fn test_token_info() {
        let token = CbeToken::new();

        assert_eq!(token.name(), "CBE Equity");
        assert_eq!(token.symbol(), "CBE");
        assert_eq!(token.decimals(), 8);
    }
}
