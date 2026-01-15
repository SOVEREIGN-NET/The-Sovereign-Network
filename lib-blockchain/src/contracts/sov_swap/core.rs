//! Core SOV Swap AMM implementation
//!
//! Implements a minimal constant product AMM for SOV↔DAO token swaps.

use super::{DEFAULT_FEE_BPS, MAX_FEE_BPS, MINIMUM_LIQUIDITY, POOL_ID_DOMAIN};
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::DAOType;
use serde::{Deserialize, Serialize};

/// Swap direction indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapDirection {
    /// Swap SOV tokens for DAO tokens
    SovToToken,
    /// Swap DAO tokens for SOV tokens
    TokenToSov,
}

/// Result of a swap operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapResult {
    /// Amount of input tokens consumed
    pub amount_in: u64,
    /// Amount of output tokens received
    pub amount_out: u64,
    /// Fee amount deducted (in input token)
    pub fee_amount: u64,
    /// New SOV reserve after swap
    pub new_sov_reserve: u64,
    /// New token reserve after swap
    pub new_token_reserve: u64,
}

/// Current state of a liquidity pool
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolState {
    /// Current SOV reserve
    pub sov_reserve: u64,
    /// Current DAO token reserve
    pub token_reserve: u64,
    /// Current k value (sov_reserve * token_reserve)
    pub k: u128,
    /// Current fee in basis points
    pub fee_bps: u16,
    /// Whether the pool is initialized
    pub initialized: bool,
}

/// Errors that can occur during swap operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapError {
    /// Pool has not been initialized
    PoolNotInitialized,
    /// Pool is already initialized
    PoolAlreadyInitialized,
    /// Input amount is zero
    ZeroInputAmount,
    /// Output amount would be zero
    ZeroOutputAmount,
    /// Insufficient liquidity in the pool
    InsufficientLiquidity,
    /// Insufficient balance for the swap
    InsufficientBalance,
    /// Slippage tolerance exceeded
    SlippageExceeded,
    /// Direct NP↔FP swap is not allowed
    DirectNpFpSwapBlocked,
    /// Only governance can perform this action
    GovernanceOnly,
    /// Fee exceeds maximum allowed
    FeeTooHigh,
    /// Initial liquidity below minimum
    InsufficientInitialLiquidity,
    /// Arithmetic overflow
    Overflow,
    /// Invalid token address
    InvalidTokenAddress,
    /// K invariant violation
    KInvariantViolation,
}

impl std::fmt::Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapError::PoolNotInitialized => write!(f, "Pool has not been initialized"),
            SwapError::PoolAlreadyInitialized => write!(f, "Pool is already initialized"),
            SwapError::ZeroInputAmount => write!(f, "Input amount cannot be zero"),
            SwapError::ZeroOutputAmount => write!(f, "Output amount would be zero"),
            SwapError::InsufficientLiquidity => write!(f, "Insufficient liquidity in pool"),
            SwapError::InsufficientBalance => write!(f, "Insufficient balance for swap"),
            SwapError::SlippageExceeded => write!(f, "Slippage tolerance exceeded"),
            SwapError::DirectNpFpSwapBlocked => {
                write!(f, "Direct NP↔FP swaps are blocked; use SOV as intermediary")
            }
            SwapError::GovernanceOnly => write!(f, "Only governance can perform this action"),
            SwapError::FeeTooHigh => write!(f, "Fee exceeds maximum allowed (10%)"),
            SwapError::InsufficientInitialLiquidity => write!(f, "Initial liquidity below minimum"),
            SwapError::Overflow => write!(f, "Arithmetic overflow"),
            SwapError::InvalidTokenAddress => write!(f, "Invalid token address"),
            SwapError::KInvariantViolation => write!(f, "K invariant violation detected"),
        }
    }
}

impl std::error::Error for SwapError {}

/// SOV Swap Pool - Minimal AMM for SOV↔DAO token swaps
///
/// Uses constant product formula: x * y = k
/// where x = SOV reserve, y = token reserve
///
/// # Invariants
///
/// ## Invariant S1: Reserve Conservation
/// After any swap: `new_sov_reserve * new_token_reserve >= k`
/// The product may increase (due to fees) but never decrease.
///
/// ## Invariant S2: SOV Intermediary
/// This pool only handles SOV↔single_token swaps.
/// NP↔FP requires two separate swaps through SOV.
///
/// ## Invariant S3: Governance Control
/// Only `governance_addr` can modify `fee_bps`.
///
/// ## Invariant S4: Initialization Atomicity
/// Pool is either fully initialized (`initialized == true`) or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovSwapPool {
    // === Immutable fields (set at init) ===
    /// Unique pool identifier
    pool_id: [u8; 32],
    /// Token ID of the DAO token in this pool
    token_id: [u8; 32],
    /// DAO type of the token (NP or FP)
    dao_type: DAOType,
    /// Address authorized to update fee parameters
    governance_addr: PublicKey,
    /// Treasury address for fee collection
    treasury_addr: PublicKey,
    /// Whether pool has been initialized
    initialized: bool,

    // === Mutable state ===
    /// Current SOV reserve
    sov_reserve: u64,
    /// Current DAO token reserve
    token_reserve: u64,
    /// Constant product k = sov_reserve * token_reserve
    k: u128,
    /// Fee in basis points (1 bps = 0.01%)
    fee_bps: u16,

    // === Fee accounting ===
    /// Accumulated fees pending transfer to treasury (in SOV)
    pending_sov_fees: u64,
    /// Accumulated fees pending transfer to treasury (in token)
    pending_token_fees: u64,
}

impl SovSwapPool {
    /// Initialize a new liquidity pool
    ///
    /// # Parameters
    /// - `token_id`: The DAO token's unique identifier
    /// - `dao_type`: Whether the token is NP or FP
    /// - `initial_sov`: Initial SOV liquidity
    /// - `initial_token`: Initial DAO token liquidity
    /// - `governance_addr`: Address authorized to change fees
    /// - `treasury_addr`: Address to receive collected fees
    ///
    /// # Returns
    /// A new initialized `SovSwapPool` or an error
    ///
    /// # Errors
    /// - `InsufficientInitialLiquidity`: If initial liquidity is below minimum
    /// - `InvalidTokenAddress`: If governance or treasury address is zero
    pub fn init_pool(
        token_id: [u8; 32],
        dao_type: DAOType,
        initial_sov: u64,
        initial_token: u64,
        governance_addr: PublicKey,
        treasury_addr: PublicKey,
    ) -> Result<Self, SwapError> {
        // Validate minimum liquidity
        if initial_sov < MINIMUM_LIQUIDITY || initial_token < MINIMUM_LIQUIDITY {
            return Err(SwapError::InsufficientInitialLiquidity);
        }

        // Validate addresses are non-zero
        if governance_addr.as_bytes().iter().all(|b| *b == 0) {
            return Err(SwapError::InvalidTokenAddress);
        }
        if treasury_addr.as_bytes().iter().all(|b| *b == 0) {
            return Err(SwapError::InvalidTokenAddress);
        }

        // Calculate initial k
        let k = (initial_sov as u128)
            .checked_mul(initial_token as u128)
            .ok_or(SwapError::Overflow)?;

        // Generate pool ID
        let pool_id = derive_pool_id(&token_id);

        Ok(SovSwapPool {
            pool_id,
            token_id,
            dao_type,
            governance_addr,
            treasury_addr,
            initialized: true,
            sov_reserve: initial_sov,
            token_reserve: initial_token,
            k,
            fee_bps: DEFAULT_FEE_BPS,
            pending_sov_fees: 0,
            pending_token_fees: 0,
        })
    }

    /// Swap SOV tokens for DAO tokens
    ///
    /// # Parameters
    /// - `caller`: The user performing the swap (for event emission)
    /// - `sov_amount`: Amount of SOV to swap
    /// - `min_token_out`: Minimum acceptable token output (slippage protection)
    ///
    /// # Returns
    /// `SwapResult` containing the swap details
    ///
    /// # Errors
    /// - `PoolNotInitialized`: Pool not yet initialized
    /// - `ZeroInputAmount`: Input is zero
    /// - `ZeroOutputAmount`: Calculated output is zero
    /// - `SlippageExceeded`: Output less than `min_token_out`
    /// - `InsufficientLiquidity`: Not enough tokens in reserve
    pub fn swap_sov_to_token(
        &mut self,
        _caller: &PublicKey,
        sov_amount: u64,
        min_token_out: Option<u64>,
    ) -> Result<SwapResult, SwapError> {
        self.require_initialized()?;

        if sov_amount == 0 {
            return Err(SwapError::ZeroInputAmount);
        }

        // Calculate fee (taken from input)
        let fee_amount = self.calculate_fee(sov_amount)?;
        let sov_amount_after_fee = sov_amount
            .checked_sub(fee_amount)
            .ok_or(SwapError::Overflow)?;

        // Calculate output using constant product formula
        // amount_out = (reserve_out * amount_in) / (reserve_in + amount_in)
        let token_out =
            self.calculate_output(sov_amount_after_fee, self.sov_reserve, self.token_reserve)?;

        if token_out == 0 {
            return Err(SwapError::ZeroOutputAmount);
        }

        // Slippage check
        if let Some(min_out) = min_token_out {
            if token_out < min_out {
                return Err(SwapError::SlippageExceeded);
            }
        }

        // Check sufficient liquidity
        if token_out >= self.token_reserve {
            return Err(SwapError::InsufficientLiquidity);
        }

        // Update reserves
        let new_sov_reserve = self
            .sov_reserve
            .checked_add(sov_amount_after_fee)
            .ok_or(SwapError::Overflow)?;
        let new_token_reserve = self
            .token_reserve
            .checked_sub(token_out)
            .ok_or(SwapError::Overflow)?;

        // Verify k invariant (new_k >= old_k due to fees)
        let new_k = (new_sov_reserve as u128)
            .checked_mul(new_token_reserve as u128)
            .ok_or(SwapError::Overflow)?;

        if new_k < self.k {
            return Err(SwapError::KInvariantViolation);
        }

        // Commit state changes
        self.sov_reserve = new_sov_reserve;
        self.token_reserve = new_token_reserve;
        self.k = new_k;

        // Accumulate fee for treasury
        self.pending_sov_fees = self
            .pending_sov_fees
            .checked_add(fee_amount)
            .ok_or(SwapError::Overflow)?;

        Ok(SwapResult {
            amount_in: sov_amount,
            amount_out: token_out,
            fee_amount,
            new_sov_reserve,
            new_token_reserve,
        })
    }

    /// Swap DAO tokens for SOV tokens
    ///
    /// # Parameters
    /// - `caller`: The user performing the swap (for event emission)
    /// - `token_amount`: Amount of DAO tokens to swap
    /// - `min_sov_out`: Minimum acceptable SOV output (slippage protection)
    ///
    /// # Returns
    /// `SwapResult` containing the swap details
    ///
    /// # Errors
    /// - `PoolNotInitialized`: Pool not yet initialized
    /// - `ZeroInputAmount`: Input is zero
    /// - `ZeroOutputAmount`: Calculated output is zero
    /// - `SlippageExceeded`: Output less than `min_sov_out`
    /// - `InsufficientLiquidity`: Not enough SOV in reserve
    pub fn swap_token_to_sov(
        &mut self,
        _caller: &PublicKey,
        token_amount: u64,
        min_sov_out: Option<u64>,
    ) -> Result<SwapResult, SwapError> {
        self.require_initialized()?;

        if token_amount == 0 {
            return Err(SwapError::ZeroInputAmount);
        }

        // Calculate fee (taken from input)
        let fee_amount = self.calculate_fee(token_amount)?;
        let token_amount_after_fee = token_amount
            .checked_sub(fee_amount)
            .ok_or(SwapError::Overflow)?;

        // Calculate output using constant product formula
        let sov_out =
            self.calculate_output(token_amount_after_fee, self.token_reserve, self.sov_reserve)?;

        if sov_out == 0 {
            return Err(SwapError::ZeroOutputAmount);
        }

        // Slippage check
        if let Some(min_out) = min_sov_out {
            if sov_out < min_out {
                return Err(SwapError::SlippageExceeded);
            }
        }

        // Check sufficient liquidity
        if sov_out >= self.sov_reserve {
            return Err(SwapError::InsufficientLiquidity);
        }

        // Update reserves
        let new_token_reserve = self
            .token_reserve
            .checked_add(token_amount_after_fee)
            .ok_or(SwapError::Overflow)?;
        let new_sov_reserve = self
            .sov_reserve
            .checked_sub(sov_out)
            .ok_or(SwapError::Overflow)?;

        // Verify k invariant
        let new_k = (new_sov_reserve as u128)
            .checked_mul(new_token_reserve as u128)
            .ok_or(SwapError::Overflow)?;

        if new_k < self.k {
            return Err(SwapError::KInvariantViolation);
        }

        // Commit state changes
        self.sov_reserve = new_sov_reserve;
        self.token_reserve = new_token_reserve;
        self.k = new_k;

        // Accumulate fee for treasury
        self.pending_token_fees = self
            .pending_token_fees
            .checked_add(fee_amount)
            .ok_or(SwapError::Overflow)?;

        Ok(SwapResult {
            amount_in: token_amount,
            amount_out: sov_out,
            fee_amount,
            new_sov_reserve,
            new_token_reserve,
        })
    }

    /// Get current price quotes
    ///
    /// # Returns
    /// Tuple of (sov_per_token, token_per_sov) as fixed-point values
    /// with 18 decimals of precision (multiply by 1e18)
    ///
    /// # Note
    /// These are spot prices and do not account for slippage on actual trades.
    pub fn get_price(&self) -> Result<(u128, u128), SwapError> {
        self.require_initialized()?;

        if self.sov_reserve == 0 || self.token_reserve == 0 {
            return Err(SwapError::InsufficientLiquidity);
        }

        const PRECISION: u128 = 1_000_000_000_000_000_000; // 1e18

        // sov_per_token = sov_reserve / token_reserve (scaled by 1e18)
        let sov_per_token = (self.sov_reserve as u128)
            .checked_mul(PRECISION)
            .ok_or(SwapError::Overflow)?
            .checked_div(self.token_reserve as u128)
            .ok_or(SwapError::InsufficientLiquidity)?;

        // token_per_sov = token_reserve / sov_reserve (scaled by 1e18)
        let token_per_sov = (self.token_reserve as u128)
            .checked_mul(PRECISION)
            .ok_or(SwapError::Overflow)?
            .checked_div(self.sov_reserve as u128)
            .ok_or(SwapError::InsufficientLiquidity)?;

        Ok((sov_per_token, token_per_sov))
    }

    /// Set the swap fee (governance only)
    ///
    /// # Parameters
    /// - `caller`: Must be the governance address
    /// - `new_fee_bps`: New fee in basis points (max 1000 = 10%)
    ///
    /// # Errors
    /// - `GovernanceOnly`: Caller is not governance
    /// - `FeeTooHigh`: Fee exceeds maximum
    pub fn set_fee_bps(&mut self, caller: &PublicKey, new_fee_bps: u16) -> Result<u16, SwapError> {
        self.require_governance(caller)?;

        if new_fee_bps > MAX_FEE_BPS {
            return Err(SwapError::FeeTooHigh);
        }

        let old_fee = self.fee_bps;
        self.fee_bps = new_fee_bps;

        Ok(old_fee)
    }

    /// Collect accumulated fees and transfer to treasury
    ///
    /// # Returns
    /// Tuple of (sov_fees_collected, token_fees_collected)
    pub fn collect_fees(&mut self) -> (u64, u64) {
        let sov_fees = self.pending_sov_fees;
        let token_fees = self.pending_token_fees;

        self.pending_sov_fees = 0;
        self.pending_token_fees = 0;

        (sov_fees, token_fees)
    }

    /// Validate that a swap between two token types is allowed
    ///
    /// # Rules
    /// - SOV↔NP: Allowed
    /// - SOV↔FP: Allowed  
    /// - NP↔FP: BLOCKED (must use SOV as intermediary)
    ///
    /// # Parameters
    /// - `from_type`: Source token type (None = SOV)
    /// - `to_type`: Destination token type (None = SOV)
    pub fn validate_swap_allowed(
        from_type: Option<DAOType>,
        to_type: Option<DAOType>,
    ) -> Result<(), SwapError> {
        match (from_type, to_type) {
            // SOV → Token: Always allowed
            (None, Some(_)) => Ok(()),
            // Token → SOV: Always allowed
            (Some(_), None) => Ok(()),
            // NP ↔ FP: Blocked
            (Some(DAOType::NP), Some(DAOType::FP)) | (Some(DAOType::FP), Some(DAOType::NP)) => {
                Err(SwapError::DirectNpFpSwapBlocked)
            }
            // Same type swap (shouldn't happen but allow)
            (Some(_), Some(_)) => Ok(()),
            // SOV → SOV: Invalid but not blocked
            (None, None) => Ok(()),
        }
    }

    /// Get current pool state
    pub fn state(&self) -> PoolState {
        PoolState {
            sov_reserve: self.sov_reserve,
            token_reserve: self.token_reserve,
            k: self.k,
            fee_bps: self.fee_bps,
            initialized: self.initialized,
        }
    }

    /// Get pool ID
    pub fn pool_id(&self) -> &[u8; 32] {
        &self.pool_id
    }

    /// Get token ID
    pub fn token_id(&self) -> &[u8; 32] {
        &self.token_id
    }

    /// Get DAO type of the pooled token
    pub fn dao_type(&self) -> DAOType {
        self.dao_type
    }

    /// Get governance address
    pub fn governance_addr(&self) -> &PublicKey {
        &self.governance_addr
    }

    /// Get treasury address
    pub fn treasury_addr(&self) -> &PublicKey {
        &self.treasury_addr
    }

    /// Get current fee in basis points
    pub fn fee_bps(&self) -> u16 {
        self.fee_bps
    }

    /// Get pending fees awaiting collection
    pub fn pending_fees(&self) -> (u64, u64) {
        (self.pending_sov_fees, self.pending_token_fees)
    }

    /// Check if pool is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // === Private helper methods ===

    /// Require pool to be initialized
    fn require_initialized(&self) -> Result<(), SwapError> {
        if !self.initialized {
            return Err(SwapError::PoolNotInitialized);
        }
        Ok(())
    }

    /// Require caller to be governance
    fn require_governance(&self, caller: &PublicKey) -> Result<(), SwapError> {
        if caller != &self.governance_addr {
            return Err(SwapError::GovernanceOnly);
        }
        Ok(())
    }

    /// Calculate fee amount
    fn calculate_fee(&self, amount: u64) -> Result<u64, SwapError> {
        // fee = amount * fee_bps / 10000
        let fee = (amount as u128)
            .checked_mul(self.fee_bps as u128)
            .ok_or(SwapError::Overflow)?
            .checked_div(10000)
            .ok_or(SwapError::Overflow)? as u64;
        Ok(fee)
    }

    /// Calculate swap output using constant product formula
    ///
    /// Formula: amount_out = (reserve_out * amount_in) / (reserve_in + amount_in)
    fn calculate_output(
        &self,
        amount_in: u64,
        reserve_in: u64,
        reserve_out: u64,
    ) -> Result<u64, SwapError> {
        if reserve_in == 0 || reserve_out == 0 {
            return Err(SwapError::InsufficientLiquidity);
        }

        // Numerator: reserve_out * amount_in
        let numerator = (reserve_out as u128)
            .checked_mul(amount_in as u128)
            .ok_or(SwapError::Overflow)?;

        // Denominator: reserve_in + amount_in
        let denominator = (reserve_in as u128)
            .checked_add(amount_in as u128)
            .ok_or(SwapError::Overflow)?;

        // amount_out = numerator / denominator
        let amount_out = numerator
            .checked_div(denominator)
            .ok_or(SwapError::Overflow)?;

        // Safe to cast since amount_out <= reserve_out which is u64
        Ok(amount_out as u64)
    }
}

/// Derive a deterministic pool ID from token ID
///
/// Pool ID = Blake3(POOL_ID_DOMAIN || token_id)
fn derive_pool_id(token_id: &[u8; 32]) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(POOL_ID_DOMAIN);
    hasher.update(token_id);

    let hash = hasher.finalize();
    let mut pool_id = [0u8; 32];
    pool_id.copy_from_slice(hash.as_bytes());
    pool_id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    fn create_test_token_id(id: u8) -> [u8; 32] {
        [id; 32]
    }

    // ========================================================================
    // Pool Initialization Tests
    // ========================================================================

    #[test]
    fn test_init_pool_success() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);

        let pool = SovSwapPool::init_pool(
            token_id,
            DAOType::NP,
            10_000,
            10_000,
            governance.clone(),
            treasury.clone(),
        )
        .unwrap();

        assert!(pool.is_initialized());
        assert_eq!(pool.sov_reserve, 10_000);
        assert_eq!(pool.token_reserve, 10_000);
        assert_eq!(pool.k, 100_000_000);
        assert_eq!(pool.fee_bps, DEFAULT_FEE_BPS);
        assert_eq!(pool.governance_addr(), &governance);
        assert_eq!(pool.treasury_addr(), &treasury);
    }

    #[test]
    fn test_init_pool_insufficient_sov_liquidity() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);

        let result = SovSwapPool::init_pool(
            token_id,
            DAOType::NP,
            500, // Below MINIMUM_LIQUIDITY
            10_000,
            governance,
            treasury,
        );

        assert_eq!(result.unwrap_err(), SwapError::InsufficientInitialLiquidity);
    }

    #[test]
    fn test_init_pool_insufficient_token_liquidity() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);

        let result = SovSwapPool::init_pool(
            token_id,
            DAOType::FP,
            10_000,
            500, // Below MINIMUM_LIQUIDITY
            governance,
            treasury,
        );

        assert_eq!(result.unwrap_err(), SwapError::InsufficientInitialLiquidity);
    }

    #[test]
    fn test_init_pool_zero_governance_addr() {
        let token_id = create_test_token_id(1);
        let governance = PublicKey::new(vec![0; 1312]);
        let treasury = create_test_public_key(2);

        let result =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury);

        assert_eq!(result.unwrap_err(), SwapError::InvalidTokenAddress);
    }

    #[test]
    fn test_init_pool_zero_treasury_addr() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = PublicKey::new(vec![0; 1312]);

        let result =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury);

        assert_eq!(result.unwrap_err(), SwapError::InvalidTokenAddress);
    }

    // ========================================================================
    // Swap SOV to Token Tests
    // ========================================================================

    #[test]
    fn test_swap_sov_to_token_basic() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let result = pool.swap_sov_to_token(&user, 1000, None).unwrap();

        // With 1% fee: 1000 - 10 = 990 effective input
        // Output = (10000 * 990) / (10000 + 990) = 9900000 / 10990 ≈ 900
        assert_eq!(result.amount_in, 1000);
        assert_eq!(result.fee_amount, 10); // 1% of 1000
        assert!(result.amount_out > 0);
        assert!(result.amount_out < 1000); // Should get less due to slippage

        // Verify reserves updated
        assert!(pool.sov_reserve > 10_000);
        assert!(pool.token_reserve < 10_000);

        // Verify fee accumulated
        assert_eq!(pool.pending_sov_fees, 10);
    }

    #[test]
    fn test_swap_sov_to_token_zero_amount() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let result = pool.swap_sov_to_token(&user, 0, None);
        assert_eq!(result.unwrap_err(), SwapError::ZeroInputAmount);
    }

    #[test]
    fn test_swap_sov_to_token_slippage_protection() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        // Request minimum output higher than possible
        let result = pool.swap_sov_to_token(&user, 1000, Some(999));
        assert_eq!(result.unwrap_err(), SwapError::SlippageExceeded);
    }

    #[test]
    fn test_swap_sov_to_token_drain_protection() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        // Try to swap enormous amount to drain pool
        let result = pool.swap_sov_to_token(&user, u64::MAX / 2, None);
        // Should either error or not fully drain (depends on implementation)
        // At minimum, should not drain to 0
        if result.is_ok() {
            assert!(pool.token_reserve > 0);
        }
    }

    // ========================================================================
    // Swap Token to SOV Tests
    // ========================================================================

    #[test]
    fn test_swap_token_to_sov_basic() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::FP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let result = pool.swap_token_to_sov(&user, 1000, None).unwrap();

        assert_eq!(result.amount_in, 1000);
        assert_eq!(result.fee_amount, 10); // 1% of 1000
        assert!(result.amount_out > 0);
        assert!(result.amount_out < 1000);

        // Verify reserves updated
        assert!(pool.token_reserve > 10_000);
        assert!(pool.sov_reserve < 10_000);

        // Verify fee accumulated (in tokens this time)
        assert_eq!(pool.pending_token_fees, 10);
    }

    #[test]
    fn test_swap_token_to_sov_zero_amount() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::FP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let result = pool.swap_token_to_sov(&user, 0, None);
        assert_eq!(result.unwrap_err(), SwapError::ZeroInputAmount);
    }

    // ========================================================================
    // Price and K-Invariant Tests
    // ========================================================================

    #[test]
    fn test_get_price_balanced_pool() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);

        let pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let (sov_per_token, token_per_sov) = pool.get_price().unwrap();

        // 1:1 ratio should give 1e18 for both
        assert_eq!(sov_per_token, 1_000_000_000_000_000_000);
        assert_eq!(token_per_sov, 1_000_000_000_000_000_000);
    }

    #[test]
    fn test_get_price_imbalanced_pool() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);

        let pool = SovSwapPool::init_pool(
            token_id,
            DAOType::NP,
            20_000, // 2x SOV
            10_000,
            governance,
            treasury,
        )
        .unwrap();

        let (sov_per_token, token_per_sov) = pool.get_price().unwrap();

        // 2:1 ratio: 1 token = 2 SOV
        assert_eq!(sov_per_token, 2_000_000_000_000_000_000);
        // 1 SOV = 0.5 token
        assert_eq!(token_per_sov, 500_000_000_000_000_000);
    }

    #[test]
    fn test_k_invariant_preserved_after_swap() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let initial_k = pool.k;

        pool.swap_sov_to_token(&user, 1000, None).unwrap();

        // K should increase or stay same (due to fees), never decrease
        assert!(pool.k >= initial_k);
    }

    #[test]
    fn test_k_increases_with_fees() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let initial_k = pool.k;

        // Do multiple swaps
        pool.swap_sov_to_token(&user, 1000, None).unwrap();
        pool.swap_token_to_sov(&user, 500, None).unwrap();
        pool.swap_sov_to_token(&user, 200, None).unwrap();

        // K should have increased due to accumulated fees
        assert!(pool.k > initial_k);
    }

    // ========================================================================
    // Fee Tests
    // ========================================================================

    #[test]
    fn test_fee_calculation() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        let result = pool.swap_sov_to_token(&user, 10_000, None).unwrap();

        // 1% of 10_000 = 100
        assert_eq!(result.fee_amount, 100);
    }

    #[test]
    fn test_set_fee_bps_governance_only() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let non_governance = create_test_public_key(3);

        let mut pool = SovSwapPool::init_pool(
            token_id,
            DAOType::NP,
            10_000,
            10_000,
            governance.clone(),
            treasury,
        )
        .unwrap();

        // Non-governance should fail
        let result = pool.set_fee_bps(&non_governance, 200);
        assert_eq!(result.unwrap_err(), SwapError::GovernanceOnly);

        // Governance should succeed
        let old_fee = pool.set_fee_bps(&governance, 200).unwrap();
        assert_eq!(old_fee, 100); // Was 1%
        assert_eq!(pool.fee_bps, 200); // Now 2%
    }

    #[test]
    fn test_set_fee_bps_max_limit() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);

        let mut pool = SovSwapPool::init_pool(
            token_id,
            DAOType::NP,
            10_000,
            10_000,
            governance.clone(),
            treasury,
        )
        .unwrap();

        // Try to set fee above max
        let result = pool.set_fee_bps(&governance, 1001);
        assert_eq!(result.unwrap_err(), SwapError::FeeTooHigh);

        // Max should work
        pool.set_fee_bps(&governance, 1000).unwrap();
        assert_eq!(pool.fee_bps, 1000);
    }

    #[test]
    fn test_collect_fees() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);
        let user = create_test_public_key(3);

        let mut pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 10_000, governance, treasury)
                .unwrap();

        // Generate some fees
        pool.swap_sov_to_token(&user, 1000, None).unwrap();
        pool.swap_token_to_sov(&user, 500, None).unwrap();

        let (sov_fees, token_fees) = pool.collect_fees();

        assert_eq!(sov_fees, 10); // 1% of 1000
        assert_eq!(token_fees, 5); // 1% of 500

        // Pending fees should be reset
        assert_eq!(pool.pending_sov_fees, 0);
        assert_eq!(pool.pending_token_fees, 0);
    }

    // ========================================================================
    // NP↔FP Blocking Tests
    // ========================================================================

    #[test]
    fn test_validate_sov_to_np_allowed() {
        let result = SovSwapPool::validate_swap_allowed(None, Some(DAOType::NP));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_sov_to_fp_allowed() {
        let result = SovSwapPool::validate_swap_allowed(None, Some(DAOType::FP));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_np_to_sov_allowed() {
        let result = SovSwapPool::validate_swap_allowed(Some(DAOType::NP), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_fp_to_sov_allowed() {
        let result = SovSwapPool::validate_swap_allowed(Some(DAOType::FP), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_np_to_fp_blocked() {
        let result = SovSwapPool::validate_swap_allowed(Some(DAOType::NP), Some(DAOType::FP));
        assert_eq!(result.unwrap_err(), SwapError::DirectNpFpSwapBlocked);
    }

    #[test]
    fn test_validate_fp_to_np_blocked() {
        let result = SovSwapPool::validate_swap_allowed(Some(DAOType::FP), Some(DAOType::NP));
        assert_eq!(result.unwrap_err(), SwapError::DirectNpFpSwapBlocked);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_pool_state_getter() {
        let token_id = create_test_token_id(1);
        let governance = create_test_public_key(1);
        let treasury = create_test_public_key(2);

        let pool =
            SovSwapPool::init_pool(token_id, DAOType::NP, 10_000, 20_000, governance, treasury)
                .unwrap();

        let state = pool.state();
        assert_eq!(state.sov_reserve, 10_000);
        assert_eq!(state.token_reserve, 20_000);
        assert_eq!(state.k, 200_000_000);
        assert_eq!(state.fee_bps, 100);
        assert!(state.initialized);
    }

    #[test]
    fn test_pool_id_deterministic() {
        let token_id = create_test_token_id(42);

        let pool_id_1 = derive_pool_id(&token_id);
        let pool_id_2 = derive_pool_id(&token_id);

        assert_eq!(pool_id_1, pool_id_2);
    }

    #[test]
    fn test_pool_id_unique_per_token() {
        let token_id_1 = create_test_token_id(1);
        let token_id_2 = create_test_token_id(2);

        let pool_id_1 = derive_pool_id(&token_id_1);
        let pool_id_2 = derive_pool_id(&token_id_2);

        assert_ne!(pool_id_1, pool_id_2);
    }
}
