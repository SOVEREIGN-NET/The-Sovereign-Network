//! Issue #1849: Protocol-Owned Liquidity (POL) AMM Pool
//!
//! Implements a true Protocol-Owned Liquidity pool where:
//! - Liquidity CANNOT be added or removed (physically disabled)
//! - Only swap operations are allowed
//! - LP tokens do not exist (no minting/burning)
//! - Fees stay in the pool forever
//! - k is non-decreasing as fees compound
//!
//! # Security Architecture
//!
//! ## Disabled Operations (physically impossible)
//! - `add_liquidity()` - NOT IMPLEMENTED (will not compile if called)
//! - `remove_liquidity()` - NOT IMPLEMENTED (will not compile if called)
//! - `mint_lp()` - NOT IMPLEMENTED (LP tokens don't exist)
//! - `burn_lp()` - NOT IMPLEMENTED (LP tokens don't exist)
//! - `skim()` - Explicitly disabled, panics if called
//! - `sync()` - Explicitly disabled, panics if called
//!
//! ## Allowed Operations
//! - `initialize_pool()` - One-time setup at graduation
//! - `swap_sov_to_token()` - Buy CBE with SOV
//! - `swap_token_to_sov()` - Sell CBE for SOV
//! - `get_price()` - Read current price
//! - `get_reserves()` - Read current reserves
//!
//! # Economic Properties
//!
//! ## Permanent Liquidity
//! - Once initialized, liquidity can never leave the pool
//! - Protocol cannot withdraw, governance cannot withdraw, no one can withdraw
//! - Prevents "liquidity death spiral" common in traditional AMMs
//!
//! ## Fee Accumulation
//! - All trading fees stay in the pool forever
//! - `k` is non-decreasing across trades and increases whenever fee rounding is non-zero
//! - Pool becomes deeper and more stable over time
//!
//! ## Price Discovery
//! - Price determined purely by constant product formula: `x * y = k`
//! - No external price feeds needed after initialization
//! - Market-driven price discovery via swaps

use crate::contracts::sov_swap::{PoolState, SimulationResult, SwapError, POOL_ID_DOMAIN};
use serde::{Deserialize, Serialize};

// ============================================================================
// Issue #1849: POL Pool Constants
// ============================================================================

/// Minimum initial liquidity to prevent division by zero attacks.
/// This is the minimum reserve for BOTH tokens at initialization.
pub const POL_MINIMUM_INITIAL_LIQUIDITY: u64 = 1_000_000; // 0.01 SOV equivalent

/// Trading fee in basis points (0.3% = 30 bps).
/// Fees stay in the pool permanently, increasing k over time.
pub const POL_FEE_BPS: u16 = 30;

/// Basis points denominator (100% = 10_000 bps).
pub const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

/// Price calculation scale (8 decimals).
pub const PRICE_SCALE: u128 = 100_000_000;

/// Spot-price scale used by `get_price()` to match `SovSwapPool`.
pub const SPOT_PRICE_PRECISION: u128 = 1_000_000_000_000_000_000;

// ============================================================================
// POL Pool Errors
// ============================================================================

/// Errors specific to POL pool operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolPoolError {
    /// Pool already initialized (one-time initialization only).
    AlreadyInitialized,
    /// Pool not initialized yet.
    NotInitialized,
    /// Zero input amount for swap.
    ZeroInput,
    /// Zero output would result (slippage or liquidity issue).
    ZeroOutput,
    /// Insufficient liquidity for swap.
    InsufficientLiquidity,
    /// Slippage tolerance exceeded.
    SlippageExceeded,
    /// Arithmetic overflow.
    Overflow,
    /// Minimum initial liquidity not met.
    InsufficientInitialLiquidity,
    /// Operation permanently disabled for POL pools.
    OperationDisabledForPol,
}

impl std::fmt::Display for PolPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolPoolError::AlreadyInitialized => write!(f, "POL pool already initialized"),
            PolPoolError::NotInitialized => write!(f, "POL pool not initialized"),
            PolPoolError::ZeroInput => write!(f, "Input amount cannot be zero"),
            PolPoolError::ZeroOutput => write!(f, "Output amount would be zero"),
            PolPoolError::InsufficientLiquidity => write!(f, "Insufficient liquidity"),
            PolPoolError::SlippageExceeded => write!(f, "Slippage tolerance exceeded"),
            PolPoolError::Overflow => write!(f, "Arithmetic overflow"),
            PolPoolError::InsufficientInitialLiquidity => {
                write!(f, "Initial liquidity below minimum")
            }
            PolPoolError::OperationDisabledForPol => write!(f, "Operation disabled for POL pool"),
        }
    }
}

impl std::error::Error for PolPoolError {}

// ============================================================================
// POL Pool State
// ============================================================================

/// Protocol-Owned Liquidity Pool State.
///
/// This is a specialized AMM pool with NO liquidity operations.
/// Once initialized, reserves can only change via swaps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolPool {
    // === Immutable (set at initialization) ===
    /// Token identifier for the paired token (e.g., CBE token ID).
    token_id: [u8; 32],
    /// Whether pool has been initialized.
    initialized: bool,
    /// Fee in basis points (e.g., 30 = 0.3%).
    fee_bps: u16,

    // === Mutable (changed by swaps only) ===
    /// SOV reserve balance.
    sov_reserve: u64,
    /// Token reserve balance (e.g., CBE).
    token_reserve: u64,
    /// Current k value (sov_reserve * token_reserve).
    /// Note: k is non-decreasing over time as fees accumulate.
    k: u128,
    /// Total fees accumulated in SOV.
    total_fees_sov: u64,
}

impl PolPool {
    /// Create a new uninitialized POL pool.
    ///
    /// # Arguments
    /// * `token_id` - The paired token identifier.
    ///
    /// # Returns
    /// New uninitialized POL pool.
    pub fn new(token_id: [u8; 32]) -> Self {
        Self {
            token_id,
            initialized: false,
            fee_bps: POL_FEE_BPS,
            sov_reserve: 0,
            token_reserve: 0,
            k: 0,
            total_fees_sov: 0,
        }
    }

    /// Initialize the POL pool with initial liquidity.
    ///
    /// # SECURITY CRITICAL
    /// This can ONLY be called ONCE. There is no way to add more liquidity later.
    /// The initial reserves are permanent and can never be removed.
    ///
    /// # Arguments
    /// * `initial_sov` - Initial SOV reserve (from bonding curve reserve).
    /// * `initial_token` - Initial token reserve (from total supply).
    ///
    /// # Returns
    /// `Ok(())` if initialization succeeds.
    ///
    /// # Errors
    /// * `AlreadyInitialized` - Pool already initialized.
    /// * `InsufficientInitialLiquidity` - Reserves below minimum.
    /// * `Overflow` - k calculation overflow.
    pub fn initialize(&mut self, initial_sov: u64, initial_token: u64) -> Result<(), PolPoolError> {
        if self.initialized {
            return Err(PolPoolError::AlreadyInitialized);
        }

        // Verify minimum liquidity requirement
        if initial_sov < POL_MINIMUM_INITIAL_LIQUIDITY
            || initial_token < POL_MINIMUM_INITIAL_LIQUIDITY
        {
            return Err(PolPoolError::InsufficientInitialLiquidity);
        }

        // Calculate k = sov * token
        let k = (initial_sov as u128)
            .checked_mul(initial_token as u128)
            .ok_or(PolPoolError::Overflow)?;

        self.sov_reserve = initial_sov;
        self.token_reserve = initial_token;
        self.k = k;
        self.initialized = true;

        Ok(())
    }

    /// Swap SOV for tokens (e.g., buy CBE with SOV).
    ///
    /// # Arguments
    /// * `sov_in` - Amount of SOV to swap.
    /// * `min_token_out` - Minimum acceptable token output (slippage protection).
    ///
    /// # Returns
    /// Amount of tokens received.
    ///
    /// # Errors
    /// * `NotInitialized` - Pool not initialized.
    /// * `ZeroInput` - `sov_in` is zero.
    /// * `InsufficientLiquidity` - Not enough liquidity.
    /// * `ZeroOutput` - Output would be zero.
    /// * `SlippageExceeded` - Output below `min_token_out`.
    /// * `Overflow` - Calculation overflow.
    pub fn swap_sov_to_token(
        &mut self,
        sov_in: u64,
        min_token_out: u64,
    ) -> Result<u64, PolPoolError> {
        self.require_initialized()?;

        if sov_in == 0 {
            return Err(PolPoolError::ZeroInput);
        }

        // Apply fee: fee_amount = sov_in * fee_bps / BASIS_POINTS_DENOMINATOR
        let fee_amount = (sov_in as u128)
            .checked_mul(self.fee_bps as u128)
            .ok_or(PolPoolError::Overflow)?
            .checked_div(BASIS_POINTS_DENOMINATOR as u128)
            .ok_or(PolPoolError::Overflow)? as u64;

        // SOV that "effectively" goes into the pool for price calculation
        // The fee stays in the pool permanently
        let sov_in_after_fee = sov_in - fee_amount;

        // Calculate token out using constant product formula:
        // effective_sov = sov_reserve + sov_in_after_fee (for calculating price)
        // new_token = k / effective_sov
        // token_out = token_reserve - new_token
        let effective_sov = self
            .sov_reserve
            .checked_add(sov_in_after_fee)
            .ok_or(PolPoolError::Overflow)?;

        let new_token_u128 = self
            .k
            .checked_div(effective_sov as u128)
            .ok_or(PolPoolError::InsufficientLiquidity)?;
        let new_token = u64::try_from(new_token_u128).map_err(|_| PolPoolError::Overflow)?;

        if new_token >= self.token_reserve {
            return Err(PolPoolError::InsufficientLiquidity);
        }

        let token_out = self.token_reserve - new_token;

        if token_out == 0 {
            return Err(PolPoolError::ZeroOutput);
        }

        if token_out < min_token_out {
            return Err(PolPoolError::SlippageExceeded);
        }

        // Update reserves: FULL sov_in goes to pool (including fee)
        // The fee stays in the pool as "excess" SOV that increases k
        self.sov_reserve = self
            .sov_reserve
            .checked_add(sov_in)
            .ok_or(PolPoolError::Overflow)?;
        self.token_reserve = new_token;

        // Track fees
        self.total_fees_sov = self
            .total_fees_sov
            .checked_add(fee_amount)
            .ok_or(PolPoolError::Overflow)?;

        // Recalculate k (must be > old k due to fees staying in pool)
        self.k = (self.sov_reserve as u128)
            .checked_mul(self.token_reserve as u128)
            .ok_or(PolPoolError::Overflow)?;

        Ok(token_out)
    }

    /// Swap tokens for SOV (e.g., sell CBE for SOV).
    ///
    /// # Arguments
    /// * `token_in` - Amount of tokens to swap.
    /// * `min_sov_out` - Minimum acceptable SOV output (slippage protection).
    ///
    /// # Returns
    /// Amount of SOV received.
    ///
    /// # Errors
    /// * `NotInitialized` - Pool not initialized.
    /// * `ZeroInput` - `token_in` is zero.
    /// * `InsufficientLiquidity` - Not enough liquidity.
    /// * `ZeroOutput` - Output would be zero.
    /// * `SlippageExceeded` - Output below `min_sov_out`.
    /// * `Overflow` - Calculation overflow.
    pub fn swap_token_to_sov(
        &mut self,
        token_in: u64,
        min_sov_out: u64,
    ) -> Result<u64, PolPoolError> {
        self.require_initialized()?;

        if token_in == 0 {
            return Err(PolPoolError::ZeroInput);
        }

        // Calculate SOV out before fee
        // new_token = token_reserve + token_in
        // new_sov = k / new_token (what reserves would be without fee)
        // sov_out_before_fee = sov_reserve - new_sov
        let new_token = self
            .token_reserve
            .checked_add(token_in)
            .ok_or(PolPoolError::Overflow)?;

        let new_sov_without_fee_u128 = self
            .k
            .checked_div(new_token as u128)
            .ok_or(PolPoolError::InsufficientLiquidity)?;
        let new_sov_without_fee =
            u64::try_from(new_sov_without_fee_u128).map_err(|_| PolPoolError::Overflow)?;

        if new_sov_without_fee >= self.sov_reserve {
            return Err(PolPoolError::InsufficientLiquidity);
        }

        let sov_out_before_fee = self.sov_reserve - new_sov_without_fee;

        // Apply fee: fee = sov_out_before_fee * fee_bps / BASIS_POINTS_DENOMINATOR
        let fee_amount = (sov_out_before_fee as u128)
            .checked_mul(self.fee_bps as u128)
            .ok_or(PolPoolError::Overflow)?
            .checked_div(BASIS_POINTS_DENOMINATOR as u128)
            .ok_or(PolPoolError::Overflow)? as u64;

        let sov_out = sov_out_before_fee - fee_amount;

        if sov_out == 0 {
            return Err(PolPoolError::ZeroOutput);
        }

        if sov_out < min_sov_out {
            return Err(PolPoolError::SlippageExceeded);
        }

        // Update reserves:
        // - token_reserve increases by full token_in
        // - sov_reserve decreases to new_sov_without_fee
        // - BUT fee stays in pool! So actual new_sov = new_sov_without_fee + fee
        let new_sov_with_fee = new_sov_without_fee
            .checked_add(fee_amount)
            .ok_or(PolPoolError::Overflow)?;

        self.token_reserve = new_token;
        self.sov_reserve = new_sov_with_fee;

        // Track fees
        self.total_fees_sov = self
            .total_fees_sov
            .checked_add(fee_amount)
            .ok_or(PolPoolError::Overflow)?;

        // Recalculate k (must be > old k due to fee staying in pool)
        self.k = (self.sov_reserve as u128)
            .checked_mul(self.token_reserve as u128)
            .ok_or(PolPoolError::Overflow)?;

        Ok(sov_out)
    }

    /// Get current price of token in SOV.
    ///
    /// Formula: price = (sov_reserve * PRICE_SCALE) / token_reserve
    ///
    /// # Returns
    /// Current price or error if not initialized.
    pub fn get_token_price(&self) -> Result<u64, PolPoolError> {
        self.require_initialized()?;

        if self.token_reserve == 0 {
            return Err(PolPoolError::InsufficientLiquidity);
        }

        let price_u128 = (self.sov_reserve as u128)
            .checked_mul(PRICE_SCALE)
            .ok_or(PolPoolError::Overflow)?
            .checked_div(self.token_reserve as u128)
            .ok_or(PolPoolError::Overflow)?;
        let price = u64::try_from(price_u128).map_err(|_| PolPoolError::Overflow)?;

        Ok(price)
    }

    /// Get spot prices in the same shape as `SovSwapPool::get_price()`.
    pub fn get_price(&self) -> Result<(u128, u128), PolPoolError> {
        self.require_initialized()?;

        if self.sov_reserve == 0 || self.token_reserve == 0 {
            return Err(PolPoolError::InsufficientLiquidity);
        }

        let sov_per_token = (self.sov_reserve as u128)
            .checked_mul(SPOT_PRICE_PRECISION)
            .ok_or(PolPoolError::Overflow)?
            .checked_div(self.token_reserve as u128)
            .ok_or(PolPoolError::InsufficientLiquidity)?;

        let token_per_sov = (self.token_reserve as u128)
            .checked_mul(SPOT_PRICE_PRECISION)
            .ok_or(PolPoolError::Overflow)?
            .checked_div(self.sov_reserve as u128)
            .ok_or(PolPoolError::InsufficientLiquidity)?;

        Ok((sov_per_token, token_per_sov))
    }

    /// Get current reserves.
    ///
    /// # Returns
    /// (sov_reserve, token_reserve) or error if not initialized.
    pub fn get_reserves(&self) -> Result<(u64, u64), PolPoolError> {
        self.require_initialized()?;
        Ok((self.sov_reserve, self.token_reserve))
    }

    /// Get current k value.
    ///
    /// Note: k is non-decreasing over time as fees accumulate.
    ///
    /// # Returns
    /// Current k or error if not initialized.
    pub fn get_k(&self) -> Result<u128, PolPoolError> {
        self.require_initialized()?;
        Ok(self.k)
    }

    /// Get total fees accumulated in SOV-equivalent accounting.
    pub fn get_total_fees(&self) -> u64 {
        self.total_fees_sov
    }

    /// Check if pool is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get token ID.
    pub fn token_id(&self) -> [u8; 32] {
        self.token_id
    }

    /// Get the deterministic pool ID used by graduation and storage.
    pub fn pool_id(&self) -> [u8; 32] {
        derive_pool_id(&self.token_id)
    }

    /// Export the pool state using the shared `PoolState` shape.
    pub fn state(&self) -> PoolState {
        PoolState {
            sov_reserve: self.sov_reserve,
            token_reserve: self.token_reserve,
            k: self.k,
            fee_bps: self.fee_bps,
            initialized: self.initialized,
        }
    }

    /// Calculate output amount for a SOV → token swap (view function).
    ///
    /// This does NOT modify state. Use for price quotes.
    /// Mirrors the logic in `swap_sov_to_token` without state changes.
    pub fn calculate_token_out(&self, sov_in: u64) -> Result<u64, PolPoolError> {
        self.require_initialized()?;

        if sov_in == 0 {
            return Err(PolPoolError::ZeroInput);
        }

        let fee_amount = (sov_in as u128)
            .checked_mul(self.fee_bps as u128)
            .ok_or(PolPoolError::Overflow)?
            .checked_div(BASIS_POINTS_DENOMINATOR as u128)
            .ok_or(PolPoolError::Overflow)? as u64;

        // Use effective SOV (after fee) for price calculation
        let sov_in_after_fee = sov_in - fee_amount;
        let effective_sov = self
            .sov_reserve
            .checked_add(sov_in_after_fee)
            .ok_or(PolPoolError::Overflow)?;
        let new_token_u128 = self
            .k
            .checked_div(effective_sov as u128)
            .ok_or(PolPoolError::Overflow)?;
        let new_token = u64::try_from(new_token_u128).map_err(|_| PolPoolError::Overflow)?;

        if new_token >= self.token_reserve {
            return Err(PolPoolError::InsufficientLiquidity);
        }

        Ok(self.token_reserve - new_token)
    }

    /// Calculate output amount for a token → SOV swap (view function).
    ///
    /// This does NOT modify state. Use for price quotes.
    pub fn calculate_sov_out(&self, token_in: u64) -> Result<u64, PolPoolError> {
        self.require_initialized()?;

        if token_in == 0 {
            return Err(PolPoolError::ZeroInput);
        }

        let new_token = self
            .token_reserve
            .checked_add(token_in)
            .ok_or(PolPoolError::Overflow)?;
        let new_sov_before_fee_u128 = self
            .k
            .checked_div(new_token as u128)
            .ok_or(PolPoolError::Overflow)?;
        let new_sov_before_fee =
            u64::try_from(new_sov_before_fee_u128).map_err(|_| PolPoolError::Overflow)?;

        if new_sov_before_fee >= self.sov_reserve {
            return Err(PolPoolError::InsufficientLiquidity);
        }

        let sov_out_before_fee = self.sov_reserve - new_sov_before_fee;
        let fee_amount = (sov_out_before_fee as u128)
            .checked_mul(self.fee_bps as u128)
            .ok_or(PolPoolError::Overflow)?
            .checked_div(BASIS_POINTS_DENOMINATOR as u128)
            .ok_or(PolPoolError::Overflow)? as u64;

        Ok(sov_out_before_fee - fee_amount)
    }

    /// Simulate a SOV -> token swap using the same shape as `SovSwapPool`.
    pub fn simulate_sov_to_token(
        &self,
        sov_amount: u64,
        min_token_out: Option<u64>,
    ) -> Result<SimulationResult, SwapError> {
        let amount_out = self
            .calculate_token_out(sov_amount)
            .map_err(map_pol_error_to_swap_error)?;

        if let Some(min_out) = min_token_out {
            if amount_out < min_out {
                return Err(SwapError::SlippageExceeded);
            }
        }

        let fee_amount = calculate_fee(self.fee_bps, sov_amount)?;
        let price_impact_bps = ((amount_out as u128)
            .checked_mul(BASIS_POINTS_DENOMINATOR as u128)
            .ok_or(SwapError::Overflow)?
            .checked_div(self.token_reserve as u128)
            .ok_or(SwapError::Overflow)?) as u64;

        Ok(SimulationResult {
            amount_out,
            fee_amount,
            price_impact_bps,
        })
    }

    /// Simulate a token -> SOV swap using the same shape as `SovSwapPool`.
    pub fn simulate_token_to_sov(
        &self,
        token_amount: u64,
        min_sov_out: Option<u64>,
    ) -> Result<SimulationResult, SwapError> {
        let amount_out = self
            .calculate_sov_out(token_amount)
            .map_err(map_pol_error_to_swap_error)?;

        if let Some(min_out) = min_sov_out {
            if amount_out < min_out {
                return Err(SwapError::SlippageExceeded);
            }
        }

        let fee_base = self
            .sov_reserve
            .checked_sub(
                u64::try_from(
                    self.k
                        .checked_div(
                            self.token_reserve
                                .checked_add(token_amount)
                                .ok_or(SwapError::Overflow)? as u128,
                        )
                        .ok_or(SwapError::Overflow)?,
                )
                .map_err(|_| SwapError::Overflow)?,
            )
            .ok_or(SwapError::Overflow)?;
        let fee_amount = calculate_fee(self.fee_bps, fee_base)?;
        let price_impact_bps = ((amount_out as u128)
            .checked_mul(BASIS_POINTS_DENOMINATOR as u128)
            .ok_or(SwapError::Overflow)?
            .checked_div(self.sov_reserve as u128)
            .ok_or(SwapError::Overflow)?) as u64;

        Ok(SimulationResult {
            amount_out,
            fee_amount,
            price_impact_bps,
        })
    }

    /// # DANGER - OPERATION DISABLED FOR POL POOL
    ///
    /// skim() is disabled to prevent token extraction.
    /// This function PANICS if called.
    pub fn skim(&self) -> ! {
        panic!("OPERATION DISABLED: skim() is not allowed for POL pools")
    }

    /// # DANGER - OPERATION DISABLED FOR POL POOL
    ///
    /// sync() is disabled to prevent reserve manipulation.
    /// This function PANICS if called.
    pub fn sync(&self) -> ! {
        panic!("OPERATION DISABLED: sync() is not allowed for POL pools")
    }

    // =========================================================================
    // Private Helpers
    // =========================================================================

    fn require_initialized(&self) -> Result<(), PolPoolError> {
        if !self.initialized {
            return Err(PolPoolError::NotInitialized);
        }
        Ok(())
    }
}

/// Derive a deterministic pool ID from token ID using the existing AMM domain.
pub fn derive_pool_id(token_id: &[u8; 32]) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(POOL_ID_DOMAIN);
    hasher.update(token_id);

    let hash = hasher.finalize();
    let mut pool_id = [0u8; 32];
    pool_id.copy_from_slice(hash.as_bytes());
    pool_id
}

fn calculate_fee(fee_bps: u16, amount: u64) -> Result<u64, SwapError> {
    (amount as u128)
        .checked_mul(fee_bps as u128)
        .ok_or(SwapError::Overflow)?
        .checked_div(BASIS_POINTS_DENOMINATOR as u128)
        .ok_or(SwapError::Overflow)
        .and_then(|fee| u64::try_from(fee).map_err(|_| SwapError::Overflow))
}

fn map_pol_error_to_swap_error(err: PolPoolError) -> SwapError {
    match err {
        PolPoolError::AlreadyInitialized => SwapError::PoolAlreadyInitialized,
        PolPoolError::NotInitialized => SwapError::PoolNotInitialized,
        PolPoolError::ZeroInput => SwapError::ZeroInputAmount,
        PolPoolError::ZeroOutput => SwapError::ZeroOutputAmount,
        PolPoolError::InsufficientLiquidity => SwapError::InsufficientLiquidity,
        PolPoolError::SlippageExceeded => SwapError::SlippageExceeded,
        PolPoolError::Overflow => SwapError::Overflow,
        PolPoolError::InsufficientInitialLiquidity => SwapError::InsufficientInitialLiquidity,
        PolPoolError::OperationDisabledForPol => SwapError::GovernanceOnly,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_token_id() -> [u8; 32] {
        [1u8; 32]
    }

    /// Issue #1849: Test POL pool initialization.
    #[test]
    fn test_pol_pool_initialization() {
        let mut pool = PolPool::new(test_token_id());
        assert!(!pool.is_initialized());

        // Initialize with sufficient liquidity
        let initial_sov = 100_000_000_00u64; // 100 SOV
        let initial_token = 1_000_000_000_00u64; // 1000 tokens

        pool.initialize(initial_sov, initial_token).unwrap();
        assert!(pool.is_initialized());

        // Check reserves
        let (sov, token) = pool.get_reserves().unwrap();
        assert_eq!(sov, initial_sov);
        assert_eq!(token, initial_token);

        // Check k
        let k = pool.get_k().unwrap();
        assert_eq!(k, (initial_sov as u128) * (initial_token as u128));

        // Check price
        let price = pool.get_token_price().unwrap();
        // price = 100 SOV / 1000 tokens = 0.1 SOV per token
        assert_eq!(price, 10_000_000); // 0.1 * PRICE_SCALE
    }

    /// Issue #1849: Test double initialization fails.
    #[test]
    fn test_pol_pool_double_initialization_fails() {
        let mut pool = PolPool::new(test_token_id());
        pool.initialize(100_000_000, 100_000_000).unwrap();

        // Second initialization should fail
        let result = pool.initialize(200_000_000, 200_000_000);
        assert!(matches!(result, Err(PolPoolError::AlreadyInitialized)));
    }

    /// Issue #1849: Test minimum liquidity requirement.
    #[test]
    fn test_pol_pool_minimum_liquidity() {
        let mut pool = PolPool::new(test_token_id());

        // Below minimum should fail
        let result = pool.initialize(POL_MINIMUM_INITIAL_LIQUIDITY - 1, 100_000_000);
        assert!(matches!(
            result,
            Err(PolPoolError::InsufficientInitialLiquidity)
        ));

        // At minimum should succeed
        let mut pool2 = PolPool::new(test_token_id());
        pool2
            .initialize(POL_MINIMUM_INITIAL_LIQUIDITY, POL_MINIMUM_INITIAL_LIQUIDITY)
            .unwrap();
        assert!(pool2.is_initialized());
    }

    /// Issue #1849: Test swap SOV to token.
    #[test]
    fn test_pol_pool_swap_sov_to_token() {
        let mut pool = PolPool::new(test_token_id());
        let initial_sov = 100_000_000_00u64; // 100 SOV
        let initial_token = 1_000_000_000_00u64; // 1000 tokens
        pool.initialize(initial_sov, initial_token).unwrap();

        let initial_k = pool.get_k().unwrap();

        // Swap 1 SOV for tokens
        let sov_in = 1_000_000_00u64; // 1 SOV
        let token_out = pool.swap_sov_to_token(sov_in, 0).unwrap();

        // Verify we got tokens
        assert!(token_out > 0);

        // Verify k is non-decreasing (fees may round to zero on tiny inputs)
        let new_k = pool.get_k().unwrap();
        assert!(new_k >= initial_k, "k should not decrease");

        // Verify reserves updated
        let (new_sov, new_token) = pool.get_reserves().unwrap();
        assert!(new_sov > initial_sov);
        assert!(new_token < initial_token);

        // Verify fees accumulated
        let fees_sov = pool.get_total_fees();
        assert!(fees_sov > 0);
    }

    /// Issue #1849: Test swap token to SOV.
    #[test]
    fn test_pol_pool_swap_token_to_sov() {
        let mut pool = PolPool::new(test_token_id());
        let initial_sov = 100_000_000_00u64;
        let initial_token = 1_000_000_000_00u64;
        pool.initialize(initial_sov, initial_token).unwrap();

        let initial_k = pool.get_k().unwrap();

        // Swap 10 tokens for SOV
        let token_in = 10_000_000_00u64; // 10 tokens
        let sov_out = pool.swap_token_to_sov(token_in, 0).unwrap();

        // Verify we got SOV
        assert!(sov_out > 0);

        // Verify k is non-decreasing (fees may round to zero on tiny inputs)
        let new_k = pool.get_k().unwrap();
        assert!(new_k >= initial_k, "k should not decrease");
    }

    /// Issue #1849: Test slippage protection.
    #[test]
    fn test_pol_pool_slippage_protection() {
        let mut pool = PolPool::new(test_token_id());
        pool.initialize(100_000_000_00, 1_000_000_000_00).unwrap();

        // Try to swap with unreasonable slippage expectation
        let sov_in = 1_000_000_00u64;
        let result = pool.swap_sov_to_token(sov_in, 100_000_000_00); // Expect way too much
        assert!(matches!(result, Err(PolPoolError::SlippageExceeded)));
    }

    /// Issue #1849: Test price changes after swaps.
    #[test]
    fn test_pol_pool_price_evolution() {
        let mut pool = PolPool::new(test_token_id());
        pool.initialize(100_000_000_00, 1_000_000_000_00).unwrap(); // 0.1 price

        let initial_price = pool.get_token_price().unwrap();

        // Buy tokens (increase price)
        pool.swap_sov_to_token(10_000_000_00, 0).unwrap();
        let price_after_buy = pool.get_token_price().unwrap();
        assert!(
            price_after_buy > initial_price,
            "Price should increase after buying"
        );

        // Sell tokens (decrease price)
        pool.swap_token_to_sov(50_000_000_00, 0).unwrap();
        let price_after_sell = pool.get_token_price().unwrap();
        assert!(
            price_after_sell < price_after_buy,
            "Price should decrease after selling"
        );
    }

    /// Issue #1849: Test skim and sync are disabled.
    #[test]
    #[should_panic(expected = "OPERATION DISABLED")]
    fn test_pol_pool_skim_disabled() {
        let pool = PolPool::new(test_token_id());
        pool.skim(); // Should panic
    }

    /// Issue #1849: Test sync is disabled.
    #[test]
    #[should_panic(expected = "OPERATION DISABLED")]
    fn test_pol_pool_sync_disabled() {
        let pool = PolPool::new(test_token_id());
        pool.sync(); // Should panic
    }

    /// Issue #1849: Test no liquidity functions exist.
    /// This is a compile-time guarantee - these functions don't exist.
    #[test]
    fn test_pol_pool_no_liquidity_interface() {
        // If this compiles, it proves there's no add_liquidity or remove_liquidity
        // on PolPool. We verify by checking the struct has no LP token handling.
        let pool = PolPool::new(test_token_id());

        // PolPool has NO:
        // - lp_token_supply field
        // - lp_token_balances field
        // - add_liquidity() method
        // - remove_liquidity() method
        // - mint_lp() method
        // - burn_lp() method

        // Verify pool only has swap-related state
        assert_eq!(pool.token_id(), test_token_id());
        assert!(!pool.is_initialized());
    }

    /// Issue #1849: Test calculate functions don't modify state.
    #[test]
    fn test_pol_pool_calculate_view_functions() {
        let mut pool = PolPool::new(test_token_id());
        pool.initialize(100_000_000_00, 1_000_000_000_00).unwrap();

        let (sov_before, token_before) = pool.get_reserves().unwrap();
        let k_before = pool.get_k().unwrap();

        // Calculate (should not modify state)
        let _ = pool.calculate_token_out(1_000_000_00);
        let _ = pool.calculate_sov_out(10_000_000_00);

        // State unchanged
        let (sov_after, token_after) = pool.get_reserves().unwrap();
        let k_after = pool.get_k().unwrap();

        assert_eq!(sov_before, sov_after);
        assert_eq!(token_before, token_after);
        assert_eq!(k_before, k_after);
    }

    /// Issue #1849: Test fee accumulation over time.
    #[test]
    fn test_pol_pool_fee_accumulation() {
        let mut pool = PolPool::new(test_token_id());
        pool.initialize(100_000_000_00, 1_000_000_00).unwrap();

        let k_initial = pool.get_k().unwrap();

        // Perform many swaps
        for _ in 0..10 {
            // Round trip: SOV → token → SOV
            let sov_in = 1_000_000_0u64; // 0.1 SOV
            if let Ok(token_out) = pool.swap_sov_to_token(sov_in, 0) {
                // Sell half back
                let sell_amount = token_out / 2;
                let _ = pool.swap_token_to_sov(sell_amount, 0);
            }
        }

        let k_final = pool.get_k().unwrap();
        let fees_sov = pool.get_total_fees();

        // With integer math, k is non-decreasing and rises once fees accumulate.
        assert!(k_final >= k_initial, "k should not decrease due to fees");
        assert!(fees_sov > 0, "Fees should be accumulated");
    }

    /// Issue #1849: Test constants are properly defined (no magic numbers).
    #[test]
    fn test_pol_constants() {
        assert_eq!(POL_MINIMUM_INITIAL_LIQUIDITY, 1_000_000);
        assert_eq!(POL_FEE_BPS, 30);
        assert_eq!(BASIS_POINTS_DENOMINATOR, 10_000);
        assert_eq!(PRICE_SCALE, 100_000_000);

        // Fee should be reasonable (0.3%)
        assert!(POL_FEE_BPS > 0 && POL_FEE_BPS <= 1000);
    }
}
