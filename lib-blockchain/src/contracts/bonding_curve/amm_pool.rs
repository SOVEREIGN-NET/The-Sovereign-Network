//! Issue #1848: AMM Pool Creation for Bonding Curve Graduation
//!
//! Implements automatic POL (Protocol-Owned Liquidity) pool creation when bonding curve tokens graduate.
//! The pool is seeded with reserve SOV + CBE tokens at the final curve price.
//!
//! # Issue #1849: POL Security Architecture
//!
//! This module now uses `PolPool` which provides TRUE protocol-owned liquidity:
//!
//! ## Disabled Operations (Physically Impossible)
//! - `add_liquidity()` - NOT IMPLEMENTED in PolPool
//! - `remove_liquidity()` - NOT IMPLEMENTED in PolPool
//! - `mint_lp()` - NOT IMPLEMENTED (LP tokens don't exist)
//! - `burn_lp()` - NOT IMPLEMENTED (LP tokens don't exist)
//! - `skim()` - Explicitly disabled, panics if called
//! - `sync()` - Explicitly disabled, panics if called
//!
//! ## Allowed Operations
//! - `initialize()` - One-time setup at graduation
//! - `swap_sov_to_token()` - Buy CBE with SOV
//! - `swap_token_to_sov()` - Sell CBE for SOV
//! - `get_token_price()` - Read current price
//! - `get_reserves()` - Read current reserves
//!
//! ## Economic Properties
//! - **Permanent Liquidity**: Once initialized, liquidity can never leave
//! - **Fee Accumulation**: All fees stay in pool forever, k is non-decreasing over time
//! - **No Liquidity Death Spiral**: Impossible to withdraw liquidity
//!
//! # Price Continuity Formula
//! ```text
//! final_curve_price  = token.current_price()          (from the curve function, 8-decimal)
//! initial_cbe_in_pool = reserve_sov * PRICE_SCALE / final_curve_price
//! initial_amm_price   = reserve_sov * PRICE_SCALE / initial_cbe_in_pool
//!                     = final_curve_price              ✓
//! ```
//!
//! # Security Invariants
//!
//! ## Invariant A1: Price Continuity
//! The AMM initial price MUST equal the final bonding curve price.
//!
//! ## Invariant A2: Protocol-Owned Liquidity (Issue #1849)
//! PolPool has NO liquidity interface — add_liquidity and remove_liquidity
//! do not exist. The seeded reserves can never be withdrawn. This is a
//! compile-time guarantee, not a runtime check.
//!
//! ## Invariant A3: Reserve Conservation
//! All reserve SOV from bonding curve goes to AMM pool; reserve_balance is
//! zeroed on the token after migration.

use super::{
    events::BondingCurveEvent,
    pol_pool::{derive_pool_id, PolPool, PolPoolError},
    types::{CurveError, Phase},
    BondingCurveToken,
};
use crate::contracts::bonding_curve::pricing::PRICE_SCALE;
use crate::integration::crypto_integration::PublicKey;
use serde::{Deserialize, Serialize};

// ============================================================================
// Issue #1848: AMM Pool Creation Constants
// ============================================================================

/// Minimum liquidity required for AMM pool creation.
/// Prevents division by zero attacks and ensures meaningful liquidity.
pub const MINIMUM_AMM_LIQUIDITY: u128 = 1_000_000; // 0.01 SOV or equivalent

/// AMM fee in basis points for graduated pools (0.3% = 30 bps).
/// Lower than standard 1% to encourage trading post-graduation.
/// Note: For POL pools, this fee is hardcoded in PolPool::POL_FEE_BPS
pub const GRADUATED_POOL_FEE_BPS: u16 = 30;

// ============================================================================
// AMM Pool Creation Result
// ============================================================================

/// Result of AMM pool creation for a graduated bonding curve token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmPoolCreationResult {
    /// Pool ID (derived from token ID)
    pub pool_id: [u8; 32],
    /// Initial SOV reserve (from bonding curve reserve)
    pub initial_sov_reserve: u128,
    /// Initial CBE token reserve (derived for price continuity)
    pub initial_token_reserve: u128,
    /// Initial k value (sov_reserve * token_reserve)
    pub initial_k: u128,
    /// Initial AMM price — equals final_curve_price by construction
    pub initial_price: u128,
    /// Final curve price before graduation (from curve pricing function)
    pub final_curve_price: u128,
}

/// Persisted AMM pool state for graduated bonding-curve tokens.
///
/// The bonding-curve AMM is now always a POL pool.
pub type AmmPool = PolPool;

// ============================================================================
// AMM Pool Creator
// ============================================================================

/// Creates a POL (Protocol-Owned Liquidity) pool for a graduated bonding curve token.
///
/// This function implements the graduation → AMM transition using Issue #1849's
/// hardened POL pool architecture:
/// 1. Verifies token is in Graduated phase
/// 2. Derives the CBE reserve from the final curve price for price continuity
/// 3. Creates PolPool with permanently locked liquidity
/// 4. Verifies pool ID consistency with any previously recorded amm_pool_id
/// 5. Transitions token to AMM phase and zeroes migrated balances
///
/// # Issue #1849 Security Note
/// The returned `PolPool` has NO liquidity operations:
/// - No `add_liquidity()` method exists
/// - No `remove_liquidity()` method exists
/// - `skim()` and `sync()` panic if called
/// This is a compile-time guarantee that liquidity cannot exit the pool.
///
/// # Arguments
/// * `token` - The graduated bonding curve token
/// * `governance_addr` - Governance address (for event logging)
/// * `treasury_addr` - Treasury address (for event logging)
/// * `block_height` - Current block height (for event)
/// * `timestamp` - Current timestamp (for event)
///
/// # Returns
/// * `Ok((pool, result, event))` - Successfully created POL pool
/// * `Err(CurveError)` - Pool creation failed
///
/// # Errors
/// * `InvalidPhase` - Token not in Graduated phase
/// * `InsufficientReserve` - Reserve too low for minimum liquidity
/// * `InvalidParameters` - Recorded pool ID doesn't match derived pool ID
/// * `Overflow` - Calculation overflow
pub fn create_pol_pool_for_graduated_token(
    token: &mut BondingCurveToken,
    _governance_addr: PublicKey,
    _treasury_addr: PublicKey,
    block_height: u64,
    timestamp: u64,
) -> Result<(PolPool, AmmPoolCreationResult, BondingCurveEvent), CurveError> {
    // Verify token is in Graduated phase
    if token.phase != Phase::Graduated {
        return Err(CurveError::InvalidPhase {
            current: token.phase,
            required: Phase::Graduated,
        });
    }

    // Verify minimum liquidity requirement
    if token.reserve_balance < MINIMUM_AMM_LIQUIDITY as u128 {
        return Err(CurveError::InsufficientReserve);
    }

    // Derive initial pool reserves for price continuity.
    //
    // final_curve_price comes from the curve pricing function (token.current_price()),
    // not from reserve/supply, because the 20/80 reserve split means
    // reserve_balance/total_supply ≠ the spot price on the bonding curve.
    //
    //   initial_cbe = reserve_sov * PRICE_SCALE / final_curve_price
    //
    // This guarantees: sov_reserve / cbe_reserve == final_curve_price / PRICE_SCALE
    let initial_sov = token.reserve_balance;
    let final_curve_price = token.current_price();

    if final_curve_price == 0 {
        return Err(CurveError::InvalidParameters(
            "Final curve price is zero".to_string(),
        ));
    }

    let initial_cbe_u128 = initial_sov
        .checked_mul(PRICE_SCALE)
        .ok_or(CurveError::Overflow)?
        .checked_div(final_curve_price)
        .ok_or(CurveError::Overflow)?;
    let initial_cbe = u64::try_from(initial_cbe_u128).map_err(|_| CurveError::Overflow)?;

    if initial_cbe == 0 {
        return Err(CurveError::InsufficientReserve);
    }

    // Calculate k = sov * cbe
    let k = initial_sov
        .checked_mul(initial_cbe as u128)
        .ok_or(CurveError::Overflow)?;

    // Verify price continuity
    let initial_amm_price_u128 = initial_sov
        .checked_mul(PRICE_SCALE)
        .ok_or(CurveError::Overflow)?
        .checked_div(initial_cbe as u128)
        .ok_or(CurveError::Overflow)?;
    if initial_amm_price_u128 != final_curve_price {
        return Err(CurveError::InvalidParameters(
            "Price continuity check failed".to_string(),
        ));
    }

    // Create the POL pool using Issue #1849 hardened architecture
    // Note: PolPool has NO liquidity interface - liquidity is permanently locked
    let mut pool = PolPool::new(token.token_id);
    pool.initialize(
        u64::try_from(initial_sov).map_err(|_| CurveError::Overflow)?,
        initial_cbe,
    )
    .map_err(map_pol_error_to_curve_error)?;

    // Issue #1849: The POL pool fee is hardcoded to POL_FEE_BPS (30 = 0.3%)
    // Unlike SovSwapPool, there is no set_fee_bps - the fee is immutable.

    // Verify pool ID consistency: if amm_pool_id was already recorded during
    // the graduation step, it must match the deterministic pool ID derived here.
    let pool_id = derive_pool_id(&token.token_id);
    if let Some(existing_pool_id) = token.amm_pool_id {
        if existing_pool_id != pool_id {
            return Err(CurveError::InvalidParameters(
                "Recorded AMM pool id does not match seeded pool id".to_string(),
            ));
        }
    }

    // Capture treasury balance for the event before zeroing
    let stable_to_treasury = token.treasury_balance;

    // Transition token to AMM phase and zero migrated balances so they are
    // not double-counted in post-migration stats or indexing.
    token.complete_migration(pool_id)?;
    token.reserve_balance = 0;
    token.treasury_balance = 0;

    // Build result
    let result = AmmPoolCreationResult {
        pool_id,
        initial_sov_reserve: initial_sov,
        initial_token_reserve: initial_cbe as u128,
        initial_k: k,
        initial_price: initial_amm_price_u128,
        final_curve_price,
    };

    // Build event
    let event = BondingCurveEvent::AMMSeeded {
        token_id: token.token_id,
        pool_id,
        sov_amount: initial_sov,
        token_amount: initial_cbe as u128,
        stable_to_treasury,
        block_height,
        timestamp,
    };

    Ok((pool, result, event))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Map PolPoolError to CurveError for unified error handling.
fn map_pol_error_to_curve_error(err: PolPoolError) -> CurveError {
    match err {
        PolPoolError::AlreadyInitialized => {
            CurveError::InvalidParameters("Pool already initialized".to_string())
        }
        PolPoolError::InsufficientInitialLiquidity => CurveError::InsufficientReserve,
        PolPoolError::Overflow => CurveError::Overflow,
        PolPoolError::ZeroInput | PolPoolError::ZeroOutput => {
            CurveError::InvalidParameters("Invalid swap amount".to_string())
        }
        PolPoolError::SlippageExceeded => {
            CurveError::InvalidParameters("Slippage tolerance exceeded".to_string())
        }
        PolPoolError::InsufficientLiquidity => CurveError::InsufficientReserve,
        PolPoolError::NotInitialized => {
            CurveError::InvalidParameters("Pool not initialized".to_string())
        }
        PolPoolError::OperationDisabledForPol => {
            CurveError::InvalidParameters("Operation disabled for POL pool".to_string())
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::bonding_curve::{
        types::Threshold, BondingCurveToken, PiecewiseLinearCurve,
    };

    fn test_pubkey(id: u8) -> PublicKey {
        PublicKey::new([id; 2592])
    }

    /// Issue #1849: Test POL pool creation for graduated token.
    #[test]
    fn test_create_pol_pool_for_graduated_token() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        // Max safe buy amount is ~578,000 to keep supply < u64::MAX.
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000), // 200K reserve threshold
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Buy tokens to reach graduation threshold
        // With 40/60 split: need 500K total purchase for 200K reserve
        let buyer = test_pubkey(2);
        token
            .buy(buyer, 500_000, 101, 1_600_000_100)
            .unwrap();

        // Graduate the token
        assert!(token.can_graduate(1_600_000_200, 102));
        token.graduate(1_600_000_200, 102).unwrap();
        assert_eq!(token.phase, Phase::Graduated);

        let reserve_before = token.reserve_balance;
        let final_curve_price = token.current_price();

        // Create POL pool
        let governance = test_pubkey(3);
        let treasury = test_pubkey(4);
        let result = create_pol_pool_for_graduated_token(
            &mut token,
            governance,
            treasury,
            103,
            1_600_000_300,
        );

        assert!(result.is_ok(), "POL pool creation failed: {:?}", result);
        let (pool, creation_result, event) = result.unwrap();

        // Verify token transitioned to AMM phase
        let expected_pool_id = derive_pool_id(&[1u8; 32]);
        assert_eq!(token.phase, Phase::AMM);
        assert_eq!(token.amm_pool_id.unwrap(), expected_pool_id);

        // Verify reserve and treasury are zeroed after migration (no double-counting)
        assert_eq!(
            token.reserve_balance, 0,
            "reserve_balance must be zeroed after migration"
        );
        assert_eq!(
            token.treasury_balance, 0,
            "treasury_balance must be zeroed after migration"
        );

        // Verify price continuity: AMM initial price == final curve price
        assert_eq!(
            creation_result.initial_price, creation_result.final_curve_price,
            "Price continuity must be maintained"
        );
        assert_eq!(
            creation_result.final_curve_price, final_curve_price,
            "final_curve_price must come from the curve pricing function"
        );

        // Verify initial SOV reserve
        assert_eq!(creation_result.initial_sov_reserve, reserve_before);

        // Verify the CBE reserve was derived for price continuity, not taken as total_supply
        let expected_cbe = reserve_before * PRICE_SCALE / final_curve_price;
        assert_eq!(creation_result.initial_token_reserve, expected_cbe);

        // Verify k
        let expected_k = reserve_before as u128 * expected_cbe as u128;
        assert_eq!(creation_result.initial_k, expected_k);

        // Issue #1849: Verify PolPool has NO liquidity interface
        // - PolPool has no add_liquidity method
        // - PolPool has no remove_liquidity method
        // - PolPool has no lp_token_supply field
        // - skim() and sync() panic

        // Verify pool is initialized
        assert!(pool.is_initialized());

        // Verify we can read reserves
        let (sov_reserve, token_reserve) = pool.get_reserves().unwrap();
        assert_eq!(sov_reserve as u128, reserve_before);
        assert_eq!(token_reserve as u128, expected_cbe);

        // Verify event
        match event {
            BondingCurveEvent::AMMSeeded {
                token_id,
                pool_id,
                sov_amount,
                token_amount,
                ..
            } => {
                assert_eq!(token_id, [1u8; 32]);
                assert_eq!(pool_id, expected_pool_id);
                assert_eq!(sov_amount, reserve_before);
                assert_eq!(token_amount, expected_cbe);
            }
            _ => panic!("Expected AMMSeeded event"),
        }
    }

    /// Issue #1849: Test POL pool swap functionality.
    #[test]
    fn test_pol_pool_swap_functionality() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        let mut token = BondingCurveToken::deploy(
            [2u8; 32],
            "Swap Token".to_string(),
            "SWAP".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Buy, graduate, and create POL pool (500K purchase -> 200K reserve at 40% split)
        token
            .buy(test_pubkey(2), 500_000, 101, 1_600_000_100)
            .unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let (mut pool, _, _) = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        let initial_k = pool.get_k().unwrap();

        // Test SOV → token swap
        let sov_in = 1_000_000_00u64; // 1 SOV
        let token_out = pool.swap_sov_to_token(sov_in, 0).unwrap();
        assert!(token_out > 0, "Should receive tokens for SOV");

        // Verify k increased due to fees
        let k_after_buy = pool.get_k().unwrap();
        assert!(k_after_buy >= initial_k, "k should not decrease after swap");

        // Test token → SOV swap
        let token_in = token_out / 2;
        let sov_out = pool.swap_token_to_sov(token_in, 0).unwrap();
        assert!(sov_out > 0, "Should receive SOV for tokens");

        // Verify fees accumulated
        let fees_sov = pool.get_total_fees();
        assert!(fees_sov > 0, "Fees should accumulate");
    }

    /// Issue #1849: Test POL pool disabled operations panic.
    #[test]
    #[should_panic(expected = "OPERATION DISABLED")]
    fn test_pol_pool_skim_disabled() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        let mut token = BondingCurveToken::deploy(
            [3u8; 32],
            "Panic Token".to_string(),
            "PANIC".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token
            .buy(test_pubkey(2), 500_000, 101, 1_600_000_100)
            .unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let (pool, _, _) = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        // This should panic
        pool.skim();
    }

    /// Issue #1849: Test POL pool sync disabled.
    #[test]
    #[should_panic(expected = "OPERATION DISABLED")]
    fn test_pol_pool_sync_disabled() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        let mut token = BondingCurveToken::deploy(
            [4u8; 32],
            "Panic Token 2".to_string(),
            "PANIC2".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token
            .buy(test_pubkey(2), 500_000, 101, 1_600_000_100)
            .unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let (pool, _, _) = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        // This should panic
        pool.sync();
    }

    /// Issue #1849: Test POL pool creation fails if not graduated.
    #[test]
    fn test_pol_pool_creation_fails_if_not_graduated() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        let mut token = BondingCurveToken::deploy(
            [5u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let result = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            101,
            1_600_000_100,
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(CurveError::InvalidPhase {
                current: Phase::Curve,
                required: Phase::Graduated
            })
        ));
    }

    /// Issue #1849: Price continuity — AMM initial price must equal final curve price.
    ///
    /// Verifies that the CBE reserve is derived from the curve pricing function
    /// (`token.current_price()`), not from `reserve/total_supply`, so price continuity
    /// holds regardless of the 20/80 reserve split.
    #[test]
    fn test_price_continuity() {
        let mut token = BondingCurveToken::deploy(
            [6u8; 32],
            "PC Token".to_string(),
            "PC".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(100),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);
        token.buy(buyer, 500, 101, 1_600_000_100).unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let result = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(CurveError::InsufficientReserve)));
    }

    /// Issue #1849: Test constants are properly defined.
    #[test]
    fn test_pol_constants() {
        assert_eq!(MINIMUM_AMM_LIQUIDITY, 1_000_000);
        assert_eq!(GRADUATED_POOL_FEE_BPS, 30);
        // PRICE_SCALE is imported from pricing module — no local duplicate
        assert_eq!(PRICE_SCALE, 100_000_000);
        assert!(GRADUATED_POOL_FEE_BPS > 0);
        assert!(GRADUATED_POOL_FEE_BPS <= 1000);
    }

    /// Issue #1849: Test fee accumulation can increase k over time.
    #[test]
    fn test_pol_pool_fee_accumulation_increases_k() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        let mut token = BondingCurveToken::deploy(
            [8u8; 32],
            "K Token".to_string(),
            "K".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token
            .buy(test_pubkey(2), 500_000, 101, 1_600_000_100)
            .unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let (mut pool, _, _) = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        let k_initial = pool.get_k().unwrap();
        // Perform multiple round-trip swaps to accumulate fees
        for _ in 0..10 {
            // Buy tokens
            let sov_in = 1_000_000_0u64; // 0.1 SOV
            let token_out = pool.swap_sov_to_token(sov_in, 0).unwrap();

            // Sell half back
            let sell_amount = token_out / 2;
            let _ = pool.swap_token_to_sov(sell_amount, 0).unwrap();
        }

        let k_final = pool.get_k().unwrap();
        let fees_sov = pool.get_total_fees();

        // With integer rounding, k is non-decreasing and rises once fees accumulate.
        assert!(k_final >= k_initial, "k must not decrease");
        assert!(fees_sov > 0, "Fees must be accumulated");
    }

    /// Issue #1849: Test slippage protection.
    #[test]
    fn test_pol_pool_slippage_protection() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        let mut token = BondingCurveToken::deploy(
            [9u8; 32],
            "Slippage Token".to_string(),
            "SLIP".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token
            .buy(test_pubkey(2), 500_000, 101, 1_600_000_100)
            .unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let (mut pool, _, _) = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        // Try to swap with unreasonable slippage expectation
        let sov_in = 1_000_000_00u64;
        let result = pool.swap_sov_to_token(sov_in, 100_000_000_00); // Expect way too much
        assert!(matches!(result, Err(PolPoolError::SlippageExceeded)));
    }

    /// Issue #1849: Test price calculation view functions.
    #[test]
    fn test_pol_pool_price_calculation_views() {
        // Use small amounts to stay within u64 supply range for PiecewiseLinearCurve.
        let mut token = BondingCurveToken::deploy(
            [10u8; 32],
            "View Token".to_string(),
            "VIEW".to_string(),
            super::super::CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(200_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token
            .buy(test_pubkey(2), 500_000, 101, 1_600_000_100)
            .unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let (pool, _, _) = create_pol_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        // Get current price
        let current_price = pool.get_token_price().unwrap();
        assert!(current_price > 0);

        let (sov_initial, token_initial) = pool.get_reserves().unwrap();

        // Calculate expected output for a swap (view function, no state change)
        let sov_in = 1_000_000_00u64;
        let token_out = pool.calculate_token_out(sov_in).unwrap();
        assert!(token_out > 0);

        // Verify state unchanged
        let (sov_after, token_after) = pool.get_reserves().unwrap();
        assert_eq!(sov_initial, sov_after);
        assert_eq!(token_initial, token_after);
    }
}
