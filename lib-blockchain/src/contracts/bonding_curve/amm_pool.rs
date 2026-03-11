//! Issue #1848: AMM Pool Creation for Bonding Curve Graduation
//!
//! Implements automatic AMM pool creation when bonding curve tokens graduate.
//! The pool is seeded with reserve SOV + CBE tokens at the final curve price.
//!
//! # Key Features
//! - Constant product AMM (x * y = k)
//! - Initial price = final curve price (price continuity)
//! - Protocol-owned liquidity (no `remove_liquidity` exists on SovSwapPool)
//! - Automatic pool seeding at graduation
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
//! ## Invariant A2: Protocol-Owned Liquidity
//! SovSwapPool has no `remove_liquidity` API — the seeded reserves can never be
//! withdrawn. This replaces a separate LP-lock mechanism.
//!
//! ## Invariant A3: Reserve Conservation
//! All reserve SOV from bonding curve goes to AMM pool; reserve_balance is
//! zeroed on the token after migration.

use super::{
    events::BondingCurveEvent,
    types::{CurveError, Phase},
    BondingCurveToken,
};
use crate::contracts::bonding_curve::pricing::PRICE_SCALE;
use crate::contracts::sov_swap::core::{SovSwapPool, SwapError};
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::DAOType;
use serde::{Deserialize, Serialize};

// ============================================================================
// Issue #1848: AMM Pool Creation Constants
// ============================================================================

/// Minimum liquidity required for AMM pool creation.
/// Prevents division by zero attacks and ensures meaningful liquidity.
pub const MINIMUM_AMM_LIQUIDITY: u64 = 1_000_000; // 0.01 SOV or equivalent

/// AMM fee in basis points for graduated pools (0.3% = 30 bps).
/// Lower than standard 1% to encourage trading post-graduation.
/// Applied immediately after pool init via `set_fee_bps`.
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
    pub initial_sov_reserve: u64,
    /// Initial CBE token reserve (derived for price continuity)
    pub initial_token_reserve: u64,
    /// Initial k value (sov_reserve * token_reserve)
    pub initial_k: u128,
    /// Initial AMM price — equals final_curve_price by construction
    pub initial_price: u64,
    /// Final curve price before graduation (from curve pricing function)
    pub final_curve_price: u64,
}

// ============================================================================
// AMM Pool Creator
// ============================================================================

/// Creates an AMM pool for a graduated bonding curve token.
///
/// This function implements the graduation → AMM transition:
/// 1. Verifies token is in Graduated phase
/// 2. Derives the CBE reserve from the final curve price for price continuity
/// 3. Creates SovSwapPool, sets fee to GRADUATED_POOL_FEE_BPS
/// 4. Verifies pool ID consistency with any previously recorded amm_pool_id
/// 5. Transitions token to AMM phase and zeroes migrated balances
///
/// # Arguments
/// * `token` - The graduated bonding curve token
/// * `governance_addr` - Governance address for pool fee control
/// * `treasury_addr` - Treasury address for fee collection
/// * `block_height` - Current block height (for event)
/// * `timestamp` - Current timestamp (for event)
///
/// # Returns
/// * `Ok((pool, result, event))` - Successfully created AMM pool
/// * `Err(CurveError)` - Pool creation failed
///
/// # Errors
/// * `InvalidPhase` - Token not in Graduated phase
/// * `InsufficientReserve` - Reserve too low for minimum liquidity
/// * `InvalidParameters` - Recorded pool ID doesn't match derived pool ID
/// * `Overflow` - Calculation overflow
pub fn create_amm_pool_for_graduated_token(
    token: &mut BondingCurveToken,
    governance_addr: PublicKey,
    treasury_addr: PublicKey,
    block_height: u64,
    timestamp: u64,
) -> Result<(SovSwapPool, AmmPoolCreationResult, BondingCurveEvent), CurveError> {
    // Verify token is in Graduated phase
    if token.phase != Phase::Graduated {
        return Err(CurveError::InvalidPhase {
            current: token.phase,
            required: Phase::Graduated,
        });
    }

    // Verify minimum liquidity requirement
    if token.reserve_balance < MINIMUM_AMM_LIQUIDITY {
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

    let initial_cbe = (initial_sov as u128)
        .checked_mul(PRICE_SCALE)
        .ok_or(CurveError::Overflow)?
        .checked_div(final_curve_price as u128)
        .ok_or(CurveError::Overflow)? as u64;

    if initial_cbe == 0 {
        return Err(CurveError::InsufficientReserve);
    }

    // Calculate k = sov * cbe
    let k = (initial_sov as u128)
        .checked_mul(initial_cbe as u128)
        .ok_or(CurveError::Overflow)?;

    // Verify price continuity
    let initial_amm_price = (initial_sov as u128)
        .checked_mul(PRICE_SCALE)
        .ok_or(CurveError::Overflow)?
        .checked_div(initial_cbe as u128)
        .ok_or(CurveError::Overflow)? as u64;

    if initial_amm_price != final_curve_price {
        return Err(CurveError::InvalidParameters(
            "Price continuity check failed".to_string(),
        ));
    }

    // Create the AMM pool using existing SovSwap infrastructure
    let mut pool = SovSwapPool::init_pool(
        token.token_id,
        DAOType::FP,
        initial_sov,
        initial_cbe,
        governance_addr.clone(),
        treasury_addr,
    )
    .map_err(map_swap_error_to_curve_error)?;

    // Set the graduated-pool fee (init_pool hardcodes DEFAULT_FEE_BPS = 1%)
    pool.set_fee_bps(&governance_addr, GRADUATED_POOL_FEE_BPS)
        .map_err(map_swap_error_to_curve_error)?;

    // Verify pool ID consistency: if amm_pool_id was already recorded during
    // the graduation step, it must match the deterministic pool ID derived here.
    let pool_id = *pool.pool_id();
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
        initial_token_reserve: initial_cbe,
        initial_k: k,
        initial_price: initial_amm_price,
        final_curve_price,
    };

    // Build event
    let event = BondingCurveEvent::AMMSeeded {
        token_id: token.token_id,
        pool_id,
        sov_amount: initial_sov,
        token_amount: initial_cbe,
        stable_to_treasury,
        block_height,
        timestamp,
    };

    Ok((pool, result, event))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Map SwapError to CurveError for unified error handling.
fn map_swap_error_to_curve_error(err: SwapError) -> CurveError {
    match err {
        SwapError::InsufficientInitialLiquidity => CurveError::InsufficientReserve,
        SwapError::InvalidTokenAddress => CurveError::InvalidParameters(
            "Invalid governance or treasury address".to_string(),
        ),
        SwapError::Overflow => CurveError::Overflow,
        SwapError::PoolAlreadyInitialized => {
            CurveError::InvalidParameters("Pool already exists".to_string())
        }
        _ => CurveError::InvalidParameters(format!("Swap error: {}", err)),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::bonding_curve::{types::Threshold, BondingCurveToken};

    fn test_pubkey(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 32])
    }

    /// Issue #1848: Test AMM pool creation for graduated token.
    #[test]
    fn test_create_amm_pool_for_graduated_token() {
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            super::super::CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(5_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Buy tokens to reach graduation threshold
        let buyer = test_pubkey(2);
        token.buy(buyer, 30_000_000_000, 101, 1_600_000_100).unwrap();

        // Graduate the token
        assert!(token.can_graduate(1_600_000_200, 102));
        token.graduate(1_600_000_200, 102).unwrap();
        assert_eq!(token.phase, Phase::Graduated);

        let reserve_before = token.reserve_balance;
        let final_curve_price = token.current_price();

        // Create AMM pool
        let governance = test_pubkey(3);
        let treasury = test_pubkey(4);
        let result = create_amm_pool_for_graduated_token(
            &mut token,
            governance.clone(),
            treasury,
            103,
            1_600_000_300,
        );

        assert!(result.is_ok(), "AMM pool creation failed: {:?}", result);
        let (pool, creation_result, event) = result.unwrap();

        // Verify token transitioned to AMM phase
        assert_eq!(token.phase, Phase::AMM);
        assert_eq!(token.amm_pool_id.unwrap(), *pool.pool_id());

        // Verify reserve and treasury are zeroed after migration (no double-counting)
        assert_eq!(token.reserve_balance, 0, "reserve_balance must be zeroed after migration");
        assert_eq!(token.treasury_balance, 0, "treasury_balance must be zeroed after migration");

        // Verify price continuity: AMM initial price == final curve price
        assert_eq!(
            creation_result.initial_price,
            creation_result.final_curve_price,
            "Price continuity must be maintained"
        );
        assert_eq!(
            creation_result.final_curve_price, final_curve_price,
            "final_curve_price must come from the curve pricing function"
        );

        // Verify initial SOV reserve
        assert_eq!(creation_result.initial_sov_reserve, reserve_before);

        // Verify the CBE reserve was derived for price continuity, not taken as total_supply
        let expected_cbe =
            (reserve_before as u128 * PRICE_SCALE / final_curve_price as u128) as u64;
        assert_eq!(creation_result.initial_token_reserve, expected_cbe);

        // Verify k
        let expected_k = reserve_before as u128 * expected_cbe as u128;
        assert_eq!(creation_result.initial_k, expected_k);

        // Verify fee was set to GRADUATED_POOL_FEE_BPS (not DEFAULT_FEE_BPS = 100)
        assert_eq!(
            pool.fee_bps(),
            GRADUATED_POOL_FEE_BPS,
            "graduated pool fee must be {} bps, not the default 100 bps",
            GRADUATED_POOL_FEE_BPS
        );

        // Verify SovSwapPool has no remove_liquidity — protocol-owned liquidity
        // is enforced structurally: there is no function to drain the pool.
        // (Compile-time check: the type has no such method.)

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
                assert_eq!(pool_id, *pool.pool_id());
                assert_eq!(sov_amount, reserve_before);
                assert_eq!(token_amount, expected_cbe);
            }
            _ => panic!("Expected AMMSeeded event"),
        }
    }

    /// Issue #1848: Test AMM pool creation fails if not graduated.
    #[test]
    fn test_amm_pool_creation_fails_if_not_graduated() {
        let mut token = BondingCurveToken::deploy(
            [2u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            super::super::CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(5_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let result = create_amm_pool_for_graduated_token(
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

    /// Issue #1848: Price continuity — AMM initial price must equal final curve price.
    ///
    /// Verifies that the CBE reserve is derived from the curve pricing function
    /// (`token.current_price()`), not from `reserve/total_supply`, so price continuity
    /// holds regardless of the 20/80 reserve split.
    #[test]
    fn test_price_continuity() {
        let mut token = BondingCurveToken::deploy(
            [5u8; 32],
            "PC Token".to_string(),
            "PC".to_string(),
            super::super::CurveType::Linear {
                base_price: 2_000_000, // $0.02
                slope: 100,            // rising price
            },
            Threshold::ReserveAmount(1_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);
        token.buy(buyer, 10_000_000_000, 101, 1_600_000_100).unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let final_curve_price = token.current_price();
        let reserve = token.reserve_balance;

        let (_, creation_result, _) = create_amm_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        assert_eq!(creation_result.final_curve_price, final_curve_price);
        assert_eq!(creation_result.initial_price, final_curve_price,
            "AMM initial price must equal final curve price");

        // Verify the CBE amount was derived for continuity, not taken as total_supply
        let expected_cbe = (reserve as u128 * PRICE_SCALE / final_curve_price as u128) as u64;
        assert_eq!(creation_result.initial_token_reserve, expected_cbe);
    }

    /// Issue #1848: Test minimum liquidity requirement.
    #[test]
    fn test_minimum_liquidity_requirement() {
        let mut token = BondingCurveToken::deploy(
            [3u8; 32],
            "Low Liquidity".to_string(),
            "LOW".to_string(),
            super::super::CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
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

        let result = create_amm_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        );

        assert!(result.is_err());
        assert!(matches!(result, Err(CurveError::InsufficientReserve)));
    }

    /// Issue #1848: Verify graduated pool fee is GRADUATED_POOL_FEE_BPS, not DEFAULT_FEE_BPS.
    #[test]
    fn test_graduated_pool_fee_is_set() {
        let mut token = BondingCurveToken::deploy(
            [4u8; 32],
            "Fee Token".to_string(),
            "FEE".to_string(),
            super::super::CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(5_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);
        token.buy(buyer, 30_000_000_000, 101, 1_600_000_100).unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        let (pool, _, _) = create_amm_pool_for_graduated_token(
            &mut token,
            test_pubkey(3),
            test_pubkey(4),
            103,
            1_600_000_300,
        )
        .unwrap();

        assert_eq!(pool.fee_bps(), GRADUATED_POOL_FEE_BPS,
            "fee must be {} bps (0.3%), not the default 100 bps (1%)",
            GRADUATED_POOL_FEE_BPS);
        assert_ne!(pool.fee_bps(), 100, "must differ from DEFAULT_FEE_BPS");
    }

    /// Issue #1848: Test constants are properly defined.
    #[test]
    fn test_amm_constants() {
        assert_eq!(MINIMUM_AMM_LIQUIDITY, 1_000_000);
        assert_eq!(GRADUATED_POOL_FEE_BPS, 30);
        // PRICE_SCALE is imported from pricing module — no local duplicate
        assert_eq!(PRICE_SCALE, 100_000_000);
        assert!(GRADUATED_POOL_FEE_BPS > 0);
        assert!(GRADUATED_POOL_FEE_BPS <= 1000);
    }
}
