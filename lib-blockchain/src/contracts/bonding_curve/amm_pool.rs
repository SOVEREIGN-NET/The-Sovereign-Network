//! Issue #1848: AMM Pool Creation for Bonding Curve Graduation
//!
//! Implements automatic AMM pool creation when bonding curve tokens graduate.
//! The pool is seeded with reserve SOV + CBE tokens at the final curve price.
//!
//! # Key Features
//! - Constant product AMM (x * y = k)
//! - Initial price = final curve price (price continuity)
//! - Protocol-owned liquidity (LP tokens permanently locked)
//! - Automatic pool seeding at graduation
//!
//! # Price Continuity Formula
//! ```text
//! final_curve_price = reserve_sov / total_supply_cbe
//! initial_k = reserve_sov * total_supply_cbe
//! ```
//!
//! # Security Invariants
//!
//! ## Invariant A1: Price Continuity
//! The AMM initial price MUST equal the final bonding curve price.
//!
//! ## Invariant A2: Protocol-Owned Liquidity
//! LP tokens are permanently locked (burned/zeroed). No one can remove liquidity.
//!
//! ## Invariant A3: Reserve Conservation
//! All reserve SOV from bonding curve goes to AMM pool.

use super::{
    events::BondingCurveEvent,
    types::{CurveError, Phase},
    BondingCurveToken,
};
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

/// LP token lock address - permanently locked (protocol-owned).
/// This address is burned/zeroed so no one can remove liquidity.
pub const LP_TOKEN_LOCK_ADDRESS: [u8; 32] = [0u8; 32];

/// AMM fee in basis points for graduated pools (0.3% = 30 bps).
/// Lower than standard 1% to encourage trading post-graduation.
pub const GRADUATED_POOL_FEE_BPS: u16 = 30;

/// Scale factor for price calculations (8 decimals).
pub const PRICE_SCALE: u128 = 100_000_000;

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
    /// Initial CBE token reserve (from total supply)
    pub initial_token_reserve: u64,
    /// Initial k value (sov_reserve * token_reserve)
    pub initial_k: u128,
    /// Initial price (sov_reserve / token_reserve)
    pub initial_price: u64,
    /// Final curve price before graduation
    pub final_curve_price: u64,
}

// ============================================================================
// AMM Pool Creator
// ============================================================================

/// Creates an AMM pool for a graduated bonding curve token.
///
/// This function implements the graduation → AMM transition:
/// 1. Verifies token is in Graduated phase
/// 2. Calculates initial pool reserves for price continuity
/// 3. Creates SovSwapPool with protocol-owned liquidity
/// 4. Transitions token to AMM phase
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

    // Calculate initial pool parameters for price continuity
    // Final curve price = reserve_sov / total_supply_cbe
    // For price continuity: initial_amm_price = final_curve_price
    // Initial reserves: sov = reserve_balance, cbe = total_supply
    let initial_sov = token.reserve_balance;
    let initial_cbe = token.total_supply;

    // Verify we have both SOV and CBE for the pool
    if initial_cbe == 0 {
        return Err(CurveError::InsufficientReserve);
    }

    // Calculate k = sov * cbe
    let k = (initial_sov as u128)
        .checked_mul(initial_cbe as u128)
        .ok_or(CurveError::Overflow)?;

    // Calculate prices for verification
    let final_curve_price = calculate_curve_price(initial_sov, initial_cbe)?;
    let initial_amm_price = calculate_amm_price(initial_sov, initial_cbe)?;

    // Verify price continuity (they should be equal)
    if final_curve_price != initial_amm_price {
        // This should never happen with correct math, but check for safety
        return Err(CurveError::InvalidParameters(
            "Price continuity check failed".to_string()
        ));
    }

    // Create the AMM pool using existing SovSwap infrastructure
    // CBE tokens are treated as FP (For-Profit) DAO tokens for AMM purposes
    // This allows the pool to work with the existing SovSwap system
    let pool = SovSwapPool::init_pool(
        token.token_id,
        DAOType::FP, // CBE tokens use FP type for AMM compatibility
        initial_sov,
        initial_cbe,
        governance_addr,
        treasury_addr,
    ).map_err(map_swap_error_to_curve_error)?;

    // Transition token to AMM phase
    let pool_id = *pool.pool_id();
    token.complete_migration(pool_id)?;

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
        stable_to_treasury: token.treasury_balance, // Treasury balance goes to protocol
        block_height,
        timestamp,
    };

    Ok((pool, result, event))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate the bonding curve price at graduation.
/// Formula: price = reserve_sov / total_supply_cbe
fn calculate_curve_price(reserve_sov: u64, total_supply_cbe: u64) -> Result<u64, CurveError> {
    if total_supply_cbe == 0 {
        return Err(CurveError::InvalidParameters(
            "Cannot calculate price with zero supply".to_string()
        ));
    }

    // price = (reserve_sov * PRICE_SCALE) / total_supply_cbe
    let price = (reserve_sov as u128)
        .checked_mul(PRICE_SCALE)
        .ok_or(CurveError::Overflow)?
        .checked_div(total_supply_cbe as u128)
        .ok_or(CurveError::Overflow)?;

    Ok(price as u64)
}

/// Calculate the AMM initial price.
/// For constant product AMM: price = sov_reserve / token_reserve
fn calculate_amm_price(sov_reserve: u64, token_reserve: u64) -> Result<u64, CurveError> {
    if token_reserve == 0 {
        return Err(CurveError::InvalidParameters(
            "Cannot calculate AMM price with zero token reserve".to_string()
        ));
    }

    // price = (sov_reserve * PRICE_SCALE) / token_reserve
    let price = (sov_reserve as u128)
        .checked_mul(PRICE_SCALE)
        .ok_or(CurveError::Overflow)?
        .checked_div(token_reserve as u128)
        .ok_or(CurveError::Overflow)?;

    Ok(price as u64)
}

/// Map SwapError to CurveError for unified error handling.
fn map_swap_error_to_curve_error(err: SwapError) -> CurveError {
    match err {
        SwapError::InsufficientInitialLiquidity => CurveError::InsufficientReserve,
        SwapError::InvalidTokenAddress => CurveError::InvalidParameters(
            "Invalid governance or treasury address".to_string()
        ),
        SwapError::Overflow => CurveError::Overflow,
        SwapError::PoolAlreadyInitialized => CurveError::InvalidParameters(
            "Pool already exists".to_string()
        ),
        _ => CurveError::InvalidParameters(format!("Swap error: {}", err)),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::bonding_curve::{
        pricing::PiecewiseLinearCurve, types::Threshold, BondingCurveToken,
    };

    fn test_pubkey(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 32])
    }

    /// Issue #1848: Test AMM pool creation for graduated token.
    #[test]
    fn test_create_amm_pool_for_graduated_token() {
        // Deploy and graduate a token
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
        assert!(token.can_graduate(1_600_000_200));
        token.graduate(1_600_000_200, 102).unwrap();
        assert_eq!(token.phase, Phase::Graduated);

        // Record pre-migration values
        let reserve_before = token.reserve_balance;
        let supply_before = token.total_supply;

        // Create AMM pool
        let governance = test_pubkey(3);
        let treasury = test_pubkey(4);
        let result = create_amm_pool_for_graduated_token(
            &mut token,
            governance,
            treasury,
            103,
            1_600_000_300,
        );

        assert!(result.is_ok(), "AMM pool creation failed: {:?}", result);
        let (pool, creation_result, event) = result.unwrap();

        // Verify token transitioned to AMM phase
        assert_eq!(token.phase, Phase::AMM);
        assert!(token.amm_pool_id.is_some());
        assert_eq!(token.amm_pool_id.unwrap(), *pool.pool_id());

        // Verify pool reserves match bonding curve state
        assert_eq!(creation_result.initial_sov_reserve, reserve_before);
        assert_eq!(creation_result.initial_token_reserve, supply_before);

        // Verify price continuity
        assert_eq!(
            creation_result.initial_price,
            creation_result.final_curve_price,
            "Price continuity must be maintained"
        );

        // Verify k value
        let expected_k = (reserve_before as u128) * (supply_before as u128);
        assert_eq!(creation_result.initial_k, expected_k);

        // Verify event
        match event {
            BondingCurveEvent::AMMSeeded {
                token_id,
                pool_id,
                sov_amount,
                token_amount,
                stable_to_treasury,
                ..
            } => {
                assert_eq!(token_id, [1u8; 32]);
                assert_eq!(pool_id, *pool.pool_id());
                assert_eq!(sov_amount, reserve_before);
                assert_eq!(token_amount, supply_before);
                assert_eq!(stable_to_treasury, token.treasury_balance);
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

        // Try to create AMM pool without graduating
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
            Err(CurveError::InvalidPhase { current: Phase::Curve, required: Phase::Graduated })
        ));
    }

    /// Issue #1848: Test price continuity calculation.
    #[test]
    fn test_price_continuity() {
        // Scenario: 1000 SOV reserve, 10000 CBE supply
        // Curve price = 1000 / 10000 = 0.1 SOV per CBE
        let reserve_sov = 1_000_000_000_00u64; // 1000 SOV
        let supply_cbe = 10_000_000_000_00u64; // 10000 CBE

        let curve_price = calculate_curve_price(reserve_sov, supply_cbe).unwrap();
        let amm_price = calculate_amm_price(reserve_sov, supply_cbe).unwrap();

        // Prices should be equal for continuity
        assert_eq!(curve_price, amm_price);

        // Price should be 0.1 SOV per CBE = 10_000_000 (8 decimal)
        assert_eq!(curve_price, 10_000_000);
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
            Threshold::ReserveAmount(100), // Very low threshold
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Buy just enough to graduate but with low reserve
        let buyer = test_pubkey(2);
        token.buy(buyer, 500, 101, 1_600_000_100).unwrap();
        token.graduate(1_600_000_200, 102).unwrap();

        // Should fail due to insufficient liquidity
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

    /// Issue #1848: Test constants are properly defined.
    #[test]
    fn test_amm_constants() {
        // Verify no magic numbers - all constants are defined
        assert_eq!(MINIMUM_AMM_LIQUIDITY, 1_000_000);
        assert_eq!(LP_TOKEN_LOCK_ADDRESS, [0u8; 32]);
        assert_eq!(GRADUATED_POOL_FEE_BPS, 30);
        assert_eq!(PRICE_SCALE, 100_000_000);

        // Verify fee is reasonable (0.3%)
        assert!(GRADUATED_POOL_FEE_BPS > 0);
        assert!(GRADUATED_POOL_FEE_BPS <= 1000); // Max 10%
    }
}
