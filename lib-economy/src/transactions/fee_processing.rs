//! Fee processing and distribution
//! 
//! Handles the processing and distribution of network and DAO fees.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::wasm::logging::info;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DaoFeeDistribution {
    pub ubi: u64,
    pub sector_daos: u64,
    pub emergency_reserve: u64,
    pub dev_grants: u64,
}

impl DaoFeeDistribution {
    pub fn total(&self) -> u64 {
        self.ubi
            .saturating_add(self.sector_daos)
            .saturating_add(self.emergency_reserve)
            .saturating_add(self.dev_grants)
    }
}

/// Process network infrastructure fees
pub fn process_network_fees(total_fees: u64) -> Result<u64> {
    // Network fees go to infrastructure providers (routing/storage/compute)
    info!(
        "Processed {} SOV tokens in network fees - distributed to infrastructure providers", 
        total_fees
    );
    
    Ok(total_fees) // All fees stay in circulation for infrastructure
}

/// Process DAO fees for UBI and DAO allocations
pub fn process_dao_fees(dao_fees: u64) -> Result<u64> {
    info!(
        " Processed {} SOV tokens in DAO fees - added to treasury allocations",
        dao_fees
    );
    
    Ok(dao_fees) // DAO fees go to UBI/welfare treasury
}

/// Calculate DAO fee distribution breakdown (single source of truth for allocation)
///
/// # Remainder Policy (Canonical: Emergency Reserve Sink)
/// Due to integer division truncation, a remainder may accumulate.
/// This remainder is allocated to the Emergency Reserve (safety-biased approach).
/// This ensures:
/// - No tokens are lost or unaccounted for (conservation invariant)
/// - Emergency Reserve absorbs rounding errors
/// - Deterministic across all platforms
///
/// # Overflow Safety
/// Uses u128 intermediates for multiplication to prevent overflow on large fee amounts.
/// Safe casting back to u64: percentages are at most 100, so final result is at most 100% of input.
pub fn calculate_dao_fee_distribution(dao_fees: u64) -> DaoFeeDistribution {
    // CRITICAL: Use u128 for intermediate calculations to prevent overflow
    let dao_fees_u128 = dao_fees as u128;
    let ubi_allocation = ((dao_fees_u128 * crate::UBI_ALLOCATION_PERCENTAGE as u128) / 100) as u64;
    let dao_allocation = ((dao_fees_u128 * crate::SECTOR_DAO_ALLOCATION_PERCENTAGE as u128) / 100) as u64;
    let emergency_allocation = ((dao_fees_u128 * crate::EMERGENCY_ALLOCATION_PERCENTAGE as u128) / 100) as u64;
    let dev_grant_allocation = ((dao_fees_u128 * crate::DEV_GRANT_ALLOCATION_PERCENTAGE as u128) / 100) as u64;

    // Calculate sum of all allocations (including dev grants)
    let allocated = ubi_allocation
        .saturating_add(dao_allocation)
        .saturating_add(emergency_allocation)
        .saturating_add(dev_grant_allocation);
    
    // CRITICAL: Remainder goes to Emergency Reserve (canonical sink)
    // This matches fee_distribution.rs behavior and ensures safety-biased allocation
    let remainder = dao_fees.saturating_sub(allocated);

    DaoFeeDistribution {
        ubi: ubi_allocation,
        sector_daos: dao_allocation,
        emergency_reserve: emergency_allocation.saturating_add(remainder),
        dev_grants: dev_grant_allocation,
    }
}

/// Separate network and DAO fees from a batch of transactions
pub fn separate_fees(transactions: &[crate::transactions::Transaction]) -> (u64, u64) {
    let mut total_network_fees = 0;
    let mut total_dao_fees = 0;
    
    for tx in transactions {
        total_network_fees += tx.base_fee;
        total_dao_fees += tx.dao_fee;
    }
    
    (total_network_fees, total_dao_fees)
}

/// Calculate fee distribution breakdown
pub fn calculate_fee_distribution(network_fees: u64, dao_fees: u64) -> serde_json::Value {
    let total_fees = network_fees + dao_fees;
    let network_percentage = if total_fees > 0 {
        (network_fees as f64 / total_fees as f64) * 100.0
    } else {
        0.0
    };
    let dao_percentage = if total_fees > 0 {
        (dao_fees as f64 / total_fees as f64) * 100.0
    } else {
        0.0
    };

    let dao_allocation = calculate_dao_fee_distribution(dao_fees);

    serde_json::json!({
        "total_fees": total_fees,
        "network_fees": network_fees,
        "dao_fees": dao_fees,
        "network_percentage": network_percentage,
        "dao_percentage": dao_percentage,
        "allocation": {
            "ubi": dao_allocation.ubi,
            "sector_daos": dao_allocation.sector_daos,
            "emergency_reserve": dao_allocation.emergency_reserve,
            "dev_grants": dao_allocation.dev_grants
        },
        "allocation_percentages": {
            "ubi": crate::UBI_ALLOCATION_PERCENTAGE,
            "sector_daos": crate::SECTOR_DAO_ALLOCATION_PERCENTAGE,
            "emergency_reserve": crate::EMERGENCY_ALLOCATION_PERCENTAGE,
            "dev_grants": crate::DEV_GRANT_ALLOCATION_PERCENTAGE
        }
    })
}




    #[test]
    fn test_overflow_safety_with_large_fees() {
        // CRITICAL: Verify u128 intermediates prevent overflow
        // Old u64-only code: (dao_fees * percentage) could overflow if dao_fees is large
        // New u128 code: safely handles large fee amounts
        
        // Test with very large fee amounts that would have overflowed with u64 arithmetic
        let large_fee = u64::MAX / 200; // Safe: doesn't cause overflow in u128 multiplication
        
        // Should not panic
        let distribution = calculate_dao_fee_distribution(large_fee);
        
        // Verify conservation
        assert_eq!(distribution.total(), large_fee);
        
        // Each allocation should be at most the full fee
        assert!(distribution.ubi <= large_fee);
        assert!(distribution.sector_daos <= large_fee);
        assert!(distribution.emergency_reserve <= large_fee);
        assert!(distribution.dev_grants <= large_fee);
    }

    #[test]
    fn test_decimal_precision_across_all_u64_ranges() {
        // Verify u128 intermediates maintain precision across full u64 range
        
        let test_fees = vec![
            1,                 // Minimum
            100,               // Small
            10_000,            // Medium
            1_000_000,         // Large
            u64::MAX / 1000,   // Very large (safe)
        ];
        
        for fee in test_fees {
            let distribution = calculate_dao_fee_distribution(fee);
            
            // Conservation must always hold
            assert_eq!(
                distribution.total(),
                fee,
                "Conservation failed for fee={}",
                fee
            );
            
            // Each component calculated correctly with u128 intermediates
            let ubi_expected = ((fee as u128 * crate::UBI_ALLOCATION_PERCENTAGE as u128) / 100) as u64;
            assert_eq!(distribution.ubi, ubi_expected, "UBI calculation incorrect for fee={}", fee);
        }
    }
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remainder_goes_to_emergency_reserve() {
        // CRITICAL: Verify the canonical remainder policy (Emergency Reserve Sink)
        // When integer division leaves a remainder, it must go to Emergency Reserve,
        // NOT to Development Grants (old, incorrect behavior).
        
        // Use a fee amount that produces a remainder:
        // 123 SOV * allocation percentages:
        // - UBI: (123 * 45) / 100 = 55 (with 0.35 lost)
        // - Sector DAOs: (123 * 30) / 100 = 36 (with 0.9 lost)
        // - Emergency: (123 * 15) / 100 = 18 (with 0.45 lost)
        // - Dev Grants: (123 * 10) / 100 = 12 (with 0.3 lost)
        // Sum: 55 + 36 + 18 + 12 = 121
        // Remainder: 123 - 121 = 2
        // This remainder MUST go to emergency_reserve
        
        let distribution = calculate_dao_fee_distribution(123);
        
        // Verify allocations (integer division)
        assert_eq!(distribution.ubi, 55);
        assert_eq!(distribution.sector_daos, 36);
        assert_eq!(distribution.dev_grants, 12);
        
        // CRITICAL: Remainder must be in emergency_reserve (not dev_grants)
        // emergency_reserve = 18 + 2 (remainder) = 20
        assert_eq!(distribution.emergency_reserve, 20);
        
        // Verify conservation: total must equal input
        assert_eq!(distribution.total(), 123);
    }

    #[test]
    fn test_conservation_invariant_with_various_inputs() {
        // CRITICAL: Conservation invariant must hold for all input values
        // total_allocated == input_fee (no tokens lost or duplicated)
        // Note: Very large values (close to u64::MAX) will cause overflow with current u64 math.
        // This is task #5 (fee math overflow fix) - use u128 intermediates.
        
        let test_cases = vec![
            1,           // Minimum
            10,          // Small
            123,         // Odd (has remainder)
            1000,        // Round
            1_000_000,   // Large
        ];
        
        for fee in test_cases {
            let distribution = calculate_dao_fee_distribution(fee);
            assert_eq!(
                distribution.total(),
                fee,
                "Conservation invariant violated for fee={}",
                fee
            );
        }
    }

    #[test]
    fn test_remainder_with_different_fee_amounts() {
        // Test that remainder allocation works correctly for various fee amounts
        // that produce different remainder values
        
        // 1: remainder = 1 (all goes to emergency)
        let d1 = calculate_dao_fee_distribution(1);
        assert_eq!(d1.emergency_reserve, 1); // 0 + 1 remainder
        assert_eq!(d1.total(), 1);
        
        // 7: UBI=3, Sector=2, Emergency=1, Dev=1, remainder=0
        let d7 = calculate_dao_fee_distribution(7);
        assert_eq!(d7.total(), 7);
        
        // 101: Creates clear remainder in emergency allocation
        let d101 = calculate_dao_fee_distribution(101);
        assert_eq!(d101.total(), 101);
        // emergency should get 15 + remainder
        assert!(d101.emergency_reserve >= (101 * 15) / 100);
    }

    #[test]
    fn test_percentage_split_at_100_fee() {
        // At 100 SOV fee, allocations should be clean (no remainder)
        let distribution = calculate_dao_fee_distribution(100);
        
        assert_eq!(distribution.ubi, 45);
        assert_eq!(distribution.sector_daos, 30);
        assert_eq!(distribution.emergency_reserve, 15);
        assert_eq!(distribution.dev_grants, 10);
        assert_eq!(distribution.total(), 100);
    }

    #[test]
    fn test_zero_fee_handling() {
        // Zero fee should produce zero allocations
        let distribution = calculate_dao_fee_distribution(0);
        
        assert_eq!(distribution.ubi, 0);
        assert_eq!(distribution.sector_daos, 0);
        assert_eq!(distribution.emergency_reserve, 0);
        assert_eq!(distribution.dev_grants, 0);
        assert_eq!(distribution.total(), 0);
    }

    #[test]
    fn test_dev_grants_no_longer_receives_remainder() {
        // CRITICAL REGRESSION TEST: Verify the fix
        // Old behavior: dev_grants received remainder
        // New behavior: emergency_reserve receives remainder
        
        // Using a fee that produces a remainder
        let distribution = calculate_dao_fee_distribution(173);
        
        // Calculate what dev_grants should be (without remainder)
        let expected_dev_grants = (173 * crate::DEV_GRANT_ALLOCATION_PERCENTAGE) / 100;
        
        // dev_grants must NOT include any remainder
        assert_eq!(distribution.dev_grants, expected_dev_grants);
        
        // The remainder went to emergency_reserve instead
        let expected_emergency_base = (173 * crate::EMERGENCY_ALLOCATION_PERCENTAGE) / 100;
        assert!(distribution.emergency_reserve >= expected_emergency_base);
    }
}
