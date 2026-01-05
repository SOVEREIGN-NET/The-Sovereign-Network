//! DAO treasury economics (calculation interface only - governance in lib-consensus)
//! 
//! Provides economic calculation interfaces for DAO treasury operations
//! while keeping governance logic centralized in the lib-consensus package.

pub mod fee_collection;
pub mod treasury_calculations;
pub mod ubi_economics;
pub mod welfare_economics;
pub mod treasury_stats;

pub use fee_collection::*;
pub use treasury_calculations::*;
pub use ubi_economics::*;
pub use welfare_economics::*;
pub use treasury_stats::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::calculate_dao_fee_distribution;
    use crate::wasm::compatibility::current_timestamp;

    #[test]
    fn test_dao_treasury_creation() {
        let treasury = DaoTreasury::new();
        
        // Test initial state
        assert_eq!(treasury.treasury_balance, 0);
        assert_eq!(treasury.ubi_allocated, 0);
        assert_eq!(treasury.sector_dao_allocated, 0);
        assert_eq!(treasury.emergency_allocated, 0);
        assert_eq!(treasury.dev_grants_allocated, 0);
        assert_eq!(treasury.total_dao_fees_collected, 0);
        assert_eq!(treasury.total_ubi_distributed, 0);
        assert_eq!(treasury.total_sector_dao_distributed, 0);
        assert_eq!(treasury.total_emergency_distributed, 0);
        assert_eq!(treasury.total_dev_grants_distributed, 0);
        assert_eq!(treasury.last_ubi_distribution, 0);
        assert_eq!(treasury.last_sector_dao_distribution, 0);
        assert_eq!(treasury.last_emergency_distribution, 0);
        assert_eq!(treasury.last_dev_grants_distribution, 0);
    }

    #[test]
    fn test_dao_fee_addition() {
        let mut treasury = DaoTreasury::new();

        // Add DAO fees
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(1000)).unwrap();

        // Check balances
        assert_eq!(treasury.treasury_balance, 1000);
        assert_eq!(treasury.total_dao_fees_collected, 1000);

        // Check allocation (45/30/15/10)
        assert_eq!(treasury.ubi_allocated, 450); // 45% of 1000
        assert_eq!(treasury.sector_dao_allocated, 300); // 30% of 1000
        assert_eq!(treasury.emergency_allocated, 150); // 15% of 1000
        assert_eq!(treasury.dev_grants_allocated, 100); // 10% of 1000

        // Add more fees
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(500)).unwrap();

        assert_eq!(treasury.treasury_balance, 1500);
        assert_eq!(treasury.total_dao_fees_collected, 1500);
        assert_eq!(treasury.ubi_allocated, 675); // 450 + (500 * 0.45)
        assert_eq!(treasury.sector_dao_allocated, 450); // 300 + (500 * 0.30)
        assert_eq!(treasury.emergency_allocated, 225); // 150 + (500 * 0.15)
        assert_eq!(treasury.dev_grants_allocated, 150); // 100 + (500 * 0.10)
    }

    #[test]
    fn test_ubi_per_citizen_calculation() {
        let mut treasury = DaoTreasury::new();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(1000)).unwrap(); // This allocates 450 to UBI (45% of 1000)

        // Test with different citizen counts
        assert_eq!(treasury.calculate_ubi_per_citizen(100), 4); // 450 / 100
        assert_eq!(treasury.calculate_ubi_per_citizen(225), 2); // 450 / 225
        assert_eq!(treasury.calculate_ubi_per_citizen(0), 0); // Division by zero protection

        // Test with no UBI allocated
        let empty_treasury = DaoTreasury::new();
        assert_eq!(empty_treasury.calculate_ubi_per_citizen(100), 0);
    }

    #[test]
    fn test_non_ubi_funding_calculation() {
        let mut treasury = DaoTreasury::new();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(2000)).unwrap();

        assert_eq!(treasury.calculate_sector_dao_funding_available(), 600);
        assert_eq!(treasury.calculate_emergency_funding_available(), 300);
        assert_eq!(treasury.calculate_dev_grants_funding_available(), 200);

        // Test with no fees
        let empty_treasury = DaoTreasury::new();
        assert_eq!(empty_treasury.calculate_sector_dao_funding_available(), 0);
        assert_eq!(empty_treasury.calculate_emergency_funding_available(), 0);
        assert_eq!(empty_treasury.calculate_dev_grants_funding_available(), 0);
    }

    #[test]
    fn test_ubi_distribution_recording() {
        let mut treasury = DaoTreasury::new();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(1000)).unwrap(); // Allocates 450 to UBI (45% of 1000)
        let timestamp = current_timestamp().unwrap();

        // Record UBI distribution
        treasury.record_ubi_distribution(225, timestamp).unwrap();

        assert_eq!(treasury.ubi_allocated, 225); // 450 - 225
        assert_eq!(treasury.total_ubi_distributed, 225);
        assert_eq!(treasury.treasury_balance, 775); // 1000 - 225
        assert_eq!(treasury.last_ubi_distribution, timestamp);

        // Try to distribute more than allocated (should fail)
        let result = treasury.record_ubi_distribution(300, timestamp);
        assert!(result.is_err());

        // Balances should remain unchanged after failed distribution
        assert_eq!(treasury.ubi_allocated, 225);
        assert_eq!(treasury.total_ubi_distributed, 225);
        assert_eq!(treasury.treasury_balance, 775);
    }

    #[test]
    fn test_sector_dao_distribution_recording() {
        let mut treasury = DaoTreasury::new();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(1000)).unwrap(); // Allocates 300 to sector DAOs
        let timestamp = current_timestamp().unwrap();

        // Record sector DAO distribution
        treasury.record_sector_dao_distribution(200, timestamp).unwrap();

        assert_eq!(treasury.sector_dao_allocated, 100); // 300 - 200
        assert_eq!(treasury.total_sector_dao_distributed, 200);
        assert_eq!(treasury.treasury_balance, 800); // 1000 - 200
        assert_eq!(treasury.last_sector_dao_distribution, timestamp);

        // Try to distribute more than allocated (should fail)
        let result = treasury.record_sector_dao_distribution(300, timestamp);
        assert!(result.is_err());

        // Balances should remain unchanged after failed distribution
        assert_eq!(treasury.sector_dao_allocated, 100);
        assert_eq!(treasury.total_sector_dao_distributed, 200);
        assert_eq!(treasury.treasury_balance, 800);
    }

    #[test]
    fn test_treasury_stats() {
        let mut treasury = DaoTreasury::new();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(2000)).unwrap(); // Allocates 900/600/300/200
        treasury.record_ubi_distribution(450, current_timestamp().unwrap()).unwrap();
        treasury.record_sector_dao_distribution(300, current_timestamp().unwrap()).unwrap();
        treasury.record_emergency_distribution(150, current_timestamp().unwrap()).unwrap();
        treasury.record_dev_grants_distribution(100, current_timestamp().unwrap()).unwrap();

        let stats = treasury.get_treasury_stats();

        // Verify stats structure
        assert_eq!(stats["treasury_balance"], 1000); // 2000 - 450 - 300 - 150 - 100
        assert_eq!(stats["total_dao_fees_collected"], 2000);
        assert_eq!(stats["total_ubi_distributed"], 450);
        assert_eq!(stats["total_sector_dao_distributed"], 300);
        assert_eq!(stats["total_emergency_distributed"], 150);
        assert_eq!(stats["total_dev_grants_distributed"], 100);
        assert_eq!(stats["ubi_allocated"], 450); // 900 - 450
        assert_eq!(stats["sector_dao_allocated"], 300); // 600 - 300
        assert_eq!(stats["emergency_allocated"], 150); // 300 - 150
        assert_eq!(stats["dev_grants_allocated"], 100); // 200 - 100

        // Check allocation percentages
        assert_eq!(stats["allocation_percentages"]["ubi_percentage"], crate::UBI_ALLOCATION_PERCENTAGE);
        assert_eq!(stats["allocation_percentages"]["sector_dao_percentage"], crate::SECTOR_DAO_ALLOCATION_PERCENTAGE);
        assert_eq!(stats["allocation_percentages"]["emergency_percentage"], crate::EMERGENCY_ALLOCATION_PERCENTAGE);
        assert_eq!(stats["allocation_percentages"]["dev_grants_percentage"], crate::DEV_GRANT_ALLOCATION_PERCENTAGE);
    }

    #[test]
    fn test_allocation_efficiency_metrics() {
        let mut treasury = DaoTreasury::new();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(1000)).unwrap(); // Allocates 450/300/150/100
        treasury.record_ubi_distribution(225, current_timestamp().unwrap()).unwrap();
        treasury.record_sector_dao_distribution(150, current_timestamp().unwrap()).unwrap();
        treasury.record_emergency_distribution(75, current_timestamp().unwrap()).unwrap();
        treasury.record_dev_grants_distribution(50, current_timestamp().unwrap()).unwrap();

        let efficiency = treasury.get_allocation_efficiency();

        // UBI efficiency: 225 / 1000 = 22.5%
        assert_eq!(efficiency["ubi_distribution_efficiency"], 22.5);

        assert_eq!(efficiency["sector_dao_distribution_efficiency"], 15.0);
        assert_eq!(efficiency["emergency_distribution_efficiency"], 7.5);
        assert_eq!(efficiency["dev_grants_distribution_efficiency"], 5.0);

        // Total efficiency: 22.5% + 15.0% + 7.5% + 5.0% = 50.0%
        assert_eq!(efficiency["total_distribution_efficiency"], 50.0);

        // Pending distribution: 225 + 150 + 75 + 50 = 500
        assert_eq!(efficiency["funds_pending_distribution"], 500);

        // Distribution lag
        assert_eq!(efficiency["distribution_lag"]["ubi_allocated_not_distributed"], 225);
        assert_eq!(efficiency["distribution_lag"]["sector_dao_allocated_not_distributed"], 150);
        assert_eq!(efficiency["distribution_lag"]["emergency_allocated_not_distributed"], 75);
        assert_eq!(efficiency["distribution_lag"]["dev_grants_allocated_not_distributed"], 50);
    }

    #[test]
    fn test_empty_treasury_efficiency() {
        let treasury = DaoTreasury::new();
        let efficiency = treasury.get_allocation_efficiency();
        
        // All efficiency metrics should be 0 for empty treasury
        assert_eq!(efficiency["ubi_distribution_efficiency"], 0.0);
        assert_eq!(efficiency["sector_dao_distribution_efficiency"], 0.0);
        assert_eq!(efficiency["emergency_distribution_efficiency"], 0.0);
        assert_eq!(efficiency["dev_grants_distribution_efficiency"], 0.0);
        assert_eq!(efficiency["total_distribution_efficiency"], 0.0);
        assert_eq!(efficiency["funds_pending_distribution"], 0);
    }

    #[test]
    fn test_allocation_percentage_constants() {
        // Verify the allocation percentages add up to 100%
        // NEW ALLOCATION (45/30/15/10): UBI / DAOs / Emergency / Dev Grants
        assert_eq!(crate::UBI_ALLOCATION_PERCENTAGE, 45);
        assert_eq!(crate::DAO_ALLOCATION_PERCENTAGE, 30);
        assert_eq!(crate::EMERGENCY_ALLOCATION_PERCENTAGE, 15);
        assert_eq!(crate::DEV_GRANT_ALLOCATION_PERCENTAGE, 10);

        let total = crate::UBI_ALLOCATION_PERCENTAGE
            + crate::DAO_ALLOCATION_PERCENTAGE
            + crate::EMERGENCY_ALLOCATION_PERCENTAGE
            + crate::DEV_GRANT_ALLOCATION_PERCENTAGE;

        assert_eq!(total, 100, "All allocation percentages must sum to 100%");
    }

    #[test]
    fn test_multiple_fee_collections() {
        let mut treasury = DaoTreasury::new();

        // Add fees multiple times
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(500)).unwrap();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(300)).unwrap();
        treasury.apply_fee_distribution(calculate_dao_fee_distribution(200)).unwrap();

        // Check total collection
        assert_eq!(treasury.total_dao_fees_collected, 1000);
        assert_eq!(treasury.treasury_balance, 1000);
        
        // Check cumulative allocation (45/30/15/10)
        assert_eq!(treasury.ubi_allocated, 450); // 45% of 1000
        assert_eq!(treasury.sector_dao_allocated, 300); // 30% of 1000
        assert_eq!(treasury.emergency_allocated, 150); // 15% of 1000
        assert_eq!(treasury.dev_grants_allocated, 100); // 10% of 1000
    }

    #[test]
    fn test_treasury_conservation_invariant() {
        let mut treasury = DaoTreasury::new();
        let distribution = calculate_dao_fee_distribution(1234);

        treasury.apply_fee_distribution(distribution).unwrap();

        let total_allocated = treasury.ubi_allocated
            + treasury.sector_dao_allocated
            + treasury.emergency_allocated
            + treasury.dev_grants_allocated;

        assert_eq!(total_allocated, treasury.treasury_balance);
        assert_eq!(total_allocated, distribution.total());
    }

    #[test]
    fn test_fee_round_trip() {
        let mut treasury = DaoTreasury::new();
        let distribution = calculate_dao_fee_distribution(1000);

        treasury.apply_fee_distribution(distribution).unwrap();

        assert_eq!(treasury.ubi_allocated, distribution.ubi);
        assert_eq!(treasury.sector_dao_allocated, distribution.sector_daos);
        assert_eq!(treasury.emergency_allocated, distribution.emergency_reserve);
        assert_eq!(treasury.dev_grants_allocated, distribution.dev_grants);
        assert_eq!(treasury.treasury_balance, distribution.total());
    }

    #[test]
    fn test_zero_fee_distribution() {
        let mut treasury = DaoTreasury::new();
        let distribution = calculate_dao_fee_distribution(0);

        treasury.apply_fee_distribution(distribution).unwrap();

        assert_eq!(treasury.treasury_balance, 0);
        assert_eq!(treasury.ubi_allocated, 0);
        assert_eq!(treasury.sector_dao_allocated, 0);
        assert_eq!(treasury.emergency_allocated, 0);
        assert_eq!(treasury.dev_grants_allocated, 0);
    }
}
