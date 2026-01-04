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
    use crate::wasm::compatibility::current_timestamp;

    #[test]
    fn test_dao_treasury_creation() {
        let treasury = DaoTreasury::new();
        
        // Test initial state
        assert_eq!(treasury.treasury_balance, 0);
        assert_eq!(treasury.ubi_allocated, 0);
        assert_eq!(treasury.welfare_allocated, 0);
        assert_eq!(treasury.total_dao_fees_collected, 0);
        assert_eq!(treasury.total_ubi_distributed, 0);
        assert_eq!(treasury.total_welfare_distributed, 0);
        assert_eq!(treasury.last_ubi_distribution, 0);
        assert_eq!(treasury.last_welfare_distribution, 0);
    }

    #[test]
    fn test_dao_fee_addition() {
        let mut treasury = DaoTreasury::new();

        // Add DAO fees
        treasury.add_dao_fees(1000).unwrap();

        // Check balances
        assert_eq!(treasury.treasury_balance, 1000);
        assert_eq!(treasury.total_dao_fees_collected, 1000);

        // Check automatic allocation (NEW: 45% UBI, 40% welfare)
        // Note: Full 45/30/15/10 split will be implemented in Phase 2
        assert_eq!(treasury.ubi_allocated, 450); // 45% of 1000 (new)
        assert_eq!(treasury.welfare_allocated, 400); // 40% of 1000 (temporary)

        // Add more fees
        treasury.add_dao_fees(500).unwrap();

        assert_eq!(treasury.treasury_balance, 1500);
        assert_eq!(treasury.total_dao_fees_collected, 1500);
        assert_eq!(treasury.ubi_allocated, 675); // 450 + (500 * 0.45)
        assert_eq!(treasury.welfare_allocated, 600); // 400 + (500 * 0.40)
    }

    #[test]
    fn test_ubi_per_citizen_calculation() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap(); // This allocates 450 to UBI (45% of 1000)

        // Test with different citizen counts
        assert_eq!(treasury.calculate_ubi_per_citizen(100), 4); // 450 / 100
        assert_eq!(treasury.calculate_ubi_per_citizen(225), 2); // 450 / 225
        assert_eq!(treasury.calculate_ubi_per_citizen(0), 0); // Division by zero protection

        // Test with no UBI allocated
        let empty_treasury = DaoTreasury::new();
        assert_eq!(empty_treasury.calculate_ubi_per_citizen(100), 0);
    }

    #[test]
    fn test_welfare_funding_calculation() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(2000).unwrap(); // This allocates 800 to welfare (40% of 2000)

        assert_eq!(treasury.calculate_welfare_funding_available(), 800);

        // Test with no fees
        let empty_treasury = DaoTreasury::new();
        assert_eq!(empty_treasury.calculate_welfare_funding_available(), 0);
    }

    #[test]
    fn test_ubi_distribution_recording() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap(); // Allocates 450 to UBI (45% of 1000)
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
    fn test_welfare_distribution_recording() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap(); // Allocates 400 to welfare (40% of 1000)
        let timestamp = current_timestamp().unwrap();

        // Record welfare distribution
        treasury.record_welfare_distribution(200, timestamp).unwrap();

        assert_eq!(treasury.welfare_allocated, 200); // 400 - 200
        assert_eq!(treasury.total_welfare_distributed, 200);
        assert_eq!(treasury.treasury_balance, 800); // 1000 - 200
        assert_eq!(treasury.last_welfare_distribution, timestamp);

        // Try to distribute more than allocated (should fail)
        let result = treasury.record_welfare_distribution(300, timestamp);
        assert!(result.is_err());

        // Balances should remain unchanged after failed distribution
        assert_eq!(treasury.welfare_allocated, 200);
        assert_eq!(treasury.total_welfare_distributed, 200);
        assert_eq!(treasury.treasury_balance, 800);
    }

    #[test]
    fn test_treasury_stats() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(2000).unwrap(); // Allocates 900 to UBI (45%), 800 to Welfare (40%)
        treasury.record_ubi_distribution(450, current_timestamp().unwrap()).unwrap();
        treasury.record_welfare_distribution(400, current_timestamp().unwrap()).unwrap();

        let stats = treasury.get_treasury_stats();

        // Verify stats structure
        assert_eq!(stats["treasury_balance"], 1150); // 2000 - 450 - 400
        assert_eq!(stats["total_dao_fees_collected"], 2000);
        assert_eq!(stats["total_ubi_distributed"], 450);
        assert_eq!(stats["total_welfare_distributed"], 400);
        assert_eq!(stats["ubi_allocated"], 450); // 900 - 450
        assert_eq!(stats["welfare_allocated"], 400); // 800 - 400

        // Check allocation percentages
        assert_eq!(stats["allocation_percentages"]["ubi_percentage"], crate::UBI_ALLOCATION_PERCENTAGE);
        assert_eq!(stats["allocation_percentages"]["welfare_percentage"], crate::WELFARE_ALLOCATION_PERCENTAGE);
    }

    #[test]
    fn test_allocation_efficiency_metrics() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap(); // Allocates 450 to UBI, 400 to Welfare
        treasury.record_ubi_distribution(225, current_timestamp().unwrap()).unwrap();
        treasury.record_welfare_distribution(200, current_timestamp().unwrap()).unwrap();

        let efficiency = treasury.get_allocation_efficiency();

        // UBI efficiency: 225 / 1000 = 22.5%
        assert_eq!(efficiency["ubi_distribution_efficiency"], 22.5);

        // Welfare efficiency: 200 / 1000 = 20.0%
        assert_eq!(efficiency["welfare_distribution_efficiency"], 20.0);

        // Total efficiency: 22.5% + 20.0% = 42.5%
        assert_eq!(efficiency["total_distribution_efficiency"], 42.5);

        // Pending distribution: (450 - 225) + (400 - 200) = 225 + 200 = 425
        assert_eq!(efficiency["funds_pending_distribution"], 425);

        // Distribution lag
        assert_eq!(efficiency["distribution_lag"]["ubi_allocated_not_distributed"], 225);
        assert_eq!(efficiency["distribution_lag"]["welfare_allocated_not_distributed"], 200);
    }

    #[test]
    fn test_empty_treasury_efficiency() {
        let treasury = DaoTreasury::new();
        let efficiency = treasury.get_allocation_efficiency();
        
        // All efficiency metrics should be 0 for empty treasury
        assert_eq!(efficiency["ubi_distribution_efficiency"], 0.0);
        assert_eq!(efficiency["welfare_distribution_efficiency"], 0.0);
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
        treasury.add_dao_fees(500).unwrap();
        treasury.add_dao_fees(300).unwrap();
        treasury.add_dao_fees(200).unwrap();

        // Check total collection
        assert_eq!(treasury.total_dao_fees_collected, 1000);
        assert_eq!(treasury.treasury_balance, 1000);
        
        // Check cumulative allocation (45% UBI, 40% Welfare)
        assert_eq!(treasury.ubi_allocated, 450); // 45% of 1000
        assert_eq!(treasury.welfare_allocated, 400); // 40% of 1000
    }
}
