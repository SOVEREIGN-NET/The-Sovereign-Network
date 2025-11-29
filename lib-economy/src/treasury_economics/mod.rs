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
        
        // Check automatic allocation (60% UBI, 40% welfare)
        assert_eq!(treasury.ubi_allocated, 600); // 60% of 1000
        assert_eq!(treasury.welfare_allocated, 400); // 40% of 1000
        
        // Add more fees
        treasury.add_dao_fees(500).unwrap();
        
        assert_eq!(treasury.treasury_balance, 1500);
        assert_eq!(treasury.total_dao_fees_collected, 1500);
        assert_eq!(treasury.ubi_allocated, 900); // 600 + (500 * 0.6)
        assert_eq!(treasury.welfare_allocated, 600); // 400 + (500 * 0.4)
    }

    #[test]
    fn test_ubi_per_citizen_calculation() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap(); // This allocates 600 to UBI
        
        // Test with different citizen counts
        assert_eq!(treasury.calculate_ubi_per_citizen(100), 6); // 600 / 100
        assert_eq!(treasury.calculate_ubi_per_citizen(200), 3); // 600 / 200
        assert_eq!(treasury.calculate_ubi_per_citizen(0), 0); // Division by zero protection
        
        // Test with no UBI allocated
        let empty_treasury = DaoTreasury::new();
        assert_eq!(empty_treasury.calculate_ubi_per_citizen(100), 0);
    }

    #[test]
    fn test_welfare_funding_calculation() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(2000).unwrap(); // This allocates 800 to welfare
        
        assert_eq!(treasury.calculate_welfare_funding_available(), 800);
        
        // Test with no fees
        let empty_treasury = DaoTreasury::new();
        assert_eq!(empty_treasury.calculate_welfare_funding_available(), 0);
    }

    #[test]
    fn test_ubi_distribution_recording() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap(); // Allocates 600 to UBI
        let timestamp = current_timestamp().unwrap();
        
        // Record UBI distribution
        treasury.record_ubi_distribution(300, timestamp).unwrap();
        
        assert_eq!(treasury.ubi_allocated, 300); // 600 - 300
        assert_eq!(treasury.total_ubi_distributed, 300);
        assert_eq!(treasury.treasury_balance, 700); // 1000 - 300
        assert_eq!(treasury.last_ubi_distribution, timestamp);
        
        // Try to distribute more than allocated (should fail)
        let result = treasury.record_ubi_distribution(400, timestamp);
        assert!(result.is_err());
        
        // Balances should remain unchanged after failed distribution
        assert_eq!(treasury.ubi_allocated, 300);
        assert_eq!(treasury.total_ubi_distributed, 300);
        assert_eq!(treasury.treasury_balance, 700);
    }

    #[test]
    fn test_welfare_distribution_recording() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap(); // Allocates 400 to welfare
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
        treasury.add_dao_fees(2000).unwrap();
        treasury.record_ubi_distribution(500, current_timestamp().unwrap()).unwrap();
        treasury.record_welfare_distribution(300, current_timestamp().unwrap()).unwrap();
        
        let stats = treasury.get_treasury_stats();
        
        // Verify stats structure
        assert_eq!(stats["treasury_balance"], 1200); // 2000 - 500 - 300
        assert_eq!(stats["total_dao_fees_collected"], 2000);
        assert_eq!(stats["total_ubi_distributed"], 500);
        assert_eq!(stats["total_welfare_distributed"], 300);
        assert_eq!(stats["ubi_allocated"], 700); // 1200 - 500
        assert_eq!(stats["welfare_allocated"], 500); // 800 - 300
        
        // Check allocation percentages
        assert_eq!(stats["allocation_percentages"]["ubi_percentage"], crate::UBI_ALLOCATION_PERCENTAGE);
        assert_eq!(stats["allocation_percentages"]["welfare_percentage"], crate::WELFARE_ALLOCATION_PERCENTAGE);
    }

    #[test]
    fn test_allocation_efficiency_metrics() {
        let mut treasury = DaoTreasury::new();
        treasury.add_dao_fees(1000).unwrap();
        treasury.record_ubi_distribution(300, current_timestamp().unwrap()).unwrap();
        treasury.record_welfare_distribution(200, current_timestamp().unwrap()).unwrap();
        
        let efficiency = treasury.get_allocation_efficiency();
        
        // UBI efficiency: 300 / 1000 = 30%
        assert_eq!(efficiency["ubi_distribution_efficiency"], 30.0);
        
        // Welfare efficiency: 200 / 1000 = 20%
        assert_eq!(efficiency["welfare_distribution_efficiency"], 20.0);
        
        // Total efficiency: 30% + 20% = 50%
        assert_eq!(efficiency["total_distribution_efficiency"], 50.0);
        
        // Pending distribution: (600 - 300) + (400 - 200) = 300 + 200 = 500
        assert_eq!(efficiency["funds_pending_distribution"], 500);
        
        // Distribution lag
        assert_eq!(efficiency["distribution_lag"]["ubi_allocated_not_distributed"], 300);
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
        assert_eq!(crate::UBI_ALLOCATION_PERCENTAGE + crate::WELFARE_ALLOCATION_PERCENTAGE, 100);
        
        // Verify individual percentages are reasonable
        assert_eq!(crate::UBI_ALLOCATION_PERCENTAGE, 60);
        assert_eq!(crate::WELFARE_ALLOCATION_PERCENTAGE, 40);
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
        
        // Check cumulative allocation
        assert_eq!(treasury.ubi_allocated, 600); // 60% of 1000
        assert_eq!(treasury.welfare_allocated, 400); // 40% of 1000
    }
}
