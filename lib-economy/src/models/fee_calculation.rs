//! Fee calculation algorithms
//! 
//! Implements the fee calculation logic for network infrastructure costs
//! and mandatory DAO fees for Universal Basic Income funding.

use crate::types::{Priority, PriorityExt};

/// Calculate network infrastructure fee based on transaction size and priority
pub fn calculate_network_fee(tx_size: u64, priority: Priority) -> u64 {
    // Base fee covers network infrastructure costs (bandwidth, storage, compute)
    let base_fee = tx_size * 1; // 1 token per byte (minimal infrastructure cost)
    
    // Apply priority multiplier for QoS
    let priority_multiplier = priority.fee_multiplier();
    let network_fee = ((base_fee as f64) * priority_multiplier) as u64;
    
    // Ensure minimum fee for network operation
    network_fee.max(crate::MINIMUM_NETWORK_FEE)
}

/// Calculate mandatory DAO fee for UBI and welfare funding
pub fn calculate_dao_fee(amount: u64) -> u64 {
    // 1% of transaction amount goes to DAO treasury (Phase 1: UBI and welfare services)
    // Use saturating arithmetic to prevent overflow
    let dao_fee = amount.saturating_mul(crate::DEFAULT_DAO_FEE_RATE) / 10000; // 1.00% mandatory (TRANSACTION_FEE_RATE)

    // Ensure minimum DAO fee contribution
    dao_fee.max(crate::MINIMUM_DAO_FEE)
}

/// Calculate total transaction fee (network + DAO)
pub fn calculate_total_fee(tx_size: u64, amount: u64, priority: Priority) -> (u64, u64, u64) {
    let network_fee = calculate_network_fee(tx_size, priority);
    let dao_fee = calculate_dao_fee(amount);
    let total_fee = network_fee + dao_fee;
    
    (network_fee, dao_fee, total_fee)
}

/// Calculate fee with exemptions for UBI and welfare distributions
pub fn calculate_fee_with_exemptions(
    tx_size: u64, 
    amount: u64, 
    priority: Priority, 
    is_ubi_or_welfare: bool
) -> (u64, u64, u64) {
    if is_ubi_or_welfare {
        // UBI and welfare distributions are completely fee-free
        (0, 0, 0)
    } else {
        calculate_total_fee(tx_size, amount, priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_fee_calculation() {
        let fee_normal = calculate_network_fee(1000, Priority::Normal);
        let fee_high = calculate_network_fee(1000, Priority::High);
        let fee_low = calculate_network_fee(1000, Priority::Low);
        
        assert!(fee_high > fee_normal);
        assert!(fee_normal > fee_low);
        assert!(fee_normal >= crate::MINIMUM_NETWORK_FEE);
    }

    #[test]
    fn test_dao_fee_calculation() {
        let fee_small = calculate_dao_fee(100);
        let fee_large = calculate_dao_fee(10000);

        assert_eq!(fee_small, crate::MINIMUM_DAO_FEE); // Minimum applied
        assert_eq!(fee_large, 100); // 1% of 10000 (TRANSACTION_FEE_RATE)
    }

    #[test]
    fn test_fee_exemptions() {
        let (net, dao, total) = calculate_fee_with_exemptions(1000, 1000, Priority::Normal, true);
        assert_eq!(net, 0);
        assert_eq!(dao, 0);
        assert_eq!(total, 0);
        
        let (net2, dao2, total2) = calculate_fee_with_exemptions(1000, 1000, Priority::Normal, false);
        assert!(net2 > 0);
        assert!(dao2 > 0);
        assert!(total2 > 0);
    }
}
