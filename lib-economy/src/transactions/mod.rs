//! Comprehensive transaction system module
//! 
//! Handles all economic transactions including fee calculation,
//! DAO fee validation, and proof generation for transparency.

pub mod transaction;
pub mod creation;
pub mod validation;
pub mod fee_processing;
pub mod dao_fee_proofs;
pub mod priority_fees;
pub mod blockchain_integration;

pub use transaction::*;
pub use creation::*;
pub use validation::*;
pub use fee_processing::*;
pub use dao_fee_proofs::*;
pub use priority_fees::*;
pub use blockchain_integration::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_transaction_creation() {
        // Test normal payment transaction
        let tx = Transaction::new_payment([1u8; 32], [2u8; 32], 5000, Priority::Normal).unwrap();
        
        assert_eq!(tx.amount, 5000);
        assert_eq!(tx.tx_type, TransactionType::Payment);
        assert!(tx.dao_fee > 0); // Should have DAO fee
        assert!(tx.base_fee > 0); // Should have network fee
        assert!(tx.total_fee > 0);
        assert_eq!(tx.total_fee, tx.base_fee + tx.dao_fee);
        assert!(tx.dao_fee_proof.is_some()); // Should have DAO fee proof
    }

    #[test]
    fn test_fee_exempt_transactions() {
        // Test UBI distribution (should be fee-free)
        let ubi_tx = Transaction::new_ubi_distribution([3u8; 32], 1000).unwrap();
        assert_eq!(ubi_tx.amount, 1000);
        assert_eq!(ubi_tx.dao_fee, 0);
        assert_eq!(ubi_tx.base_fee, 0);
        assert_eq!(ubi_tx.total_fee, 0);
        assert_eq!(ubi_tx.tx_type, TransactionType::UbiDistribution);
        assert!(ubi_tx.dao_fee_proof.is_none()); // No proof needed for fee-free
        
        // Test welfare distribution (should be fee-free)
        let welfare_tx = Transaction::new_welfare_distribution([4u8; 32], 2000).unwrap();
        assert_eq!(welfare_tx.amount, 2000);
        assert_eq!(welfare_tx.dao_fee, 0);
        assert_eq!(welfare_tx.base_fee, 0);
        assert_eq!(welfare_tx.total_fee, 0);
        assert_eq!(welfare_tx.tx_type, TransactionType::WelfareDistribution);
    }

    #[test]
    fn test_transaction_priority_fees() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let amount = 10000u64;
        let tx_size = 250u64;
        
        // Create transactions with different priorities
        let tx_low = Transaction::new(from, to, amount, TransactionType::Payment, tx_size, Priority::Low).unwrap();
        let tx_normal = Transaction::new(from, to, amount, TransactionType::Payment, tx_size, Priority::Normal).unwrap();
        let tx_high = Transaction::new(from, to, amount, TransactionType::Payment, tx_size, Priority::High).unwrap();
        let tx_urgent = Transaction::new(from, to, amount, TransactionType::Payment, tx_size, Priority::Urgent).unwrap();
        
        // Network fees should scale with priority
        assert!(tx_low.base_fee < tx_normal.base_fee);
        assert!(tx_normal.base_fee < tx_high.base_fee);
        assert!(tx_high.base_fee < tx_urgent.base_fee);
        
        // DAO fees should be the same regardless of priority
        assert_eq!(tx_low.dao_fee, tx_normal.dao_fee);
        assert_eq!(tx_normal.dao_fee, tx_high.dao_fee);
        assert_eq!(tx_high.dao_fee, tx_urgent.dao_fee);
        
        // Total fees should reflect priority scaling
        assert!(tx_low.total_fee < tx_normal.total_fee);
        assert!(tx_normal.total_fee < tx_high.total_fee);
        assert!(tx_high.total_fee < tx_urgent.total_fee);
    }

    #[test]
    fn test_transaction_properties() {
        let tx = Transaction::new_payment([5u8; 32], [6u8; 32], 7500, Priority::High).unwrap();
        
        // Test total cost calculation
        let expected_cost = tx.amount + tx.total_fee;
        assert_eq!(tx.total_cost(), expected_cost);
        
        // Test UBI contribution check
        assert!(tx.contributes_to_ubi());
        
        // Test DAO distribution check
        assert!(!tx.is_dao_distribution());
        
        // Test transaction summary
        let summary = tx.summary();
        assert_eq!(summary["amount"], 7500);
        assert!(summary["has_dao_proof"].as_bool().unwrap());
    }

    #[test]
    fn test_reward_transactions() {
        let reward_tx = Transaction::new_reward([7u8; 32], 350).unwrap();
        
        assert_eq!(reward_tx.amount, 350);
        assert_eq!(reward_tx.tx_type, TransactionType::Reward);
        assert_eq!(reward_tx.from, [0u8; 32]); // Network address
        assert!(reward_tx.dao_fee > 0); // Rewards still pay DAO fee
        assert!(reward_tx.contributes_to_ubi());
    }

    #[test]
    fn test_dao_distribution_transactions() {
        let ubi_tx = Transaction::new_ubi_distribution([8u8; 32], 500).unwrap();
        let welfare_tx = Transaction::new_welfare_distribution([9u8; 32], 750).unwrap();
        
        // Both should be DAO distributions
        assert!(ubi_tx.is_dao_distribution());
        assert!(welfare_tx.is_dao_distribution());
        
        // Both should be fee-free
        assert_eq!(ubi_tx.total_fee, 0);
        assert_eq!(welfare_tx.total_fee, 0);
        
        // Neither should contribute to UBI (they come FROM UBI fund)
        assert!(!ubi_tx.contributes_to_ubi());
        assert!(!welfare_tx.contributes_to_ubi());
    }

    #[test]
    fn test_signing_hash_consistency() {
        let tx1 = Transaction::new_payment([10u8; 32], [11u8; 32], 1000, Priority::Normal).unwrap();
        
        // Use different parameters to ensure different hash
        let tx2 = Transaction::new_payment([12u8; 32], [13u8; 32], 1001, Priority::Normal).unwrap();
        
        // Different transactions should have different signing hashes
        assert_ne!(tx1.signing_hash(), tx2.signing_hash());
        
        // Same transaction should have consistent signing hash
        let hash1 = tx1.signing_hash();
        let hash2 = tx1.signing_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_transaction_type_properties() {
        // Test fee exemption
        assert!(TransactionType::UbiDistribution.is_fee_exempt());
        assert!(TransactionType::WelfareDistribution.is_fee_exempt());
        assert!(!TransactionType::Payment.is_fee_exempt());
        assert!(!TransactionType::Reward.is_fee_exempt());
        
        // Test DAO fee requirement
        assert!(TransactionType::Payment.requires_dao_fee());
        assert!(TransactionType::Reward.requires_dao_fee());
        assert!(!TransactionType::UbiDistribution.requires_dao_fee());
        assert!(!TransactionType::WelfareDistribution.requires_dao_fee());
        assert!(!TransactionType::DaoFee.requires_dao_fee()); // DAO fee itself doesn't pay DAO fee
        
        // Test gas costs
        assert_eq!(TransactionType::Payment.base_gas_cost(), 1000);
        assert_eq!(TransactionType::UbiDistribution.base_gas_cost(), 0);
        assert_eq!(TransactionType::ProposalVote.base_gas_cost(), 2000);
    }

    #[test]
    fn test_priority_multipliers() {
        assert_eq!(Priority::Low.fee_multiplier(), 0.5);
        assert_eq!(Priority::Normal.fee_multiplier(), 1.0);
        assert_eq!(Priority::High.fee_multiplier(), 1.5);
        assert_eq!(Priority::Urgent.fee_multiplier(), 2.0);
        
        // Test processing order
        assert_eq!(Priority::Urgent.processing_order(), 0);
        assert_eq!(Priority::High.processing_order(), 1);
        assert_eq!(Priority::Normal.processing_order(), 2);
        assert_eq!(Priority::Low.processing_order(), 3);
    }
}
