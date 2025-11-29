//! Wallet economics and balance management
//! 
//! Handles wallet integration, balance tracking, and reward management.

pub mod wallet_balance;
pub mod reward_management;
pub mod staking_system;
pub mod mesh_discovery_rewards;
pub mod multi_wallet;
pub mod transaction_history;

// Re-export main types for convenience
pub use wallet_balance::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use crate::types::*;

    #[test]
    fn test_wallet_creation() {
        let node_id = [42u8; 32];
        let wallet = WalletBalance::new(node_id);
        
        assert_eq!(wallet.node_id, node_id);
        assert_eq!(wallet.available_balance, 0);
        assert_eq!(wallet.staked_balance, 0);
        assert_eq!(wallet.pending_rewards, 0);
        assert_eq!(wallet.transaction_history.len(), 0);
        assert_eq!(wallet.total_balance(), 0);
    }

    #[test]
    fn test_wallet_reward_system() {
        let mut wallet = WalletBalance::new([1u8; 32]);
        
        let reward = TokenReward {
            routing_reward: 100,
            storage_reward: 200,
            compute_reward: 50,
            quality_bonus: 25,
            uptime_bonus: 25,
            total_reward: 400,
            currency: "SOV".to_string(),
        };
        
        // Add reward
        wallet.add_reward(&reward).unwrap();
        assert_eq!(wallet.pending_rewards, 400);
        assert_eq!(wallet.available_balance, 0); // Not claimed yet
        assert_eq!(wallet.transaction_history.len(), 1);
        
        // Verify transaction record
        let tx = &wallet.transaction_history[0];
        assert_eq!(tx.amount, 400);
        assert_eq!(tx.tx_type, TransactionType::Reward);
        assert_eq!(tx.from, [0u8; 32]); // Network address
        assert_eq!(tx.to, wallet.node_id);
        
        // Claim rewards
        let claimed = wallet.claim_rewards().unwrap();
        assert_eq!(claimed, 400);
        assert_eq!(wallet.available_balance, 400);
        assert_eq!(wallet.pending_rewards, 0);
        assert_eq!(wallet.total_balance(), 400);
    }

    #[test]
    fn test_wallet_spending_capability() {
        let mut wallet = WalletBalance::new([2u8; 32]);
        
        // Initially can't afford anything
        assert!(!wallet.can_afford(1));
        assert!(!wallet.can_afford(100));
        
        // Add some balance
        wallet.available_balance = 1000;
        
        // Test spending capability
        assert!(wallet.can_afford(500));
        assert!(wallet.can_afford(1000));
        assert!(!wallet.can_afford(1001));
        assert!(!wallet.can_afford(2000));
    }

    #[test]
    fn test_multiple_rewards() {
        let mut wallet = WalletBalance::new([3u8; 32]);
        
        // Add multiple rewards
        let reward1 = TokenReward {
            routing_reward: 50,
            storage_reward: 100,
            compute_reward: 25,
            quality_bonus: 10,
            uptime_bonus: 15,
            total_reward: 200,
            currency: "SOV".to_string(),
        };
        
        let reward2 = TokenReward {
            routing_reward: 75,
            storage_reward: 150,
            compute_reward: 30,
            quality_bonus: 20,
            uptime_bonus: 25,
            total_reward: 300,
            currency: "SOV".to_string(),
        };
        
        wallet.add_reward(&reward1).unwrap();
        wallet.add_reward(&reward2).unwrap();
        
        // Check accumulated pending rewards
        assert_eq!(wallet.pending_rewards, 500); // 200 + 300
        assert_eq!(wallet.transaction_history.len(), 2);
        
        // Claim all rewards
        let total_claimed = wallet.claim_rewards().unwrap();
        assert_eq!(total_claimed, 500);
        assert_eq!(wallet.available_balance, 500);
        assert_eq!(wallet.pending_rewards, 0);
    }

    #[test]
    fn test_wallet_balance_components() {
        let mut wallet = WalletBalance::new([4u8; 32]);
        
        // Set up different balance components
        wallet.available_balance = 1000;
        wallet.staked_balance = 500;
        wallet.pending_rewards = 300;
        
        // Test total balance calculation
        assert_eq!(wallet.total_balance(), 1800); // 1000 + 500 + 300
        
        // Test spending capability (only available balance counts)
        assert!(wallet.can_afford(800));
        assert!(!wallet.can_afford(1200)); // Can't spend staked or pending
    }

    #[test]
    fn test_reward_transaction_properties() {
        let mut wallet = WalletBalance::new([5u8; 32]);
        
        let reward = TokenReward {
            routing_reward: 60,
            storage_reward: 90,
            compute_reward: 30,
            quality_bonus: 15,
            uptime_bonus: 5,
            total_reward: 200,
            currency: "SOV".to_string(),
        };
        
        wallet.add_reward(&reward).unwrap();
        
        let tx = &wallet.transaction_history[0];
        assert_eq!(tx.dao_fee, 0); // Reward transactions don't pay DAO fee
        assert_eq!(tx.base_fee, 0); // Reward transactions don't pay network fee
        assert_eq!(tx.total_fee, 0);
        assert!(tx.dao_fee_proof.is_none());
        assert_eq!(tx.block_height, 0); // Would be set by consensus layer
    }

    #[test]
    fn test_empty_reward_handling() {
        let mut wallet = WalletBalance::new([6u8; 32]);
        
        let empty_reward = TokenReward::default();
        assert_eq!(empty_reward.total_reward, 0);
        
        wallet.add_reward(&empty_reward).unwrap();
        assert_eq!(wallet.pending_rewards, 0);
        assert_eq!(wallet.transaction_history.len(), 1); // Transaction still recorded
        
        let claimed = wallet.claim_rewards().unwrap();
        assert_eq!(claimed, 0);
        assert_eq!(wallet.available_balance, 0);
    }

    #[test]
    fn test_claim_rewards_idempotency() {
        let mut wallet = WalletBalance::new([7u8; 32]);
        
        let reward = TokenReward {
            routing_reward: 100,
            storage_reward: 0,
            compute_reward: 0,
            quality_bonus: 0,
            uptime_bonus: 0,
            total_reward: 100,
            currency: "SOV".to_string(),
        };
        
        wallet.add_reward(&reward).unwrap();
        
        // First claim
        let claimed1 = wallet.claim_rewards().unwrap();
        assert_eq!(claimed1, 100);
        assert_eq!(wallet.available_balance, 100);
        assert_eq!(wallet.pending_rewards, 0);
        
        // Second claim should return 0
        let claimed2 = wallet.claim_rewards().unwrap();
        assert_eq!(claimed2, 0);
        assert_eq!(wallet.available_balance, 100); // Unchanged
        assert_eq!(wallet.pending_rewards, 0); // Still zero
    }
}
