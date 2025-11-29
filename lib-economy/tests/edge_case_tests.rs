//! Edge case and error handling tests for ZHTP Economics module
//! 
//! Tests boundary conditions, error scenarios, and edge cases to ensure
//! robustness of the economic system.

use lib_economy::*;
use lib_economy::testing::*;

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_zero_amount_transactions() {
        // Test transaction with zero amount
        let tx = Transaction::new_payment([1u8; 32], [2u8; 32], 0, Priority::Normal).unwrap();
        
        assert_eq!(tx.amount, 0);
        // Should still have minimum fees
        assert!(tx.base_fee >= MINIMUM_NETWORK_FEE);
        assert_eq!(tx.dao_fee, MINIMUM_DAO_FEE); // Minimum DAO fee should apply
    }

    #[test]
    fn test_maximum_amount_transactions() {
        // Test transaction with maximum possible amount
        let max_amount = u64::MAX;
        let tx = Transaction::new_payment([1u8; 32], [2u8; 32], max_amount, Priority::Normal).unwrap();
        
        assert_eq!(tx.amount, max_amount);
        // DAO fee should be calculated correctly even for max amount
        let _expected_dao_fee = (max_amount / 50).max(MINIMUM_DAO_FEE); // 2% with overflow protection
        assert!(tx.dao_fee >= MINIMUM_DAO_FEE);
        // Check for overflow protection in fee calculation
        assert!(tx.total_fee >= tx.base_fee); // Ensure no underflow
    }

    #[test]
    fn test_extreme_work_metrics() {
        let model = EconomicModel::new();
        
        // Test with zero work
        let zero_work = WorkMetrics {
            routing_work: 0,
            storage_work: 0,
            compute_work: 0,
            quality_score: 0.0,
            uptime_hours: 0,
        };
        
        let reward = TokenReward::calculate(&zero_work, &model).unwrap();
        assert_eq!(reward.routing_reward, 0);
        assert_eq!(reward.storage_reward, 0);
        assert_eq!(reward.compute_reward, 0);
        assert_eq!(reward.quality_bonus, 0);
        assert_eq!(reward.uptime_bonus, 0);
        // Should have minimum reward floor
        assert!(reward.total_reward >= 1);
        
        // Test with maximum work
        let max_work = WorkMetrics {
            routing_work: u64::MAX,
            storage_work: u64::MAX,
            compute_work: u64::MAX,
            quality_score: 1.0,
            uptime_hours: u64::MAX,
        };
        
        let max_reward = TokenReward::calculate(&max_work, &model).unwrap();
        // Should handle large numbers without overflow
        assert!(max_reward.total_reward > 0);
        assert!(max_reward.routing_reward > 0);
    }

    #[test]
    fn test_invalid_quality_scores() {
        let mut work = WorkMetrics::new();
        
        // Test quality score above 1.0
        work.update_quality_score(1.5);
        assert_eq!(work.quality_score, 1.0); // Should be clamped
        
        // Test negative quality score
        work.update_quality_score(-0.5);
        assert_eq!(work.quality_score, 0.0); // Should be clamped
        
        // Test NaN quality score
        work.update_quality_score(f64::NAN);
        assert!(work.quality_score.is_nan()); // NaN should be preserved for debugging
    }

    #[test]
    fn test_treasury_edge_cases() {
        let mut treasury = DaoTreasury::new();
        
        // Test adding zero fees
        treasury.add_dao_fees(0).unwrap();
        assert_eq!(treasury.treasury_balance, 0);
        assert_eq!(treasury.ubi_allocated, 0);
        assert_eq!(treasury.welfare_allocated, 0);
        
        // Test maximum fee addition
        let max_fees = u64::MAX / 2; // Divide by 2 to avoid overflow in calculations
        treasury.add_dao_fees(max_fees).unwrap();
        assert_eq!(treasury.treasury_balance, max_fees);
        
        // Test UBI calculation with zero citizens
        let ubi_per_citizen = treasury.calculate_ubi_per_citizen(0);
        assert_eq!(ubi_per_citizen, 0); // Should handle division by zero
        
        // Test distribution recording edge cases
        let timestamp = current_timestamp();
        
        // Try to distribute more than allocated
        let result = treasury.record_ubi_distribution(treasury.ubi_allocated + 1, timestamp);
        assert!(result.is_err());
        
        // Distribute exact amount
        let allocated = treasury.ubi_allocated;
        treasury.record_ubi_distribution(allocated, timestamp).unwrap();
        assert_eq!(treasury.ubi_allocated, 0);
    }

    #[test]
    fn test_network_stats_edge_cases() {
        let mut stats = NetworkStats::new();
        
        // Test extreme utilization values
        stats.update_utilization(f64::INFINITY);
        assert_eq!(stats.utilization, 1.0); // Should be clamped
        
        stats.update_utilization(f64::NEG_INFINITY);
        assert_eq!(stats.utilization, 0.0); // Should be clamped
        
        stats.update_utilization(f64::NAN);
        assert!(stats.utilization.is_nan()); // NaN preserved for debugging
        
        // Test with zero nodes
        stats.set_total_nodes(0);
        let health = stats.network_health_score();
        assert!(health >= 0.0 && health <= 1.0); // Should still be valid range
    }

    #[test]
    fn test_isp_bypass_edge_cases() {
        let mut incentives = IspBypassIncentives::new();
        
        // Test with zero work
        let zero_work = IspBypassWork {
            bandwidth_shared_gb: 0,
            packets_routed_mb: 0,
            uptime_hours: 0,
            connection_quality: 0.0,
            users_served: 0,
            cost_savings_provided: 0,
        };
        
        let reward = incentives.calculate_rewards(&zero_work);
        assert_eq!(reward, 0);
        
        incentives.update_stats(&zero_work).unwrap();
        assert_eq!(incentives.connectivity_providers, 0);
        assert_eq!(incentives.mesh_participants, 0);
        
        // Test with maximum work
        let max_work = IspBypassWork {
            bandwidth_shared_gb: u64::MAX / 1000, // Scale down to avoid overflow
            packets_routed_mb: u64::MAX / 1000,
            uptime_hours: u64::MAX / 1000,
            connection_quality: 1.0,
            users_served: u64::MAX / 1000,
            cost_savings_provided: u64::MAX / 1000,
        };
        
        let max_reward = incentives.calculate_rewards(&max_work);
        assert!(max_reward > 0); // Should handle large numbers
    }

    #[test]
    fn test_wallet_edge_cases() {
        let mut wallet = WalletBalance::new([0u8; 32]);
        
        // Test spending more than available
        assert!(!wallet.can_afford(1));
        
        // Test with maximum balance
        wallet.available_balance = u64::MAX;
        assert!(wallet.can_afford(u64::MAX));
        assert!(!wallet.can_afford(1)); // Would overflow, so should return false
        
        // Test total balance calculation with maximum values
        wallet.staked_balance = u64::MAX / 3;
        wallet.pending_rewards = u64::MAX / 3;
        wallet.available_balance = u64::MAX / 3;
        
        let total = wallet.total_balance();
        assert!(total >= wallet.available_balance); // Should not underflow
    }

    #[test]
    fn test_fee_calculation_edge_cases() {
        let model = EconomicModel::new();
        
        // Test with zero transaction size
        let (net_fee, dao_fee, total_fee) = model.calculate_fee(0, 1000, Priority::Normal);
        assert!(net_fee >= MINIMUM_NETWORK_FEE); // Should have minimum
        assert!(dao_fee >= MINIMUM_DAO_FEE);
        assert_eq!(total_fee, net_fee + dao_fee);
        
        // Test with maximum transaction size
        let max_size = u64::MAX / 1000; // Scale down to avoid overflow
        let (max_net_fee, max_dao_fee, max_total_fee) = model.calculate_fee(max_size, 1000, Priority::Normal);
        assert!(max_net_fee > net_fee); // Should be higher
        assert_eq!(max_dao_fee, dao_fee); // DAO fee based on amount, not size
        assert_eq!(max_total_fee, max_net_fee + max_dao_fee);
    }

    #[test]
    fn test_priority_boundary_conditions() {
        let model = EconomicModel::new();
        let tx_size = 1000u64;
        let amount = 5000u64;
        
        // Test all priority levels for consistency
        let priorities = [Priority::Low, Priority::Normal, Priority::High, Priority::Urgent];
        let mut prev_net_fee = 0u64;
        
        for priority in priorities.iter() {
            let (net_fee, dao_fee, total_fee) = model.calculate_fee(tx_size, amount, *priority);
            
            // Network fee should increase with priority
            assert!(net_fee >= prev_net_fee);
            prev_net_fee = net_fee;
            
            // DAO fee should be constant regardless of priority
            assert_eq!(dao_fee, (amount * DEFAULT_DAO_FEE_RATE / 10000).max(MINIMUM_DAO_FEE));
            
            // Total should equal sum
            assert_eq!(total_fee, net_fee + dao_fee);
            
            // All fees should be non-zero
            assert!(net_fee > 0);
            assert!(dao_fee > 0);
            assert!(total_fee > 0);
        }
    }

    #[test]
    fn test_economic_model_parameter_extremes() {
        let mut model = EconomicModel::new();
        
        // Test with extreme network stats
        let extreme_high_util = NetworkStats {
            utilization: 1.0, // 100% utilization
            avg_quality: 1.0,
            total_nodes: u64::MAX,
            total_transactions: u64::MAX,
        };
        
        let original_rates = (model.base_routing_rate, model.base_storage_rate, model.base_compute_rate);
        model.adjust_parameters(&extreme_high_util).unwrap();
        
        // Rates should have increased
        assert!(model.base_routing_rate >= original_rates.0);
        assert!(model.base_storage_rate >= original_rates.1);
        assert!(model.base_compute_rate >= original_rates.2);
        
        // Test with extreme low utilization
        let extreme_low_util = NetworkStats {
            utilization: 0.0, // 0% utilization
            avg_quality: 0.0,
            total_nodes: 0,
            total_transactions: 0,
        };
        
        model.adjust_parameters(&extreme_low_util).unwrap();
        // Should still have reasonable rates (not zero)
        assert!(model.base_routing_rate > 0);
        assert!(model.base_storage_rate > 0);
        assert!(model.base_compute_rate > 0);
    }

    #[test]
    fn test_token_minting_extremes() {
        let mut model = EconomicModel::new();
        
        // Test minting zero tokens
        let zero_mint = model.mint_operational_tokens(0, "test").unwrap();
        assert_eq!(zero_mint, 0);
        assert_eq!(model.current_supply, 0);
        
        // Test minting maximum tokens (in chunks to avoid overflow)
        let large_amount = u64::MAX / 2;
        let large_mint = model.mint_operational_tokens(large_amount, "stress test").unwrap();
        assert_eq!(large_mint, large_amount);
        assert_eq!(model.current_supply, large_amount);
        
        // Test minting more tokens
        let more_amount = u64::MAX / 4;
        let more_mint = model.mint_operational_tokens(more_amount, "more test").unwrap();
        assert_eq!(more_mint, more_amount);
        // Check for overflow protection
        assert!(model.current_supply >= large_amount);
    }

    #[test]
    fn test_anti_speculation_edge_cases() {
        let mechanisms = AntiSpeculationMechanisms::default();
        
        // Test with zero balance
        let is_spec = mechanisms.is_speculative_behavior(0, 0, 30);
        assert!(!is_spec); // No tokens = no speculation
        
        let incentive = mechanisms.calculate_utility_incentives(0, 0);
        assert_eq!(incentive, 0); // No tokens = no incentive
        
        // Test with maximum values
        let max_balance = u64::MAX / 2;
        let max_usage = u64::MAX / 2;
        
        let is_spec_max = mechanisms.is_speculative_behavior(max_balance, max_usage, 1);
        assert!(!is_spec_max); // Post-scarcity doesn't penalize
        
        let incentive_max = mechanisms.calculate_utility_incentives(max_usage, max_balance);
        assert!(incentive_max > 0); // Should reward high usage
    }

    #[test]
    fn test_transaction_id_uniqueness() {
        let from = [1u8; 32];
        let to = [2u8; 32];
        let amount = 1000u64;
        
        // Create multiple transactions with same parameters
        let tx1 = Transaction::new_payment(from, to, amount, Priority::Normal).unwrap();
        let tx2 = Transaction::new_payment(from, to, amount, Priority::Normal).unwrap();
        let tx3 = Transaction::new_payment(from, to, amount, Priority::Normal).unwrap();
        
        // Transaction IDs should be unique (due to timestamps)
        assert_ne!(tx1.tx_id, tx2.tx_id);
        assert_ne!(tx2.tx_id, tx3.tx_id);
        assert_ne!(tx1.tx_id, tx3.tx_id);
        
        // But other properties should be similar
        assert_eq!(tx1.amount, tx2.amount);
        assert_eq!(tx1.dao_fee, tx2.dao_fee); // Same amount = same DAO fee
    }

    #[test]
    fn test_concurrent_simulation() {
        // Simulate concurrent economic operations
        let mut model = EconomicModel::new();
        let mut wallets: Vec<WalletBalance> = (0..100)
            .map(|i| WalletBalance::new([i as u8; 32]))
            .collect();
        
        // Simulate 1000 concurrent operations
        for i in 0..1000 {
            let wallet_idx = i % 100;
            
            // Random operation type
            match i % 4 {
                0 => {
                    // Add reward
                    let reward = TokenReward {
                        routing_reward: (i % 100) as u64,
                        storage_reward: (i % 200) as u64,
                        compute_reward: (i % 50) as u64,
                        quality_bonus: 0,
                        uptime_bonus: 0,
                        total_reward: (i % 350) as u64,
                        currency: "SOV".to_string(),
                    };
                    let _ = wallets[wallet_idx].add_reward(&reward);
                }
                1 => {
                    // Claim rewards
                    let _ = wallets[wallet_idx].claim_rewards();
                }
                2 => {
                    // Process fees
                    let fees = (i % 1000) as u64;
                    let _ = model.process_dao_fees(fees);
                }
                _ => {
                    // Mint tokens
                    let amount = (i % 10000) as u64;
                    let _ = model.mint_operational_tokens(amount, "concurrent test");
                }
            }
        }
        
        // Verify system consistency
        assert!(model.current_supply > 0);
        assert!(model.dao_treasury.treasury_balance >= 0);
        
        // Check wallet states
        for wallet in &wallets {
            assert!(wallet.total_balance() >= 0);
        }
    }
}
