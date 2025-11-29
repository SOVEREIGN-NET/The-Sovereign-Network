//! Integration tests for ZHTP Economics module
//! 
//! Comprehensive tests covering all economic functionality including
//! fee calculation, reward distribution, UBI mechanics, and  economics.

use lib_economy::*;
use lib_economy::testing::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_economic_flow() {
        // Create economic model
        let mut economic_model = EconomicModel::new();
        
        // Verify initial state
        assert_eq!(economic_model.current_supply, 0);
        assert_eq!(economic_model.base_routing_rate, DEFAULT_ROUTING_RATE);
        assert_eq!(economic_model.dao_treasury.treasury_balance, 2_500_000);
        
        // Test fee calculation
        let (network_fee, dao_fee, total_fee) = economic_model.calculate_fee(1000, 10000, Priority::Normal);
        assert!(network_fee >= MINIMUM_NETWORK_FEE);
        assert!(dao_fee >= MINIMUM_DAO_FEE);
        assert_eq!(total_fee, network_fee + dao_fee);
        
        // Test token minting
        let minted = economic_model.mint_operational_tokens(50000, "test infrastructure").unwrap();
        assert_eq!(minted, 50000);
        assert_eq!(economic_model.current_supply, 50000);
        
        // Test DAO fee processing
        let dao_fees_processed = economic_model.process_dao_fees(1000).unwrap();
        assert_eq!(dao_fees_processed, 1000);
        assert_eq!(economic_model.dao_treasury.treasury_balance, 2_501_000); // 2.5M + 1K
    }

    #[test]
    fn test_transaction_creation_and_validation() {
        // Test normal payment transaction
        let tx = Transaction::new_payment([1u8; 32], [2u8; 32], 5000, Priority::High).unwrap();
        assert_eq!(tx.amount, 5000);
        assert!(tx.dao_fee > 0); // Should have DAO fee
        assert!(tx.base_fee > 0); // Should have network fee
        assert_eq!(tx.tx_type, TransactionType::Payment);
        
        // Test UBI distribution (should be fee-free)
        let ubi_tx = Transaction::new_ubi_distribution([3u8; 32], 1000).unwrap();
        assert_eq!(ubi_tx.amount, 1000);
        assert_eq!(ubi_tx.dao_fee, 0); // UBI distributions are fee-free
        assert_eq!(ubi_tx.base_fee, 0);
        assert_eq!(ubi_tx.tx_type, TransactionType::UbiDistribution);
        
        // Test welfare distribution (should be fee-free)
        let welfare_tx = Transaction::new_welfare_distribution([4u8; 32], 2000).unwrap();
        assert_eq!(welfare_tx.amount, 2000);
        assert_eq!(welfare_tx.dao_fee, 0);
        assert_eq!(welfare_tx.base_fee, 0);
        assert_eq!(welfare_tx.tx_type, TransactionType::WelfareDistribution);
    }

    #[test]
    fn test_wallet_economics() {
        let mut wallet = WalletBalance::new([1u8; 32]);
        
        // Test initial state
        assert_eq!(wallet.available_balance, 0);
        assert_eq!(wallet.staked_balance, 0);
        assert_eq!(wallet.pending_rewards, 0);
        
        // Test reward addition
        let reward = TokenReward {
            routing_reward: 100,
            storage_reward: 200,
            compute_reward: 50,
            quality_bonus: 25,
            uptime_bonus: 25,
            total_reward: 400,
            currency: "SOV".to_string(),
        };
        
        wallet.add_reward(&reward).unwrap();
        assert_eq!(wallet.pending_rewards, 400);
        
        // Test reward claiming
        let claimed = wallet.claim_rewards().unwrap();
        assert_eq!(claimed, 400);
        assert_eq!(wallet.available_balance, 400);
        assert_eq!(wallet.pending_rewards, 0);
        
        // Test spending capability check
        assert!(wallet.can_afford(300));
        assert!(!wallet.can_afford(500));
    }

    #[test]
    fn test_isp_bypass_economics() {
        let mut incentives = IspBypassIncentives::new();
        
        // Create  work
        let bypass_work = IspBypassWork {
            bandwidth_shared_gb: 10,
            packets_routed_mb: 500,
            uptime_hours: 24,
            connection_quality: 0.95,
            users_served: 5,
            cost_savings_provided: 250, // $250 saved
        };
        
        // Calculate rewards
        let reward = incentives.calculate_rewards(&bypass_work);
        let expected_base = (10 * ISP_BYPASS_CONNECTIVITY_RATE) + 
                           (500 * ISP_BYPASS_MESH_RATE) + 
                           (24 * ISP_BYPASS_UPTIME_BONUS);
        let expected_with_quality = ((expected_base as f64) * 1.5) as u64; // High quality multiplier
        
        assert_eq!(reward, expected_with_quality);
        
        // Update statistics
        incentives.update_stats(&bypass_work).unwrap();
        assert_eq!(incentives.total_bandwidth_shared, 10);
        assert_eq!(incentives.total_isp_cost_savings, 250);
        assert_eq!(incentives.connectivity_providers, 1);
    }

    #[test]
    fn test_priority_fee_system() {
        let model = EconomicModel::new();
        let tx_size = 1000u64;
        let amount = 5000u64;
        
        // Test all priority levels
        let (net_low, dao_low, total_low) = model.calculate_fee(tx_size, amount, Priority::Low);
        let (net_normal, dao_normal, total_normal) = model.calculate_fee(tx_size, amount, Priority::Normal);
        let (net_high, dao_high, total_high) = model.calculate_fee(tx_size, amount, Priority::High);
        let (net_urgent, dao_urgent, total_urgent) = model.calculate_fee(tx_size, amount, Priority::Urgent);
        
        // Network fees should scale with priority
        assert!(net_low < net_normal);
        assert!(net_normal < net_high);
        assert!(net_high < net_urgent);
        
        // DAO fees should be the same regardless of priority
        assert_eq!(dao_low, dao_normal);
        assert_eq!(dao_normal, dao_high);
        assert_eq!(dao_high, dao_urgent);
        
        // Total fees should reflect priority scaling
        assert!(total_low < total_normal);
        assert!(total_normal < total_high);
        assert!(total_high < total_urgent);
    }

    #[test]
    fn test_treasury_allocation() {
        let mut treasury = DaoTreasury::new();
        
        // Test initial state
        assert_eq!(treasury.treasury_balance, 0);
        assert_eq!(treasury.ubi_allocated, 0);
        assert_eq!(treasury.welfare_allocated, 0);
        
        // Add DAO fees
        treasury.add_dao_fees(1000).unwrap();
        
        // Check automatic allocation (60% UBI, 40% welfare)
        assert_eq!(treasury.treasury_balance, 1000);
        assert_eq!(treasury.ubi_allocated, 600); // 60% of 1000
        assert_eq!(treasury.welfare_allocated, 400); // 40% of 1000
        assert_eq!(treasury.total_dao_fees_collected, 1000);
        
        // Test UBI calculation
        let ubi_per_citizen = treasury.calculate_ubi_per_citizen(100); // 100 citizens
        assert_eq!(ubi_per_citizen, 6); // 600 / 100
        
        // Test welfare funding
        let welfare_available = treasury.calculate_welfare_funding_available();
        assert_eq!(welfare_available, 400);
    }

    #[test]
    fn test_network_parameter_adjustment() {
        let mut model = EconomicModel::new();
        
        // Set higher initial rates to allow for meaningful decreases
        model.base_routing_rate = 10;
        model.base_storage_rate = 20;
        model.base_compute_rate = 15;
        
        let initial_routing_rate = model.base_routing_rate;
        
        // Test high utilization adjustment
        let high_util_stats = NetworkStats {
            utilization: 0.95, // High utilization
            avg_quality: 0.8,
            total_nodes: 1000,
            total_transactions: 100000,
        };
        
        model.adjust_parameters(&high_util_stats).unwrap();
        assert!(model.base_routing_rate > initial_routing_rate); // Should increase
        
        // Reset for low utilization test
        model.base_routing_rate = initial_routing_rate;
        
        // Test low utilization adjustment
        let low_util_stats = NetworkStats {
            utilization: 0.25, // Low utilization
            avg_quality: 0.8,
            total_nodes: 1000,
            total_transactions: 10000,
        };
        
        model.adjust_parameters(&low_util_stats).unwrap();
        assert!(model.base_routing_rate < initial_routing_rate); // Should decrease
    }

    #[test]
    fn test_reward_calculation() {
        let model = EconomicModel::new();
        let work_metrics = WorkMetrics {
            routing_work: 1_000_000, // 1MB
            storage_work: 1_000_000_000, // 1GB
            compute_work: 10,
            quality_score: 0.96, // Above bonus threshold
            uptime_hours: 24, // Above bonus threshold
        };
        
        let reward = TokenReward::calculate(&work_metrics, &model).unwrap();
        
        // Check base rewards
        assert_eq!(reward.routing_reward, 1); // 1 MB * 1 token/MB
        assert_eq!(reward.storage_reward, 10); // 1 GB * 10 tokens/GB
        assert_eq!(reward.compute_reward, 50); // 10 * 5 tokens/computation
        
        // Check bonuses (should be > 0 due to high quality and uptime)
        assert!(reward.quality_bonus > 0);
        assert!(reward.uptime_bonus > 0);
        
        // Check total
        let expected_base = reward.routing_reward + reward.storage_reward + reward.compute_reward;
        assert_eq!(reward.total_reward, expected_base + reward.quality_bonus + reward.uptime_bonus);
    }

    #[test]
    fn test_anti_speculation_mechanics() {
        let config = AntiSpeculationConfig::post_scarcity();
        let mechanisms = AntiSpeculationMechanisms::new(config);
        
        // Test that post-scarcity model doesn't penalize holding
        let is_speculative = mechanisms.is_speculative_behavior(1_000_000, 0, 30);
        assert!(!is_speculative); // Should not be considered speculative
        
        // Test utility incentives
        let incentive = mechanisms.calculate_utility_incentives(2000, 10000); // 20% usage
        assert!(incentive > 0); // Should reward utility usage
        
        let no_incentive = mechanisms.calculate_utility_incentives(500, 10000); // 5% usage
        assert_eq!(no_incentive, 0); // Low usage gets no bonus
        
        // Test post-scarcity effects
        let effects = mechanisms.apply_post_scarcity_principles(10000);
        assert!(effects.speculation_deterrent);
        assert!(effects.utility_focused);
        assert!(effects.hoarding_meaningless);
        assert!(effects.value_from_utility);
    }

    #[test]
    fn test_transaction_fee_exemptions() {
        // Test fee calculation with exemptions
        let (net_exempt, dao_exempt, total_exempt) = 
            calculate_fee_with_exemptions(1000, 5000, Priority::Normal, true);
        assert_eq!(net_exempt, 0);
        assert_eq!(dao_exempt, 0);
        assert_eq!(total_exempt, 0);
        
        let (net_normal, dao_normal, total_normal) = 
            calculate_fee_with_exemptions(1000, 5000, Priority::Normal, false);
        assert!(net_normal > 0);
        assert!(dao_normal > 0);
        assert!(total_normal > 0);
    }

    #[test]
    fn test_work_metrics_functionality() {
        let mut metrics = WorkMetrics::new();
        
        // Test initial state
        assert_eq!(metrics.routing_work, 0);
        assert_eq!(metrics.quality_score, 0.0);
        
        // Test adding work
        metrics.add_routing_work(1000);
        metrics.add_storage_work(2000);
        metrics.add_compute_work(50);
        metrics.update_quality_score(0.97);
        metrics.add_uptime_hours(25);
        
        // Verify values
        assert_eq!(metrics.routing_work, 1000);
        assert_eq!(metrics.storage_work, 2000);
        assert_eq!(metrics.compute_work, 50);
        assert_eq!(metrics.quality_score, 0.97);
        assert_eq!(metrics.uptime_hours, 25);
        
        // Test bonus qualifications
        assert!(metrics.qualifies_for_quality_bonus());
        assert!(metrics.qualifies_for_uptime_bonus());
    }

    #[test]
    fn test_network_stats_analysis() {
        let mut stats = NetworkStats::new();
        
        // Test updates
        stats.update_utilization(0.85);
        stats.update_avg_quality(0.92);
        stats.set_total_nodes(1500);
        stats.add_transactions(75000);
        
        // Test thresholds
        assert!(!stats.is_high_utilization()); // 0.85 < 0.9
        assert!(!stats.is_low_utilization());  // 0.85 > 0.3
        
        // Test adjustment multiplier
        assert_eq!(stats.get_reward_adjustment_multiplier(), 100); // No adjustment
        
        // Test network health score
        let health = stats.network_health_score();
        assert!(health > 0.0 && health <= 1.0);
    }

    #[test]
    fn test_economic_constants() {
        // Verify all constants are set correctly
        assert_eq!(DEFAULT_DAO_FEE_RATE, 200); // 2%
        assert_eq!(MINIMUM_DAO_FEE, 5);
        assert_eq!(UBI_ALLOCATION_PERCENTAGE, 60);
        assert_eq!(WELFARE_ALLOCATION_PERCENTAGE, 40);
        assert_eq!(DEFAULT_ROUTING_RATE, 1);
        assert_eq!(DEFAULT_STORAGE_RATE, 10);
        assert_eq!(ISP_BYPASS_CONNECTIVITY_RATE, 100);
        assert_eq!(HIGH_UTILIZATION_THRESHOLD, 0.9);
        assert_eq!(LOW_UTILIZATION_THRESHOLD, 0.3);
    }

    #[test]
    fn test_cross_platform_compatibility() {
        // Test WASM compatibility functions
        let timestamp = crate::wasm::compatibility::current_timestamp().unwrap();
        assert!(timestamp > 0);
        
        // Test hash function
        let hash = crate::wasm::hash_blake3(b"test data");
        assert_eq!(hash.len(), 32);
        
        // Test random generation
        let random_bytes = crate::wasm::compatibility::generate_random_bytes(16);
        assert_eq!(random_bytes.len(), 16);
    }
}
