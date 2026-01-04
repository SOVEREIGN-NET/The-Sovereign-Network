//! Economic models and calculation engine module
//! 
//! Contains the core economic models, reward calculation algorithms,
//! and parameter adjustment mechanisms for the ZHTP network.

pub mod economic_model;
pub mod token_reward;
pub mod fee_calculation;
pub mod parameter_adjustment;
pub mod anti_speculation;
pub mod reward_adjustments;

pub use economic_model::*;
pub use token_reward::*;
pub use fee_calculation::*;
pub use parameter_adjustment::*;
pub use anti_speculation::*;
pub use reward_adjustments::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_economic_model_creation() {
        let model = EconomicModel::new();
        
        // Test default values
        assert_eq!(model.base_routing_rate, crate::DEFAULT_ROUTING_RATE);
        assert_eq!(model.base_storage_rate, crate::DEFAULT_STORAGE_RATE);
        assert_eq!(model.base_compute_rate, crate::DEFAULT_COMPUTE_RATE);
        assert_eq!(model.inflation_rate, 0.0);
        assert_eq!(model.max_supply, u64::MAX);
        assert_eq!(model.current_supply, 0);
        assert_eq!(model.burn_rate, 0.0);
        
        // Test treasury initialization
        assert_eq!(model.dao_treasury.treasury_balance, 2_500_000);
        assert_eq!(model.dao_treasury.ubi_allocated, 1_500_000);
        assert_eq!(model.dao_treasury.welfare_allocated, 1_000_000);
    }

    #[test]
    fn test_economic_model_stats() {
        let model = EconomicModel::new();
        let stats = model.get_economic_stats();

        // Verify all required fields are present
        assert!(stats["base_routing_rate"].is_u64());
        assert!(stats["base_storage_rate"].is_u64());
        assert!(stats["current_supply"].is_u64());
        assert!(stats["treasury_balance"].is_u64());
        // Note: isp_bypass_total_bandwidth was removed from stats
    }

    #[test]
    fn test_token_reward_calculation() {
        let model = EconomicModel::new();
        let work = WorkMetrics {
            routing_work: 5_000_000, // 5MB
            storage_work: 2_000_000_000, // 2GB
            compute_work: 20,
            quality_score: 0.98, // High quality
            uptime_hours: 24, // Perfect uptime
        };
        
        let reward = TokenReward::calculate(&work, &model).unwrap();
        
        // Base rewards
        assert_eq!(reward.routing_reward, 5); // 5MB * 1 token/MB
        assert_eq!(reward.storage_reward, 20); // 2GB * 10 tokens/GB
        assert_eq!(reward.compute_reward, 100); // 20 * 5 tokens/computation
        
        // Bonuses should be present for high quality/uptime
        assert!(reward.quality_bonus > 0);
        assert!(reward.uptime_bonus > 0);
        assert_eq!(reward.currency, "ZHTP");
    }

    #[test]
    fn test_token_reward_isp_bypass() {
        let work = IspBypassWork {
            bandwidth_shared_gb: 5,
            packets_routed_mb: 200,
            uptime_hours: 12,
            connection_quality: 0.95,
            users_served: 3,
            cost_savings_provided: 150,
        };
        
        let reward = TokenReward::calculate_isp_bypass(&work).unwrap();
        
        // Expected calculations
        let expected_bandwidth = 5 * crate::ISP_BYPASS_CONNECTIVITY_RATE; // 5 * 100 = 500
        let expected_routing = 200 * crate::ISP_BYPASS_MESH_RATE; // 200 * 1 = 200
        let expected_uptime = 12 * crate::ISP_BYPASS_UPTIME_BONUS; // 12 * 10 = 120
        let expected_base = expected_bandwidth + expected_routing + expected_uptime; // 820
        let expected_with_quality = expected_base + ((expected_base as f64) * 0.5) as u64; // 820 + 410 = 1230
        
        assert_eq!(reward.routing_reward, expected_routing);
        assert_eq!(reward.uptime_bonus, expected_uptime);
        assert_eq!(reward.quality_bonus, (expected_base as f64 * 0.5) as u64);
        assert_eq!(reward.total_reward, expected_with_quality);
    }

    #[test]
    fn test_fee_calculation_components() {
        // Test individual fee calculation functions
        let network_fee = calculate_network_fee(1000, Priority::Normal);
        assert!(network_fee >= crate::MINIMUM_NETWORK_FEE);

        let dao_fee = super::fee_calculation::calculate_dao_fee(10000);
        assert_eq!(dao_fee, 100); // 1% of 10000 (TRANSACTION_FEE_RATE)

        let small_dao_fee = super::fee_calculation::calculate_dao_fee(100);
        assert_eq!(small_dao_fee, crate::MINIMUM_DAO_FEE); // Minimum applied

        // Test total fee calculation
        let (net, dao, total) = calculate_total_fee(1000, 10000, Priority::High);
        assert_eq!(total, net + dao);
        assert!(net > calculate_network_fee(1000, Priority::Normal)); // High priority costs more
    }

    #[test]
    fn test_anti_speculation_mechanisms() {
        let mechanisms = AntiSpeculationMechanisms::default();
        
        // Test speculative behavior detection (should be lenient in post-scarcity)
        let is_spec1 = mechanisms.is_speculative_behavior(1_000_000, 0, 30);
        assert!(!is_spec1); // Post-scarcity doesn't penalize holding
        
        // Test utility incentives
        let high_usage_incentive = mechanisms.calculate_utility_incentives(2000, 10000); // 20% usage
        assert!(high_usage_incentive > 0);
        
        let low_usage_incentive = mechanisms.calculate_utility_incentives(500, 10000); // 5% usage
        assert_eq!(low_usage_incentive, 0);
    }
}
