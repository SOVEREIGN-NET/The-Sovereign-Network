//! Core economic types module
//! 
//! Defines all fundamental data structures used throughout the economics system.

pub mod priority;
pub mod transaction_type;
pub mod work_metrics;
pub mod network_stats;

pub use priority::*;
pub use transaction_type::*;
pub use work_metrics::*;
pub use network_stats::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_fee_multipliers() {
        assert_eq!(Priority::Low.fee_multiplier(), 0.5);
        assert_eq!(Priority::Normal.fee_multiplier(), 1.0);
        assert_eq!(Priority::High.fee_multiplier(), 1.5);
        assert_eq!(Priority::Urgent.fee_multiplier(), 2.0);
    }

    #[test]
    fn test_priority_processing_order() {
        assert_eq!(Priority::Urgent.processing_order(), 0); // Highest priority
        assert_eq!(Priority::High.processing_order(), 1);
        assert_eq!(Priority::Normal.processing_order(), 2);
        assert_eq!(Priority::Low.processing_order(), 3); // Lowest priority
    }

    #[test]
    fn test_priority_descriptions() {
        assert_eq!(Priority::Low.description(), "Background processing");
        assert_eq!(Priority::Normal.description(), "Standard priority");
        assert_eq!(Priority::High.description(), "Premium service");
        assert_eq!(Priority::Urgent.description(), "Emergency priority");
    }

    #[test]
    fn test_priority_default() {
        assert_eq!(Priority::default(), Priority::Normal);
    }

    #[test]
    fn test_transaction_type_fee_exemptions() {
        // Fee-exempt types
        assert!(TransactionType::UbiDistribution.is_fee_exempt());
        assert!(TransactionType::WelfareDistribution.is_fee_exempt());
        
        // Non-exempt types
        assert!(!TransactionType::Payment.is_fee_exempt());
        assert!(!TransactionType::Reward.is_fee_exempt());
        assert!(!TransactionType::Stake.is_fee_exempt());
    }

    #[test]
    fn test_transaction_type_dao_fee_requirements() {
        // Should require DAO fee
        assert!(TransactionType::Payment.requires_dao_fee());
        assert!(TransactionType::Reward.requires_dao_fee());
        assert!(TransactionType::Stake.requires_dao_fee());
        assert!(TransactionType::Unstake.requires_dao_fee());
        
        // Should not require DAO fee
        assert!(!TransactionType::UbiDistribution.requires_dao_fee());
        assert!(!TransactionType::WelfareDistribution.requires_dao_fee());
        assert!(!TransactionType::DaoFee.requires_dao_fee()); // DAO fee itself
    }

    #[test]
    fn test_transaction_type_gas_costs() {
        assert_eq!(TransactionType::Payment.base_gas_cost(), 1000);
        assert_eq!(TransactionType::Reward.base_gas_cost(), 800);
        assert_eq!(TransactionType::Stake.base_gas_cost(), 1200);
        assert_eq!(TransactionType::Unstake.base_gas_cost(), 1200);
        assert_eq!(TransactionType::UbiDistribution.base_gas_cost(), 0);
        assert_eq!(TransactionType::WelfareDistribution.base_gas_cost(), 0);
        assert_eq!(TransactionType::ProposalVote.base_gas_cost(), 2000);
        assert_eq!(TransactionType::ProposalExecution.base_gas_cost(), 3000);
    }

    #[test]
    fn test_transaction_type_descriptions() {
        assert_eq!(TransactionType::Payment.description(), "User payment");
        assert_eq!(TransactionType::Reward.description(), "Network service reward");
        assert_eq!(TransactionType::UbiDistribution.description(), "Universal Basic Income");
        assert_eq!(TransactionType::WelfareDistribution.description(), "Welfare service funding");
        assert_eq!(TransactionType::ProposalVote.description(), "DAO proposal vote");
    }

    #[test]
    fn test_work_metrics_creation() {
        let metrics = WorkMetrics::new();
        
        assert_eq!(metrics.routing_work, 0);
        assert_eq!(metrics.storage_work, 0);
        assert_eq!(metrics.compute_work, 0);
        assert_eq!(metrics.quality_score, 0.0);
        assert_eq!(metrics.uptime_hours, 0);
    }

    #[test]
    fn test_work_metrics_operations() {
        let mut metrics = WorkMetrics::new();
        
        metrics.add_routing_work(1000);
        metrics.add_storage_work(2000);
        metrics.add_compute_work(50);
        metrics.update_quality_score(0.97);
        metrics.add_uptime_hours(25);
        
        assert_eq!(metrics.routing_work, 1000);
        assert_eq!(metrics.storage_work, 2000);
        assert_eq!(metrics.compute_work, 50);
        assert_eq!(metrics.quality_score, 0.97);
        assert_eq!(metrics.uptime_hours, 25);
    }

    #[test]
    fn test_work_metrics_bonus_qualifications() {
        let mut metrics = WorkMetrics::new();
        
        // Test quality bonus qualification
        metrics.update_quality_score(0.94);
        assert!(!metrics.qualifies_for_quality_bonus()); // Below threshold
        
        metrics.update_quality_score(0.96);
        assert!(metrics.qualifies_for_quality_bonus()); // Above threshold
        
        // Test uptime bonus qualification
        metrics.add_uptime_hours(22);
        assert!(!metrics.qualifies_for_uptime_bonus()); // Below threshold
        
        metrics.add_uptime_hours(2); // Now 24 hours
        assert!(metrics.qualifies_for_uptime_bonus()); // Above threshold
    }

    #[test]
    fn test_work_metrics_quality_bounds() {
        let mut metrics = WorkMetrics::new();
        
        // Test upper bound
        metrics.update_quality_score(1.5);
        assert_eq!(metrics.quality_score, 1.0);
        
        // Test lower bound
        metrics.update_quality_score(-0.5);
        assert_eq!(metrics.quality_score, 0.0);
        
        // Test normal value
        metrics.update_quality_score(0.85);
        assert_eq!(metrics.quality_score, 0.85);
    }

    #[test]
    fn test_isp_bypass_work_creation() {
        let work = IspBypassWork::new();
        
        assert_eq!(work.bandwidth_shared_gb, 0);
        assert_eq!(work.packets_routed_mb, 0);
        assert_eq!(work.uptime_hours, 0);
        assert_eq!(work.connection_quality, 0.0);
        assert_eq!(work.users_served, 0);
        assert_eq!(work.cost_savings_provided, 0);
    }

    #[test]
    fn test_isp_bypass_work_operations() {
        let mut work = IspBypassWork::new();
        
        work.add_bandwidth_shared(10);
        work.add_packets_routed(500);
        work.update_connection_quality(0.95);
        work.add_users_served(5);
        work.add_cost_savings(250);
        work.uptime_hours = 24;
        
        assert_eq!(work.bandwidth_shared_gb, 10);
        assert_eq!(work.packets_routed_mb, 500);
        assert_eq!(work.connection_quality, 0.95);
        assert_eq!(work.users_served, 5);
        assert_eq!(work.cost_savings_provided, 250);
        assert_eq!(work.uptime_hours, 24);
    }

    #[test]
    fn test_network_stats_creation() {
        let stats = NetworkStats::new();
        
        assert_eq!(stats.utilization, 0.0);
        assert_eq!(stats.avg_quality, 0.0);
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.total_transactions, 0);
    }

    #[test]
    fn test_network_stats_operations() {
        let mut stats = NetworkStats::new();
        
        stats.update_utilization(0.75);
        stats.update_avg_quality(0.88);
        stats.set_total_nodes(1500);
        stats.add_transactions(25000);
        
        assert_eq!(stats.utilization, 0.75);
        assert_eq!(stats.avg_quality, 0.88);
        assert_eq!(stats.total_nodes, 1500);
        assert_eq!(stats.total_transactions, 25000);
    }

    #[test]
    fn test_network_stats_utilization_bounds() {
        let mut stats = NetworkStats::new();
        
        // Test upper bound
        stats.update_utilization(1.5);
        assert_eq!(stats.utilization, 1.0);
        
        // Test lower bound
        stats.update_utilization(-0.5);
        assert_eq!(stats.utilization, 0.0);
        
        // Test normal value
        stats.update_utilization(0.65);
        assert_eq!(stats.utilization, 0.65);
    }

    #[test]
    fn test_network_stats_thresholds() {
        let mut stats = NetworkStats::new();
        
        // Test high utilization threshold
        stats.update_utilization(0.95);
        assert!(stats.is_high_utilization());
        assert!(!stats.is_low_utilization());
        
        // Test low utilization threshold
        stats.update_utilization(0.25);
        assert!(!stats.is_high_utilization());
        assert!(stats.is_low_utilization());
        
        // Test normal utilization
        stats.update_utilization(0.60);
        assert!(!stats.is_high_utilization());
        assert!(!stats.is_low_utilization());
    }

    #[test]
    fn test_network_stats_adjustment_multipliers() {
        let mut stats = NetworkStats::new();
        
        // High utilization adjustment
        stats.update_utilization(0.95);
        assert_eq!(stats.get_reward_adjustment_multiplier(), crate::HIGH_UTILIZATION_ADJUSTMENT);
        
        // Low utilization adjustment
        stats.update_utilization(0.25);
        assert_eq!(stats.get_reward_adjustment_multiplier(), crate::LOW_UTILIZATION_ADJUSTMENT);
        
        // Normal utilization (no adjustment)
        stats.update_utilization(0.60);
        assert_eq!(stats.get_reward_adjustment_multiplier(), 100);
    }

    #[test]
    fn test_network_health_score() {
        let mut stats = NetworkStats::new();
        
        // Test with good utilization and quality
        stats.update_utilization(0.70); // Good utilization
        stats.update_avg_quality(0.90); // High quality
        let health = stats.network_health_score();
        assert!(health > 0.8); // Should be high
        
        // Test with over-utilization
        stats.update_utilization(0.95); // Over-utilized
        stats.update_avg_quality(0.90);
        let health2 = stats.network_health_score();
        assert!(health2 < health); // Should be lower due to over-utilization
        
        // Test with poor quality
        stats.update_utilization(0.70);
        stats.update_avg_quality(0.50); // Poor quality
        let health3 = stats.network_health_score();
        assert!(health3 < health); // Should be lower due to poor quality
        
        // Health score should always be between 0 and 1
        assert!(health >= 0.0 && health <= 1.0);
        assert!(health2 >= 0.0 && health2 <= 1.0);
        assert!(health3 >= 0.0 && health3 <= 1.0);
    }
}
