//! Core economic types module
//! 
//! Defines all fundamental data structures used throughout the economics system.
//! Pure data types are re-exported from lib-types.
//! Behavior is added via extension traits.

use serde::{Serialize, Deserialize};

// Re-export pure data types from lib-types (canonical location)
pub use lib_types::economy::{
    Priority, TransactionType, TreasuryFund, TreasuryOperationType, UbiRecipientCategory,
    WorkMetrics, IspBypassWork, NetworkStats, TreasuryFundData, FundEfficiencyMetrics,
    UbiDistributionStats, MonthlyUbiData, UbiImpactMetrics, TreasuryOperation,
    GovernanceApproval, TreasuryHealthMetrics, TreasurySettings, TreasuryStats,
    SOV_TOTAL_SUPPLY, TRANSACTION_FEE_RATE, UBI_ALLOCATION_PERCENTAGE,
    SECTOR_DAO_ALLOCATION_PERCENTAGE, EMERGENCY_ALLOCATION_PERCENTAGE,
    DEV_GRANT_ALLOCATION_PERCENTAGE, DEFAULT_ROUTING_RATE, DEFAULT_STORAGE_RATE,
    DEFAULT_COMPUTE_RATE, ISP_BYPASS_CONNECTIVITY_RATE, ISP_BYPASS_MESH_RATE,
    ISP_BYPASS_UPTIME_BONUS, QUALITY_BONUS_THRESHOLD, UPTIME_BONUS_THRESHOLD,
    HIGH_UTILIZATION_THRESHOLD, LOW_UTILIZATION_THRESHOLD,
    HIGH_UTILIZATION_ADJUSTMENT, LOW_UTILIZATION_ADJUSTMENT,
};

// Note: Economic constants are defined in lib.rs and lib-types::economy
// Use crate::UBI_ALLOCATION_PERCENTAGE or lib_types::economy::UBI_ALLOCATION_PERCENTAGE

// =============================================================================
// EXTENSION TRAITS (Behavior for lib-types data types)
// =============================================================================

/// Extension trait for Priority with behavior
pub trait PriorityExt {
    /// Get the fee multiplier for this priority level
    fn fee_multiplier(&self) -> f64;
    /// Get the processing order (lower number = higher priority)
    fn processing_order(&self) -> u8;
    /// Get human-readable description
    fn description(&self) -> &'static str;
}

impl PriorityExt for Priority {
    fn fee_multiplier(&self) -> f64 {
        match self {
            Priority::Low => 0.5,    // 50% discount for background traffic
            Priority::Normal => 1.0, // Standard network priority
            Priority::High => 1.5,   // Premium traffic (50% premium)
            Priority::Urgent => 2.0, // Emergency traffic (100% premium)
        }
    }
    
    fn processing_order(&self) -> u8 {
        match self {
            Priority::Urgent => 0,
            Priority::High => 1,
            Priority::Normal => 2,
            Priority::Low => 3,
        }
    }
    
    fn description(&self) -> &'static str {
        match self {
            Priority::Low => "Background processing",
            Priority::Normal => "Standard priority",
            Priority::High => "Premium service",
            Priority::Urgent => "Emergency priority",
        }
    }
}

/// Extension trait for TransactionType with behavior
pub trait TransactionTypeExt {
    /// Check if this transaction type is fee-exempt
    fn is_fee_exempt(&self) -> bool;
    /// Check if this transaction type requires DAO fee
    fn requires_dao_fee(&self) -> bool;
    /// Get the base gas cost for this transaction type
    fn base_gas_cost(&self) -> u64;
    /// Get human-readable description
    fn description(&self) -> &'static str;
}

impl TransactionTypeExt for TransactionType {
    fn is_fee_exempt(&self) -> bool {
        matches!(self, 
            TransactionType::UbiDistribution | 
            TransactionType::WelfareDistribution
        )
    }
    
    fn requires_dao_fee(&self) -> bool {
        !self.is_fee_exempt() && !matches!(self, TransactionType::DaoFee)
    }
    
    fn base_gas_cost(&self) -> u64 {
        match self {
            TransactionType::Payment => 1000,
            TransactionType::Reward => 800,
            TransactionType::Stake | TransactionType::Unstake => 1200,
            TransactionType::NetworkFee | TransactionType::DaoFee => 500,
            TransactionType::Burn => 1500,
            TransactionType::UbiDistribution => 0, // Fee-free
            TransactionType::WelfareDistribution => 0, // Fee-free
            TransactionType::ProposalVote => 2000,
            TransactionType::ProposalExecution => 3000,
        }
    }
    
    fn description(&self) -> &'static str {
        match self {
            TransactionType::Reward => "Network service reward",
            TransactionType::Payment => "User payment",
            TransactionType::Stake => "Stake tokens",
            TransactionType::Unstake => "Unstake tokens",
            TransactionType::NetworkFee => "Network infrastructure fee",
            TransactionType::DaoFee => "DAO fee for UBI fund",
            TransactionType::Burn => "Token burn",
            TransactionType::UbiDistribution => "Universal Basic Income",
            TransactionType::WelfareDistribution => "Welfare service funding",
            TransactionType::ProposalVote => "DAO proposal vote",
            TransactionType::ProposalExecution => "DAO proposal execution",
        }
    }
}

/// Extension trait for TreasuryFund with behavior
pub trait TreasuryFundExt {
    /// Get fund description
    fn description(&self) -> &'static str;
    /// Get recommended allocation percentage for this fund
    fn recommended_allocation_percentage(&self) -> f64;
    /// Check if this fund requires governance approval for expenditure
    fn requires_governance_approval(&self) -> bool;
}

impl TreasuryFundExt for TreasuryFund {
    fn description(&self) -> &'static str {
        match self {
            TreasuryFund::Operations => "General operational expenses and maintenance",
            TreasuryFund::UbiDistribution => "Universal Basic Income distribution to verified users",
            TreasuryFund::Infrastructure => "Network infrastructure development and expansion",
            TreasuryFund::Governance => "DAO governance operations and proposal funding",
            TreasuryFund::Research => "Research and development initiatives",
            TreasuryFund::EmergencyReserve => "Emergency fund for critical situations",
            TreasuryFund::ValidatorRewards => "Validator and consensus participant rewards",
            TreasuryFund::IspBypassFund => "ISP Bypass service provider incentives",
            TreasuryFund::MeshDiscoveryFund => "Mesh network discovery and topology rewards",
            TreasuryFund::BridgeFund => "Cross-chain bridge operation funding",
            TreasuryFund::SmartContractFund => "Smart contract development incentives",
        }
    }

    fn recommended_allocation_percentage(&self) -> f64 {
        match self {
            TreasuryFund::Operations => 15.0,
            TreasuryFund::UbiDistribution => 30.0,
            TreasuryFund::Infrastructure => 20.0,
            TreasuryFund::Governance => 5.0,
            TreasuryFund::Research => 10.0,
            TreasuryFund::EmergencyReserve => 10.0,
            TreasuryFund::ValidatorRewards => 5.0,
            TreasuryFund::IspBypassFund => 2.0,
            TreasuryFund::MeshDiscoveryFund => 1.5,
            TreasuryFund::BridgeFund => 1.0,
            TreasuryFund::SmartContractFund => 0.5,
        }
    }

    fn requires_governance_approval(&self) -> bool {
        matches!(
            self,
            TreasuryFund::EmergencyReserve | 
            TreasuryFund::Research | 
            TreasuryFund::Infrastructure |
            TreasuryFund::Governance
        )
    }
}

/// Extension trait for WorkMetrics with behavior
pub trait WorkMetricsExt {
    /// Add routing work
    fn add_routing_work(&mut self, bytes: u64);
    /// Add storage work
    fn add_storage_work(&mut self, bytes: u64);
    /// Add compute work
    fn add_compute_work(&mut self, operations: u64);
    /// Update quality score
    fn update_quality_score(&mut self, score: f64);
    /// Add uptime hours
    fn add_uptime_hours(&mut self, hours: u64);
    /// Check if quality meets bonus threshold
    fn qualifies_for_quality_bonus(&self) -> bool;
    /// Check if uptime meets bonus threshold
    fn qualifies_for_uptime_bonus(&self) -> bool;
}

impl WorkMetricsExt for WorkMetrics {
    fn add_routing_work(&mut self, bytes: u64) {
        self.routing_work += bytes;
    }
    
    fn add_storage_work(&mut self, bytes: u64) {
        self.storage_work += bytes;
    }
    
    fn add_compute_work(&mut self, operations: u64) {
        self.compute_work += operations;
    }
    
    fn update_quality_score(&mut self, score: f64) {
        if score.is_nan() {
            self.quality_score = score;
        } else {
            self.quality_score = score.max(0.0).min(1.0);
        }
    }
    
    fn add_uptime_hours(&mut self, hours: u64) {
        self.uptime_hours += hours;
    }
    
    fn qualifies_for_quality_bonus(&self) -> bool {
        self.quality_score > crate::QUALITY_BONUS_THRESHOLD
    }
    
    fn qualifies_for_uptime_bonus(&self) -> bool {
        self.uptime_hours >= crate::UPTIME_BONUS_THRESHOLD
    }
}

/// Extension trait for IspBypassWork with behavior
pub trait IspBypassWorkExt {
    /// Add bandwidth sharing
    fn add_bandwidth_shared(&mut self, gb: u64);
    /// Add packet routing
    fn add_packets_routed(&mut self, mb: u64);
    /// Update connection quality
    fn update_connection_quality(&mut self, quality: f64);
    /// Add users served
    fn add_users_served(&mut self, count: u64);
    /// Add cost savings
    fn add_cost_savings(&mut self, usd_equivalent: u64);
    /// Calculate total ISP bypass value
    fn total_isp_bypass_value(&self) -> u64;
}

impl IspBypassWorkExt for IspBypassWork {
    fn add_bandwidth_shared(&mut self, gb: u64) {
        self.bandwidth_shared_gb += gb;
    }
    
    fn add_packets_routed(&mut self, mb: u64) {
        self.packets_routed_mb += mb;
    }
    
    fn update_connection_quality(&mut self, quality: f64) {
        self.connection_quality = quality.max(0.0).min(1.0);
    }
    
    fn add_users_served(&mut self, count: u64) {
        self.users_served += count;
    }
    
    fn add_cost_savings(&mut self, usd_equivalent: u64) {
        self.cost_savings_provided += usd_equivalent;
    }
    
    fn total_isp_bypass_value(&self) -> u64 {
        let bandwidth_reward = self.bandwidth_shared_gb * crate::ISP_BYPASS_CONNECTIVITY_RATE;
        let routing_reward = self.packets_routed_mb * crate::ISP_BYPASS_MESH_RATE;
        let uptime_bonus = self.uptime_hours * crate::ISP_BYPASS_UPTIME_BONUS;
        
        let base_reward = bandwidth_reward + routing_reward + uptime_bonus;
        
        if self.connection_quality > 0.9 {
            ((base_reward as f64) * 1.5) as u64
        } else {
            base_reward
        }
    }
}

/// Extension trait for NetworkStats with behavior
pub trait NetworkStatsExt {
    /// Update utilization percentage
    fn update_utilization(&mut self, utilization: f64);
    /// Update average quality
    fn update_avg_quality(&mut self, quality: f64);
    /// Set total nodes
    fn set_total_nodes(&mut self, nodes: u64);
    /// Add transactions
    fn add_transactions(&mut self, count: u64);
    /// Check if network is highly utilized
    fn is_high_utilization(&self) -> bool;
    /// Check if network is under-utilized
    fn is_low_utilization(&self) -> bool;
    /// Get recommended adjustment multiplier for rewards
    fn get_reward_adjustment_multiplier(&self) -> u64;
    /// Calculate network health score (0.0-1.0)
    fn network_health_score(&self) -> f64;
}

impl NetworkStatsExt for NetworkStats {
    fn update_utilization(&mut self, utilization: f64) {
        if utilization.is_nan() {
            self.utilization = utilization;
        } else if utilization.is_infinite() {
            if utilization.is_sign_positive() {
                self.utilization = 1.0;
            } else {
                self.utilization = 0.0;
            }
        } else {
            self.utilization = utilization.max(0.0).min(1.0);
        }
    }
    
    fn update_avg_quality(&mut self, quality: f64) {
        self.avg_quality = quality.max(0.0).min(1.0);
    }
    
    fn set_total_nodes(&mut self, nodes: u64) {
        self.total_nodes = nodes;
    }
    
    fn add_transactions(&mut self, count: u64) {
        self.total_transactions += count;
    }
    
    fn is_high_utilization(&self) -> bool {
        self.utilization > crate::HIGH_UTILIZATION_THRESHOLD
    }
    
    fn is_low_utilization(&self) -> bool {
        self.utilization < crate::LOW_UTILIZATION_THRESHOLD
    }
    
    fn get_reward_adjustment_multiplier(&self) -> u64 {
        if self.is_high_utilization() {
            crate::HIGH_UTILIZATION_ADJUSTMENT
        } else if self.is_low_utilization() {
            crate::LOW_UTILIZATION_ADJUSTMENT
        } else {
            100
        }
    }
    
    fn network_health_score(&self) -> f64 {
        if self.utilization.is_nan() || self.avg_quality.is_nan() {
            return 0.0;
        }
        
        let utilization_factor = if self.utilization > 0.8 {
            1.0 - (self.utilization - 0.8) / 0.2
        } else {
            self.utilization / 0.8
        };
        
        let quality_factor = self.avg_quality;
        let health = (utilization_factor + quality_factor) / 2.0;
        
        health.max(0.0).min(1.0)
    }
}

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
        assert_eq!(Priority::Urgent.processing_order(), 0);
        assert_eq!(Priority::High.processing_order(), 1);
        assert_eq!(Priority::Normal.processing_order(), 2);
        assert_eq!(Priority::Low.processing_order(), 3);
    }

    #[test]
    fn test_priority_descriptions() {
        assert_eq!(Priority::Low.description(), "Background processing");
        assert_eq!(Priority::Normal.description(), "Standard priority");
        assert_eq!(Priority::High.description(), "Premium service");
        assert_eq!(Priority::Urgent.description(), "Emergency priority");
    }

    #[test]
    fn test_transaction_type_fee_exemptions() {
        assert!(TransactionType::UbiDistribution.is_fee_exempt());
        assert!(TransactionType::WelfareDistribution.is_fee_exempt());
        
        assert!(!TransactionType::Payment.is_fee_exempt());
        assert!(!TransactionType::Reward.is_fee_exempt());
        assert!(!TransactionType::Stake.is_fee_exempt());
    }

    #[test]
    fn test_transaction_type_dao_fee_requirements() {
        assert!(TransactionType::Payment.requires_dao_fee());
        assert!(TransactionType::Reward.requires_dao_fee());
        assert!(TransactionType::Stake.requires_dao_fee());
        
        assert!(!TransactionType::UbiDistribution.requires_dao_fee());
        assert!(!TransactionType::WelfareDistribution.requires_dao_fee());
        assert!(!TransactionType::DaoFee.requires_dao_fee());
    }

    #[test]
    fn test_transaction_type_gas_costs() {
        assert_eq!(TransactionType::Payment.base_gas_cost(), 1000);
        assert_eq!(TransactionType::Reward.base_gas_cost(), 800);
        assert_eq!(TransactionType::Stake.base_gas_cost(), 1200);
        assert_eq!(TransactionType::Unstake.base_gas_cost(), 1200);
        assert_eq!(TransactionType::UbiDistribution.base_gas_cost(), 0);
        assert_eq!(TransactionType::WelfareDistribution.base_gas_cost(), 0);
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
        
        metrics.update_quality_score(0.94);
        assert!(!metrics.qualifies_for_quality_bonus());
        
        metrics.update_quality_score(0.96);
        assert!(metrics.qualifies_for_quality_bonus());
        
        metrics.add_uptime_hours(22);
        assert!(!metrics.qualifies_for_uptime_bonus());
        
        metrics.add_uptime_hours(2);
        assert!(metrics.qualifies_for_uptime_bonus());
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
    fn test_fund_allocation_percentages() {
        let total: f64 = [
            TreasuryFund::Operations,
            TreasuryFund::UbiDistribution,
            TreasuryFund::Infrastructure,
            TreasuryFund::Governance,
            TreasuryFund::Research,
            TreasuryFund::EmergencyReserve,
            TreasuryFund::ValidatorRewards,
            TreasuryFund::IspBypassFund,
            TreasuryFund::MeshDiscoveryFund,
            TreasuryFund::BridgeFund,
            TreasuryFund::SmartContractFund,
        ].iter().map(|fund| fund.recommended_allocation_percentage()).sum();
        
        assert!((total - 100.0).abs() < 0.1);
    }
}
