//! DAO Treasury statistics and analytics system
//! 
//! Provides comprehensive treasury management, UBI distribution tracking,
//! and financial analytics for the economics system.
//!
//! Note: All pure data types are re-exported from lib-types::economy.
//! This module adds behavior through the TreasuryStatsManager.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::wasm::logging::info;
use crate::network_types::{get_mesh_status, get_network_statistics};
use crate::types::{
    TreasuryFund, TreasuryFundData, FundEfficiencyMetrics, UbiDistributionStats,
    TreasuryOperation, TreasuryHealthMetrics, TreasurySettings, UbiImpactMetrics,
};
use crate::types::TreasuryFundExt;

// Local stub functions to avoid circular dependencies with lib-consensus
async fn get_validator_stats() -> Result<ValidatorStats> {
    Ok(ValidatorStats {
        total_validators: 100,
        active_validators: 85,
        total_stake: 1_000_000_000,
        average_uptime: 0.98,
        uptime_percentage: 98.0,
    })
}

async fn get_current_epoch() -> Result<u64> {
    Ok(12345) // Placeholder epoch
}

async fn get_staking_rewards() -> Result<StakingRewards> {
    Ok(StakingRewards {
        total_rewards: 5_000_000,
        rewards_per_epoch: 50_000,
        apy: 8.5,
        total_distributed: 4_500_000,
    })
}

// Stub types for consensus data
#[derive(Debug, Clone)]
struct ValidatorStats {
    total_validators: u64,
    active_validators: u64,
    total_stake: u64,
    average_uptime: f64,
    uptime_percentage: f64,
}

#[derive(Debug, Clone)]
struct StakingRewards {
    total_rewards: u64,
    rewards_per_epoch: u64,
    apy: f64,
    total_distributed: u64,
}

/// Comprehensive DAO Treasury Statistics Manager
/// 
/// This struct adds behavior (methods) to the pure data types from lib-types.
/// All data fields use types re-exported from lib-types::economy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStatsManager {
    /// Total treasury balance across all funds
    pub total_treasury_balance: u64,
    /// Individual fund data
    pub fund_data: HashMap<TreasuryFund, TreasuryFundData>,
    /// UBI distribution statistics
    pub ubi_stats: UbiDistributionStats,
    /// Treasury operation history
    pub operations_history: Vec<TreasuryOperation>,
    /// Treasury health metrics
    pub health_metrics: TreasuryHealthMetrics,
    /// Last update timestamp
    pub last_updated: u64,
    /// Treasury configuration settings
    pub settings: TreasurySettings,
}

impl TreasuryStatsManager {
    /// Create new treasury statistics manager
    pub async fn new() -> Result<Self> {
        // Initialize with default values - blockchain integration will happen at higher level
        let total_treasury_balance = 0u64; // Default value, will be updated by integration layer

        // Initialize fund data with recommended allocations
        let mut fund_data = HashMap::new();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        for fund in [
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
        ] {
            let allocated_percentage = fund.recommended_allocation_percentage();
            let allocated_amount = (total_treasury_balance as f64 * allocated_percentage / 100.0) as u64;
            
            fund_data.insert(fund.clone(), TreasuryFundData {
                fund: fund.clone(),
                current_balance: allocated_amount,
                allocated_percentage,
                total_allocated: allocated_amount,
                total_spent: 0,
                pending_expenditures: 0,
                last_allocation: current_time,
                utilization_rate: 0.0,
                average_monthly_expenditure: 0.0,
                efficiency_metrics: FundEfficiencyMetrics::default(),
            });
        }

        // Initialize UBI statistics
        let ubi_stats = init_ubi_stats().await?;

        // Calculate initial health metrics
        let health_metrics = Self::calculate_health_metrics(&fund_data, total_treasury_balance);

        let manager = Self {
            total_treasury_balance,
            fund_data,
            ubi_stats,
            operations_history: Vec::new(),
            health_metrics,
            last_updated: current_time,
            settings: TreasurySettings::default(),
        };

        info!(
            " Treasury stats manager initialized with {} SOV across {} funds",
            total_treasury_balance, manager.fund_data.len()
        );

        Ok(manager)
    }

    /// Update treasury statistics with new data (blockchain integration handled externally)
    pub async fn update_treasury_balance(&mut self, new_total_balance: u64) -> Result<()> {
        // Update total treasury balance
        if new_total_balance != self.total_treasury_balance {
            info!(
                "Treasury balance updated: {} -> {} SOV",
                self.total_treasury_balance, new_total_balance
            );
            self.total_treasury_balance = new_total_balance;
        }

        // Update validator rewards data using all ValidatorStats fields
        if let Ok(validator_stats) = get_validator_stats().await {
            if let Some(validator_fund) = self.fund_data.get_mut(&TreasuryFund::ValidatorRewards) {
                // Use validator statistics to update fund metrics
                validator_fund.efficiency_metrics.project_success_rate = validator_stats.uptime_percentage;
                validator_fund.efficiency_metrics.roi_percentage = validator_stats.average_uptime * 100.0;
                
                // Calculate validator participation metrics
                let participation_rate = validator_stats.active_validators as f64 / validator_stats.total_validators as f64;
                validator_fund.efficiency_metrics.impact_score = participation_rate * 100.0;
                
                // Update fund utilization based on validator activity
                validator_fund.utilization_rate = participation_rate;
                
                // Estimate fund allocation needs based on total stake
                let recommended_allocation = (validator_stats.total_stake as f64 * 0.05) as u64; // 5% of total stake
                if recommended_allocation > validator_fund.current_balance {
                    validator_fund.pending_expenditures = recommended_allocation - validator_fund.current_balance;
                }
                
                info!(
                    "Validator fund updated: {}/{} active validators, {:.1}% uptime, {} total stake",
                    validator_stats.active_validators, validator_stats.total_validators, 
                    validator_stats.average_uptime * 100.0, validator_stats.total_stake
                );
            }
        }

        // Update staking rewards using all StakingRewards fields
        if let Ok(staking_rewards) = get_staking_rewards().await {
            if let Some(validator_fund) = self.fund_data.get_mut(&TreasuryFund::ValidatorRewards) {
                // Update spending based on actual distributions
                validator_fund.total_spent += staking_rewards.total_distributed;
                
                // Update efficiency metrics based on staking performance
                validator_fund.efficiency_metrics.roi_percentage = staking_rewards.apy;
                
                // Calculate average monthly expenditure from per-epoch rewards
                let epochs_per_month = 30; // Assuming daily epochs
                validator_fund.average_monthly_expenditure = (staking_rewards.rewards_per_epoch * epochs_per_month) as f64;
                
                // Update fund allocation if needed for future rewards
                let projected_monthly_need = validator_fund.average_monthly_expenditure;
                if (validator_fund.current_balance as f64) < projected_monthly_need * 3.0 { // 3 months runway
                    validator_fund.pending_expenditures += projected_monthly_need as u64;
                }
                
                info!(
                    "Staking rewards updated: {} total rewards, {} per epoch, {:.1}% APY",
                    staking_rewards.total_rewards, staking_rewards.rewards_per_epoch, staking_rewards.apy
                );
            }
        }

        // Update UBI statistics
        update_ubi_stats_from_blockchain(&mut self.ubi_stats).await?;

        // Recalculate health metrics
        self.health_metrics = Self::calculate_health_metrics(&self.fund_data, self.total_treasury_balance);

        // Update timestamp
        self.last_updated = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        Ok(())
    }

    /// Get comprehensive treasury analytics
    pub async fn get_treasury_analytics(&self) -> Result<serde_json::Value> {
        let network_stats = get_network_statistics().await.map_err(|e| anyhow::anyhow!("Network stats error: {}", e))?;
        let mesh_status = get_mesh_status().await.map_err(|e| anyhow::anyhow!("Mesh status error: {}", e))?;
        let current_epoch = get_current_epoch().await.map_err(|e| anyhow::anyhow!("Epoch error: {}", e))?;

        // Calculate fund summaries
        let fund_summaries: HashMap<String, serde_json::Value> = self.fund_data.iter().map(|(fund, data)| {
            (
                format!("{:?}", fund),
                serde_json::json!({
                    "current_balance": data.current_balance,
                    "allocated_percentage": data.allocated_percentage,
                    "total_spent": data.total_spent,
                    "utilization_rate": data.utilization_rate,
                    "efficiency_score": data.efficiency_metrics.impact_score,
                    "description": fund.description()
                })
            )
        }).collect();

        // Recent operations summary
        let recent_operations: Vec<serde_json::Value> = self.operations_history.iter()
            .rev()
            .take(10)
            .map(|op| serde_json::json!({
                "operation_type": format!("{:?}", op.operation_type),
                "fund": format!("{:?}", op.fund),
                "amount": op.amount,
                "timestamp": op.timestamp,
                "description": op.description
            }))
            .collect();

        Ok(serde_json::json!({
            "treasury_overview": {
                "total_balance": self.total_treasury_balance,
                "fund_count": self.fund_data.len(),
                "last_updated": self.last_updated,
                "current_epoch": current_epoch,
                "health_score": self.health_metrics.sustainability_index
            },
            "fund_allocation": fund_summaries,
            "ubi_distribution": {
                "active_recipients": self.ubi_stats.active_recipients,
                "monthly_distribution": self.ubi_stats.monthly_distribution,
                "total_distributed": self.ubi_stats.total_distributed,
                "distribution_efficiency": self.ubi_stats.distribution_efficiency
            },
            "health_metrics": {
                "monthly_burn_rate": self.health_metrics.monthly_burn_rate,
                "runway_months": self.health_metrics.runway_months,
                "emergency_fund_ratio": self.health_metrics.emergency_fund_ratio,
                "risk_score": self.health_metrics.risk_score
            },
            "recent_operations": recent_operations,
            "network_context": {
                "peer_count": mesh_status.active_nodes,
                "network_tps": network_stats.transactions_per_second,
                "total_transactions": network_stats.total_transactions
            }
        }))
    }

    /// Get UBI distribution report
    pub fn get_ubi_distribution_report(&self) -> Result<serde_json::Value> {
        let current_month = chrono::Utc::now().format("%Y-%m").to_string();
        let current_data = self.ubi_stats.distribution_timeline.get(&current_month);

        Ok(serde_json::json!({
            "current_status": {
                "active_recipients": self.ubi_stats.active_recipients,
                "monthly_distribution": self.ubi_stats.monthly_distribution,
                "average_per_recipient": self.ubi_stats.average_ubi_per_recipient,
                "distribution_efficiency": self.ubi_stats.distribution_efficiency
            },
            "current_month": current_data,
            "recipient_categories": self.ubi_stats.recipient_categories,
            "geographic_distribution": self.ubi_stats.geographic_distribution,
            "impact_metrics": self.ubi_stats.impact_metrics,
            "timeline": self.ubi_stats.distribution_timeline
        }))
    }

    // Private helper methods

    fn calculate_health_metrics(fund_data: &HashMap<TreasuryFund, TreasuryFundData>, total_balance: u64) -> TreasuryHealthMetrics {
        // Calculate monthly burn rate (simplified)
        let total_monthly_expenditure: f64 = fund_data.values()
            .map(|fund| fund.average_monthly_expenditure)
            .sum();

        let monthly_burn_rate = total_monthly_expenditure;
        let runway_months = if monthly_burn_rate > 0.0 {
            total_balance as f64 / monthly_burn_rate
        } else {
            f64::INFINITY
        };

        // Calculate emergency fund ratio
        let emergency_balance = fund_data.get(&TreasuryFund::EmergencyReserve)
            .map(|fund| fund.current_balance)
            .unwrap_or(0);
        let emergency_fund_ratio = emergency_balance as f64 / total_balance as f64;

        // Calculate diversification score (simplified)
        let active_funds = fund_data.values().filter(|fund| fund.current_balance > 0).count();
        let diversification_score = (active_funds as f64 / fund_data.len() as f64) * 100.0;

        // Calculate risk score (lower is better)
        let risk_score = if runway_months < 6.0 {
            100.0 - (runway_months * 10.0)
        } else {
            40.0 - (emergency_fund_ratio * 100.0)
        }.max(0.0).min(100.0);

        // Calculate sustainability index
        let sustainability_index = ((runway_months.min(12.0) / 12.0) * 0.4 +
                                  (emergency_fund_ratio * 10.0).min(1.0) * 0.3 +
                                  (diversification_score / 100.0) * 0.3) * 100.0;

        TreasuryHealthMetrics {
            monthly_burn_rate,
            runway_months,
            revenue_growth_rate: 0.0, // Would calculate from historical data
            diversification_score,
            risk_score,
            sustainability_index,
            emergency_fund_ratio,
        }
    }
}

// Helper function to initialize UBI stats
async fn init_ubi_stats() -> Result<UbiDistributionStats> {
    // In production, this would load from blockchain/database
    Ok(UbiDistributionStats {
        active_recipients: 0,
        total_distributed: 0,
        monthly_distribution: 0,
        average_ubi_per_recipient: 0.0,
        distribution_efficiency: 100.0,
        geographic_distribution: HashMap::new(),
        recipient_categories: HashMap::new(),
        distribution_timeline: BTreeMap::new(),
        impact_metrics: UbiImpactMetrics::default(),
    })
}

// Helper function to update UBI stats from blockchain
async fn update_ubi_stats_from_blockchain(_stats: &mut UbiDistributionStats) -> Result<()> {
    // In production, update from blockchain data
    Ok(())
}

// Note: All public items in this module are automatically re-exported by
// treasury_economics/mod.rs via `pub use treasury_stats::*`

/// Main public function for getting treasury statistics (maintaining compatibility)
pub async fn get_treasury_statistics() -> Result<serde_json::Value> {
    let manager = TreasuryStatsManager::new().await?;
    manager.get_treasury_analytics().await
}

/// Create treasury statistics manager
pub async fn create_treasury_stats_manager() -> Result<TreasuryStatsManager> {
    TreasuryStatsManager::new().await
}

/// Get current treasury health score
pub async fn get_treasury_health_score() -> Result<f64> {
    let manager = TreasuryStatsManager::new().await?;
    Ok(manager.health_metrics.sustainability_index)
}

/// Get UBI distribution statistics
pub async fn get_ubi_distribution_statistics() -> Result<serde_json::Value> {
    let manager = TreasuryStatsManager::new().await?;
    manager.get_ubi_distribution_report()
}

/// Get treasury fund breakdown
pub async fn get_treasury_fund_breakdown() -> Result<serde_json::Value> {
    let manager = TreasuryStatsManager::new().await?;
    
    let fund_breakdown: HashMap<String, serde_json::Value> = manager.fund_data.iter().map(|(fund, data)| {
        (
            format!("{:?}", fund),
            serde_json::json!({
                "current_balance": data.current_balance,
                "allocated_percentage": data.allocated_percentage,
                "total_allocated": data.total_allocated,
                "total_spent": data.total_spent,
                "utilization_rate": data.utilization_rate,
                "description": fund.description(),
                "requires_governance": fund.requires_governance_approval()
            })
        )
    }).collect();

    Ok(serde_json::json!({
        "total_treasury_balance": manager.total_treasury_balance,
        "fund_breakdown": fund_breakdown,
        "health_score": manager.health_metrics.sustainability_index,
        "last_updated": manager.last_updated
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_treasury_manager_creation() {
        let manager = TreasuryStatsManager::new().await.unwrap();

        // Treasury starts at 0, will be updated by integration layer
        assert_eq!(manager.total_treasury_balance, 0);
        assert!(!manager.fund_data.is_empty());
        assert_eq!(manager.operations_history.len(), 0);
    }

    #[tokio::test]
    async fn test_fund_allocation_percentages() {
        let total_percentage: f64 = [
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
        
        assert!((total_percentage - 100.0).abs() < 0.1); // Should sum to ~100%
    }

    #[tokio::test]
    async fn test_get_treasury_statistics() {
        let stats = get_treasury_statistics().await.unwrap();
        
        // Verify expected structure
        assert!(stats.get("treasury_overview").is_some());
        assert!(stats.get("fund_allocation").is_some());
        assert!(stats.get("ubi_distribution").is_some());
        assert!(stats.get("health_metrics").is_some());
    }

    #[tokio::test]
    async fn test_treasury_health_score() {
        let health_score = get_treasury_health_score().await.unwrap();
        
        assert!(health_score >= 0.0);
        assert!(health_score <= 100.0);
    }
}
