//! DAO Treasury for managing UBI and DAO allocations (economics interface only)
//! 
//! This is the economics calculation interface for treasury operations.
//! The actual DAO governance logic is centralized in lib-consensus package.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::transactions::DaoFeeDistribution;
use crate::wasm::logging::info;

/// DAO Treasury for managing UBI and DAO allocations (economics interface only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoTreasury {
    /// Current treasury balance
    pub treasury_balance: u64,
    /// Amount allocated for UBI distribution
    pub ubi_allocated: u64,
    /// Amount allocated for sector DAOs
    pub sector_dao_allocated: u64,
    /// Amount allocated for emergency reserves
    pub emergency_allocated: u64,
    /// Amount allocated for development grants
    pub dev_grants_allocated: u64,
    /// Total DAO fees collected (for accounting)
    pub total_dao_fees_collected: u64,
    /// Total UBI distributed (for accounting)
    pub total_ubi_distributed: u64,
    /// Total sector DAO distributions (for accounting)
    pub total_sector_dao_distributed: u64,
    /// Total emergency reserve distributions (for accounting)
    pub total_emergency_distributed: u64,
    /// Total development grant distributions (for accounting)
    pub total_dev_grants_distributed: u64,
    /// Last UBI distribution timestamp
    pub last_ubi_distribution: u64,
    /// Last sector DAO distribution timestamp
    pub last_sector_dao_distribution: u64,
    /// Last emergency reserve distribution timestamp
    pub last_emergency_distribution: u64,
    /// Last development grant distribution timestamp
    pub last_dev_grants_distribution: u64,
}

impl DaoTreasury {
    /// Create a new DAO treasury (economics interface only)
    pub fn new() -> Self {
        DaoTreasury {
            treasury_balance: 0,
            ubi_allocated: 0,
            sector_dao_allocated: 0,
            emergency_allocated: 0,
            dev_grants_allocated: 0,
            total_dao_fees_collected: 0,
            total_ubi_distributed: 0,
            total_sector_dao_distributed: 0,
            total_emergency_distributed: 0,
            total_dev_grants_distributed: 0,
            last_ubi_distribution: 0,
            last_sector_dao_distribution: 0,
            last_emergency_distribution: 0,
            last_dev_grants_distribution: 0,
        }
    }

    /// Apply DAO fee distribution to treasury (economics calculation only)
    pub fn apply_fee_distribution(&mut self, distribution: DaoFeeDistribution) -> Result<()> {
        let total = distribution.total();

        self.treasury_balance = self.treasury_balance.saturating_add(total);
        self.total_dao_fees_collected = self.total_dao_fees_collected.saturating_add(total);

        self.ubi_allocated = self.ubi_allocated.saturating_add(distribution.ubi);
        self.sector_dao_allocated = self.sector_dao_allocated.saturating_add(distribution.sector_daos);
        self.emergency_allocated = self.emergency_allocated.saturating_add(distribution.emergency_reserve);
        self.dev_grants_allocated = self.dev_grants_allocated.saturating_add(distribution.dev_grants);

        self.assert_accounting_invariant();

        info!(
            " Added {} ZHTP to DAO treasury - UBI: +{}, Sector DAOs: +{}, Emergency: +{}, Dev Grants: +{}, Total: {}",
            total,
            distribution.ubi,
            distribution.sector_daos,
            distribution.emergency_reserve,
            distribution.dev_grants,
            self.treasury_balance
        );

        Ok(())
    }

    /// Get current treasury stats for economic reporting
    pub fn get_treasury_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "treasury_balance": self.treasury_balance,
            "total_dao_fees_collected": self.total_dao_fees_collected,
            "total_ubi_distributed": self.total_ubi_distributed,
            "total_sector_dao_distributed": self.total_sector_dao_distributed,
            "total_emergency_distributed": self.total_emergency_distributed,
            "total_dev_grants_distributed": self.total_dev_grants_distributed,
            "ubi_allocated": self.ubi_allocated,
            "sector_dao_allocated": self.sector_dao_allocated,
            "emergency_allocated": self.emergency_allocated,
            "dev_grants_allocated": self.dev_grants_allocated,
            "last_ubi_distribution": self.last_ubi_distribution,
            "last_sector_dao_distribution": self.last_sector_dao_distribution,
            "last_emergency_distribution": self.last_emergency_distribution,
            "last_dev_grants_distribution": self.last_dev_grants_distribution,
            "allocation_percentages": {
                "ubi_percentage": crate::UBI_ALLOCATION_PERCENTAGE,
                "sector_dao_percentage": crate::DAO_ALLOCATION_PERCENTAGE,
                "emergency_percentage": crate::EMERGENCY_ALLOCATION_PERCENTAGE,
                "dev_grants_percentage": crate::DEV_GRANT_ALLOCATION_PERCENTAGE
            }
        })
    }
    
    /// Calculate UBI distribution amount per citizen
    pub fn calculate_ubi_per_citizen(&self, total_citizens: u64) -> u64 {
        if total_citizens > 0 && self.ubi_allocated > 0 {
            self.ubi_allocated / total_citizens
        } else {
            0
        }
    }
    
    /// Calculate sector DAO funding available
    pub fn calculate_sector_dao_funding_available(&self) -> u64 {
        self.sector_dao_allocated
    }

    /// Calculate emergency reserve funding available
    pub fn calculate_emergency_funding_available(&self) -> u64 {
        self.emergency_allocated
    }

    /// Calculate development grants funding available
    pub fn calculate_dev_grants_funding_available(&self) -> u64 {
        self.dev_grants_allocated
    }
    
    /// Record UBI distribution (for accounting)
    pub fn record_ubi_distribution(&mut self, amount: u64, timestamp: u64) -> Result<()> {
        if amount > self.ubi_allocated {
            return Err(anyhow::anyhow!("UBI distribution exceeds allocated amount"));
        }
        
        self.ubi_allocated -= amount;
        self.total_ubi_distributed += amount;
        self.treasury_balance -= amount;
        self.last_ubi_distribution = timestamp;
        self.assert_accounting_invariant();
        
        info!(
            "Recorded UBI distribution: {} ZHTP to citizens, remaining allocated: {}",
            amount, self.ubi_allocated
        );
        
        Ok(())
    }
    
    /// Record sector DAO distribution (for accounting)
    pub fn record_sector_dao_distribution(&mut self, amount: u64, timestamp: u64) -> Result<()> {
        if amount > self.sector_dao_allocated {
            return Err(anyhow::anyhow!("Sector DAO distribution exceeds allocated amount"));
        }

        self.sector_dao_allocated -= amount;
        self.total_sector_dao_distributed += amount;
        self.treasury_balance -= amount;
        self.last_sector_dao_distribution = timestamp;
        self.assert_accounting_invariant();

        info!(
            " Recorded sector DAO distribution: {} ZHTP, remaining allocated: {}",
            amount, self.sector_dao_allocated
        );

        Ok(())
    }

    /// Record emergency reserve distribution (for accounting)
    pub fn record_emergency_distribution(&mut self, amount: u64, timestamp: u64) -> Result<()> {
        if amount > self.emergency_allocated {
            return Err(anyhow::anyhow!("Emergency distribution exceeds allocated amount"));
        }

        self.emergency_allocated -= amount;
        self.total_emergency_distributed += amount;
        self.treasury_balance -= amount;
        self.last_emergency_distribution = timestamp;
        self.assert_accounting_invariant();

        info!(
            " Recorded emergency distribution: {} ZHTP, remaining allocated: {}",
            amount, self.emergency_allocated
        );

        Ok(())
    }

    /// Record development grant distribution (for accounting)
    pub fn record_dev_grants_distribution(&mut self, amount: u64, timestamp: u64) -> Result<()> {
        if amount > self.dev_grants_allocated {
            return Err(anyhow::anyhow!("Dev grant distribution exceeds allocated amount"));
        }

        self.dev_grants_allocated -= amount;
        self.total_dev_grants_distributed += amount;
        self.treasury_balance -= amount;
        self.last_dev_grants_distribution = timestamp;
        self.assert_accounting_invariant();

        info!(
            " Recorded dev grants distribution: {} ZHTP, remaining allocated: {}",
            amount, self.dev_grants_allocated
        );

        Ok(())
    }
    
    /// Get allocation efficiency metrics
    pub fn get_allocation_efficiency(&self) -> serde_json::Value {
        let ubi_efficiency = if self.total_dao_fees_collected > 0 {
            (self.total_ubi_distributed as f64 / self.total_dao_fees_collected as f64) * 100.0
        } else {
            0.0
        };
        
        let sector_dao_efficiency = if self.total_dao_fees_collected > 0 {
            (self.total_sector_dao_distributed as f64 / self.total_dao_fees_collected as f64) * 100.0
        } else {
            0.0
        };

        let emergency_efficiency = if self.total_dao_fees_collected > 0 {
            (self.total_emergency_distributed as f64 / self.total_dao_fees_collected as f64) * 100.0
        } else {
            0.0
        };

        let dev_grants_efficiency = if self.total_dao_fees_collected > 0 {
            (self.total_dev_grants_distributed as f64 / self.total_dao_fees_collected as f64) * 100.0
        } else {
            0.0
        };
        
        serde_json::json!({
            "ubi_distribution_efficiency": ubi_efficiency,
            "sector_dao_distribution_efficiency": sector_dao_efficiency,
            "emergency_distribution_efficiency": emergency_efficiency,
            "dev_grants_distribution_efficiency": dev_grants_efficiency,
            "total_distribution_efficiency": ubi_efficiency + sector_dao_efficiency + emergency_efficiency + dev_grants_efficiency,
            "funds_pending_distribution": self.total_allocated(),
            "distribution_lag": {
                "ubi_allocated_not_distributed": self.ubi_allocated,
                "sector_dao_allocated_not_distributed": self.sector_dao_allocated,
                "emergency_allocated_not_distributed": self.emergency_allocated,
                "dev_grants_allocated_not_distributed": self.dev_grants_allocated
            }
        })
    }

    fn total_allocated(&self) -> u64 {
        self.ubi_allocated
            .saturating_add(self.sector_dao_allocated)
            .saturating_add(self.emergency_allocated)
            .saturating_add(self.dev_grants_allocated)
    }

    fn assert_accounting_invariant(&self) {
        assert_eq!(
            self.total_allocated(),
            self.treasury_balance,
            "Treasury accounting invariant violated"
        );
    }
}

impl Default for DaoTreasury {
    fn default() -> Self {
        Self::new()
    }
}
