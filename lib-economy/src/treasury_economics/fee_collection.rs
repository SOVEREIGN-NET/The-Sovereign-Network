//! DAO Treasury for managing UBI and welfare funds (economics interface only)
//! 
//! This is the economics calculation interface for treasury operations.
//! The actual DAO governance logic is centralized in lib-consensus package.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::wasm::logging::info;

/// DAO Treasury for managing UBI and welfare funds (economics interface only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoTreasury {
    /// Current treasury balance
    pub treasury_balance: u64,
    /// Amount allocated for UBI distribution
    pub ubi_allocated: u64,
    /// Amount allocated for welfare services
    pub welfare_allocated: u64,
    /// Total DAO fees collected (for accounting)
    pub total_dao_fees_collected: u64,
    /// Total UBI distributed (for accounting)
    pub total_ubi_distributed: u64,
    /// Total welfare distributed (for accounting)
    pub total_welfare_distributed: u64,
    /// Last UBI distribution timestamp
    pub last_ubi_distribution: u64,
    /// Last welfare distribution timestamp
    pub last_welfare_distribution: u64,
}

impl DaoTreasury {
    /// Create a new DAO treasury (economics interface only)
    pub fn new() -> Self {
        DaoTreasury {
            treasury_balance: 0,
            ubi_allocated: 0,
            welfare_allocated: 0,
            total_dao_fees_collected: 0,
            total_ubi_distributed: 0,
            total_welfare_distributed: 0,
            last_ubi_distribution: 0,
            last_welfare_distribution: 0,
        }
    }

    /// Add DAO fees to treasury (economics calculation only)
    pub fn add_dao_fees(&mut self, amount: u64) -> Result<()> {
        self.treasury_balance = self.treasury_balance.saturating_add(amount);
        self.total_dao_fees_collected = self.total_dao_fees_collected.saturating_add(amount);
        
        // Automatically allocate percentages (economic calculation) with overflow protection
        let ubi_allocation = amount.saturating_mul(crate::UBI_ALLOCATION_PERCENTAGE) / 100; // 60% to UBI
        let welfare_allocation = amount.saturating_mul(crate::WELFARE_ALLOCATION_PERCENTAGE) / 100; // 40% to welfare
        
        self.ubi_allocated = self.ubi_allocated.saturating_add(ubi_allocation);
        self.welfare_allocated = self.welfare_allocated.saturating_add(welfare_allocation);
        
        info!(
            " Added {} ZHTP to DAO treasury - UBI: +{}, Welfare: +{}, Total: {}",
            amount, ubi_allocation, welfare_allocation, self.treasury_balance
        );
        
        Ok(())
    }

    /// Get current treasury stats for economic reporting
    pub fn get_treasury_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "treasury_balance": self.treasury_balance,
            "total_dao_fees_collected": self.total_dao_fees_collected,
            "total_ubi_distributed": self.total_ubi_distributed,
            "total_welfare_distributed": self.total_welfare_distributed,
            "ubi_allocated": self.ubi_allocated,
            "welfare_allocated": self.welfare_allocated,
            "last_ubi_distribution": self.last_ubi_distribution,
            "last_welfare_distribution": self.last_welfare_distribution,
            "allocation_percentages": {
                "ubi_percentage": crate::UBI_ALLOCATION_PERCENTAGE,
                "welfare_percentage": crate::WELFARE_ALLOCATION_PERCENTAGE
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
    
    /// Calculate welfare funding available
    pub fn calculate_welfare_funding_available(&self) -> u64 {
        self.welfare_allocated
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
        
        info!(
            "Recorded UBI distribution: {} ZHTP to citizens, remaining allocated: {}",
            amount, self.ubi_allocated
        );
        
        Ok(())
    }
    
    /// Record welfare distribution (for accounting)
    pub fn record_welfare_distribution(&mut self, amount: u64, timestamp: u64) -> Result<()> {
        if amount > self.welfare_allocated {
            return Err(anyhow::anyhow!("Welfare distribution exceeds allocated amount"));
        }
        
        self.welfare_allocated -= amount;
        self.total_welfare_distributed += amount;
        self.treasury_balance -= amount;
        self.last_welfare_distribution = timestamp;
        
        info!(
            "🏥 Recorded welfare distribution: {} ZHTP to services, remaining allocated: {}",
            amount, self.welfare_allocated
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
        
        let welfare_efficiency = if self.total_dao_fees_collected > 0 {
            (self.total_welfare_distributed as f64 / self.total_dao_fees_collected as f64) * 100.0
        } else {
            0.0
        };
        
        serde_json::json!({
            "ubi_distribution_efficiency": ubi_efficiency,
            "welfare_distribution_efficiency": welfare_efficiency,
            "total_distribution_efficiency": ubi_efficiency + welfare_efficiency,
            "funds_pending_distribution": self.ubi_allocated + self.welfare_allocated,
            "distribution_lag": {
                "ubi_allocated_not_distributed": self.ubi_allocated,
                "welfare_allocated_not_distributed": self.welfare_allocated
            }
        })
    }
}

impl Default for DaoTreasury {
    fn default() -> Self {
        Self::new()
    }
}
