//! Total supply tracking and calculations for post-scarcity economics
//! 
//! Manages token supply calculations based on network utility rather than artificial scarcity.
//! In the SOV model, supply grows with network demand to maintain stable utility value.

use anyhow::Result;
use serde::{Serialize, Deserialize};

/// Supply metrics for post-scarcity economics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyMetrics {
    /// Current circulating supply
    pub circulating_supply: u64,
    /// Total supply ever minted
    pub total_minted: u64,
    /// Total supply ever burned (minimal in post-scarcity)
    pub total_burned: u64,
    /// Operational tokens minted (for infrastructure)
    pub operational_minted: u64,
    /// UBI tokens minted
    pub ubi_minted: u64,
    /// Infrastructure reward tokens minted
    pub infrastructure_minted: u64,
    /// Supply growth rate (utility-based)
    pub supply_growth_rate: f64,
}

impl SupplyMetrics {
    /// Create new supply metrics
    pub fn new() -> Self {
        SupplyMetrics {
            circulating_supply: 0,
            total_minted: 0,
            total_burned: 0,
            operational_minted: 0,
            ubi_minted: 0,
            infrastructure_minted: 0,
            supply_growth_rate: 0.0,
        }
    }
    
    /// Record token minting for specific purpose
    pub fn record_minting(&mut self, amount: u64, purpose: MintingPurpose) -> Result<()> {
        self.total_minted += amount;
        self.circulating_supply += amount;
        
        match purpose {
            MintingPurpose::Operational => self.operational_minted += amount,
            MintingPurpose::UBI => self.ubi_minted += amount,
            MintingPurpose::Infrastructure => self.infrastructure_minted += amount,
        }
        
        Ok(())
    }
    
    /// Record token burning (rare in post-scarcity model)
    pub fn record_burning(&mut self, amount: u64) -> Result<()> {
        if amount > self.circulating_supply {
            return Err(anyhow::anyhow!("Cannot burn more than circulating supply"));
        }
        
        self.total_burned += amount;
        self.circulating_supply -= amount;
        
        Ok(())
    }
    
    /// Calculate supply growth rate based on utility demand
    pub fn calculate_growth_rate(&mut self, network_utilization: f64, demand_factor: f64) -> f64 {
        // Growth rate increases with network utilization and demand
        // Post-scarcity: unlimited growth for actual utility
        let base_growth = network_utilization * 0.02; // 2% max base growth
        let demand_adjustment = demand_factor * 0.05; // 5% max demand adjustment
        
        self.supply_growth_rate = (base_growth + demand_adjustment).min(0.10); // Cap at 10% growth
        self.supply_growth_rate
    }
    
    /// Get supply statistics
    pub fn get_stats(&self) -> serde_json::Value {
        let burn_rate = if self.total_minted > 0 {
            (self.total_burned as f64 / self.total_minted as f64) * 100.0
        } else {
            0.0
        };
        
        serde_json::json!({
            "circulating_supply": self.circulating_supply,
            "total_minted": self.total_minted,
            "total_burned": self.total_burned,
            "operational_minted": self.operational_minted,
            "ubi_minted": self.ubi_minted,
            "infrastructure_minted": self.infrastructure_minted,
            "supply_growth_rate": self.supply_growth_rate,
            "burn_rate_percent": burn_rate,
            "net_supply": self.total_minted - self.total_burned
        })
    }
}

/// Purposes for token minting
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MintingPurpose {
    /// Operational tokens for network services
    Operational,
    /// UBI distribution tokens
    UBI,
    /// Infrastructure reward tokens
    Infrastructure,
}

/// Calculate total supply metrics for post-scarcity economics
pub fn calculate_total_supply_with_metrics(
    current_metrics: &SupplyMetrics,
    network_utilization: f64,
    monthly_transaction_volume: u64,
) -> SupplyMetrics {
    let mut updated_metrics = current_metrics.clone();
    
    // In post-scarcity model, supply adapts to demand
    let demand_factor = (monthly_transaction_volume as f64) / 1_000_000.0; // Normalize to millions
    updated_metrics.calculate_growth_rate(network_utilization, demand_factor);
    
    updated_metrics
}

/// Get supply growth rate based on network usage (post-scarcity model)
pub fn get_supply_growth_rate(network_utilization: f64, infrastructure_demand: f64) -> f64 {
    // Higher utilization and infrastructure demand = higher growth rate
    // This is GOOD in post-scarcity - more utility = more tokens for that utility
    let base_rate = network_utilization * 0.05; // 5% max from utilization
    let infrastructure_rate = infrastructure_demand * 0.03; // 3% max from infrastructure
    
    (base_rate + infrastructure_rate).min(0.15) // Cap at 15% annual growth
}

/// Calculate inflation rate for post-scarcity model
pub fn calculate_inflation_rate(current_supply: u64, minted_tokens: u64, time_period_days: u64) -> f64 {
    if current_supply == 0 || time_period_days == 0 {
        return 0.0;
    }
    
    // Annualized inflation rate
    let period_inflation = minted_tokens as f64 / current_supply as f64;
    let annual_multiplier = 365.0 / time_period_days as f64;
    
    period_inflation * annual_multiplier
}

/// Calculate optimal supply for network utility
pub fn calculate_optimal_supply_for_utility(
    daily_transaction_volume: u64,
    average_transaction_size: u64,
    infrastructure_participants: u64,
) -> u64 {
    // Calculate supply needed to maintain smooth economic operations
    let daily_transaction_value = daily_transaction_volume * average_transaction_size;
    let monthly_transaction_value = daily_transaction_value * 30;
    
    // Infrastructure rewards (assume 10% of transaction value goes to infrastructure)
    let monthly_infrastructure_rewards = monthly_transaction_value / 10;
    
    // UBI requirements (assume 1000 tokens per person per month)
    let monthly_ubi_requirement = infrastructure_participants * 1000;
    
    // Total monthly supply needed
    let monthly_supply_needed = monthly_transaction_value + monthly_infrastructure_rewards + monthly_ubi_requirement;
    
    // Recommend 6 months of supply for stability
    monthly_supply_needed * 6
}

/// Get current supply statistics
pub fn get_current_supply_stats(metrics: &SupplyMetrics, target_supply: u64) -> serde_json::Value {
    let supply_ratio = if target_supply > 0 {
        (metrics.circulating_supply as f64 / target_supply as f64) * 100.0
    } else {
        0.0
    };
    
    let minting_breakdown = serde_json::json!({
        "operational_percent": if metrics.total_minted > 0 { (metrics.operational_minted as f64 / metrics.total_minted as f64) * 100.0 } else { 0.0 },
        "ubi_percent": if metrics.total_minted > 0 { (metrics.ubi_minted as f64 / metrics.total_minted as f64) * 100.0 } else { 0.0 },
        "infrastructure_percent": if metrics.total_minted > 0 { (metrics.infrastructure_minted as f64 / metrics.total_minted as f64) * 100.0 } else { 0.0 }
    });
    
    serde_json::json!({
        "current_supply": metrics.circulating_supply,
        "target_supply": target_supply,
        "supply_ratio_percent": supply_ratio,
        "growth_rate": metrics.supply_growth_rate,
        "total_minted": metrics.total_minted,
        "total_burned": metrics.total_burned,
        "minting_breakdown": minting_breakdown,
        "supply_status": if supply_ratio >= 80.0 { "adequate" } else if supply_ratio >= 50.0 { "moderate" } else { "low" }
    })
}

impl Default for SupplyMetrics {
    fn default() -> Self {
        Self::new()
    }
}
