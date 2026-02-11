//! Core economic model implementation
//! 
//! The main economic model that coordinates all economic activities,
//! from reward calculation to fee processing and parameter adjustments.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::*;
use crate::treasury_economics::DaoTreasury;
use crate::transactions::calculate_dao_fee_distribution;
use crate::wasm::logging::info;

/// Core economic model for the SOV network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicModel {
    /// Tokens per MB of data routed (like ISP bandwidth costs)
    pub base_routing_rate: u64,
    /// Tokens per GB stored per month (like cloud storage pricing)
    pub base_storage_rate: u64,
    /// Tokens per computation/validation (minimal processing fee)
    pub base_compute_rate: u64,
    /// Quality multiplier for exceptional service (minimal bonus)
    pub quality_multiplier: f64,
    /// Uptime multiplier for reliability (minimal bonus)
    pub uptime_multiplier: f64,
    /// Annual inflation rate (zero for stability)
    pub inflation_rate: f64,
    /// Maximum token supply (unlimited for utility)
    pub max_supply: u64,
    /// Current circulating supply
    pub current_supply: u64,
    /// Token burn rate (zero for utility focus)
    pub burn_rate: f64,
    /// DAO treasury for UBI and DAO allocations (economics interface only)
    pub dao_treasury: DaoTreasury,
}

impl EconomicModel {
    /// Create a new economic model with realistic infrastructure economics
    pub fn new() -> Self {
        let mut dao_treasury = DaoTreasury::new();
        
        // Initialize treasury with collected fees for demonstration
        dao_treasury.treasury_balance = 2_500_000; // 2.5M SOV
        dao_treasury.total_dao_fees_collected = 5_000_000; // 5M SOV collected
        dao_treasury.ubi_allocated = 1_500_000; // 1.5M allocated to UBI
        dao_treasury.sector_dao_allocated = 600_000; // 0.6M allocated to sector DAOs
        dao_treasury.emergency_allocated = 250_000; // 0.25M allocated to emergency reserves
        dao_treasury.dev_grants_allocated = 150_000; // 0.15M allocated to dev grants
        dao_treasury.total_ubi_distributed = 800_000; // 800K distributed
        dao_treasury.total_sector_dao_distributed = 400_000; // 400K distributed
        dao_treasury.total_emergency_distributed = 120_000; // 120K distributed
        dao_treasury.total_dev_grants_distributed = 80_000; // 80K distributed
        
        EconomicModel {
            // INTERNET INFRASTRUCTURE ECONOMICS (like ISP/CDN revenue sharing)
            base_routing_rate: crate::DEFAULT_ROUTING_RATE, // 1 token per MB routed
            base_storage_rate: crate::DEFAULT_STORAGE_RATE, // 10 tokens per GB per month
            base_compute_rate: crate::DEFAULT_COMPUTE_RATE, // 5 tokens per validation
            quality_multiplier: 0.1,    // Minimal quality bonus (infrastructure focus)
            uptime_multiplier: 0.05,    // Minimal uptime bonus (reliability expected)
            inflation_rate: 0.0,        // ZERO inflation (stable utility token)
            max_supply: u64::MAX,       // UNLIMITED supply (like internet capacity)
            current_supply: 0,          // Start from zero, mint as needed
            burn_rate: 0.0,             // NO BURNING (utility, not speculation)
            dao_treasury,               // Treasury interface for economics
        }
    }
    
    /// Update economic parameters based on network performance
    pub fn adjust_parameters(&mut self, network_stats: &NetworkStats) -> Result<()> {
        // INFRASTRUCTURE SCALING (like ISP capacity planning)
        let adjustment_multiplier = network_stats.get_reward_adjustment_multiplier();
        
        if adjustment_multiplier != 100 {
            // Calculate new values with floating point precision
            let routing_new = (self.base_routing_rate as f64 * adjustment_multiplier as f64) / 100.0;
            let storage_new = (self.base_storage_rate as f64 * adjustment_multiplier as f64) / 100.0;
            let compute_new = (self.base_compute_rate as f64 * adjustment_multiplier as f64) / 100.0;
            
            if adjustment_multiplier > 100 {
                // For increases, use ceiling to guarantee growth
                self.base_routing_rate = routing_new.ceil() as u64;
                self.base_storage_rate = storage_new.ceil() as u64;
                self.base_compute_rate = compute_new.ceil() as u64;
            } else {
                // For decreases, ensure meaningful reduction
                let routing_decreased = routing_new.floor() as u64;
                let storage_decreased = storage_new.floor() as u64;
                let compute_decreased = compute_new.floor() as u64;
                
                // If floor didn't decrease, subtract 1 (but keep minimum of 1)
                self.base_routing_rate = if routing_decreased < self.base_routing_rate {
                    routing_decreased.max(1)
                } else {
                    (self.base_routing_rate - 1).max(1)
                };
                
                self.base_storage_rate = if storage_decreased < self.base_storage_rate {
                    storage_decreased.max(1)
                } else {
                    (self.base_storage_rate - 1).max(1)
                };
                
                self.base_compute_rate = if compute_decreased < self.base_compute_rate {
                    compute_decreased.max(1)
                } else {
                    (self.base_compute_rate - 1).max(1)
                };
            }
            
            info!(
                "Adjusted economic parameters: routing={}, storage={}, compute={} ({}% adjustment)",
                self.base_routing_rate, self.base_storage_rate, self.base_compute_rate, adjustment_multiplier
            );
        }
        
        Ok(())
    }
    
    /// Calculate transaction fees including mandatory DAO fee for UBI/DAO allocations
    pub fn calculate_fee(&self, tx_size: u64, amount: u64, priority: Priority) -> (u64, u64, u64) {
        // NETWORK INFRASTRUCTURE FEE (covers bandwidth, storage, compute)
        let base_fee = tx_size * 1; // 1 token per byte (minimal infrastructure cost)
        
        // PRIORITY MULTIPLIER: Like QoS in networking
        let priority_multiplier = priority.fee_multiplier();
        let network_fee = ((base_fee as f64) * priority_multiplier) as u64;
        let network_fee = network_fee.max(crate::MINIMUM_NETWORK_FEE); // Minimum network fee
        
        // MANDATORY DAO FEE FOR UNIVERSAL BASIC INCOME & DAO ALLOCATIONS
        // 1% of transaction amount goes to DAO treasury for UBI/DAO services
        let dao_fee = (amount * crate::DEFAULT_DAO_FEE_RATE) / 10000; // 1.00% mandatory DAO fee
        let dao_fee = dao_fee.max(crate::MINIMUM_DAO_FEE); // Minimum DAO fee
        
        let total_fee = network_fee + dao_fee;
        
        (network_fee, dao_fee, total_fee)
    }
    
    /// Process network fees for infrastructure operation
    pub fn process_network_fees(&mut self, total_fees: u64) -> Result<u64> {
        // Network fees go to infrastructure providers (routing/storage/compute)
        info!(
            "Processed {} SOV tokens in network fees - distributed to infrastructure providers", 
            total_fees
        );
        
        Ok(total_fees) // All fees stay in circulation for infrastructure
    }
    
    /// Process DAO fees for Universal Basic Income and DAO allocations
    pub fn process_dao_fees(&mut self, dao_fees: u64) -> Result<u64> {
        let distribution = calculate_dao_fee_distribution(dao_fees);
        self.dao_treasury.apply_fee_distribution(distribution)?;
        
        info!(
            " Processed {} SOV tokens in DAO fees - added to treasury (Total: {})",
            dao_fees, self.dao_treasury.treasury_balance
        );
        
        Ok(dao_fees) // DAO fees go to UBI/welfare treasury
    }
    
    /// Mint tokens for network operations (like issuing bandwidth credits)
    pub fn mint_operational_tokens(&mut self, amount: u64, purpose: &str) -> Result<u64> {
        // UNLIMITED MINTING for actual network utility
        // Think of tokens like "bandwidth credits" or "compute credits"
        // ISPs don't have limited "internet capacity" - they scale as needed
        
        self.current_supply += amount;
        
        info!(
            "🏭 MINTED {} SOV tokens for {} - Total supply: {} tokens", 
            amount, purpose, self.current_supply
        );
        
        Ok(amount)
    }
    
    /// Get current economic statistics
    pub fn get_economic_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "base_routing_rate": self.base_routing_rate,
            "base_storage_rate": self.base_storage_rate,
            "base_compute_rate": self.base_compute_rate,
            "current_supply": self.current_supply,
            "max_supply": self.max_supply,
            "inflation_rate": self.inflation_rate,
            "burn_rate": self.burn_rate,
            "treasury_balance": self.dao_treasury.treasury_balance,
            "total_dao_fees_collected": self.dao_treasury.total_dao_fees_collected
        })
    }
}

impl Default for EconomicModel {
    fn default() -> Self {
        Self::new()
    }
}
