//! Staking system for infrastructure investment rewards
//! 
//! Provides staking mechanisms for users to invest in network infrastructure
//! and earn yields based on network activity and infrastructure quality.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::wasm::logging::info;

/// Staking pool for infrastructure investment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingPool {
    /// Total tokens staked in the pool
    pub total_staked: u64,
    /// Daily yield rate (in basis points, 10000 = 100%)
    pub daily_yield_rate: u64,
    /// Minimum staking amount
    pub minimum_stake: u64,
    /// Lock period in days
    pub lock_period_days: u64,
    /// Pool creation timestamp
    pub created_at: u64,
    /// Last yield calculation timestamp
    pub last_yield_calculation: u64,
}

impl StakingPool {
    /// Create a new staking pool
    pub fn new(daily_yield_rate: u64, minimum_stake: u64, lock_period_days: u64) -> Self {
        let timestamp = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        
        StakingPool {
            total_staked: 0,
            daily_yield_rate,
            minimum_stake,
            lock_period_days,
            created_at: timestamp,
            last_yield_calculation: timestamp,
        }
    }
    
    /// Add stake to the pool
    pub fn add_stake(&mut self, amount: u64) -> Result<()> {
        if amount < self.minimum_stake {
            return Err(anyhow::anyhow!("Stake amount below minimum: {}", self.minimum_stake));
        }
        
        self.total_staked += amount;
        
        info!(
            "🏦 Added {} ZHTP to staking pool - Total staked: {}",
            amount, self.total_staked
        );
        
        Ok(())
    }
    
    /// Remove stake from the pool
    pub fn remove_stake(&mut self, amount: u64) -> Result<()> {
        if amount > self.total_staked {
            return Err(anyhow::anyhow!("Insufficient staked amount"));
        }
        
        self.total_staked -= amount;
        
        info!(
            "🏦 Removed {} ZHTP from staking pool - Total staked: {}",
            amount, self.total_staked
        );
        
        Ok(())
    }
    
    /// Calculate yield for a given stake amount and time period
    pub fn calculate_yield(&self, stake_amount: u64, days: u64) -> u64 {
        let daily_yield = (stake_amount * self.daily_yield_rate) / 10000;
        daily_yield * days
    }
    
    /// Get pool statistics
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_staked": self.total_staked,
            "daily_yield_rate": self.daily_yield_rate,
            "minimum_stake": self.minimum_stake,
            "lock_period_days": self.lock_period_days,
            "annual_yield_rate": self.daily_yield_rate * 365,
            "pool_age_days": (crate::wasm::compatibility::current_timestamp().unwrap_or(0) - self.created_at) / 86400
        })
    }
}

/// Individual staking position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingPosition {
    /// User's wallet address
    pub wallet_address: [u8; 32],
    /// Amount staked
    pub staked_amount: u64,
    /// Staking start timestamp
    pub stake_start: u64,
    /// Lock period end timestamp  
    pub lock_end: u64,
    /// Accumulated yield earned
    pub yield_earned: u64,
    /// Last yield calculation timestamp
    pub last_yield_claim: u64,
}

impl StakingPosition {
    /// Create a new staking position
    pub fn new(wallet_address: [u8; 32], amount: u64, lock_period_days: u64) -> Self {
        let timestamp = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        let lock_end = timestamp + (lock_period_days * 86400); // Convert days to seconds
        
        StakingPosition {
            wallet_address,
            staked_amount: amount,
            stake_start: timestamp,
            lock_end,
            yield_earned: 0,
            last_yield_claim: timestamp,
        }
    }
    
    /// Check if the staking period is complete
    pub fn is_unlocked(&self) -> bool {
        let current_time = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        current_time >= self.lock_end
    }
    
    /// Calculate pending yield
    pub fn calculate_pending_yield(&self, daily_yield_rate: u64) -> u64 {
        let current_time = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        let days_since_last_claim = (current_time - self.last_yield_claim) / 86400;
        
        if days_since_last_claim > 0 {
            let daily_yield = (self.staked_amount * daily_yield_rate) / 10000;
            daily_yield * days_since_last_claim
        } else {
            0
        }
    }
    
    /// Claim accumulated yield
    pub fn claim_yield(&mut self, daily_yield_rate: u64) -> Result<u64> {
        let pending_yield = self.calculate_pending_yield(daily_yield_rate);
        
        if pending_yield > 0 {
            self.yield_earned += pending_yield;
            self.last_yield_claim = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
            
            info!(
                "Claimed {} SOV yield for staking position - Total earned: {}",
                pending_yield, self.yield_earned
            );
        }
        
        Ok(pending_yield)
    }
    
    /// Get staking position summary
    pub fn get_summary(&self) -> serde_json::Value {
        let current_time = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        let days_staked = (current_time - self.stake_start) / 86400;
        let days_remaining = if self.lock_end > current_time {
            (self.lock_end - current_time) / 86400
        } else {
            0
        };
        
        serde_json::json!({
            "wallet_address": hex::encode(self.wallet_address),
            "staked_amount": self.staked_amount,
            "yield_earned": self.yield_earned,
            "days_staked": days_staked,
            "days_remaining": days_remaining,
            "is_unlocked": self.is_unlocked(),
            "stake_start": self.stake_start,
            "lock_end": self.lock_end
        })
    }
}

/// Infrastructure staking system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureStaking {
    /// Large infrastructure staking pool (100K+ ZHTP)
    pub large_infrastructure_pool: StakingPool,
    /// Small infrastructure staking pool (<100K ZHTP)
    pub small_infrastructure_pool: StakingPool,
    /// All active staking positions
    pub positions: Vec<StakingPosition>,
}

impl InfrastructureStaking {
    /// Create new infrastructure staking system
    pub fn new() -> Self {
        InfrastructureStaking {
            large_infrastructure_pool: StakingPool::new(
                crate::LARGE_INFRASTRUCTURE_DAILY_YIELD,  // 0.01% daily
                crate::LARGE_INFRASTRUCTURE_THRESHOLD,    // 100K ZHTP minimum
                365,                                      // 1 year lock
            ),
            small_infrastructure_pool: StakingPool::new(
                crate::SMALL_INFRASTRUCTURE_DAILY_YIELD,  // 0.02% daily  
                1000,                                     // 1K ZHTP minimum
                90,                                       // 3 months lock
            ),
            positions: Vec::new(),
        }
    }
    
    /// Stake tokens in appropriate pool
    pub fn stake_tokens(&mut self, wallet_address: [u8; 32], amount: u64) -> Result<()> {
        // Determine appropriate pool
        let (pool, lock_period) = if amount >= crate::LARGE_INFRASTRUCTURE_THRESHOLD {
            (&mut self.large_infrastructure_pool, 365)
        } else {
            (&mut self.small_infrastructure_pool, 90)
        };
        
        // Add to pool
        pool.add_stake(amount)?;
        
        // Create position
        let position = StakingPosition::new(wallet_address, amount, lock_period);
        self.positions.push(position);
        
        info!(
            "Staked {} ZHTP from wallet {} in {} infrastructure pool",
            amount,
            hex::encode(wallet_address),
            if amount >= crate::LARGE_INFRASTRUCTURE_THRESHOLD { "large" } else { "small" }
        );
        
        Ok(())
    }
    
    /// Unstake tokens from a position
    pub fn unstake_tokens(&mut self, wallet_address: [u8; 32], amount: u64) -> Result<()> {
        // Find position
        let position_index = self.positions.iter().position(|p| 
            p.wallet_address == wallet_address && p.staked_amount >= amount
        ).ok_or_else(|| anyhow::anyhow!("Staking position not found"))?;
        
        let position = &self.positions[position_index];
        
        if !position.is_unlocked() {
            return Err(anyhow::anyhow!("Staking position is still locked"));
        }
        
        // Determine which pool to remove from
        let pool = if position.staked_amount >= crate::LARGE_INFRASTRUCTURE_THRESHOLD {
            &mut self.large_infrastructure_pool
        } else {
            &mut self.small_infrastructure_pool
        };
        
        // Remove from pool
        pool.remove_stake(amount)?;
        
        // Update or remove position
        if self.positions[position_index].staked_amount == amount {
            self.positions.remove(position_index);
        } else {
            self.positions[position_index].staked_amount -= amount;
        }
        
        info!(
            "Unstaked {} ZHTP from wallet {}",
            amount,
            hex::encode(wallet_address)
        );
        
        Ok(())
    }
    
    /// Claim yield from all positions for a wallet
    pub fn claim_all_yield(&mut self, wallet_address: [u8; 32]) -> Result<u64> {
        let mut total_yield = 0u64;
        
        for position in self.positions.iter_mut() {
            if position.wallet_address == wallet_address {
                let daily_rate = if position.staked_amount >= crate::LARGE_INFRASTRUCTURE_THRESHOLD {
                    self.large_infrastructure_pool.daily_yield_rate
                } else {
                    self.small_infrastructure_pool.daily_yield_rate
                };
                
                let yield_claimed = position.claim_yield(daily_rate)?;
                total_yield += yield_claimed;
            }
        }
        
        if total_yield > 0 {
            info!(
                "Claimed total {} SOV yield for wallet {}",
                total_yield,
                hex::encode(wallet_address)
            );
        }
        
        Ok(total_yield)
    }
    
    /// Get staking statistics
    pub fn get_staking_stats(&self) -> serde_json::Value {
        let total_staked = self.large_infrastructure_pool.total_staked + 
                          self.small_infrastructure_pool.total_staked;
        
        serde_json::json!({
            "total_staked": total_staked,
            "large_infrastructure_pool": self.large_infrastructure_pool.get_stats(),
            "small_infrastructure_pool": self.small_infrastructure_pool.get_stats(),
            "total_positions": self.positions.len(),
            "large_infrastructure_threshold": crate::LARGE_INFRASTRUCTURE_THRESHOLD
        })
    }
}

impl Default for InfrastructureStaking {
    fn default() -> Self {
        Self::new()
    }
}
