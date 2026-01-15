//! Automated payout system for recurring distributions
//! 
//! Handles scheduled UBI distributions, infrastructure rewards,
//! and other automated economic operations.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::treasury_economics::DaoTreasury;
use crate::wallets::WalletBalance;
use crate::wasm::logging::info;
use std::collections::HashMap;
use lib_identity::citizenship::UbiRegistration;
use lib_crypto::Hash;

/// Automated payout schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutSchedule {
    /// Payout frequency in seconds
    pub frequency_seconds: u64,
    /// Last payout timestamp
    pub last_payout: u64,
    /// Next scheduled payout
    pub next_payout: u64,
    /// Amount per payout
    pub amount_per_payout: u64,
    /// Total payouts processed
    pub total_payouts: u64,
    /// Total amount paid out
    pub total_amount_paid: u64,
}

impl PayoutSchedule {
    /// Create a new payout schedule
    pub fn new(frequency_seconds: u64, amount_per_payout: u64) -> Self {
        let current_time = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        
        PayoutSchedule {
            frequency_seconds,
            last_payout: 0,
            next_payout: current_time + frequency_seconds,
            amount_per_payout,
            total_payouts: 0,
            total_amount_paid: 0,
        }
    }
    
    /// Check if payout is due
    pub fn is_payout_due(&self) -> bool {
        let current_time = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        current_time >= self.next_payout
    }
    
    /// Process payout and update schedule
    pub fn process_payout(&mut self) -> Result<u64> {
        if !self.is_payout_due() {
            return Ok(0);
        }
        
        let current_time = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        self.last_payout = current_time;
        self.next_payout = current_time + self.frequency_seconds;
        self.total_payouts += 1;
        self.total_amount_paid += self.amount_per_payout;
        
        Ok(self.amount_per_payout)
    }
}

/// Automated UBI distribution system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedUBI {
    /// UBI payout schedule
    pub schedule: PayoutSchedule,
    /// Registered UBI recipients
    pub recipients: HashMap<String, [u8; 32]>, // citizen_id -> wallet_address
    /// UBI amount per recipient
    pub ubi_per_recipient: u64,
}

impl AutomatedUBI {
    /// Create new automated UBI system
    pub fn new(monthly_ubi_amount: u64) -> Self {
        let monthly_frequency = 30 * 24 * 3600; // 30 days in seconds
        
        AutomatedUBI {
            schedule: PayoutSchedule::new(monthly_frequency, 0), // Amount calculated per distribution
            recipients: HashMap::new(),
            ubi_per_recipient: monthly_ubi_amount,
        }
    }
    
    /// Register UBI recipient
    pub fn register_recipient(&mut self, citizen_id: String, wallet_address: [u8; 32]) -> Result<()> {
        self.recipients.insert(citizen_id.clone(), wallet_address);
        
        info!(
            "Registered UBI recipient: {} -> {}",
            citizen_id,
            hex::encode(wallet_address)
        );
        
        Ok(())
    }
    
    /// Process UBI distribution with state synchronization to registrations
    /// NOTE: Thread safety - when called from concurrent contexts, callers MUST ensure
    /// exclusive access to wallets and registrations HashMaps. Use Arc<RwLock<>> in
    /// multi-threaded environments to prevent race conditions on wallet balance updates.
    pub fn process_ubi_distribution(
        &mut self,
        treasury: &mut DaoTreasury,
        wallets: &mut HashMap<[u8; 32], WalletBalance>,
        registrations: &mut HashMap<Hash, UbiRegistration>,
        current_block: u64,
    ) -> Result<u64> {
        if !self.schedule.is_payout_due() || self.recipients.is_empty() {
            return Ok(0);
        }

        let total_recipients = self.recipients.len() as u64;
        let ubi_per_citizen = treasury.calculate_ubi_per_citizen(total_recipients);

        if ubi_per_citizen == 0 {
            info!("No UBI funds available for distribution");
            return Ok(0);
        }

        let total_distribution = match ubi_per_citizen.checked_mul(total_recipients) {
            Some(amount) => amount,
            None => {
                info!("UBI distribution overflow: ubi_per_citizen ({}) * recipients ({}) exceeds u64::MAX", ubi_per_citizen, total_recipients);
                return Ok(0);
            }
        };
        let current_time = crate::wasm::compatibility::current_timestamp().unwrap_or(0);

        // Record distribution in treasury
        treasury.record_ubi_distribution(total_distribution, current_time)?;

        // Distribute to recipients with state synchronization
        let mut successful_distributions = 0u64;
        for (citizen_id, wallet_address) in &self.recipients {
            if let Some(wallet) = wallets.get_mut(wallet_address) {
                wallet.available_balance = wallet.available_balance.saturating_add(ubi_per_citizen);
                successful_distributions += 1;

                // Synchronize registration state - record the payout with block height
                // Handles remainder distribution automatically
                let wallet_hash = Hash(*wallet_address);
                let actual_payout = if let Some(registration) = registrations.get_mut(&wallet_hash) {
                    registration.record_payout(ubi_per_citizen, current_block)
                } else {
                    ubi_per_citizen
                };

                // If remainder was distributed, update wallet accordingly
                if actual_payout > ubi_per_citizen {
                    let remainder = actual_payout - ubi_per_citizen;
                    wallet.available_balance = wallet.available_balance.saturating_add(remainder);
                }

                info!(
                    "Distributed {} ZHTP UBI to citizen {} (wallet: {}) at block {}",
                    ubi_per_citizen,
                    citizen_id,
                    hex::encode(wallet_address),
                    current_block
                );
            }
        }
        
        // Update schedule
        self.schedule.amount_per_payout = total_distribution;
        self.schedule.process_payout()?;
        
        info!(
            "Completed UBI distribution: {} ZHTP to {} recipients",
            total_distribution, successful_distributions
        );
        
        Ok(total_distribution)
    }
    
    /// Get UBI statistics
    pub fn get_ubi_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_recipients": self.recipients.len(),
            "ubi_per_recipient": self.ubi_per_recipient,
            "total_payouts": self.schedule.total_payouts,
            "total_amount_paid": self.schedule.total_amount_paid,
            "next_payout": self.schedule.next_payout,
            "last_payout": self.schedule.last_payout,
            "frequency_days": self.schedule.frequency_seconds / 86400
        })
    }
}

/// Automated infrastructure rewards system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedInfrastructureRewards {
    /// Infrastructure reward schedule
    pub schedule: PayoutSchedule,
    /// Infrastructure providers
    pub providers: HashMap<[u8; 32], u64>, // wallet_address -> contribution_score
}

impl AutomatedInfrastructureRewards {
    /// Create new automated infrastructure rewards
    pub fn new(daily_reward_pool: u64) -> Self {
        let daily_frequency = 24 * 3600; // 24 hours in seconds
        
        AutomatedInfrastructureRewards {
            schedule: PayoutSchedule::new(daily_frequency, daily_reward_pool),
            providers: HashMap::new(),
        }
    }
    
    /// Register infrastructure provider
    pub fn register_provider(&mut self, wallet_address: [u8; 32], contribution_score: u64) -> Result<()> {
        self.providers.insert(wallet_address, contribution_score);
        
        info!(
            "🏭 Registered infrastructure provider: {} (score: {})",
            hex::encode(wallet_address),
            contribution_score
        );
        
        Ok(())
    }
    
    /// Process infrastructure rewards distribution
    pub fn process_infrastructure_rewards(
        &mut self,
        wallets: &mut HashMap<[u8; 32], WalletBalance>,
    ) -> Result<u64> {
        if !self.schedule.is_payout_due() || self.providers.is_empty() {
            return Ok(0);
        }
        
        let total_contribution_score: u64 = self.providers.values().sum();
        
        if total_contribution_score == 0 {
            return Ok(0);
        }
        
        let reward_pool = self.schedule.amount_per_payout;
        let mut total_distributed = 0u64;
        
        // Distribute rewards proportionally
        for (wallet_address, contribution_score) in &self.providers {
            let provider_reward = (reward_pool * contribution_score) / total_contribution_score;
            
            if let Some(wallet) = wallets.get_mut(wallet_address) {
                wallet.available_balance += provider_reward;
                total_distributed += provider_reward;
                
                info!(
                    "🏭 Distributed {} ZHTP infrastructure reward to provider {}",
                    provider_reward,
                    hex::encode(wallet_address)
                );
            }
        }
        
        // Update schedule
        self.schedule.process_payout()?;
        
        info!(
            "🏭 Completed infrastructure rewards: {} ZHTP to {} providers",
            total_distributed, self.providers.len()
        );
        
        Ok(total_distributed)
    }
    
    /// Get infrastructure rewards statistics
    pub fn get_infrastructure_stats(&self) -> serde_json::Value {
        let total_score: u64 = self.providers.values().sum();
        
        serde_json::json!({
            "total_providers": self.providers.len(),
            "total_contribution_score": total_score,
            "daily_reward_pool": self.schedule.amount_per_payout,
            "total_payouts": self.schedule.total_payouts,
            "total_amount_paid": self.schedule.total_amount_paid,
            "next_payout": self.schedule.next_payout,
            "last_payout": self.schedule.last_payout
        })
    }
}

/// Main automated payout processor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedPayoutProcessor {
    /// UBI distribution system
    pub ubi_system: AutomatedUBI,
    /// Infrastructure rewards system
    pub infrastructure_system: AutomatedInfrastructureRewards,
}

impl AutomatedPayoutProcessor {
    /// Create new automated payout processor
    pub fn new(monthly_ubi: u64, daily_infrastructure_rewards: u64) -> Self {
        AutomatedPayoutProcessor {
            ubi_system: AutomatedUBI::new(monthly_ubi),
            infrastructure_system: AutomatedInfrastructureRewards::new(daily_infrastructure_rewards),
        }
    }
    
    /// Process all scheduled payouts with state synchronization
    pub fn process_all_payouts(
        &mut self,
        treasury: &mut DaoTreasury,
        wallets: &mut HashMap<[u8; 32], WalletBalance>,
        registrations: &mut HashMap<Hash, UbiRegistration>,
        current_block: u64,
    ) -> Result<(u64, u64)> {
        let ubi_distributed = self.ubi_system.process_ubi_distribution(treasury, wallets, registrations, current_block)?;
        let infrastructure_distributed = self.infrastructure_system.process_infrastructure_rewards(wallets)?;

        Ok((ubi_distributed, infrastructure_distributed))
    }
    
    /// Get combined payout statistics
    pub fn get_payout_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "ubi_stats": self.ubi_system.get_ubi_stats(),
            "infrastructure_stats": self.infrastructure_system.get_infrastructure_stats(),
            "total_systems": 2
        })
    }
}

/// Process automated payouts (main entry point with state synchronization)
pub fn process_automated_payouts(
    processor: &mut AutomatedPayoutProcessor,
    treasury: &mut DaoTreasury,
    wallets: &mut HashMap<[u8; 32], WalletBalance>,
    registrations: &mut HashMap<Hash, UbiRegistration>,
    current_block: u64,
) -> Result<()> {
    let (ubi_distributed, infrastructure_distributed) = processor.process_all_payouts(treasury, wallets, registrations, current_block)?;

    if ubi_distributed > 0 || infrastructure_distributed > 0 {
        info!(
            " Automated payouts completed: {} UBI + {} infrastructure = {} total ZHTP at block {}",
            ubi_distributed, infrastructure_distributed, ubi_distributed + infrastructure_distributed, current_block
        );
    }

    Ok(())
}

impl Default for AutomatedPayoutProcessor {
    fn default() -> Self {
        Self::new(1000, 10000) // Default: 1000 ZHTP monthly UBI, 10000 ZHTP daily infrastructure
    }
}
