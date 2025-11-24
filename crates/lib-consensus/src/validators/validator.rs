//! Validator implementation

use serde::{Deserialize, Serialize};
use lib_identity::IdentityId;
use crate::types::{ValidatorStatus, SlashType};

/// Consensus validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Validator identity
    pub identity: IdentityId,
    /// Staked amount (ZHTP tokens)
    pub stake: u64,
    /// Storage provided (bytes)
    pub storage_provided: u64,
    /// Validator status
    pub status: ValidatorStatus,
    /// Public key for consensus
    pub consensus_key: Vec<u8>,
    /// Voting power (calculated from stake + storage)
    pub voting_power: u64,
    /// Commission rate (percentage)
    pub commission_rate: u8,
    /// Reputation score
    pub reputation: u32,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Slash count
    pub slash_count: u32,
    /// Jail release time (if jailed)
    pub jail_until: Option<u64>,
}

impl Validator {
    /// Create a new validator
    pub fn new(
        identity: IdentityId,
        stake: u64,
        storage_provided: u64,
        consensus_key: Vec<u8>,
        commission_rate: u8,
    ) -> Self {
        let voting_power = Self::calculate_voting_power(stake, storage_provided);
        
        Self {
            identity,
            stake,
            storage_provided,
            status: ValidatorStatus::Active,
            consensus_key,
            voting_power,
            commission_rate,
            reputation: 100, // Start with perfect reputation
            last_activity: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            slash_count: 0,
            jail_until: None,
        }
    }
    
    /// Calculate voting power based primarily on stake, with optional storage bonus
    fn calculate_voting_power(stake: u64, storage_provided: u64) -> u64 {
        // Primary voting power comes from stake (traditional validator model)
        let base_power = (stake as f64).sqrt();
        
        // Optional storage bonus (max 20% bonus for significant storage)
        let storage_bonus = if storage_provided > 0 {
            let storage_gb = storage_provided as f64 / (1024.0 * 1024.0 * 1024.0);
            (storage_gb.ln().max(0.0) * 0.1).min(0.2) // Logarithmic bonus, capped at 20%
        } else {
            0.0
        };
        
        let total_power = base_power * (1.0 + storage_bonus);
        total_power as u64
    }
    
    /// Update validator's voting power when stake or storage changes
    pub fn update_voting_power(&mut self) {
        self.voting_power = Self::calculate_voting_power(self.stake, self.storage_provided);
    }
    
    /// Check if validator is active and can participate in consensus
    pub fn can_participate(&self) -> bool {
        match self.status {
            ValidatorStatus::Active => {
                // Check if jailed
                if let Some(jail_until) = self.jail_until {
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    current_time >= jail_until
                } else {
                    true
                }
            },
            _ => false,
        }
    }
    
    /// Slash validator for misbehavior
    pub fn slash(&mut self, slash_type: SlashType, slash_percentage: u8) -> anyhow::Result<u64> {
        let slash_amount = (self.stake * slash_percentage as u64) / 100;
        
        // Apply slashing
        self.stake = self.stake.saturating_sub(slash_amount);
        self.slash_count += 1;
        
        // Update reputation based on slash type
        let reputation_penalty = match slash_type {
            SlashType::DoubleSign => 20,
            SlashType::Liveness => 5,
            SlashType::InvalidProposal => 10,
            SlashType::InvalidVote => 5,
        };
        
        self.reputation = self.reputation.saturating_sub(reputation_penalty);
        
        // Jail validator if severely slashed
        if slash_percentage >= 10 || self.slash_count >= 3 {
            self.jail(24 * 3600); // Jail for 24 hours
        }
        
        // Update voting power after slashing
        self.update_voting_power();
        
        tracing::warn!(
            " Validator {:?} slashed {} ZHTP for {:?} (slash count: {})",
            self.identity, slash_amount, slash_type, self.slash_count
        );
        
        Ok(slash_amount)
    }
    
    /// Jail validator for a specified duration
    pub fn jail(&mut self, duration_seconds: u64) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.status = ValidatorStatus::Jailed;
        self.jail_until = Some(current_time + duration_seconds);
        
        tracing::warn!(
            " Validator {:?} jailed until timestamp {}",
            self.identity, self.jail_until.unwrap()
        );
    }
    
    /// Release validator from jail if jail period has expired
    pub fn try_release_from_jail(&mut self) -> bool {
        if let Some(jail_until) = self.jail_until {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            if current_time >= jail_until {
                self.status = ValidatorStatus::Active;
                self.jail_until = None;
                
                tracing::info!(
                    "🔓 Validator {:?} released from jail",
                    self.identity
                );
                
                return true;
            }
        }
        false
    }
    
    /// Update validator's last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Check if validator has been inactive for too long
    pub fn is_inactive(&self, max_inactive_seconds: u64) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        current_time - self.last_activity > max_inactive_seconds
    }
    
    /// Calculate validator's effective reputation score
    pub fn effective_reputation(&self) -> f64 {
        let base_reputation = self.reputation as f64 / 100.0; // Normalize to 0-1
        
        // Apply penalties for slashing history
        let slash_penalty = (self.slash_count as f64) * 0.1;
        
        (base_reputation - slash_penalty).max(0.0).min(1.0)
    }
    
    /// Add stake to validator
    pub fn add_stake(&mut self, amount: u64) {
        self.stake += amount;
        self.update_voting_power();
        
        tracing::info!(
            "Validator {:?} added {} ZHTP stake (total: {} ZHTP)",
            self.identity, amount, self.stake
        );
    }
    
    /// Remove stake from validator (if not locked)
    pub fn remove_stake(&mut self, amount: u64) -> anyhow::Result<()> {
        if amount > self.stake {
            return Err(anyhow::anyhow!("Cannot remove more stake than available"));
        }
        
        // Check minimum stake requirement
        let min_stake = 1000 * 1_000_000; // 1000 ZHTP minimum
        if self.stake - amount < min_stake {
            return Err(anyhow::anyhow!("Cannot reduce stake below minimum requirement"));
        }
        
        self.stake -= amount;
        self.update_voting_power();
        
        tracing::info!(
            " Validator {:?} removed {} ZHTP stake (remaining: {} ZHTP)",
            self.identity, amount, self.stake
        );
        
        Ok(())
    }
}
