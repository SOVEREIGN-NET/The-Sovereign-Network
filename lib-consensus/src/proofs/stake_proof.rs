//! Stake proof implementation for Proof of Stake consensus

use anyhow::Result;
use lib_crypto::Hash;
use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};

/// Proof of Stake for consensus participation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeProof {
    /// Validator identity
    pub validator: IdentityId,
    /// Amount staked (in micro-ZHTP)
    pub staked_amount: u64,
    /// Stake transaction hash
    pub stake_tx_hash: Hash,
    /// Block height when stake was made
    pub stake_height: u64,
    /// Stake lock time (blocks)
    pub lock_time: u64,
    /// Delegation details (if any)
    pub delegations: Vec<StakeDelegation>,
    /// Validator's consensus weight
    pub voting_power: u64,
}

/// Delegation of stake to a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeDelegation {
    /// Delegator identity
    pub delegator: IdentityId,
    /// Amount delegated
    pub amount: u64,
    /// Delegation transaction hash
    pub tx_hash: Hash,
    /// Delegation timestamp
    pub timestamp: u64,
    /// Commission rate for validator
    pub commission_rate: f64,
}

impl StakeProof {
    /// Create a new stake proof
    pub fn new(
        validator: IdentityId,
        staked_amount: u64,
        stake_tx_hash: Hash,
        stake_height: u64,
        lock_time: u64,
    ) -> Result<Self> {
        // Calculate initial voting power based on stake
        let voting_power = Self::calculate_voting_power(staked_amount, &[]);

        Ok(StakeProof {
            validator,
            staked_amount,
            stake_tx_hash,
            stake_height,
            lock_time,
            delegations: Vec::new(),
            voting_power,
        })
    }

    /// Add a delegation to this stake proof
    pub fn add_delegation(&mut self, delegation: StakeDelegation) -> Result<()> {
        self.delegations.push(delegation);

        // Recalculate voting power with new delegations
        self.voting_power = Self::calculate_voting_power(self.staked_amount, &self.delegations);

        Ok(())
    }

    /// Calculate voting power based on stake and delegations
    fn calculate_voting_power(staked_amount: u64, delegations: &[StakeDelegation]) -> u64 {
        let delegated_amount: u64 = delegations.iter().map(|d| d.amount).sum();
        let total_stake = staked_amount + delegated_amount;

        // Apply square root to prevent excessive concentration of power
        (total_stake as f64).sqrt() as u64
    }

    /// Verify the stake proof is valid
    pub fn verify(&self, current_height: u64) -> Result<bool> {
        // Check minimum stake requirements
        if self.staked_amount < 1000 * 1_000_000 {
            // 1000 ZHTP minimum
            return Ok(false);
        }

        // Check stake is not expired (if lock_time is set)
        if self.lock_time > 0 && current_height > self.stake_height + self.lock_time {
            return Ok(false);
        }

        // Verify all delegations are valid
        for delegation in &self.delegations {
            if !self.verify_delegation(delegation)? {
                return Ok(false);
            }
        }

        // Verify voting power calculation
        let expected_power = Self::calculate_voting_power(self.staked_amount, &self.delegations);
        if self.voting_power != expected_power {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify a single delegation
    fn verify_delegation(&self, delegation: &StakeDelegation) -> Result<bool> {
        // Check delegation amount is positive
        if delegation.amount == 0 {
            return Ok(false);
        }

        // Check commission rate is reasonable (0-100%)
        if delegation.commission_rate < 0.0 || delegation.commission_rate > 1.0 {
            return Ok(false);
        }

        // In a implementation, would verify delegation transaction on-chain
        Ok(true)
    }

    /// Get total stake (own stake + delegated stake)
    pub fn total_stake(&self) -> u64 {
        let delegated_amount: u64 = self.delegations.iter().map(|d| d.amount).sum();
        self.staked_amount + delegated_amount
    }

    /// Calculate rewards to distribute to delegators
    pub fn calculate_delegation_rewards(&self, total_rewards: u64) -> Vec<(IdentityId, u64)> {
        let mut delegation_rewards = Vec::new();
        let total_stake = self.total_stake();

        for delegation in &self.delegations {
            // Calculate delegator's share of rewards
            let delegator_share =
                (delegation.amount as f64 / total_stake as f64) * total_rewards as f64;

            // Apply commission (validator takes commission_rate%)
            let commission = delegator_share * delegation.commission_rate;
            let delegator_reward = delegator_share - commission;

            delegation_rewards.push((delegation.delegator.clone(), delegator_reward as u64));
        }

        delegation_rewards
    }

    /// Check if stake is locked (cannot be withdrawn)
    pub fn is_locked(&self, current_height: u64) -> bool {
        self.lock_time > 0 && current_height < self.stake_height + self.lock_time
    }
}
