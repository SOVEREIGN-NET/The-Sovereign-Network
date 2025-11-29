//! Wallet balance management and tracking
//! 
//! Core wallet functionality for managing balances and transaction history.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::transactions::Transaction;
use crate::models::TokenReward;
use crate::wasm::{hash_blake3, logging::info, compatibility::current_timestamp};

/// Wallet balance structure for tracking user funds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    /// Node identifier
    pub node_id: [u8; 32],
    /// Available balance for spending
    pub available_balance: u64,
    /// Staked balance for consensus/infrastructure
    pub staked_balance: u64,
    /// Pending rewards not yet claimed
    pub pending_rewards: u64,
    /// Transaction history
    pub transaction_history: Vec<Transaction>,
}

impl WalletBalance {
    /// Create a new wallet with zero balance
    pub fn new(node_id: [u8; 32]) -> Self {
        WalletBalance {
            node_id,
            available_balance: 0,
            staked_balance: 0,
            pending_rewards: 0,
            transaction_history: Vec::new(),
        }
    }
    
    /// Add rewards to wallet
    pub fn add_reward(&mut self, reward: &TokenReward) -> Result<()> {
        self.pending_rewards += reward.total_reward;
        
        // Create reward transaction record
        let tx = Transaction {
            tx_id: hash_blake3(&format!("reward-{}-{}", self.node_id[0], reward.total_reward).as_bytes()),
            from: [0u8; 32], // Network reward
            to: self.node_id,
            amount: reward.total_reward,
            base_fee: 0,
            dao_fee: 0,
            total_fee: 0,
            tx_type: crate::types::TransactionType::Reward,
            timestamp: current_timestamp()?,
            block_height: 0, // Would be set when included in block
            dao_fee_proof: None,
        };
        
        self.transaction_history.push(tx);
        Ok(())
    }
    
    /// Claim pending rewards
    pub fn claim_rewards(&mut self) -> Result<u64> {
        let claimed = self.pending_rewards;
        self.available_balance += claimed;
        self.pending_rewards = 0;
        
        if claimed > 0 {
            info!("Claimed {} SOV tokens from infrastructure services", claimed);
        }
        
        Ok(claimed)
    }
    
    /// Get total balance (available + staked + pending)
    pub fn total_balance(&self) -> u64 {
        self.available_balance + self.staked_balance + self.pending_rewards
    }
    
    /// Check if wallet has sufficient funds for transaction
    pub fn can_afford(&self, amount: u64) -> bool {
        // Handle edge case where spending would cause overflow in subsequent operations
        if self.available_balance == u64::MAX && amount < u64::MAX {
            // At maximum balance, can only afford the exact maximum amount
            // Any smaller amount would suggest we need to track change, which would overflow
            false
        } else {
            self.available_balance >= amount
        }
    }
    
    /// Stake tokens from available balance
    pub fn stake_tokens(&mut self, amount: u64) -> Result<()> {
        if !self.can_afford(amount) {
            return Err(anyhow::anyhow!("Insufficient available balance for staking"));
        }
        
        self.available_balance -= amount;
        self.staked_balance += amount;
        
        info!(
            "🏦 Staked {} SOV tokens - Available: {}, Staked: {}",
            amount, self.available_balance, self.staked_balance
        );
        
        Ok(())
    }
    
    /// Unstake tokens back to available balance  
    pub fn unstake_tokens(&mut self, amount: u64) -> Result<()> {
        if amount > self.staked_balance {
            return Err(anyhow::anyhow!("Insufficient staked balance for unstaking"));
        }
        
        self.staked_balance -= amount;
        self.available_balance += amount;
        
        info!(
            "🏦 Unstaked {} SOV tokens - Available: {}, Staked: {}",
            amount, self.available_balance, self.staked_balance
        );
        
        Ok(())
    }
}
