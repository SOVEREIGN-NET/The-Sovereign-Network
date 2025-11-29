//! Transaction creation utilities
//! 
//! Provides convenient functions for creating different types of transactions.

use anyhow::Result;
use crate::types::{TransactionType, Priority};
use crate::transactions::Transaction;
use crate::wasm::IdentityId;

/// Create a payment transaction between users
pub fn create_payment_transaction(
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    priority: Priority,
) -> Result<Transaction> {
    // Transaction::new_payment already sets the TransactionType::Payment
    Transaction::new_payment(from, to, amount, priority)
}

/// Create a reward transaction for network services
pub fn create_reward_transaction(recipient: [u8; 32], amount: u64) -> Result<Transaction> {
    // Transaction::new_reward already sets the TransactionType::Reward
    Transaction::new_reward(recipient, amount)
}

/// Create multiple UBI distribution transactions
pub fn create_ubi_distributions(citizens: &[(IdentityId, u64)]) -> Result<Vec<Transaction>> {
    let mut distributions = Vec::new();
    
    for (citizen_id, ubi_amount) in citizens {
        // Transaction::new_ubi_distribution already sets TransactionType::UbiDistribution
        let ubi_tx = Transaction::new_ubi_distribution(citizen_id.as_bytes().clone(), *ubi_amount)?;
        distributions.push(ubi_tx);
    }
    
    Ok(distributions)
}

/// Create welfare service funding transactions
pub fn create_welfare_funding(services: &[(String, [u8; 32], u64)]) -> Result<Vec<Transaction>> {
    let mut funding_txs = Vec::new();
    
    for (_service_name, service_address, funding_amount) in services {
        // Transaction::new_welfare_distribution already sets TransactionType::WelfareDistribution
        let welfare_tx = Transaction::new_welfare_distribution(*service_address, *funding_amount)?;
        funding_txs.push(welfare_tx);
    }
    
    Ok(funding_txs)
}

/// Create a staking transaction
pub fn create_stake_transaction(staker: [u8; 32], amount: u64, priority: Priority) -> Result<Transaction> {
    // For staking, we need to manually create the transaction with correct type
    Transaction::new(staker, staker, amount, TransactionType::Stake, 250, priority)
}

/// Create an unstaking transaction
pub fn create_unstake_transaction(staker: [u8; 32], amount: u64, priority: Priority) -> Result<Transaction> {
    // For unstaking, we need to manually create the transaction with correct type
    Transaction::new(staker, staker, amount, TransactionType::Unstake, 250, priority)
}

/// Create a DAO fee transaction
pub fn create_dao_fee_transaction(payer: [u8; 32], fee_amount: u64) -> Result<Transaction> {
    let dao_treasury = [0u8; 32]; // DAO treasury address (placeholder)
    // For DAO fee, we need to manually create the transaction with correct type
    Transaction::new(payer, dao_treasury, fee_amount, TransactionType::DaoFee, 200, Priority::Normal)
}
