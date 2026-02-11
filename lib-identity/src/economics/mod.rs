//! Economic integration for SOV Identity
//! 
//! This module provides integration with the SOV economic system,
//! enabling UBI distribution, DAO governance, and token economics.

pub mod transaction;

// Re-exports for compatibility with original identity.rs
pub use transaction::{Transaction, TransactionType, Priority};
use crate::constants::SOV_ATOMIC_UNITS;

// Temporary economic model for integration
// This should be replaced with actual lib-economy integration
#[derive(Debug, Clone)]
pub struct EconomicModel {
    /// UBI treasury balance
    pub ubi_treasury: u64,
    /// DAO treasury balance
    pub dao_treasury: u64,
    /// Welcome bonus treasury
    pub welcome_treasury: u64,
    /// Total SOV supply
    pub total_supply: u64,
    /// Current block height
    pub current_block: u64,
}

impl EconomicModel {
    /// Create a new economic model
    pub fn new() -> Self {
        Self {
            ubi_treasury: 1_000_000_000u64.saturating_mul(SOV_ATOMIC_UNITS), // 1B SOV for UBI
            dao_treasury: 500_000_000u64.saturating_mul(SOV_ATOMIC_UNITS),   // 500M SOV for DAO
            welcome_treasury: 100_000_000u64.saturating_mul(SOV_ATOMIC_UNITS), // 100M SOV for welcome bonuses
            total_supply: 21_000_000_000u64.saturating_mul(SOV_ATOMIC_UNITS), // 21B SOV total
            current_block: 0,
        }
    }
    
    /// Check if UBI distribution is possible
    pub fn can_distribute_ubi(&self, amount: u64) -> bool {
        self.ubi_treasury >= amount
    }
    
    /// Distribute UBI amount
    pub fn distribute_ubi(&mut self, amount: u64) -> Result<(), &'static str> {
        if self.can_distribute_ubi(amount) {
            self.ubi_treasury -= amount;
            Ok(())
        } else {
            Err("Insufficient UBI treasury funds")
        }
    }
    
    /// Check if welcome bonus is possible
    pub fn can_give_welcome_bonus(&self, amount: u64) -> bool {
        self.welcome_treasury >= amount
    }
    
    /// Give welcome bonus
    pub fn give_welcome_bonus(&mut self, amount: u64) -> Result<(), &'static str> {
        if self.can_give_welcome_bonus(amount) {
            self.welcome_treasury -= amount;
            Ok(())
        } else {
            Err("Insufficient welcome bonus treasury funds")
        }
    }
}

impl Default for EconomicModel {
    fn default() -> Self {
        Self::new()
    }
}
