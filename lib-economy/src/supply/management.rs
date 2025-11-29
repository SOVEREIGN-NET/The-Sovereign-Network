//! Token supply management for utility-focused economics
//! 
//! Manages token minting and supply tracking for network operations,
//! focusing on utility rather than artificial scarcity.

use anyhow::Result;
use crate::wasm::logging::info;

/// Token supply management structure - manages unlimited utility-based token supply
#[derive(Debug, Clone)]
pub struct SupplyManager {
    /// Current circulating supply
    pub current_supply: u64,
    /// Maximum supply (unlimited for utility)
    pub max_supply: u64,
    /// Total tokens minted for operations
    pub total_minted: u64,
    /// Total tokens burned (minimal for utility focus)
    pub total_burned: u64,
}

impl SupplyManager {
    /// Create new supply manager with unlimited supply model
    pub fn new() -> Self {
        SupplyManager {
            current_supply: 0,
            max_supply: u64::MAX, // Unlimited supply for utility
            total_minted: 0,
            total_burned: 0,
        }
    }
    
    /// Mint tokens for network operations (unlimited utility minting)
    pub fn mint_operational_tokens(&mut self, amount: u64, purpose: &str) -> Result<u64> {
        // UNLIMITED MINTING for actual network utility
        // Think of tokens like "bandwidth credits" or "compute credits"
        // ISPs don't have limited "internet capacity" - they scale as needed
        
        self.current_supply += amount;
        self.total_minted += amount;
        
        info!(
            "🏭 MINTED {} SOV tokens for {} - Total supply: {} tokens", 
            amount, purpose, self.current_supply
        );
        
        Ok(amount)
    }
    
    /// Mint tokens for UBI distribution
    pub fn mint_for_ubi(&mut self, amount: u64) -> Result<u64> {
        self.mint_operational_tokens(amount, "UBI distribution")
    }
    
    /// Mint tokens for welfare services
    pub fn mint_for_welfare(&mut self, amount: u64) -> Result<u64> {
        self.mint_operational_tokens(amount, "welfare services")
    }
    
    /// Mint tokens for infrastructure rewards
    pub fn mint_for_infrastructure(&mut self, amount: u64) -> Result<u64> {
        self.mint_operational_tokens(amount, "infrastructure rewards")
    }

    /// Legacy method for backward compatibility - delegates to mint_operational_tokens
    pub fn mint_tokens(&mut self, amount: u64) -> Result<(), String> {
        self.mint_operational_tokens(amount, "legacy mint")
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Calculate new tokens to mint based on economic activity
    pub fn calculate_mint_amount(&self, infrastructure_usage: u64, network_activity: u64) -> u64 {
        // Post-scarcity model: mint based on utility, not scarcity
        let base_mint = infrastructure_usage * 10; // 10 SOV per unit of infrastructure
        let activity_bonus = network_activity * 5; // 5 SOV per unit of network activity
        
        base_mint + activity_bonus
    }
    
    /// Burn tokens (minimal use for utility-focused economics)
    pub fn burn_tokens(&mut self, amount: u64, reason: &str) -> Result<u64> {
        if amount > self.current_supply {
            return Err(anyhow::anyhow!("Cannot burn more tokens than current supply"));
        }
        
        self.current_supply -= amount;
        self.total_burned += amount;
        
        info!(
            "🔥 BURNED {} SOV tokens for {} - Remaining supply: {} tokens", 
            amount, reason, self.current_supply
        );
        
        Ok(amount)
    }
    
    /// Get current supply statistics (enhanced version with JSON output)
    pub fn get_supply_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "current_supply": self.current_supply,
            "max_supply": self.max_supply,
            "total_minted": self.total_minted,
            "total_burned": self.total_burned,
            "net_supply": self.current_supply,
            "supply_utilization": if self.max_supply == u64::MAX { 
                0.0 
            } else { 
                (self.current_supply as f64) / (self.max_supply as f64) * 100.0 
            }
        })
    }

    /// Get supply stats as tuple (legacy compatibility)
    pub fn get_supply_stats_tuple(&self) -> (u64, u64, f64) {
        let utilization = if self.max_supply == u64::MAX {
            0.0
        } else {
            self.current_supply as f64 / self.max_supply as f64
        };
        (self.current_supply, self.max_supply, utilization)
    }
    
    /// Check if additional minting is needed for operations
    pub fn needs_additional_minting(&self, required_amount: u64) -> bool {
        // Always allow minting for utility purposes
        // No artificial scarcity constraints
        required_amount > 0
    }
    
    /// Calculate recommended mint amount for network operations
    pub fn calculate_operational_mint(&self, network_demand: u64, reserve_ratio: f64) -> u64 {
        // Calculate how much to mint based on network demand
        let base_mint = network_demand;
        
        // Add reserve for future operations
        let reserve_amount = ((base_mint as f64) * reserve_ratio) as u64;
        
        base_mint + reserve_amount
    }
}

impl Default for SupplyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operational_minting() {
        let mut manager = SupplyManager::new();
        
        let minted = manager.mint_operational_tokens(1000, "test operation").unwrap();
        assert_eq!(minted, 1000);
        assert_eq!(manager.current_supply, 1000);
        assert_eq!(manager.total_minted, 1000);
    }

    #[test]
    fn test_ubi_minting() {
        let mut manager = SupplyManager::new();
        
        let minted = manager.mint_for_ubi(5000).unwrap();
        assert_eq!(minted, 5000);
        assert_eq!(manager.current_supply, 5000);
    }

    #[test]
    fn test_token_burning() {
        let mut manager = SupplyManager::new();
        manager.mint_operational_tokens(1000, "test").unwrap();
        
        let burned = manager.burn_tokens(200, "test burn").unwrap();
        assert_eq!(burned, 200);
        assert_eq!(manager.current_supply, 800);
        assert_eq!(manager.total_burned, 200);
    }

    #[test]
    fn test_burn_more_than_supply() {
        let mut manager = SupplyManager::new();
        manager.mint_operational_tokens(100, "test").unwrap();
        
        let result = manager.burn_tokens(200, "invalid burn");
        assert!(result.is_err());
    }

    #[test]
    fn test_operational_mint_calculation() {
        let manager = SupplyManager::new();
        
        let mint_amount = manager.calculate_operational_mint(1000, 0.1);
        assert_eq!(mint_amount, 1100); // 1000 + 10% reserve
    }

    #[test]
    fn test_legacy_mint_tokens() {
        let mut manager = SupplyManager::new();
        
        let result = manager.mint_tokens(500);
        assert!(result.is_ok());
        assert_eq!(manager.current_supply, 500);
    }

    #[test]
    fn test_calculate_mint_amount() {
        let manager = SupplyManager::new();
        
        let amount = manager.calculate_mint_amount(100, 50);
        assert_eq!(amount, 1250); // 100*10 + 50*5
    }
}
