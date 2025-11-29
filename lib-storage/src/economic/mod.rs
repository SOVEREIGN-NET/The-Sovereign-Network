//! Economic Storage Layer - Phase C Implementation
//! 
//! This module implements the economic incentive system for the ZHTP storage network.
//! It builds on top of the DHT foundation layer to provide:
//! - Dynamic pricing based on supply and demand
//! - Storage contracts with SLAs
//! - Payment processing and escrow
//! - Reputation and quality scoring
//! - Market mechanisms for storage resources

pub mod pricing;
pub mod contracts; 
pub mod payments;
pub mod reputation;
pub mod market;
pub mod incentives;
pub mod quality;
pub mod penalties;
pub mod rewards;
pub mod manager;

// Re-export key components
pub use pricing::*;
pub use contracts::*;
pub use payments::*;
pub use reputation::*;
pub use market::*;
pub use incentives::*;
pub use quality::*;
pub use penalties::*;
pub use rewards::*;
pub use manager::*;

// Economic system configuration
pub const BASE_STORAGE_PRICE: u64 = 100; // Base price per GB per day in tokens
pub const MIN_CONTRACT_DURATION: u64 = 86400; // 1 day in seconds
pub const MAX_CONTRACT_DURATION: u64 = 31536000; // 1 year in seconds
pub const REPUTATION_DECAY_RATE: f64 = 0.01; // Daily reputation decay
pub const QUALITY_THRESHOLD: f64 = 0.8; // Minimum quality score for contracts

// Incentive parameters
pub const PROVIDER_COMMISSION: f64 = 0.85; // 85% to provider, 15% to network
pub const EARLY_PROVIDER_BONUS: f64 = 0.1; // 10% bonus for early network participants
pub const RELIABILITY_BONUS_THRESHOLD: f64 = 0.95; // 95% uptime for bonus
pub const RELIABILITY_BONUS: f64 = 0.05; // 5% bonus for high reliability

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_economic_constants() {
        assert_eq!(BASE_STORAGE_PRICE, 100);
        assert_eq!(PROVIDER_COMMISSION, 0.85);
        assert!(QUALITY_THRESHOLD > 0.0 && QUALITY_THRESHOLD < 1.0);
    }
}
