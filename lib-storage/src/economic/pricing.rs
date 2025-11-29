//! Dynamic Pricing System
//! 
//! Implements market-based pricing for storage services based on:
//! - Supply and demand dynamics
//! - Storage tier (Hot, Warm, Cold, Archive)
//! - Quality of service requirements
//! - Geographic and network locality
//! - Provider reputation and reliability

use crate::types::*;
use anyhow::Result;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Dynamic pricing engine that adjusts storage costs based on market conditions
#[derive(Debug, Clone)]
pub struct PricingEngine {
    /// Base pricing per storage tier
    base_prices: HashMap<StorageTier, u64>,
    /// Current supply metrics per tier
    supply_metrics: HashMap<StorageTier, SupplyMetrics>,
    /// Demand metrics per tier
    demand_metrics: HashMap<StorageTier, DemandMetrics>,
    /// Geographic pricing adjustments
    geographic_multipliers: HashMap<String, f64>,
    /// Quality pricing premiums
    quality_premiums: HashMap<QualityLevel, f64>,
}

/// Supply metrics for pricing calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyMetrics {
    /// Total available storage in bytes
    pub total_capacity: u64,
    /// Currently utilized storage in bytes
    pub utilized_capacity: u64,
    /// Number of active providers
    pub provider_count: u32,
    /// Average provider reliability score
    pub avg_reliability: f64,
    /// Geographic distribution of providers
    pub geographic_spread: f64,
}

/// Demand metrics for pricing calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemandMetrics {
    /// Storage requests in last 24h
    pub daily_requests: u32,
    /// Average request size
    pub avg_request_size: u64,
    /// Peak demand periods
    pub peak_demand_ratio: f64,
    /// Request urgency distribution
    pub urgency_distribution: HashMap<UrgencyLevel, f64>,
}

/// Quality levels for premium pricing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QualityLevel {
    Basic,      // Standard service
    Premium,    // Enhanced SLA
    Enterprise, // Enterprise-grade service
}

/// Request urgency levels
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UrgencyLevel {
    Low,     // Can wait hours/days
    Normal,  // Standard processing
    High,    // Need within minutes
    Critical,// Need immediately
}

/// Pricing quote for a storage request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingQuote {
    /// Base price per GB per day
    pub base_price: u64,
    /// Supply/demand adjustment multiplier
    pub market_multiplier: f64,
    /// Quality premium multiplier
    pub quality_multiplier: f64,
    /// Geographic adjustment multiplier
    pub geographic_multiplier: f64,
    /// Urgency premium multiplier
    pub urgency_multiplier: f64,
    /// Final calculated price
    pub final_price: u64,
    /// Quote validity period in seconds
    pub validity_period: u64,
    /// Quote timestamp
    pub timestamp: u64,
}

/// Storage request for pricing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRequest {
    /// Size in bytes
    pub size: u64,
    /// Storage tier required
    pub tier: StorageTier,
    /// Duration in seconds
    pub duration: u64,
    /// Quality level required
    pub quality_level: QualityLevel,
    /// Geographic preference
    pub geographic_region: Option<String>,
    /// Urgency level
    pub urgency: UrgencyLevel,
    /// Required replication factor
    pub replication_factor: u8,
}

impl PricingEngine {
    /// Create a new pricing engine with default parameters
    pub fn new() -> Self {
        let mut base_prices = HashMap::new();
        base_prices.insert(StorageTier::Hot, 1000);      // 10x base for hot storage
        base_prices.insert(StorageTier::Warm, 300);      // 3x base for warm storage
        base_prices.insert(StorageTier::Cold, 100);      // 1x base for cold storage
        base_prices.insert(StorageTier::Archive, 30);    // 0.3x base for archive

        let mut quality_premiums = HashMap::new();
        quality_premiums.insert(QualityLevel::Basic, 1.0);      // No premium
        quality_premiums.insert(QualityLevel::Premium, 1.5);    // 50% premium
        quality_premiums.insert(QualityLevel::Enterprise, 2.0); // 100% premium

        Self {
            base_prices,
            supply_metrics: HashMap::new(),
            demand_metrics: HashMap::new(),
            geographic_multipliers: HashMap::new(),
            quality_premiums,
        }
    }

    /// Update supply metrics for a storage tier
    pub fn update_supply_metrics(&mut self, tier: StorageTier, metrics: SupplyMetrics) {
        self.supply_metrics.insert(tier, metrics);
    }

    /// Update demand metrics for a storage tier
    pub fn update_demand_metrics(&mut self, tier: StorageTier, metrics: DemandMetrics) {
        self.demand_metrics.insert(tier, metrics);
    }

    /// Set geographic pricing multiplier
    pub fn set_geographic_multiplier(&mut self, region: String, multiplier: f64) {
        self.geographic_multipliers.insert(region, multiplier);
    }

    /// Calculate pricing quote for a storage request
    pub fn calculate_quote(&self, request: &StorageRequest) -> Result<PricingQuote> {
        let base_price = self.base_prices.get(&request.tier)
            .copied()
            .unwrap_or(crate::economic::BASE_STORAGE_PRICE);

        // Calculate market multiplier based on supply/demand
        let market_multiplier = self.calculate_market_multiplier(&request.tier)?;

        // Quality premium
        let quality_multiplier = self.quality_premiums.get(&request.quality_level)
            .copied()
            .unwrap_or(1.0);

        // Geographic multiplier
        let geographic_multiplier = request.geographic_region
            .as_ref()
            .and_then(|region| self.geographic_multipliers.get(region))
            .copied()
            .unwrap_or(1.0);

        // Urgency multiplier
        let urgency_multiplier = match request.urgency {
            UrgencyLevel::Low => 0.8,      // 20% discount for flexible timing
            UrgencyLevel::Normal => 1.0,   // Standard pricing
            UrgencyLevel::High => 1.5,     // 50% premium for fast service
            UrgencyLevel::Critical => 2.0, // 100% premium for immediate service
        };

        // Calculate final price
        let total_multiplier = market_multiplier * quality_multiplier * 
                              geographic_multiplier * urgency_multiplier;
        
        let size_gb = (request.size as f64 / (1024.0 * 1024.0 * 1024.0)).ceil() as u64;
        let duration_days = (request.duration as f64 / 86400.0).ceil() as u64;
        
        let final_price = ((base_price as f64 * total_multiplier) as u64) 
                         * size_gb 
                         * duration_days 
                         * (request.replication_factor as u64);

        Ok(PricingQuote {
            base_price,
            market_multiplier,
            quality_multiplier,
            geographic_multiplier,
            urgency_multiplier,
            final_price,
            validity_period: 300, // 5 minutes
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Calculate market multiplier based on supply/demand ratio
    fn calculate_market_multiplier(&self, tier: &StorageTier) -> Result<f64> {
        let supply = self.supply_metrics.get(tier);
        let demand = self.demand_metrics.get(tier);

        match (supply, demand) {
            (Some(supply), Some(demand)) => {
                // Calculate utilization ratio
                let utilization = supply.utilized_capacity as f64 / supply.total_capacity as f64;
                
                // Base multiplier on utilization
                let utilization_multiplier = if utilization < 0.5 {
                    0.8 // Discount when underutilized
                } else if utilization < 0.8 {
                    1.0 // Standard pricing
                } else if utilization < 0.95 {
                    1.5 // Premium when getting full
                } else {
                    2.0 // High premium when nearly full
                };

                // Adjust for demand pressure
                let demand_pressure = (demand.daily_requests as f64) / (supply.provider_count as f64);
                let demand_multiplier = if demand_pressure < 10.0 {
                    1.0
                } else if demand_pressure < 50.0 {
                    1.2
                } else {
                    1.5
                };

                Ok(utilization_multiplier * demand_multiplier)
            }
            _ => {
                // Default multiplier when no metrics available
                Ok(1.0)
            }
        }
    }

    /// Get current market conditions summary
    pub fn get_market_summary(&self) -> MarketSummary {
        let mut tier_summaries = HashMap::new();

        for (tier, supply) in &self.supply_metrics {
            if let Some(demand) = self.demand_metrics.get(tier) {
                let utilization = supply.utilized_capacity as f64 / supply.total_capacity as f64;
                let market_multiplier = self.calculate_market_multiplier(tier).unwrap_or(1.0);
                
                tier_summaries.insert(tier.clone(), TierSummary {
                    base_price: self.base_prices.get(tier).copied().unwrap_or(100),
                    market_multiplier,
                    utilization,
                    provider_count: supply.provider_count,
                    daily_requests: demand.daily_requests,
                });
            }
        }

        MarketSummary {
            tier_summaries,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Market conditions summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketSummary {
    pub tier_summaries: HashMap<StorageTier, TierSummary>,
    pub timestamp: u64,
}

/// Summary for a specific storage tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierSummary {
    pub base_price: u64,
    pub market_multiplier: f64,
    pub utilization: f64,
    pub provider_count: u32,
    pub daily_requests: u32,
}

impl Default for PricingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pricing_engine_creation() {
        let engine = PricingEngine::new();
        assert!(engine.base_prices.contains_key(&StorageTier::Hot));
        assert!(engine.base_prices.contains_key(&StorageTier::Cold));
    }

    #[test]
    fn test_basic_pricing_quote() {
        let engine = PricingEngine::new();
        
        let request = StorageRequest {
            size: 1024 * 1024 * 1024, // 1 GB
            tier: StorageTier::Cold,
            duration: 86400, // 1 day
            quality_level: QualityLevel::Basic,
            geographic_region: None,
            urgency: UrgencyLevel::Normal,
            replication_factor: 3,
        };

        let quote = engine.calculate_quote(&request).unwrap();
        assert!(quote.final_price > 0);
        assert_eq!(quote.base_price, 100);
    }

    #[test]
    fn test_urgency_pricing() {
        let engine = PricingEngine::new();
        
        let normal_request = StorageRequest {
            size: 1024 * 1024 * 1024,
            tier: StorageTier::Cold,
            duration: 86400,
            quality_level: QualityLevel::Basic,
            geographic_region: None,
            urgency: UrgencyLevel::Normal,
            replication_factor: 3,
        };

        let critical_request = StorageRequest {
            urgency: UrgencyLevel::Critical,
            ..normal_request.clone()
        };

        let normal_quote = engine.calculate_quote(&normal_request).unwrap();
        let critical_quote = engine.calculate_quote(&critical_request).unwrap();

        assert!(critical_quote.final_price > normal_quote.final_price);
        assert_eq!(critical_quote.urgency_multiplier, 2.0);
    }
}
