//! Unified Token Pricing System
//!
//! Implements Issue #1819: Unified Token Pricing System (SOV + CBE)
//! with Pre/Post-Graduation Modes.
//!
//! Key Concepts:
//! - SOV price transitions from FIXED (SRV) to DYNAMIC (CBE_USD / CBE_SOV)
//! - CBE price starts as curve-based, switches to oracle when available
//! - Graduation ($269K reserve) only enables external CBE trading, not price calculation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fixed-point scale for price calculations (8 decimals = 100_000_000)
pub const PRICE_SCALE: u128 = 100_000_000;

/// Genesis/fallback SRV value in 8-decimal precision
pub const GENESIS_SRV_8DEC: u64 = 2_180_000; // $0.0218

/// Pricing mode for a token
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PricingMode {
    /// Fixed price (e.g., SOV using SRV before oracle provides CBE/USD)
    Fixed,
    /// Dynamic price derived from other signals (e.g., SOV = CBE_USD / CBE_SOV)
    Dynamic,
    /// Pre-graduation bonding curve pricing
    PreGraduation,
    /// Post-graduation oracle pricing
    PostGraduation,
}

impl std::fmt::Display for PricingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PricingMode::Fixed => write!(f, "fixed"),
            PricingMode::Dynamic => write!(f, "dynamic"),
            PricingMode::PreGraduation => write!(f, "pre_graduation"),
            PricingMode::PostGraduation => write!(f, "post_graduation"),
        }
    }
}

/// Price source indicator
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PriceSource {
    /// SRV (System Reference Value)
    Srv,
    /// Bonding curve calculation
    BondingCurve,
    /// External oracle
    Oracle,
    /// Derived from other prices
    Derived,
}

impl std::fmt::Display for PriceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PriceSource::Srv => write!(f, "srv"),
            PriceSource::BondingCurve => write!(f, "bonding_curve"),
            PriceSource::Oracle => write!(f, "oracle"),
            PriceSource::Derived => write!(f, "derived"),
        }
    }
}

/// Token price information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPrice {
    /// Token ID
    pub token_id: String,
    /// Token symbol
    pub symbol: String,
    /// Price in USD (cents for API compatibility)
    pub price_usd_cents: u64,
    /// Pricing mode
    pub price_mode: PricingMode,
    /// Source of the price
    pub price_source: PriceSource,
    /// Component prices used in calculation
    pub components: PriceComponents,
    /// Unix timestamp of last update
    pub last_updated: u64,
}

/// Component prices for transparent calculation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PriceComponents {
    /// SRV value (for SOV fixed pricing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srv: Option<f64>,
    /// CBE/USD price from oracle (external)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cbe_usd: Option<f64>,
    /// CBE/SOV ratio from bonding curve (internal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cbe_sov: Option<f64>,
    /// Curve price in SOV for CBE tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve_price_sov: Option<f64>,
    /// SOV/USD price used for CBE calculation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sov_usd: Option<f64>,
}

/// CBE-specific price information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbePriceInfo {
    /// Current price in USD (cents)
    pub price_usd_cents: u64,
    /// Pricing mode
    pub price_mode: PricingMode,
    /// Price source
    pub price_source: PriceSource,
    /// Current phase
    pub phase: String,
    /// Reserve in USD (micro-USD for precision)
    pub reserve_usd: u64,
    /// Total supply
    pub supply: u64,
    /// Component prices
    pub components: PriceComponents,
    /// Oracle confidence (0-1, None if not from oracle)
    pub oracle_confidence: Option<f64>,
    /// Last update timestamp
    pub last_updated: u64,
}

/// Unified pricing state for all tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenPricingState {
    /// Current CBE/USD price from oracle (8-decimal precision)
    pub cbe_usd_price: Option<u128>,
    /// Internal CBE/SOV ratio from bonding curve (8-decimal precision)
    pub cbe_sov_ratio: Option<u128>,
    /// Epoch when CBE/USD was last updated
    pub cbe_price_epoch: Option<u64>,
    /// Whether dynamic pricing is active (both signals available)
    pub dynamic_pricing_active: bool,
    /// Last SOV price calculation (8-decimal precision)
    pub last_sov_price_8dec: u128,
    /// Timestamp of last update
    pub last_updated: u64,
    /// Price history (token_id -> [(timestamp, price)])
    #[serde(default)]
    pub price_history: HashMap<String, Vec<(u64, u64)>>,
}

impl TokenPricingState {
    /// Create new pricing state with genesis values
    pub fn new() -> Self {
        Self {
            cbe_usd_price: None,
            cbe_sov_ratio: None,
            cbe_price_epoch: None,
            dynamic_pricing_active: false,
            last_sov_price_8dec: GENESIS_SRV_8DEC as u128,
            last_updated: 0,
            price_history: HashMap::new(),
        }
    }

    /// Update CBE/USD price from oracle
    pub fn update_cbe_usd_price(&mut self, price_8dec: u128, epoch: u64, timestamp: u64) {
        self.cbe_usd_price = Some(price_8dec);
        self.cbe_price_epoch = Some(epoch);
        self.last_updated = timestamp;
        self.check_dynamic_pricing_ready();
    }

    /// Update internal CBE/SOV ratio from bonding curve
    pub fn update_cbe_sov_ratio(&mut self, ratio_8dec: u128, timestamp: u64) {
        self.cbe_sov_ratio = Some(ratio_8dec);
        self.last_updated = timestamp;
        self.check_dynamic_pricing_ready();
    }

    /// Check if both signals are available for dynamic pricing
    fn check_dynamic_pricing_ready(&mut self) {
        self.dynamic_pricing_active = self.cbe_usd_price.is_some() && self.cbe_sov_ratio.is_some();
        
        if self.dynamic_pricing_active {
            // Calculate dynamic SOV price: CBE_USD / CBE_SOV
            if let (Some(cbe_usd), Some(cbe_sov)) = (self.cbe_usd_price, self.cbe_sov_ratio) {
                if cbe_sov > 0 {
                    // SOV/USD = CBE_USD / CBE_SOV
                    self.last_sov_price_8dec = (cbe_usd * PRICE_SCALE) / cbe_sov;
                }
            }
        }
    }

    /// Get current SOV price in 8-decimal precision
    pub fn get_sov_price_8dec(&self) -> u128 {
        if self.dynamic_pricing_active {
            self.last_sov_price_8dec
        } else {
            GENESIS_SRV_8DEC as u128
        }
    }

    /// Get SOV price components
    pub fn get_sov_components(&self) -> PriceComponents {
        let srv = GENESIS_SRV_8DEC as f64 / PRICE_SCALE as f64;
        
        PriceComponents {
            srv: Some(srv),
            cbe_usd: self.cbe_usd_price.map(|p| p as f64 / PRICE_SCALE as f64),
            cbe_sov: self.cbe_sov_ratio.map(|r| r as f64 / PRICE_SCALE as f64),
            curve_price_sov: None,
            sov_usd: None,
        }
    }

    /// Get current SOV pricing mode
    pub fn get_sov_pricing_mode(&self) -> PricingMode {
        if self.dynamic_pricing_active {
            PricingMode::Dynamic
        } else {
            PricingMode::Fixed
        }
    }

    /// Get current SOV price source
    pub fn get_sov_price_source(&self) -> PriceSource {
        if self.dynamic_pricing_active {
            PriceSource::Derived
        } else {
            PriceSource::Srv
        }
    }

    /// Calculate CBE price components
    pub fn calculate_cbe_price(&self, sov_price_8dec: u128, curve_price_sov: u64) -> (u64, PriceComponents) {
        let sov_usd = sov_price_8dec as f64 / PRICE_SCALE as f64;
        let curve_sov = curve_price_sov as f64 / PRICE_SCALE as f64;
        
        // CBE/USD = CBE/SOV * SOV/USD
        let cbe_usd = curve_sov * sov_usd;
        let cbe_usd_cents = (cbe_usd * 100.0) as u64;

        let components = PriceComponents {
            srv: None,
            cbe_usd: self.cbe_usd_price.map(|p| p as f64 / PRICE_SCALE as f64),
            cbe_sov: self.cbe_sov_ratio.map(|r| r as f64 / PRICE_SCALE as f64),
            curve_price_sov: Some(curve_sov),
            sov_usd: Some(sov_usd),
        };

        (cbe_usd_cents, components)
    }

    /// Record price in history
    pub fn record_price(&mut self, token_id: &str, timestamp: u64, price_cents: u64) {
        let history = self.price_history.entry(token_id.to_string()).or_default();
        history.push((timestamp, price_cents));
        
        // Keep only last 1000 entries
        if history.len() > 1000 {
            history.remove(0);
        }
    }
}

/// Pricing calculator for unified price computations
pub struct PricingCalculator;

impl PricingCalculator {
    /// Calculate SOV price given CBE/USD and CBE/SOV
    /// 
    /// Formula: SOV/USD = CBE/USD ÷ CBE/SOV
    /// 
    /// Example:
    /// - CBE/USD = $3 (from oracle)
    /// - CBE/SOV = 60 (from curve)
    /// - SOV/USD = 3 / 60 = $0.05
    pub fn calculate_sov_price(cbe_usd_8dec: u128, cbe_sov_8dec: u128) -> Option<u128> {
        if cbe_sov_8dec == 0 {
            return None;
        }
        // SOV/USD = CBE/USD / CBE/SOV
        // Result in 8-decimal precision
        Some((cbe_usd_8dec * PRICE_SCALE) / cbe_sov_8dec)
    }

    /// Calculate CBE/USD price given CBE/SOV and SOV/USD
    ///
    /// Formula: CBE/USD = CBE/SOV × SOV/USD
    pub fn calculate_cbe_usd(cbe_sov_8dec: u128, sov_usd_8dec: u128) -> u128 {
        // CBE/USD = CBE/SOV * SOV/USD / PRICE_SCALE
        (cbe_sov_8dec * sov_usd_8dec) / PRICE_SCALE
    }

    /// Convert 8-decimal price to cents
    pub fn to_cents(price_8dec: u128) -> u64 {
        ((price_8dec * 100) / PRICE_SCALE) as u64
    }

    /// Convert cents to 8-decimal price
    pub fn from_cents(cents: u64) -> u128 {
        (cents as u128 * PRICE_SCALE) / 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sov_price() {
        // Example from spec:
        // CBE/USD = $3 = 3 * 100_000_000 = 300_000_000
        // CBE/SOV = 60 = 60 * 100_000_000 = 6_000_000_000
        // SOV/USD = 3 / 60 = $0.05 = 5_000_000
        
        let cbe_usd = 300_000_000u128; // $3
        let cbe_sov = 6_000_000_000u128; // 60 SOV per CBE
        
        let sov_price = PricingCalculator::calculate_sov_price(cbe_usd, cbe_sov);
        assert_eq!(sov_price, Some(5_000_000)); // $0.05
    }

    #[test]
    fn test_calculate_cbe_usd() {
        // CBE/SOV = 60, SOV/USD = $0.05
        // CBE/USD = 60 * 0.05 = $3
        
        let cbe_sov = 6_000_000_000u128; // 60
        let sov_usd = 5_000_000u128; // $0.05
        
        let cbe_usd = PricingCalculator::calculate_cbe_usd(cbe_sov, sov_usd);
        assert_eq!(cbe_usd, 300_000_000); // $3
    }

    #[test]
    fn test_conversions() {
        // $0.0218 = 2.18 cents
        let cents = 218u64;
        let price_8dec = PricingCalculator::from_cents(cents);
        assert_eq!(price_8dec, 2_180_000);
        
        // Round trip
        let back_to_cents = PricingCalculator::to_cents(price_8dec);
        assert_eq!(back_to_cents, cents);
    }

    #[test]
    fn test_pricing_state_fixed_mode() {
        let state = TokenPricingState::new();
        
        // Initially in fixed mode (no oracle data)
        assert!(!state.dynamic_pricing_active);
        assert_eq!(state.get_sov_pricing_mode(), PricingMode::Fixed);
        assert_eq!(state.get_sov_price_source(), PriceSource::Srv);
        assert_eq!(state.get_sov_price_8dec(), GENESIS_SRV_8DEC as u128);
    }

    #[test]
    fn test_pricing_state_dynamic_mode() {
        let mut state = TokenPricingState::new();
        
        // Provide both signals
        // CBE/USD = $3
        state.update_cbe_usd_price(300_000_000, 10, 1_700_000_000);
        assert!(!state.dynamic_pricing_active); // Still need CBE/SOV
        
        // CBE/SOV = 60
        state.update_cbe_sov_ratio(6_000_000_000, 1_700_000_000);
        assert!(state.dynamic_pricing_active);
        assert_eq!(state.get_sov_pricing_mode(), PricingMode::Dynamic);
        assert_eq!(state.get_sov_price_source(), PriceSource::Derived);
        
        // SOV price should be $0.05 = 5_000_000
        assert_eq!(state.get_sov_price_8dec(), 5_000_000);
    }
}
