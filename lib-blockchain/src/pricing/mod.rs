//! Issue #1852: Simplified Token Pricing System (Document-Compliant)
//!
//! Refactored from Issue #1819 to make bonding curve PRIMARY and oracle SECONDARY.
//!
//! Key Principle:
//! > "reliance on internal mechanisms rather than external oracles for price discovery"
//!
//! Architecture:
//! ```text
//! Bonding Curve (CBE/SOV) → Market Price → Oracle Observes
//! Bonding Curve = PRIMARY price source
//! Oracle = SECONDARY observer (graduation threshold validation only)
//! ```
//!
//! Changes from #1819:
//! - Removed oracle-derived SOV pricing (CBE/USD ÷ CBE/SOV)
//! - Removed dynamic pricing mode
//! - Simplified TokenPricingState to observer role
//! - Bonding curve is sole price source during Phase 1

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fixed-point scale for price calculations (8 decimals = 100_000_000)
pub const PRICE_SCALE: u128 = 100_000_000;

/// Genesis/fallback SRV value in 8-decimal precision
pub const GENESIS_SRV_8DEC: u64 = 2_180_000; // $0.0218

/// Pricing phase for CBE token
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PricingPhase {
    /// Phase 1: Bonding curve is sole price source
    Curve,
    /// Phase 2: AMM is price source (post-graduation)
    AMM,
}

impl Default for PricingPhase {
    fn default() -> Self {
        PricingPhase::Curve
    }
}

impl std::fmt::Display for PricingPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PricingPhase::Curve => write!(f, "curve"),
            PricingPhase::AMM => write!(f, "amm"),
        }
    }
}

/// Price source indicator
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PriceSource {
    /// SRV (System Reference Value) for SOV
    Srv,
    /// Bonding curve calculation (PRIMARY for CBE)
    BondingCurve,
    /// AMM pool price (post-graduation)
    AMM,
    /// Oracle observation (SECONDARY, read-only)
    Oracle,
}

impl std::fmt::Display for PriceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PriceSource::Srv => write!(f, "srv"),
            PriceSource::BondingCurve => write!(f, "bonding_curve"),
            PriceSource::AMM => write!(f, "amm"),
            PriceSource::Oracle => write!(f, "oracle"),
        }
    }
}

/// Component prices for transparent calculation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PriceComponents {
    /// SRV value in 8-decimal fixed-point units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srv: Option<u128>,
    /// CBE/USD price from oracle (deprecated - Issue #1852), 8-decimal units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cbe_usd: Option<u128>,
    /// CBE/SOV ratio from bonding curve in 8-decimal units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cbe_sov: Option<u128>,
    /// Curve price in SOV for CBE tokens, 8-decimal units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve_price_sov: Option<u128>,
    /// SOV/USD price used for CBE calculation, 8-decimal units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sov_usd: Option<u128>,
}

/// Token price information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPrice {
    /// Token ID
    pub token_id: String,
    /// Token symbol
    pub symbol: String,
    /// Price in USD cents
    pub price_usd_cents: u128,
    /// Pricing phase
    pub pricing_phase: PricingPhase,
    /// Pricing mode (Issue #1852: deprecated, use pricing_phase)
    pub price_mode: PricingMode,
    /// Source of the price
    pub price_source: PriceSource,
    /// Component prices
    pub components: PriceComponents,
    /// Unix timestamp of last update
    pub last_updated: u64,
}

/// Issue #1852: Simplified pricing state (observer role only)
///
/// The oracle only observes and validates - it does NOT create prices.
/// Bonding curve is the sole price source for CBE.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenPricingState {
    /// Current CBE price observed from bonding curve (8-decimal precision)
    /// This is OBSERVED, not set by oracle
    pub observed_curve_price: Option<u128>,
    /// Current pricing phase
    pub phase: PricingPhase,
    /// Timestamp of last update
    pub last_updated: u64,
    /// Price history (token_id -> [(timestamp, price)])
    #[serde(default)]
    pub price_history: HashMap<String, Vec<(u64, u128)>>,
    
    // Legacy fields for backward compatibility (Issue #1852 transition)
    /// Deprecated: CBE/USD from oracle (now observer-only)
    #[serde(default)]
    pub cbe_usd_price: Option<u128>,
    /// Deprecated: CBE/SOV ratio (use bonding curve directly)
    #[serde(default)]
    pub cbe_sov_ratio: Option<u128>,
    /// Deprecated: Dynamic pricing flag (always false now)
    #[serde(default)]
    pub dynamic_pricing_active: bool,
    /// Deprecated: Last SOV price (use SRV directly)
    #[serde(default = "default_srv")]
    pub last_sov_price_8dec: u128,
}

fn default_srv() -> u128 {
    GENESIS_SRV_8DEC as u128
}

// Issue #1852: Deprecated types kept for backward compatibility during transition

/// Deprecated: Use PricingPhase instead
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PricingMode {
    /// Fixed price (SRV)
    Fixed,
    /// Dynamic price (deprecated - no longer used)
    #[deprecated(since = "Issue #1852", note = "Bonding curve is PRIMARY, oracle is observer-only")]
    Dynamic,
    /// Pre-graduation bonding curve pricing
    PreGraduation,
    /// Post-graduation pricing
    PostGraduation,
}

/// CBE price info (Issue #1852: oracle is observer-only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbePriceInfo {
    /// Current price in USD (cents)
    pub price_usd_cents: u128,
    /// Pricing mode
    pub price_mode: PricingMode,
    /// Price source
    pub price_source: PriceSource,
    /// Current phase
    pub phase: String,
    /// Reserve in USD
    pub reserve_usd: u128,
    /// Total supply
    pub supply: u128,
    /// Component prices
    pub components: PriceComponents,
    /// Deprecated: confidence in basis points (oracle is observer-only)
    pub oracle_confidence_bps: Option<u16>,
    /// Last update timestamp
    pub last_updated: u64,
}

impl TokenPricingState {
    /// Create new pricing state
    pub fn new() -> Self {
        Self {
            observed_curve_price: None,
            phase: PricingPhase::Curve,
            last_updated: 0,
            price_history: HashMap::new(),
            // Legacy fields for backward compatibility
            cbe_usd_price: None,
            cbe_sov_ratio: None,
            dynamic_pricing_active: false,
            last_sov_price_8dec: GENESIS_SRV_8DEC as u128,
        }
    }

    /// Update observed curve price (from bonding curve, NOT oracle)
    pub fn observe_curve_price(&mut self, price_8dec: u128, timestamp: u64) {
        self.observed_curve_price = Some(price_8dec);
        self.last_updated = timestamp;
    }

    /// Transition to AMM phase (post-graduation)
    pub fn transition_to_amm(&mut self, timestamp: u64) {
        self.phase = PricingPhase::AMM;
        self.last_updated = timestamp;
    }

    /// Get current observed price
    pub fn get_observed_price(&self) -> Option<u128> {
        self.observed_curve_price
    }

    /// Get current pricing phase
    pub fn get_phase(&self) -> PricingPhase {
        self.phase
    }

    /// Record price in history
    pub fn record_price(&mut self, token_id: &str, timestamp: u64, price_cents: u128) {
        let history = self.price_history.entry(token_id.to_string()).or_default();
        history.push((timestamp, price_cents));
        
        // Keep only last 1000 entries
        if history.len() > 1000 {
            history.remove(0);
        }
    }

    /// Get price history for a token
    pub fn get_price_history(&self, token_id: &str) -> Vec<(u64, u128)> {
        self.price_history.get(token_id).cloned().unwrap_or_default()
    }

    // Issue #1852: Legacy methods for backward compatibility

    /// Deprecated: Get SOV price in 8-decimal (always returns SRV now)
    pub fn get_sov_price_8dec(&self) -> u128 {
        GENESIS_SRV_8DEC as u128
    }

    /// Deprecated: Get SOV pricing mode (always Fixed now)
    pub fn get_sov_pricing_mode(&self) -> PricingMode {
        PricingMode::Fixed
    }

    /// Deprecated: Get SOV price source (always Srv now)
    pub fn get_sov_price_source(&self) -> PriceSource {
        PriceSource::Srv
    }

    /// Deprecated: Calculate CBE price components
    pub fn calculate_cbe_price(&self, _sov_price_8dec: u128, curve_price_sov: u128) -> (u128, PriceComponents) {
        let sov_usd = GENESIS_SRV_8DEC as u128;
        let cbe_usd_8dec = PricingCalculator::calculate_cbe_usd(curve_price_sov, sov_usd);
        let cbe_usd_cents = PricingCalculator::to_cents(cbe_usd_8dec);

        let components = PriceComponents {
            srv: Some(sov_usd),
            cbe_usd: None, // Issue #1852: oracle is observer-only
            cbe_sov: None,
            curve_price_sov: Some(curve_price_sov),
            sov_usd: Some(sov_usd),
        };

        (cbe_usd_cents, components)
    }

    /// Deprecated: Update CBE/USD price from oracle (Issue #1852: oracle is observer-only)
    /// This method is kept for backward compatibility but does not affect pricing.
    pub fn update_cbe_usd_price(&mut self, price_8dec: u128, _epoch: u64, timestamp: u64) {
        self.cbe_usd_price = Some(price_8dec);
        self.last_updated = timestamp;
        // Issue #1852: No longer affects dynamic pricing
    }

    /// Deprecated: Update CBE/SOV ratio (use bonding curve directly instead)
    pub fn update_cbe_sov_ratio(&mut self, ratio_8dec: u128, timestamp: u64) {
        self.cbe_sov_ratio = Some(ratio_8dec);
        self.last_updated = timestamp;
        // Issue #1852: No longer affects dynamic pricing
    }

    /// Deprecated: Get SOV price components
    pub fn get_sov_components(&self) -> PriceComponents {
        let srv = GENESIS_SRV_8DEC as u128;
        
        PriceComponents {
            srv: Some(srv),
            cbe_usd: None, // Issue #1852: oracle is observer-only
            cbe_sov: None,
            curve_price_sov: None,
            sov_usd: None,
        }
    }
}

/// Issue #1852: Simplified pricing calculator
///
/// Removed: calculate_sov_price() using CBE/USD ÷ CBE/SOV
/// Reason: Bonding curve is PRIMARY, oracle is observer-only
pub struct PricingCalculator;

impl PricingCalculator {
    /// Calculate CBE/USD price given CBE/SOV and SOV/USD
    ///
    /// Formula: CBE/USD = CBE/SOV × SOV/USD
    pub fn calculate_cbe_usd(cbe_sov_8dec: u128, sov_usd_8dec: u128) -> u128 {
        // CBE/USD = CBE/SOV * SOV/USD / PRICE_SCALE
        (cbe_sov_8dec * sov_usd_8dec) / PRICE_SCALE
    }

    /// Convert 8-decimal price to 4-decimal USD units (price_usd_cents = price_usd * 10_000)
    /// 1 unit = $0.0001. Example: 2_180_000 (=$0.0218) → 218
    pub fn to_cents(price_8dec: u128) -> u128 {
        (price_8dec * 10_000) / PRICE_SCALE
    }

    /// Convert 4-decimal USD units to 8-decimal price
    /// Example: 218 (=$0.0218) → 2_180_000
    pub fn from_cents(cents: u128) -> u128 {
        (cents * PRICE_SCALE) / 10_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pricing_state_observer_role() {
        let mut state = TokenPricingState::new();
        
        // Initially no observed price
        assert!(state.observed_curve_price.is_none());
        assert_eq!(state.phase, PricingPhase::Curve);
        
        // Observe curve price (from bonding curve, not oracle)
        state.observe_curve_price(31_334_570, 1_700_000_000);
        assert_eq!(state.observed_curve_price, Some(31_334_570));
        
        // Phase transition
        state.transition_to_amm(1_700_000_100);
        assert_eq!(state.phase, PricingPhase::AMM);
    }

    #[test]
    fn test_calculate_cbe_usd() {
        // CBE/SOV = 60, SOV/USD = $0.05
        // CBE/USD = 60 * 0.05 = $3
        
        let cbe_sov = 60u128 * PRICE_SCALE; // 60
        let sov_usd = 5_000_000u128; // $0.05
        
        let cbe_usd = PricingCalculator::calculate_cbe_usd(cbe_sov, sov_usd);
        assert_eq!(cbe_usd, 300_000_000); // $3
    }

    #[test]
    fn test_conversions() {
        // price_usd_cents uses 4-decimal units: 1 unit = $0.0001
        // Example: $0.0218 → 218 units (0.0218 * 10_000 = 218)
        // 8-decimal representation: 0.0218 * 100_000_000 = 2_180_000
        //
        // from_cents formula: cents * PRICE_SCALE / 10_000
        // 218 * 100_000_000 / 10_000 = 2_180_000
        let cents = 218u128; // $0.0218 in 4-decimal units
        let price_8dec = PricingCalculator::from_cents(cents);
        assert_eq!(price_8dec, 2_180_000);

        // Round trip: to_cents formula: (price_8dec * 10_000) / PRICE_SCALE
        // (2_180_000 * 10_000) / 100_000_000 = 218
        let back_to_cents = PricingCalculator::to_cents(price_8dec);
        assert_eq!(back_to_cents, cents);
    }

    #[test]
    fn test_price_history() {
        let mut state = TokenPricingState::new();
        
        // Record some prices
        state.record_price("CBE", 1_700_000_000, 300); // $3.00
        state.record_price("CBE", 1_700_000_100, 310); // $3.10
        state.record_price("CBE", 1_700_000_200, 305); // $3.05
        
        let history = state.get_price_history("CBE");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], (1_700_000_000, 300));
        assert_eq!(history[2], (1_700_000_200, 305));
    }

    /// Issue #1852: Verify oracle is observer-only
    #[test]
    fn test_oracle_observer_only() {
        let state = TokenPricingState::new();
        
        // Oracle does not set prices - only observes.
        // update_cbe_usd_price() and dynamic_pricing_active still exist as deprecated
        // backward-compatibility stubs but do not affect computed prices.
        // The only active price path is observe_curve_price() from the bonding curve.
        assert!(state.observed_curve_price.is_none());
        assert!(!state.dynamic_pricing_active); // deprecated field, always false
        // Calling the deprecated update method must not change observed_curve_price
        let mut state_mut = state;
        state_mut.update_cbe_usd_price(999_000_000, 1, 1_700_000_000);
        assert!(state_mut.observed_curve_price.is_none(), "oracle update must not set observed price");
    }
}
