//! Piecewise Linear Bonding Curve Pricing
//!
//! Implements Issue #1842: Document-compliant piecewise linear curve
//! with 4 supply bands and price continuity across boundaries.
//!
//! # Price Function
//! ```text
//! price(S) = m_i × S + b_i
//! ```
//! Where:
//! - S = circulating supply in atomic units (8 decimals, 1 token = 10^8 units)
//! - m_i = slope for supply band i (scaled by COMBINED_SCALE = 10^16)
//! - b_i = base offset for supply band i (scaled by PRICE_SCALE = 10^8)
//!
//! # Supply Bands (from specification)
//! | Band | Supply Range      | Slope      | Base          |
//! |------|-------------------|------------|---------------|
//! | 1    | [0 – 10B]         | 2.5e-12    | 0.0003133457  |
//! | 2    | [10B – 30B]       | 7.5e-12    | -0.000024     |
//! | 3    | [30B – 60B]       | 1.5e-11    | -0.000249     |
//! | 4    | [60B – 100B]      | 3.0e-11    | -0.001149     |
//!
//! NOTE: The specification's base values do NOT produce continuous pricing
//! with the given slopes. We use adjusted base values that ensure continuity.

use serde::{Deserialize, Serialize};

/// Fixed-point scale for price calculations (8 decimals = 10^8)
pub const PRICE_SCALE: u128 = 100_000_000;

/// Supply scale (1 token = 10^8 atomic units)
pub const SUPPLY_SCALE: u128 = 100_000_000;

/// Combined scale for slope calculations (PRICE_SCALE * SUPPLY_SCALE = 10^16)
pub const COMBINED_SCALE: u128 = 10_000_000_000_000_000u128;

/// Supply band definition for piecewise linear curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyBand {
    /// Start of supply range (inclusive, atomic units)
    pub start_supply: u64,
    /// End of supply range (exclusive, atomic units)
    pub end_supply: u64,
    /// Slope (m_i) scaled by COMBINED_SCALE
    /// Actual slope = slope / COMBINED_SCALE
    pub slope: u64,
    /// Base offset (b_i) scaled by PRICE_SCALE
    /// Actual base = base_offset / PRICE_SCALE
    pub base_offset: i64,
}

/// Piecewise linear bonding curve
///
/// Implements the document-compliant 4-band linear curve for CBE token launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiecewiseLinearCurve {
    /// Supply bands (must be sorted by start_supply)
    pub bands: Vec<SupplyBand>,
    /// Maximum supply (100B CBE in atomic units)
    pub max_supply: u64,
}

impl Default for PiecewiseLinearCurve {
    fn default() -> Self {
        Self::cbe_default()
    }
}

impl PiecewiseLinearCurve {
    /// Create the default CBE curve with 4 bands
    ///
    /// Uses adjusted base values to ensure price continuity.
    /// The slopes match the specification exactly.
    pub fn cbe_default() -> Self {
        let one_billion = 1_000_000_000u64;
        let token_scale = 100_000_000u64; // 8 decimals, 1 CBE = 10^8 atomic units

        // Calculate slopes in fixed-point
        // slope_fixed = slope_actual × COMBINED_SCALE
        // COMBINED_SCALE = 10^16
        //
        // Band 1: slope = 2.5e-12
        // slope_fixed = 2.5e-12 × 10^16 = 25,000
        //
        // Band 2: slope = 7.5e-12
        // slope_fixed = 7.5e-12 × 10^16 = 75,000
        //
        // Band 3: slope = 1.5e-11
        // slope_fixed = 1.5e-11 × 10^16 = 150,000
        //
        // Band 4: slope = 3.0e-11
        // slope_fixed = 3.0e-11 × 10^16 = 300,000

        let slope_1: u64 = 25_000;
        let slope_2: u64 = 75_000;
        let slope_3: u64 = 150_000;
        let slope_4: u64 = 300_000;

        // Calculate bases for continuity
        // Formula: price(S) = base_i + slope_i × S / COMBINED_SCALE
        //
        // For continuity at boundary between band i and i+1:
        // base_i + slope_i × S_boundary / COMBINED_SCALE = base_{i+1} + slope_{i+1} × S_boundary / COMBINED_SCALE
        // => base_{i+1} = base_i + (slope_i - slope_{i+1}) × S_boundary / COMBINED_SCALE
        //
        // Since slope_{i+1} > slope_i (steeper curves in later bands),
        // (slope_i - slope_{i+1}) is negative, so bases decrease.

        let base_1: i64 = 31_335; // 0.0003133457 × 10^8

        // Band 1 to 2 boundary at 10B tokens = 10^9 × 10^8 = 10^18 atomic units
        let boundary_1: u128 = (10 * one_billion as u128) * (token_scale as u128);
        let delta_1 = ((slope_2 as i128 - slope_1 as i128) * boundary_1 as i128) / COMBINED_SCALE as i128;
        let base_2: i64 = base_1 - delta_1 as i64;

        // Band 2 to 3 boundary at 30B tokens
        let boundary_2: u128 = (30 * one_billion as u128) * (token_scale as u128);
        let delta_2 = ((slope_3 as i128 - slope_2 as i128) * boundary_2 as i128) / COMBINED_SCALE as i128;
        let base_3: i64 = base_2 - delta_2 as i64;

        // Band 3 to 4 boundary at 60B tokens
        let boundary_3: u128 = (60 * one_billion as u128) * (token_scale as u128);
        let delta_3 = ((slope_4 as i128 - slope_3 as i128) * boundary_3 as i128) / COMBINED_SCALE as i128;
        let base_4: i64 = base_3 - delta_3 as i64;

        Self {
            bands: vec![
                SupplyBand {
                    start_supply: 0,
                    end_supply: 10 * one_billion * token_scale,
                    slope: slope_1,
                    base_offset: base_1,
                },
                SupplyBand {
                    start_supply: 10 * one_billion * token_scale,
                    end_supply: 30 * one_billion * token_scale,
                    slope: slope_2,
                    base_offset: base_2,
                },
                SupplyBand {
                    start_supply: 30 * one_billion * token_scale,
                    end_supply: 60 * one_billion * token_scale,
                    slope: slope_3,
                    base_offset: base_3,
                },
                SupplyBand {
                    start_supply: 60 * one_billion * token_scale,
                    end_supply: 100 * one_billion * token_scale,
                    slope: slope_4,
                    base_offset: base_4,
                },
            ],
            max_supply: 100 * one_billion * token_scale,
        }
    }

    /// Calculate price at given supply
    ///
    /// Formula: price(S) = base_i + slope_i × S / COMBINED_SCALE
    ///
    /// # Arguments
    /// * `supply` - Current circulating supply (atomic units, 8 decimals)
    ///
    /// # Returns
    /// Price per token in SOV (8-decimal fixed-point)
    pub fn price_at(&self, supply: u64) -> u128 {
        let band = self.band_for_supply(supply);
        
        // price = base + slope × supply / COMBINED_SCALE
        // Use signed arithmetic, then convert to unsigned
        let supply_scaled = supply as i128;
        let slope_component = (band.slope as i128).saturating_mul(supply_scaled) / COMBINED_SCALE as i128;
        let price = (band.base_offset as i128).saturating_add(slope_component);
        
        price.max(1) as u128 // Ensure non-zero price
    }

    /// Get the supply band for a given supply amount
    pub fn band_for_supply(&self, supply: u64) -> &SupplyBand {
        self.bands
            .iter()
            .find(|b| supply >= b.start_supply && supply < b.end_supply)
            .unwrap_or_else(|| self.bands.last().expect("at least one band"))
    }

    /// Get the band index (1-indexed for human readability)
    pub fn band_index_for_supply(&self, supply: u64) -> usize {
        self.bands
            .iter()
            .position(|b| supply >= b.start_supply && supply < b.end_supply)
            .map(|i| i + 1)
            .unwrap_or(self.bands.len())
    }

    /// Verify price continuity at band boundaries
    pub fn verify_continuity(&self) -> bool {
        for i in 1..self.bands.len() {
            let prev_band = &self.bands[i - 1];
            let curr_band = &self.bands[i];

            // Price at end of previous band (just before boundary)
            let s_prev = (prev_band.end_supply - 1) as i128;
            let slope_prev = (prev_band.slope as i128).saturating_mul(s_prev) / COMBINED_SCALE as i128;
            let price_prev = (prev_band.base_offset as i128) + slope_prev;

            // Price at start of current band (at boundary)
            let s_curr = curr_band.start_supply as i128;
            let slope_curr = (curr_band.slope as i128).saturating_mul(s_curr) / COMBINED_SCALE as i128;
            let price_curr = (curr_band.base_offset as i128) + slope_curr;

            // Allow small rounding error (1 unit)
            if price_prev.abs_diff(price_curr) > 1 {
                return false;
            }
        }
        true
    }

    /// Get initial price (at supply = 0)
    pub fn initial_price(&self) -> u128 {
        self.price_at(0)
    }

    /// Quote buy: calculate CBE tokens received for SOV input
    /// This is a simplified implementation
    pub fn quote_buy(&self, current_supply: u64, sov_in: u64) -> u64 {
        if sov_in == 0 || current_supply >= self.max_supply {
            return 0;
        }

        // Simplified: use average price approximation
        let current_price = self.price_at(current_supply);
        let approximate_tokens = (sov_in as u128 * PRICE_SCALE) / current_price.max(1);
        
        approximate_tokens.min((self.max_supply - current_supply) as u128) as u64
    }

    /// Quote sell: calculate SOV received for CBE input
    /// This is a simplified implementation
    pub fn quote_sell(&self, current_supply: u64, cbe_in: u64) -> u64 {
        if cbe_in == 0 || cbe_in > current_supply {
            return 0;
        }

        // Simplified: use average price approximation
        let avg_supply = current_supply - cbe_in / 2;
        let avg_price = self.price_at(avg_supply);
        
        ((cbe_in as u128) * avg_price / PRICE_SCALE) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_price() {
        let curve = PiecewiseLinearCurve::cbe_default();
        let price = curve.initial_price();
        // Expected: ~0.0003133457 SOV per CBE = ~31,335 in 8-decimal
        assert!(price > 30_000 && price < 35_000, "Initial price should be ~31,335, got {}", price);
    }

    #[test]
    fn test_price_continuity_at_boundaries() {
        let curve = PiecewiseLinearCurve::cbe_default();
        assert!(curve.verify_continuity(), "Price must be continuous at band boundaries");
    }

    #[test]
    fn test_price_increases_with_supply() {
        let curve = PiecewiseLinearCurve::cbe_default();
        let price_low = curve.price_at(1_000_000_000); // Low supply
        let price_high = curve.price_at(50_000_000_000_000_000); // High supply (50B)
        assert!(price_high > price_low, "Price must increase with supply");
    }

    #[test]
    fn test_band_detection() {
        let curve = PiecewiseLinearCurve::cbe_default();
        
        // Band 1: 0-10B
        assert_eq!(curve.band_index_for_supply(0), 1);
        
        // Band 2: 10B-30B
        let band2_start = 10_000_000_000_000_000_00u64;
        assert_eq!(curve.band_index_for_supply(band2_start), 2);
        
        // Band 3: 30B-60B
        let band3_start = 30_000_000_000_000_000_00u64;
        assert_eq!(curve.band_index_for_supply(band3_start), 3);
        
        // Band 4: 60B-100B
        let band4_start = 60_000_000_000_000_000_00u64;
        assert_eq!(curve.band_index_for_supply(band4_start), 4);
    }

    #[test]
    fn test_buy_quote_non_zero() {
        let curve = PiecewiseLinearCurve::cbe_default();
        let sov_in = 1_000_000_000; // 10 SOV
        let tokens = curve.quote_buy(0, sov_in);
        assert!(tokens > 0, "Should receive tokens for SOV input");
    }

    #[test]
    fn test_zero_buy_returns_zero() {
        let curve = PiecewiseLinearCurve::cbe_default();
        let tokens = curve.quote_buy(0, 0);
        assert_eq!(tokens, 0);
    }

    #[test]
    fn test_zero_sell_returns_zero() {
        let curve = PiecewiseLinearCurve::cbe_default();
        let sov = curve.quote_sell(1_000_000, 0);
        assert_eq!(sov, 0);
    }
}
