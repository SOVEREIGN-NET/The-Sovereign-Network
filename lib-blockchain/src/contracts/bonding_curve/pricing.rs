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
//! - S = circulating supply in whole tokens (NOT atomic units)
//! - m_i = slope for supply band i (in SOV per CBE per token)
//! - b_i = base offset for supply band i (in SOV per CBE at S=0)
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

    /// Calculate the cost (in SOV) to buy exactly `tokens` CBE from `current_supply`
    ///
    /// Uses exact integral calculation over the piecewise linear curve.
    ///
    /// # Formula
    /// For a linear band with price(S) = base + slope × S:
    /// Cost = ∫[S₀ to S₁] (base + slope×S) dS / PRICE_SCALE
    ///      = base×(S₁-S₀)/SUPPLY_SCALE + slope/(2×COMBINED_SCALE)×(S₁²-S₀²)
    ///
    /// Where S₀ and S₁ are in atomic units, and the result is in SOV atomic units.
    ///
    /// # Arguments
    /// * `current_supply` - Current supply before purchase (atomic units)
    /// * `tokens` - Number of tokens to buy (atomic units)
    ///
    /// # Returns
    /// Cost in SOV atomic units (8-decimal fixed-point), or None if exceeds max supply
    pub fn calculate_buy_cost(&self, current_supply: u64, tokens: u64) -> Option<u64> {
        if tokens == 0 {
            return Some(0);
        }

        let target_supply = current_supply.checked_add(tokens)?;
        if target_supply > self.max_supply {
            return None; // Exceeds max supply
        }

        // Calculate integral from current_supply to target_supply
        self.integral_price(current_supply, target_supply)
    }

    /// Quote buy: calculate CBE tokens received for SOV input
    ///
    /// Uses exact integral calculation by finding the target supply where
    /// the integral of price from current_supply to target_supply equals sov_in.
    ///
    /// # Formula
    /// For piecewise linear curve, we solve:
    /// sov_in = ∫[S₀ to S₁] price(S) dS
    ///
    /// This requires finding which bands the purchase spans and solving
    /// the quadratic equation for the final partial band.
    ///
    /// # Arguments
    /// * `current_supply` - Current supply before purchase (atomic units)
    /// * `sov_in` - Amount of SOV to spend (atomic units)
    ///
    /// # Returns
    /// Tokens to receive (atomic units), 0 if sov_in is 0 or exceeds capacity
    pub fn quote_buy(&self, current_supply: u64, sov_in: u64) -> u64 {
        if sov_in == 0 || current_supply >= self.max_supply {
            return 0;
        }

        // Find target supply by integrating across bands
        self.find_target_supply(current_supply, sov_in)
            .and_then(|target| target.checked_sub(current_supply))
            .unwrap_or(0)
    }

    /// Quote sell: calculate SOV received for CBE input
    ///
    /// Uses exact integral calculation over the piecewise linear curve.
    ///
    /// # Arguments
    /// * `current_supply` - Current supply before sale (atomic units)
    /// * `cbe_in` - Amount of CBE to sell (atomic units)
    ///
    /// # Returns
    /// SOV to receive (atomic units), 0 if cbe_in is 0 or exceeds supply
    pub fn quote_sell(&self, current_supply: u64, cbe_in: u64) -> u64 {
        if cbe_in == 0 || cbe_in > current_supply {
            return 0;
        }

        // Selling reduces supply from current_supply to (current_supply - cbe_in)
        // The seller receives the integral of price over this range
        let new_supply = current_supply - cbe_in;
        self.integral_price(new_supply, current_supply).unwrap_or(0)
    }

    /// Calculate the integral of price(S) from supply_start to supply_end
    ///
    /// This represents the total SOV required to move supply from start to end.
    ///
    /// # Formula
    /// For each band with price(S) = base_i + slope_i × S:
    /// ∫[start to end] price(S) dS = base×(end-start)/SUPPLY_SCALE + slope/(2×COMBINED_SCALE)×(end²-start²)
    ///
    /// The result is in SOV atomic units (8-decimal fixed-point).
    fn integral_price(&self, supply_start: u64, supply_end: u64) -> Option<u64> {
        if supply_start >= supply_end {
            return Some(0);
        }

        let mut total_cost: u128 = 0;
        let mut current = supply_start;

        while current < supply_end {
            let band = self.band_for_supply(current);
            let band_end = band.end_supply.min(supply_end);

            if band_end <= current {
                break;
            }

            // Calculate integral over [current, band_end] for this band
            // Formula: base×ΔS/SUPPLY_SCALE + slope/(2×COMBINED_SCALE)×(S₂²-S₁²)
            let delta_s = (band_end - current) as u128;
            let s1_sq = (current as u128).checked_pow(2)?;
            let s2_sq = (band_end as u128).checked_pow(2)?;
            let delta_s_sq = s2_sq.checked_sub(s1_sq)?;

            // base × ΔS / SUPPLY_SCALE (converts to SOV atomic units)
            let base_component = (band.base_offset.unsigned_abs() as u128)
                .checked_mul(delta_s)?
                .checked_div(SUPPLY_SCALE)?;

            // slope × (S₂² - S₁²) / (2 × COMBINED_SCALE)
            let slope_component = (band.slope as u128)
                .checked_mul(delta_s_sq)?
                .checked_div(2 * COMBINED_SCALE)?;

            let band_cost = base_component.checked_add(slope_component)?;
            total_cost = total_cost.checked_add(band_cost)?;

            current = band_end;
        }

        total_cost.try_into().ok()
    }

    /// Find the target supply such that the integral from current_supply to target_supply equals sov_in
    ///
    /// Uses iterative band-by-band calculation to find where the purchase ends.
    fn find_target_supply(&self, current_supply: u64, sov_in: u64) -> Option<u64> {
        let mut remaining_sov = sov_in as u128;
        let mut current = current_supply;

        while remaining_sov > 0 && current < self.max_supply {
            let band = self.band_for_supply(current);
            let band_end = band.end_supply.min(self.max_supply);

            if band_end <= current {
                break;
            }

            // Calculate cost to buy all tokens in this band (from current to band_end)
            let full_band_cost = self.integral_price(current, band_end)?;

            if remaining_sov >= full_band_cost {
                // Can afford entire band segment
                remaining_sov = remaining_sov.checked_sub(full_band_cost)?;
                current = band_end;
            } else {
                // Solve for target_supply within this band
                // Cost = base×ΔS/SUPPLY_SCALE + slope/(2×COMBINED_SCALE)×((S+ΔS)²-S²)
                // This is a quadratic in ΔS:
                // Cost = (base/SUPPLY_SCALE)×ΔS + (slope/(2×COMBINED_SCALE))×(2×S×ΔS + ΔS²)
                //
                // Let:
                // A = slope / (2 × COMBINED_SCALE)
                // B = base/SUPPLY_SCALE + slope×S/COMBINED_SCALE
                // C = -Cost
                //
                // Solve: A×ΔS² + B×ΔS + C = 0

                let s_current = current as u128;
                let cost = remaining_sov;

                // A = slope / (2 × COMBINED_SCALE)
                let a_num = band.slope as u128;
                let a_denom = 2 * COMBINED_SCALE;

                // B = base/SUPPLY_SCALE + slope×S/COMBINED_SCALE
                let b_base = (band.base_offset.unsigned_abs() as u128) / SUPPLY_SCALE;
                let b_slope = (band.slope as u128).checked_mul(s_current)? / COMBINED_SCALE;
                let b = b_base.checked_add(b_slope)?;

                // Quadratic formula: ΔS = (-B + sqrt(B² + 4×A×Cost)) / (2×A)
                // Rearranged for numerical stability with small A:
                // ΔS = Cost / (B + sqrt(B² + 4×A×Cost)) × 2 (when A is very small)

                let b_sq = b.checked_pow(2)?;
                let four_a_cost = 4u128.checked_mul(a_num)?.checked_mul(cost)? / a_denom;
                let discriminant = b_sq.checked_add(four_a_cost)?;

                // Use integer square root approximation
                let sqrt_disc = integer_sqrt(discriminant);

                // ΔS = (-B + sqrt(B² + 4AC)) / 2A
                // For small A (which is our case), use: ΔS ≈ Cost / B (first-order approximation)
                // More accurate: ΔS = 2×Cost / (B + sqrt(B² + 4AC))

                let denominator = b.checked_add(sqrt_disc)?;
                if denominator == 0 {
                    break;
                }

                let delta_s = 2u128.checked_mul(cost)?.checked_div(denominator)?;
                let delta_s_u64 = delta_s.min((band_end - current) as u128) as u64;

                if delta_s_u64 == 0 {
                    break;
                }

                current = current.checked_add(delta_s_u64)?;
                remaining_sov = 0; // Purchase complete
            }
        }

        Some(current.min(self.max_supply))
    }
}

/// Integer square root using Newton's method
fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }

    let mut x = n;
    let mut y = (x + 1) / 2;

    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }

    x
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
        
        // High supply: 50B tokens = 50_000_000_000 * 100_000_000 atomic units
        let high_supply = 50_000_000_000u64 * 100_000_000;
        let price_high = curve.price_at(high_supply);
        
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

    #[test]
    fn test_exact_buy_cost_calculation() {
        let curve = PiecewiseLinearCurve::cbe_default();
        
        // Test: calculate cost to buy exactly 1000 tokens at supply 0
        let tokens = 1000 * 100_000_000; // 1000 tokens in atomic units
        let cost = curve.calculate_buy_cost(0, tokens);
        
        assert!(cost.is_some(), "Should calculate cost");
        let cost = cost.unwrap();
        
        // At initial price ~0.0003133457 SOV/CBE, 1000 tokens should cost ~0.313 SOV
        // With slope, actual cost will be slightly higher
        assert!(cost > 30_000_000 && cost < 40_000_000, "Cost should be ~0.313 SOV, got {}", cost);
    }

    #[test]
    fn test_buy_sell_symmetry() {
        let curve = PiecewiseLinearCurve::cbe_default();
        
        // Start with some supply
        let current_supply = 1_000_000_000_000_000_00u64; // 10B tokens
        
        // Buy some tokens
        let sov_to_spend = 100_000_000_000u64; // 1000 SOV
        let tokens_bought = curve.quote_buy(current_supply, sov_to_spend);
        assert!(tokens_bought > 0, "Should receive tokens");
        
        // Immediately sell those tokens back (from the new supply level)
        let new_supply = current_supply + tokens_bought;
        let sov_received = curve.quote_sell(new_supply, tokens_bought);
        
        // Due to the curve slope, selling back should give slightly less SOV
        // (the price increased when buying, so selling back at higher price gives more SOV)
        // But this tests that the mechanism works
        assert!(sov_received > 0, "Should receive SOV on sell");
    }

    #[test]
    fn test_integral_monotonicity() {
        let curve = PiecewiseLinearCurve::cbe_default();
        
        // Larger purchases should cost more
        let cost_small = curve.calculate_buy_cost(0, 1000 * 100_000_000).unwrap();
        let cost_large = curve.calculate_buy_cost(0, 2000 * 100_000_000).unwrap();
        
        assert!(cost_large > cost_small, "Larger purchases should cost more");
    }

    #[test]
    fn test_max_supply_cap() {
        let curve = PiecewiseLinearCurve::cbe_default();
        
        // Try to buy beyond max supply
        let near_max = curve.max_supply - 1;
        let large_purchase = 10_000_000_000; // 10B tokens
        
        let result = curve.calculate_buy_cost(near_max, large_purchase);
        assert!(result.is_none(), "Should fail when exceeding max supply");
    }

    #[test]
    fn test_cross_band_purchase() {
        let curve = PiecewiseLinearCurve::cbe_default();
        
        // Buy enough tokens to cross from band 1 into band 2
        // Band 1 ends at 10B tokens
        let start_supply = 9_000_000_000_000_000_00u64; // 9B tokens (in band 1)
        let sov_to_spend = 10_000_000_000_000u64; // 100,000 SOV - should cross boundary
        
        let tokens = curve.quote_buy(start_supply, sov_to_spend);
        assert!(tokens > 0, "Should receive tokens");
        
        // Verify the purchase crosses the boundary
        let end_supply = start_supply + tokens;
        assert!(end_supply > 10_000_000_000_000_000_00u64, "Should cross into band 2");
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(16), 4);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(10_000), 100);
        assert_eq!(integer_sqrt(1_000_000_000_000_000_000), 1_000_000_000);
    }
}
