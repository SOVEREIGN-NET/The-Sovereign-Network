//! Bonding Curve Token Types
//!
//! Defines the state machine and core types for the bonding curve → AMM graduation system.
//!
//! # State Machine
//! ```text
//!   ┌─────────┐     Threshold Met      ┌───────────┐     Pool Seeded      ┌─────┐
//!   │  Curve  │ ─────────────────────▶ │ Graduated │ ──────────────────▶ │ AMM │
//!   └─────────┘    (irreversible)      └───────────┘    (irreversible)   └─────┘
//! ```
//!
//! # Phase Transitions
//! - Curve → Graduated: Automatic when threshold met, or callable if condition true
//! - Graduated → AMM: After AMM pool is seeded with liquidity
//! - No reverse transitions allowed

use serde::{Deserialize, Serialize};

/// Token scale: 1 whole token = 10^8 atomic units (8 decimals).
/// Matches `pricing::SUPPLY_SCALE`; defined here to avoid cross-module imports.
const TOKEN_SCALE: u64 = 100_000_000;

/// Basis points denominator (10_000 bps = 100%)
const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

// ============================================================================
// Issue #1846: Graduation Threshold Constants
// ============================================================================

/// Graduation threshold in USD (whole dollars).
/// 
/// Per CBE Token Launch specification: $269,000 USD reserve value triggers graduation.
/// This constant ensures the threshold is defined in one place and used consistently.
pub const GRADUATION_THRESHOLD_USD: u64 = 269_000;

/// Maximum acceptable age for oracle price data (in seconds).
/// 
/// Safety mechanism: If oracle price is older than this, graduation cannot proceed.
/// Prevents manipulation using stale price data.
pub const MAX_ORACLE_PRICE_AGE_SECONDS: u64 = 300; // 5 minutes

/// Required confirmation period before graduation (in blocks).
/// 
/// Safety mechanism: Graduation must be pending for this many blocks before execution.
/// Allows time for validators to detect and challenge invalid graduation attempts.
pub const GRADUATION_CONFIRMATION_BLOCKS: u64 = 3;

/// Price scale for fixed-point arithmetic (8 decimals).
/// Used for USD value calculations with SOV/USD oracle price.
pub const USD_PRICE_SCALE: u128 = 100_000_000;

/// Maximum iterations for the iterative buy approximation (overflow guard)
const MAX_BUY_ITERATIONS: u32 = 1_000;

/// Maximum supply-in-whole-tokens fed into growth-rate exponential to prevent overflow
const MAX_SUPPLY_WHOLE_FOR_GROWTH: u64 = 100;

/// Sigmoid: divisor that produces half-max price at midpoint supply
/// = 2 × TOKEN_SCALE, derived from: ratio(midpoint) × max_price / (2 × TOKEN_SCALE) = max_price / 2
const SIGMOID_HALF_MAX_DIVISOR: u128 = 2 * TOKEN_SCALE as u128;

/// Token lifecycle phase
///
/// Explicit state machine for bonding curve → AMM graduation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Active bonding curve pricing and minting
    Curve,
    /// Threshold met, curve frozen, preparing for AMM
    Graduated,
    /// AMM pool active, market-driven pricing
    AMM,
}

impl Phase {
    /// Check if token can be purchased via curve
    pub fn can_buy_curve(&self) -> bool {
        matches!(self, Phase::Curve)
    }

    /// Check if token can be sold via curve (if sell enabled)
    pub fn can_sell_curve(&self) -> bool {
        matches!(self, Phase::Curve)
    }

    /// Check if curve pricing is active
    pub fn is_curve_active(&self) -> bool {
        matches!(self, Phase::Curve)
    }

    /// Check if token has graduated
    pub fn is_graduated(&self) -> bool {
        matches!(self, Phase::Graduated | Phase::AMM)
    }

    /// Check if AMM is active
    pub fn is_amm_active(&self) -> bool {
        matches!(self, Phase::AMM)
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::Curve => write!(f, "curve"),
            Phase::Graduated => write!(f, "graduated"),
            Phase::AMM => write!(f, "amm"),
        }
    }
}

/// Bonding curve pricing formula types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurveType {
    /// Linear: price = base_price + slope × supply
    Linear {
        /// Initial price at zero supply (in stablecoin atomic units)
        base_price: u64,
        /// Price increase per token (in stablecoin atomic units)
        slope: u64,
    },
    /// Exponential: price = base_price × (1 + growth_rate)^supply
    Exponential {
        /// Initial price (in stablecoin atomic units)
        base_price: u64,
        /// Growth rate per token (in basis points, e.g., 100 = 1%)
        growth_rate_bps: u64,
    },
    /// Sigmoid: price = max_price / (1 + e^(-steepness × (supply - midpoint)))
    Sigmoid {
        /// Maximum price at saturation (in stablecoin atomic units)
        max_price: u64,
        /// Supply at which price is 50% of max
        midpoint_supply: u64,
        /// Steepness of the curve (higher = steeper)
        steepness: u64,
    },
    /// Piecewise Linear: Document-compliant 4-band curve
    /// See: lib-blockchain/src/contracts/bonding_curve/pricing.rs
    PiecewiseLinear(crate::contracts::bonding_curve::pricing::PiecewiseLinearCurve),
}

impl CurveType {
    /// Calculate price at given supply
    ///
    /// # Arguments
    /// * `supply` - Current token supply (in token atomic units)
    ///
    /// # Returns
    /// Price per token in stablecoin atomic units
    pub fn calculate_price(&self, supply: u64) -> u64 {
        match self {
            CurveType::Linear { base_price, slope } => {
                // price = base_price + slope × supply
                // Note: supply is in atomic units, need to normalize
                let supply_whole = supply / TOKEN_SCALE; // Convert to whole tokens
                base_price.saturating_add(slope.saturating_mul(supply_whole))
            }
            CurveType::Exponential {
                base_price,
                growth_rate_bps,
            } => {
                // For small growth rates, use approximation
                // price = base_price × (1 + rate)^supply
                // Simplified: linear approximation for small supplies
                let supply_whole = supply / TOKEN_SCALE;
                let multiplier = BASIS_POINTS_DENOMINATOR.saturating_add(
                    growth_rate_bps.saturating_mul(supply_whole.min(MAX_SUPPLY_WHOLE_FOR_GROWTH)),
                );
                (*base_price as u128)
                    .saturating_mul(multiplier as u128)
                    .saturating_div(BASIS_POINTS_DENOMINATOR as u128) as u64
            }
            CurveType::Sigmoid {
                max_price,
                midpoint_supply,
                steepness,
            } => {
                // Simplified sigmoid: piecewise linear approximation
                // For supply << midpoint: price ≈ max_price × e^(steepness × (supply - midpoint))
                // For supply ≈ midpoint: price ≈ max_price / 2
                // For supply >> midpoint: price ≈ max_price
                if supply <= *midpoint_supply {
                    let ratio = (supply as u128)
                        .saturating_mul(TOKEN_SCALE as u128)
                        .saturating_div(*midpoint_supply as u128);
                    (*max_price as u128)
                        .saturating_mul(ratio)
                        .saturating_div(SIGMOID_HALF_MAX_DIVISOR) as u64
                } else {
                    let excess = supply.saturating_sub(*midpoint_supply);
                    let approach_factor = excess.saturating_mul(*steepness).min(TOKEN_SCALE);
                    let half_max = (*max_price).saturating_div(2);
                    let remaining = (*max_price).saturating_sub(half_max);
                    let additional = (remaining as u128)
                        .saturating_mul(approach_factor as u128)
                        .saturating_div(TOKEN_SCALE as u128) as u64;
                    half_max.saturating_add(additional)
                }
            }
            CurveType::PiecewiseLinear(curve) => {
                curve.price_at(supply).min(u64::MAX as u128) as u64
            }
        }
    }

    /// Get display name for the curve type
    pub fn name(&self) -> &'static str {
        match self {
            CurveType::Linear { .. } => "linear",
            CurveType::Exponential { .. } => "exponential",
            CurveType::Sigmoid { .. } => "sigmoid",
            CurveType::PiecewiseLinear(_) => "piecewise_linear",
        }
    }

    /// Calculate tokens received for a given stablecoin amount (buy)
    ///
    /// Uses integral of price curve to calculate exact token amount.
    /// For linear curves: tokens = (sqrt(base² + 2×slope×stable) - base) / slope
    ///
    /// # Arguments
    /// * `current_supply` - Current token supply
    /// * `stable_amount` - Amount of stablecoin to spend
    ///
    /// # Returns
    /// Tokens to mint (in atomic units)
    pub fn calculate_buy_tokens(&self, current_supply: u64, stable_amount: u64) -> u64 {
        match self {
            CurveType::PiecewiseLinear(curve) => {
                curve.quote_buy(current_supply, stable_amount)
            }
            CurveType::Linear { base_price, slope } => {
                // For linear curve: price = base + slope × supply
                // Cost to buy from supply S1 to S2:
                // ∫(base + slope×s) ds from S1 to S2 = base×(S2-S1) + slope/2×(S2²-S1²)
                // Solving for S2 given cost C:
                // S2 = (-base + sqrt(base² + 2×slope×C + 2×base×slope×S1 + slope²×S1²)) / slope - S1
                // Simplified: use iterative approach for accuracy

                if *slope == 0 {
                    // Constant price: tokens = stable / base
                    return (stable_amount as u128)
                        .saturating_mul(TOKEN_SCALE as u128)
                        .saturating_div((*base_price).max(1) as u128)
                        as u64;
                }

                let supply_whole = current_supply / TOKEN_SCALE;
                let mut tokens_out: u64 = 0;
                let mut remaining_stable = stable_amount;
                let mut current_price =
                    (*base_price).saturating_add((*slope).saturating_mul(supply_whole));

                // Iterative approximation (MAX_BUY_ITERATIONS cap prevents unbounded loops)
                for _ in 0..MAX_BUY_ITERATIONS {
                    if remaining_stable == 0 || current_price == 0 {
                        break;
                    }

                    // Buy one atomic-unit chunk at a time
                    let token_chunk = remaining_stable
                        .saturating_div(current_price)
                        .min(TOKEN_SCALE);
                    if token_chunk == 0 {
                        break;
                    }

                    tokens_out = tokens_out.saturating_add(token_chunk);
                    remaining_stable = remaining_stable.saturating_sub(
                        (token_chunk as u128)
                            .saturating_mul(current_price as u128)
                            .saturating_div(TOKEN_SCALE as u128) as u64,
                    );

                    // Update price for next iteration
                    let new_supply_whole = supply_whole.saturating_add(tokens_out / TOKEN_SCALE);
                    current_price =
                        (*base_price).saturating_add((*slope).saturating_mul(new_supply_whole));
                }

                tokens_out
            }
            CurveType::Exponential {
                base_price,
                growth_rate_bps,
            } => {
                // Approximate: treat as linear with average growth
                let supply_whole = current_supply / TOKEN_SCALE;
                let current_price = (*base_price).saturating_add(
                    (*base_price)
                        .saturating_mul((*growth_rate_bps).saturating_mul(supply_whole.min(MAX_SUPPLY_WHOLE_FOR_GROWTH)))
                        / BASIS_POINTS_DENOMINATOR,
                );

                (stable_amount as u128)
                    .saturating_mul(TOKEN_SCALE as u128)
                    .saturating_div(current_price.max(1) as u128) as u64
            }
            CurveType::Sigmoid {
                max_price,
                midpoint_supply,
                steepness: _,
            } => {
                // Approximate based on current price level
                let current_price = if current_supply <= *midpoint_supply {
                    let ratio = (current_supply as u128)
                        .saturating_mul(TOKEN_SCALE as u128)
                        .saturating_div(*midpoint_supply as u128);
                    (*max_price as u128)
                        .saturating_mul(ratio)
                        .saturating_div(SIGMOID_HALF_MAX_DIVISOR) as u64
                } else {
                    (*max_price).saturating_div(2)
                };

                (stable_amount as u128)
                    .saturating_mul(TOKEN_SCALE as u128)
                    .saturating_div(current_price.max(1) as u128) as u64
            }
        }
    }

    /// Calculate stablecoin received for selling tokens (sell)
    ///
    /// # Arguments
    /// * `current_supply` - Current token supply
    /// * `token_amount` - Amount of tokens to sell
    ///
    /// # Returns
    /// Stablecoin to return (in atomic units)
    pub fn calculate_sell_stable(&self, current_supply: u64, token_amount: u64) -> u64 {
        match self {
            CurveType::PiecewiseLinear(curve) => {
                curve.quote_sell(current_supply, token_amount)
            }
            CurveType::Linear { base_price, slope } => {
                // Area under curve from (supply - tokens) to supply
                let supply_whole = current_supply / TOKEN_SCALE;
                let tokens_whole = token_amount / TOKEN_SCALE;
                let start_supply = supply_whole.saturating_sub(tokens_whole);

                // Integral: base×tokens + slope/2×(supply² - start²)
                let base_component = (*base_price).saturating_mul(tokens_whole);

                let slope_component = (*slope).saturating_mul(
                    supply_whole
                        .saturating_mul(supply_whole)
                        .saturating_sub(start_supply.saturating_mul(start_supply)),
                ) / 2;

                base_component.saturating_add(slope_component)
            }
            CurveType::Exponential {
                base_price,
                growth_rate_bps,
            } => {
                let supply_whole = current_supply / TOKEN_SCALE;
                let tokens_whole = token_amount / TOKEN_SCALE;
                let avg_supply = supply_whole.saturating_sub(tokens_whole / 2);

                let avg_price = (*base_price).saturating_add(
                    (*base_price).saturating_mul((*growth_rate_bps).saturating_mul(avg_supply.min(MAX_SUPPLY_WHOLE_FOR_GROWTH)))
                        / BASIS_POINTS_DENOMINATOR,
                );

                (token_amount as u128)
                    .saturating_mul(avg_price as u128)
                    .saturating_div(TOKEN_SCALE as u128) as u64
            }
            CurveType::Sigmoid {
                max_price,
                midpoint_supply,
                steepness: _,
            } => {
                let supply_whole = current_supply / TOKEN_SCALE;
                let tokens_whole = token_amount / TOKEN_SCALE;
                let avg_supply = supply_whole.saturating_sub(tokens_whole / 2);

                let avg_price = if avg_supply <= *midpoint_supply {
                    let ratio = (avg_supply as u128)
                        .saturating_mul(TOKEN_SCALE as u128)
                        .saturating_div(*midpoint_supply as u128);
                    (*max_price as u128)
                        .saturating_mul(ratio)
                        .saturating_div(SIGMOID_HALF_MAX_DIVISOR) as u64
                } else {
                    (*max_price).saturating_div(2)
                };

                (token_amount as u128)
                    .saturating_mul(avg_price as u128)
                    .saturating_div(TOKEN_SCALE as u128) as u64
            }
        }
    }
}

/// Graduation threshold conditions
///
/// Defines when a bonding curve token graduates to AMM phase.
/// Thresholds are immutable after deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Threshold {
    /// Minimum reserve amount in stablecoin
    ReserveAmount(u64),
    /// Minimum token supply
    SupplyAmount(u64),
    /// Time elapsed AND minimum reserve
    TimeAndReserve {
        min_time_seconds: u64,
        min_reserve: u64,
    },
    /// Time elapsed AND minimum supply
    TimeAndSupply {
        min_time_seconds: u64,
        min_supply: u64,
    },
    /// Issue #1846: Reserve value in USD using oracle price.
    /// 
    /// Graduation triggers when `reserve_sov * sov_usd_price >= threshold_usd`.
    /// Requires oracle price data that is not stale (within MAX_ORACLE_PRICE_AGE_SECONDS).
    ReserveValueUsd {
        /// Minimum reserve value in USD (whole dollars, e.g., 269_000 for $269K)
        threshold_usd: u64,
        /// Maximum age of oracle price (seconds) - safety mechanism
        max_price_age_seconds: u64,
        /// Required confirmation blocks - safety mechanism
        confirmation_blocks: u64,
    },
}

impl Threshold {
    /// Check if graduation threshold is met
    ///
    /// # Arguments
    /// * `reserve` - Current reserve balance
    /// * `supply` - Current token supply
    /// * `elapsed_seconds` - Time since deployment
    pub fn is_met(&self, reserve: u64, supply: u64, elapsed_seconds: u64) -> bool {
        match self {
            Threshold::ReserveAmount(min_reserve) => reserve >= *min_reserve,
            Threshold::SupplyAmount(min_supply) => supply >= *min_supply,
            Threshold::TimeAndReserve {
                min_time_seconds,
                min_reserve,
            } => elapsed_seconds >= *min_time_seconds && reserve >= *min_reserve,
            Threshold::TimeAndSupply {
                min_time_seconds,
                min_supply,
            } => elapsed_seconds >= *min_time_seconds && supply >= *min_supply,
            Threshold::ReserveValueUsd { .. } => {
                // USD-based check requires oracle price - use `is_met_with_oracle`
                false
            }
        }
    }

    /// Issue #1846: Check if USD-based graduation threshold is met.
    ///
    /// Calculates reserve value in USD using oracle SOV/USD price.
    /// Includes safety checks for stale price data.
    ///
    /// # Arguments
    /// * `reserve_sov` - Current reserve balance in SOV (atomic units)
    /// * `sov_usd_price` - Oracle SOV/USD price (8-decimal fixed-point)
    /// * `price_age_seconds` - Age of oracle price (seconds)
    /// * `pending_blocks` - Number of blocks graduation has been pending (0 to skip confirmation check)
    ///
    /// # Returns
    /// `true` if threshold is met and all safety checks pass
    pub fn is_met_with_oracle(
        &self,
        reserve_sov: u64,
        sov_usd_price: u64,
        price_age_seconds: u64,
        pending_blocks: u64,
    ) -> bool {
        let Threshold::ReserveValueUsd {
            threshold_usd,
            max_price_age_seconds,
            confirmation_blocks,
        } = self else {
            // Non-USD thresholds use standard is_met
            return false;
        };

        // Safety check 1: Oracle price must not be stale
        if price_age_seconds > *max_price_age_seconds {
            return false;
        }

        // Safety check 2: Confirmation period (only if pending_blocks > 0 or we're checking specifically)
        // Note: When pending_blocks is 0, we skip this check to allow checking threshold value only
        if pending_blocks > 0 && pending_blocks < *confirmation_blocks {
            return false;
        }

        // Calculate reserve value in USD:
        // 1. Convert reserve from atomic to whole SOV: reserve_sov / TOKEN_SCALE
        // 2. Multiply by price: whole_sov * sov_usd_price
        // 3. Divide by USD_PRICE_SCALE to get whole USD
        let reserve_whole_sov = reserve_sov / TOKEN_SCALE;
        let reserve_value_usd = (reserve_whole_sov as u128)
            .saturating_mul(sov_usd_price as u128)
            .saturating_div(USD_PRICE_SCALE);

        // Check if threshold is met
        reserve_value_usd >= *threshold_usd as u128
    }

    /// Get human-readable description
    pub fn description(&self) -> String {
        match self {
            Threshold::ReserveAmount(r) => format!("Reserve >= ${}", r / 100),
            Threshold::SupplyAmount(s) => format!("Supply >= {} tokens", s / TOKEN_SCALE),
            Threshold::TimeAndReserve {
                min_time_seconds,
                min_reserve,
            } => format!(
                "Time >= {}s AND Reserve >= ${}",
                min_time_seconds,
                min_reserve / 100
            ),
            Threshold::TimeAndSupply {
                min_time_seconds,
                min_supply,
            } => format!(
                "Time >= {}s AND Supply >= {} tokens",
                min_time_seconds,
                min_supply / 100_000_000
            ),
            Threshold::ReserveValueUsd {
                threshold_usd,
                max_price_age_seconds,
                confirmation_blocks,
            } => format!(
                "Reserve Value >= ${} USD (max_price_age: {}s, confirmation: {} blocks)",
                threshold_usd, max_price_age_seconds, confirmation_blocks
            ),
        }
    }

    /// Get the USD threshold value (if applicable)
    pub fn threshold_usd(&self) -> Option<u64> {
        match self {
            Threshold::ReserveValueUsd { threshold_usd, .. } => Some(*threshold_usd),
            _ => None,
        }
    }
}

/// Price confidence level for valuation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Deterministic curve pricing
    DeterministicCurve,
    /// TWAP with sufficient liquidity
    TwapLiquiditySufficient,
    /// TWAP with low liquidity (higher risk)
    TwapLowLiquidity,
    /// No reliable price available
    None,
}

impl ConfidenceLevel {
    /// Check if price is reliable for protocol operations
    pub fn is_reliable(&self) -> bool {
        !matches!(self, ConfidenceLevel::None)
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            ConfidenceLevel::DeterministicCurve => "deterministic_curve",
            ConfidenceLevel::TwapLiquiditySufficient => "twap_liquidity_sufficient",
            ConfidenceLevel::TwapLowLiquidity => "twap_low_liquidity",
            ConfidenceLevel::None => "none",
        }
    }
}

/// Token valuation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Valuation {
    /// Price per token in USD cents
    pub price_usd_cents: u64,
    /// Value of queried amount in USD cents
    pub value_usd_cents: u64,
    /// Price source
    pub source: PriceSource,
    /// Confidence level
    pub confidence: ConfidenceLevel,
}

/// Price source for valuation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriceSource {
    /// SRV from Treasury Kernel (SOV only)
    SRV,
    /// Bonding curve pricing
    BondingCurve,
    /// AMM spot price
    AMM_Spot,
    /// AMM TWAP price
    AMM_TWAP,
}

impl PriceSource {
    pub fn name(&self) -> &'static str {
        match self {
            PriceSource::SRV => "srv",
            PriceSource::BondingCurve => "bonding_curve",
            PriceSource::AMM_Spot => "amm_spot",
            PriceSource::AMM_TWAP => "amm_twap",
        }
    }
}

/// Bonding curve token statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurveStats {
    /// Current token supply
    pub total_supply: u64,
    /// Current reserve balance in stablecoin (20% of purchases)
    pub reserve_balance: u64,
    /// Current price in stablecoin
    pub current_price: u64,
    /// Time since deployment (seconds)
    pub elapsed_seconds: u64,
    /// Graduation threshold progress (0-100)
    pub graduation_progress_percent: u8,
    /// Whether threshold is currently met
    pub can_graduate: bool,
    /// Current treasury balance in stablecoin (80% of purchases)
    /// Issue #1844: Reserve and Treasury 20/80 Split
    /// NOTE: Field is at end of struct intentionally — bincode is positional.
    #[serde(default)]
    pub treasury_balance: u64,
}

/// Errors for bonding curve operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurveError {
    /// Invalid phase for operation
    InvalidPhase { current: Phase, required: Phase },
    /// Curve has already graduated
    AlreadyGraduated,
    /// Insufficient reserve for sell operation
    InsufficientReserve,
    /// Zero amount not allowed
    ZeroAmount,
    /// Arithmetic overflow
    Overflow,
    /// Invalid curve parameters
    InvalidParameters(String),
    /// Threshold not yet met
    ThresholdNotMet,
    /// AMM pool not found
    PoolNotFound,
    /// Unauthorized operation
    Unauthorized,
}

impl std::fmt::Display for CurveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurveError::InvalidPhase { current, required } => {
                write!(
                    f,
                    "Invalid phase: current={}, required={}",
                    current, required
                )
            }
            CurveError::AlreadyGraduated => write!(f, "Token has already graduated"),
            CurveError::InsufficientReserve => write!(f, "Insufficient reserve for operation"),
            CurveError::ZeroAmount => write!(f, "Amount must be greater than zero"),
            CurveError::Overflow => write!(f, "Arithmetic overflow"),
            CurveError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            CurveError::ThresholdNotMet => write!(f, "Graduation threshold not yet met"),
            CurveError::PoolNotFound => write!(f, "AMM pool not found"),
            CurveError::Unauthorized => write!(f, "Unauthorized operation"),
        }
    }
}

impl std::error::Error for CurveError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_transitions() {
        assert!(Phase::Curve.can_buy_curve());
        assert!(!Phase::Graduated.can_buy_curve());
        assert!(!Phase::AMM.can_buy_curve());

        assert!(!Phase::Curve.is_graduated());
        assert!(Phase::Graduated.is_graduated());
        assert!(Phase::AMM.is_graduated());

        assert!(!Phase::Curve.is_amm_active());
        assert!(!Phase::Graduated.is_amm_active());
        assert!(Phase::AMM.is_amm_active());
    }

    #[test]
    fn test_linear_curve_pricing() {
        // Linear: price = 0.10 + 0.0001 × supply
        let curve = CurveType::Linear {
            base_price: 10_000_000, // $0.10
            slope: 10_000,          // $0.0001 per token
        };

        // At 0 supply: price = $0.10
        assert_eq!(curve.calculate_price(0), 10_000_000);

        // At 1000 tokens: price = $0.10 + $0.0001 × 1000 = $0.20
        let price_1000 = curve.calculate_price(1_000 * 100_000_000);
        assert_eq!(price_1000, 20_000_000);

        // At 5000 tokens: price = $0.10 + $0.0001 × 5000 = $0.60
        let price_5000 = curve.calculate_price(5_000 * 100_000_000);
        assert_eq!(price_5000, 60_000_000);
    }

    #[test]
    fn test_threshold_check() {
        let threshold = Threshold::ReserveAmount(100_000_000); // $1M

        assert!(!threshold.is_met(99_999_999, 0, 0));
        assert!(threshold.is_met(100_000_000, 0, 0));
        assert!(threshold.is_met(150_000_000, 0, 0));

        let threshold = Threshold::TimeAndReserve {
            min_time_seconds: 3600,
            min_reserve: 100_000_000,
        };

        assert!(!threshold.is_met(100_000_000, 0, 3599)); // Time not met
        assert!(threshold.is_met(100_000_000, 0, 3600)); // Both met
        assert!(!threshold.is_met(99_999_999, 0, 3600)); // Reserve not met
    }

    #[test]
    fn test_curve_type_names() {
        let linear = CurveType::Linear {
            base_price: 100,
            slope: 1,
        };
        assert_eq!(linear.name(), "linear");

        let exp = CurveType::Exponential {
            base_price: 100,
            growth_rate_bps: 100,
        };
        assert_eq!(exp.name(), "exponential");

        let sigmoid = CurveType::Sigmoid {
            max_price: 1000,
            midpoint_supply: 1000 * 100_000_000,
            steepness: 1000,
        };
        assert_eq!(sigmoid.name(), "sigmoid");
    }
}
