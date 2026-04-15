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

use super::canonical::SCALE;

/// Token scale: 1 whole token = 10^18 atomic units (18 decimals).
const TOKEN_SCALE: u128 = SCALE;

// ============================================================================
// Issue #1846: Graduation Threshold Constants
// ============================================================================

/// Graduation threshold in USD (whole dollars).
///
/// Configuration B: $2,724,844 USD reserve value triggers graduation.
///
/// Derived from AMM crash analysis with 20B genesis CBE UNLOCKED:
///   S_c at graduation ≈ 0.97B CBE, total circulating ≈ 20.97B CBE
///   $2.7M reserve → AMM opens at ~40% of last curve price (60% discount)
///   This is the survivable AMM open scenario.
///
/// If 20B genesis tokens are LOCKED, revert to $269,000.
/// The two thresholds are paired to the lock decision.
///
/// This constant is the single source of truth — every graduation check
/// must reference this value, never a hardcoded literal.
pub const GRADUATION_THRESHOLD_USD: u128 = 2_724_844;

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
/// Re-exported from oracle to keep both modules in sync.
pub use crate::oracle::ORACLE_PRICE_SCALE as USD_PRICE_SCALE;

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
    /// Canonical 4-band CBE curve.
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
    pub fn calculate_price(&self, supply: u128) -> u128 {
        match self {
            CurveType::PiecewiseLinear(curve) => {
                // PiecewiseLinear was designed for u64 supply; with 18-decimal u128
                // values, supply routinely exceeds u64::MAX. Silently clamping to
                // u64::MAX produces incorrect prices — return 0 to signal out-of-range.
                match u64::try_from(supply) {
                    Ok(s) => curve.price_at(s),
                    Err(_) => 0,
                }
            }
        }
    }

    /// Get display name for the curve type
    pub fn name(&self) -> &'static str {
        match self {
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
    pub fn calculate_buy_tokens(&self, current_supply: u128, stable_amount: u128) -> u128 {
        match self {
            CurveType::PiecewiseLinear(curve) => {
                // PiecewiseLinear was designed for u64 inputs; with 18-decimal u128
                // amounts, both current_supply and stable_amount routinely exceed u64::MAX.
                // Return 0 (no tokens quoted) rather than clamping to u64::MAX, which
                // would silently return tokens for an out-of-range buy amount.
                let s = match u64::try_from(current_supply) {
                    Ok(v) => v,
                    Err(_) => return 0,
                };
                let amt = match u64::try_from(stable_amount) {
                    Ok(v) => v,
                    Err(_) => return 0,
                };
                curve.quote_buy(s, amt) as u128
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
    pub fn calculate_sell_stable(&self, current_supply: u128, token_amount: u128) -> u128 {
        match self {
            CurveType::PiecewiseLinear(curve) => curve.quote_sell(
                u64::try_from(current_supply).unwrap_or(u64::MAX),
                u64::try_from(token_amount).unwrap_or(u64::MAX),
            ) as u128,
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
    ReserveAmount(u128),
    /// Minimum token supply
    SupplyAmount(u128),
    /// Time elapsed AND minimum reserve
    TimeAndReserve {
        min_time_seconds: u64,
        min_reserve: u128,
    },
    /// Time elapsed AND minimum supply
    TimeAndSupply {
        min_time_seconds: u64,
        min_supply: u128,
    },
    /// Issue #1846: Reserve value in USD using oracle price.
    ///
    /// Graduation triggers when `reserve_sov * sov_usd_price >= threshold_usd`.
    /// Requires oracle price data that is not stale (within MAX_ORACLE_PRICE_AGE_SECONDS).
    ReserveValueUsd {
        /// Minimum reserve value in USD (whole dollars) — use GRADUATION_THRESHOLD_USD
        threshold_usd: u128,
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
    pub fn is_met(&self, reserve: u128, supply: u128, elapsed_seconds: u64) -> bool {
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
        reserve_sov: u128,
        sov_usd_price: u128,
        price_age_seconds: u64,
        pending_blocks: u64,
    ) -> bool {
        let Threshold::ReserveValueUsd {
            threshold_usd,
            max_price_age_seconds,
            confirmation_blocks,
        } = self
        else {
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

        // Calculate reserve value in USD using full-precision arithmetic:
        //   reserve_value_usd = (reserve_sov_atomic * sov_usd_price) / (TOKEN_SCALE * USD_PRICE_SCALE)
        //
        // Multiply first to preserve fractional SOV — dividing reserve_sov by TOKEN_SCALE first
        // would truncate up to (TOKEN_SCALE - 1) atomic units (~0.99 SOV) before applying the
        // price, causing off-by-one threshold decisions near the graduation boundary.
        //
        // Use checked arithmetic: on overflow, conservatively treat threshold as not met.
        let numerator = match reserve_sov.checked_mul(sov_usd_price) {
            Some(v) => v,
            None => return false,
        };
        let denominator = TOKEN_SCALE * USD_PRICE_SCALE;
        let reserve_value_usd = numerator / denominator;

        // Check if threshold is met
        reserve_value_usd >= *threshold_usd
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
    pub fn threshold_usd(&self) -> Option<u128> {
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
    pub price_usd_cents: u128,
    /// Value of queried amount in USD cents
    pub value_usd_cents: u128,
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
    #[allow(non_camel_case_types)]
    AMM_Spot,
    /// AMM TWAP price
    #[allow(non_camel_case_types)]
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
    pub total_supply: u128,
    /// Current reserve balance in stablecoin (20% of purchases)
    pub reserve_balance: u128,
    /// Current price in stablecoin
    pub current_price: u128,
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
    pub treasury_balance: u128,
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
    fn test_piecewise_curve_pricing() {
        let curve = CurveType::PiecewiseLinear(
            crate::contracts::bonding_curve::pricing::PiecewiseLinearCurve::cbe_default(),
        );

        let initial_price = curve.calculate_price(0);
        let mid_price = curve.calculate_price(1_000_000_000);

        assert!(initial_price > 0);
        assert!(mid_price >= initial_price);
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
        let curve = CurveType::PiecewiseLinear(
            crate::contracts::bonding_curve::pricing::PiecewiseLinearCurve::cbe_default(),
        );
        assert_eq!(curve.name(), "piecewise_linear");
    }
}
