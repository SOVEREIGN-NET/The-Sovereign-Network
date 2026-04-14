//! Canonical tokenomics constants and arithmetic — protocol-level only.
//!
//! Only the SOV system token lives here. DAO tokens (CBE, etc.) define their
//! own constants in their respective contract modules.
//!
//! # Usage
//!
//! All SOV amounts MUST go through the [`sov`] helpers. Never multiply by
//! raw scale factors. This ensures a single source of truth for decimals.
//!
//! ```rust,ignore
//! use lib_types::tokenomics::sov;
//! let welcome_bonus = sov::atoms(5_000);  // 5,000 SOV in atomic units
//! let display = sov::to_display(balance); // atomic units → human-readable f64
//! ```

/// Canonical 18-decimal scale for SOV.
pub const TOKEN_SCALE_18: u128 = 1_000_000_000_000_000_000;

/// SOV display decimals.
pub const SOV_DECIMALS: u8 = 18;

/// Total SOV supply in whole tokens.
pub const SOV_TOTAL_SUPPLY_TOKENS: u128 = 1_000_000_000_000;

/// Total SOV supply in atomic units.
pub const SOV_MAX_SUPPLY: u128 = SOV_TOTAL_SUPPLY_TOKENS * TOKEN_SCALE_18;

/// SOV arithmetic helpers — single source of truth for decimal conversion.
///
/// Every SOV amount calculation in the codebase must use these functions
/// instead of raw `* 100_000_000` or `* TOKEN_SCALE_18` multiplication.
pub mod sov {
    use super::TOKEN_SCALE_18;

    /// Convert whole SOV tokens to atomic units (18 decimals).
    /// `sov::atoms(5_000)` = 5,000 × 10^18
    #[inline]
    pub const fn atoms(whole_tokens: u128) -> u128 {
        whole_tokens * TOKEN_SCALE_18
    }

    /// Convert a fractional SOV amount to atomic units.
    /// `sov::frac_atoms(1, 10)` = 0.1 SOV = 10^17 atoms.
    /// Panics if `denominator` is 0.
    #[inline]
    pub const fn frac_atoms(numerator: u128, denominator: u128) -> u128 {
        (numerator * TOKEN_SCALE_18) / denominator
    }

    /// Convert atomic units to human-readable f64 (lossy, for display only).
    #[inline]
    pub fn to_display(atomic_units: u128) -> f64 {
        atomic_units as f64 / TOKEN_SCALE_18 as f64
    }

    /// The scale factor itself (10^18). Prefer `atoms()` over using this directly.
    pub const SCALE: u128 = TOKEN_SCALE_18;
}
