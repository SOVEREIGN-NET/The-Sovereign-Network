//! Canonical tokenomics constants — protocol-level only.
//!
//! Only the SOV system token lives here. DAO tokens (CBE, etc.) define their
//! own constants in their respective contract modules.

/// Canonical 18-decimal scale for SOV.
pub const TOKEN_SCALE_18: u128 = 1_000_000_000_000_000_000;

/// SOV display decimals.
pub const SOV_DECIMALS: u8 = 18;

/// Total SOV supply in whole tokens.
pub const SOV_TOTAL_SUPPLY_TOKENS: u128 = 1_000_000_000_000;

/// Total SOV supply in atomic units.
pub const SOV_MAX_SUPPLY: u128 = SOV_TOTAL_SUPPLY_TOKENS * TOKEN_SCALE_18;
