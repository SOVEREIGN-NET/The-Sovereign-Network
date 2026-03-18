//! Canonical tokenomics constants.
//!
//! These are the semantic protocol values for token supply and decimals.
//! Domain crates that still use legacy `u64` token accounting may need
//! compatibility adapters until they are widened to `u128`.

/// Canonical 18-decimal scale shared by CBE and SOV.
pub const TOKEN_SCALE_18: u128 = 1_000_000_000_000_000_000;

/// SOV display decimals.
pub const SOV_DECIMALS: u8 = 18;

/// Total SOV supply in whole tokens.
pub const SOV_TOTAL_SUPPLY_TOKENS: u128 = 1_000_000_000_000;

/// Total SOV supply in atomic units.
pub const SOV_MAX_SUPPLY: u128 = SOV_TOTAL_SUPPLY_TOKENS * TOKEN_SCALE_18;

/// CBE display decimals.
pub const CBE_DECIMALS: u8 = 18;

/// Total CBE supply in whole tokens.
pub const CBE_TOTAL_SUPPLY_TOKENS: u128 = 100_000_000_000;

/// Total CBE supply in atomic units.
pub const CBE_MAX_SUPPLY: u128 = CBE_TOTAL_SUPPLY_TOKENS * TOKEN_SCALE_18;
