//! SOV token constants.
//!
//! The semantic protocol values live in `lib-types::tokenomics`.
//! This module keeps the existing `u64` runtime token-contract compatibility
//! constants until the token core/storage model is widened to `u128`.

/// Token name
pub const SOV_TOKEN_NAME: &str = "Sovereign";

/// Token symbol
pub const SOV_TOKEN_SYMBOL: &str = "SOV";

/// Canonical protocol decimals.
pub use lib_types::SOV_DECIMALS as SOV_PROTOCOL_DECIMALS;

/// Canonical protocol total supply in whole tokens.
pub use lib_types::SOV_TOTAL_SUPPLY_TOKENS;

/// Canonical protocol max supply in atomic units.
pub use lib_types::SOV_MAX_SUPPLY as SOV_PROTOCOL_MAX_SUPPLY;

/// Legacy runtime decimals still used by the `u64` token contract.
pub const SOV_TOKEN_DECIMALS: u8 = 8;

/// Legacy runtime max-supply ceiling for the `u64` token contract.
/// This is a compatibility ceiling, not the semantic SOV issuance target.
pub const SOV_TOKEN_MAX_SUPPLY: u64 = 21_000_000 * 100_000_000;

/// Transaction fee rate: 100 basis points = 1%
pub const SOV_FEE_RATE_BPS: u16 = 100;
