//! SOV token constants — single source of truth for runtime.
//!
//! SOV uses 18 decimals everywhere: protocol constants, runtime contracts,
//! and storage (sled already uses u128 via `Amount`).

/// Token name
pub const SOV_TOKEN_NAME: &str = "Sovereign";

/// Token symbol
pub const SOV_TOKEN_SYMBOL: &str = "SOV";

/// Canonical protocol decimals (re-exported from lib-types).
pub use lib_types::SOV_DECIMALS as SOV_PROTOCOL_DECIMALS;

/// Canonical protocol total supply in whole tokens.
pub use lib_types::SOV_TOTAL_SUPPLY_TOKENS;

/// Canonical protocol max supply in atomic units (18 decimals).
pub use lib_types::SOV_MAX_SUPPLY as SOV_PROTOCOL_MAX_SUPPLY;

/// Runtime decimals — unified with protocol (18 decimals).
pub const SOV_TOKEN_DECIMALS: u8 = 18;

/// Runtime max-supply ceiling in atomic units (18 decimals).
/// 1 trillion SOV × 10^18 atoms per token.
pub const SOV_TOKEN_MAX_SUPPLY: u128 = lib_types::SOV_MAX_SUPPLY;

/// Transaction fee rate: 100 basis points = 1%
pub const SOV_FEE_RATE_BPS: u16 = 100;
