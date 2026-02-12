//! Canonical SOV Token Constants — Single Source of Truth
//!
//! ALL SOV-related constants MUST be defined here. No other file should
//! define SOV constants — only re-export from this module.
//!
//! # On-Chain Compatibility
//!
//! `SOV_TOKEN_MAX_SUPPLY` is the runtime value used by `new_sov_native()` and
//! persisted in `blockchain.dat` via bincode. Changing it would break deserialization
//! of existing chain data. This value serves as a u64 ceiling for the TokenContract,
//! not a distribution target.

/// Token name
pub const SOV_TOKEN_NAME: &str = "Sovereign";

/// Token symbol
pub const SOV_TOKEN_SYMBOL: &str = "SOV";

/// Number of decimal places (1 SOV = 10^8 atomic units)
pub const SOV_TOKEN_DECIMALS: u8 = 8;

/// Maximum supply ceiling for the TokenContract (u64).
/// This is the value stored on-chain in existing `.dat` files.
/// 21,000,000 * 10^8 = 2,100,000,000,000,000 atomic units.
pub const SOV_TOKEN_MAX_SUPPLY: u64 = 21_000_000 * 100_000_000;

/// Transaction fee rate: 100 basis points = 1%
pub const SOV_FEE_RATE_BPS: u16 = 100;
