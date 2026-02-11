//! Constants for API handlers
//! Centralized location for all magic numbers and configuration constants

/// SOV atomic units (8 decimals): 1 SOV = 100,000,000 units
pub const SOV_ATOMIC_UNITS: u64 = 100_000_000;

/// SOV token welcome bonus amount (human units)
pub const SOV_WELCOME_BONUS_SOV: u64 = 5_000;

/// SOV token welcome bonus amount for new users (atomic units)
pub const SOV_WELCOME_BONUS: u64 = SOV_WELCOME_BONUS_SOV * SOV_ATOMIC_UNITS;

/// Custom ZHTP recovery phrase word count
pub const ZHTP_RECOVERY_PHRASE_WORD_COUNT: usize = 20;

/// Standard BIP39 mnemonic word count
pub const BIP39_WORD_COUNT: usize = 24;
