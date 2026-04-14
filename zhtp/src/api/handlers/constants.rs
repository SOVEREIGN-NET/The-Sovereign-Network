//! Constants for API handlers
//! Centralized location for all magic numbers and configuration constants

/// SOV atomic units (18 decimals): 1 SOV = 10^18 units
pub const SOV_ATOMIC_UNITS: u128 = lib_types::sov::SCALE;

/// SOV token welcome bonus amount (human units)
pub const SOV_WELCOME_BONUS_SOV: u128 = 5_000;

/// SOV token welcome bonus amount for new users (atomic units)
pub const SOV_WELCOME_BONUS: u128 = lib_types::sov::atoms(5_000);

/// Custom ZHTP recovery phrase word count
pub const ZHTP_RECOVERY_PHRASE_WORD_COUNT: usize = 20;

/// Standard BIP39 mnemonic word count
pub const BIP39_WORD_COUNT: usize = 24;
