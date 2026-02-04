//! Constants for API handlers
//! Centralized location for all magic numbers and configuration constants

/// SOV token welcome bonus amount for new users
pub const SOV_WELCOME_BONUS: u64 = 5000;

/// Minimum word count for recovery phrases
pub const RECOVERY_PHRASE_MIN_WORDS: usize = 20;

/// Maximum word count for recovery phrases
pub const RECOVERY_PHRASE_MAX_WORDS: usize = 24;

/// Standard BIP39 mnemonic word count
pub const BIP39_WORD_COUNT: usize = 24;

/// Custom ZHTP recovery phrase word count
pub const ZHTP_RECOVERY_PHRASE_WORD_COUNT: usize = 20;
