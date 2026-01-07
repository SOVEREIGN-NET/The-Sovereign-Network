use serde::{Deserialize, Serialize};
use std::fmt;

/// Month index - deterministic height-based identification
/// month_index = current_height / blocks_per_month
pub type MonthIndex = u64;

/// Amount in smallest token units with overflow checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    /// Create a new Amount with validation (non-zero)
    ///
    /// # Errors
    /// Returns error if value is zero
    pub fn try_new(value: u64) -> Result<Self, Error> {
        if value == 0 {
            return Err(Error::ZeroAmount);
        }
        Ok(Amount(value))
    }

    /// Create Amount from u64, allowing zero (for initial state)
    pub fn from_u64(value: u64) -> Self {
        Amount(value)
    }

    /// Get the inner value
    pub fn get(self) -> u64 {
        self.0
    }

    /// Check if amount is zero
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Safe addition with overflow check
    pub fn checked_add(self, other: Amount) -> Result<Amount, Error> {
        self.0
            .checked_add(other.0)
            .map(Amount)
            .ok_or(Error::Overflow)
    }

    /// Safe subtraction with underflow check
    pub fn checked_sub(self, other: Amount) -> Result<Amount, Error> {
        self.0
            .checked_sub(other.0)
            .map(Amount)
            .ok_or(Error::Overflow)
    }
}

/// Error types for UBI Distribution contract
///
/// All failures return explicit errors (no panics, no silent failures)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Caller is not the governance authority
    Unauthorized,

    /// Citizen (by key_id) already registered
    AlreadyRegistered,

    /// Citizen (by key_id) not registered
    NotRegistered,

    /// Citizen already claimed UBI for this month
    AlreadyPaidThisMonth,

    /// Contract balance insufficient for payout
    InsufficientFunds,

    /// Amount is zero (not allowed)
    ZeroAmount,

    /// Arithmetic overflow/underflow
    Overflow,

    /// Token transfer failed
    TokenTransferFailed,

    /// Invalid schedule configuration (e.g., end_month < start_month)
    InvalidSchedule,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unauthorized => write!(f, "Unauthorized: not governance authority"),
            Error::AlreadyRegistered => write!(f, "Citizen already registered"),
            Error::NotRegistered => write!(f, "Citizen not registered"),
            Error::AlreadyPaidThisMonth => write!(f, "Citizen already paid this month"),
            Error::InsufficientFunds => write!(f, "Insufficient funds for payout"),
            Error::ZeroAmount => write!(f, "Amount must be greater than zero"),
            Error::Overflow => write!(f, "Arithmetic overflow/underflow"),
            Error::TokenTransferFailed => write!(f, "Token transfer failed"),
            Error::InvalidSchedule => write!(f, "Invalid schedule configuration"),
        }
    }
}
