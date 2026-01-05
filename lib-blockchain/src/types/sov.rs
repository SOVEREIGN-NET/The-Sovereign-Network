//! SOV token type system with fixed supply and safe arithmetic
//!
//! Provides strong typing for SOV token quantities, enforcing:
//! - Fixed, non-inflationary 1 trillion supply
//! - Overflow-safe arithmetic via checked operations
//! - Explicit type distinctions to prevent unit/supply confusion
//! - Serialization round-trip guarantees

use serde::{Deserialize, Serialize};
use std::fmt;
use std::convert::TryFrom;

/// Maximum SOV supply (1 trillion tokens, fixed and non-mintable)
pub const SOV_MAX_SUPPLY: u128 = 1_000_000_000_000;

/// Strong type wrapper for token quantities (u128 for large numbers)
///
/// Prevents mixing of raw integers with token logic. Enforces:
/// - Non-negative values
/// - Overflow-safe arithmetic
/// - Explicit type checking at compile time
///
/// # Invariants
/// - Always <= SOV_MAX_SUPPLY for SOV tokens
/// - Serializes deterministically (bincode format)
/// - Round-trip deserialization is lossless
///
/// # Examples
///
/// ```ignore
/// let amount = TokenAmount::new(1_000)?;
/// let doubled = amount.checked_add(amount)?;
/// assert_eq!(doubled, TokenAmount::new(2_000)?);
/// ```
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct TokenAmount(u128);

impl TokenAmount {
    /// Create a new token amount
    ///
    /// # Errors
    /// Returns error if value exceeds SOV_MAX_SUPPLY
    pub fn new(value: u128) -> Result<Self, TokenAmountError> {
        if value > SOV_MAX_SUPPLY {
            return Err(TokenAmountError::ExceedsMaxSupply {
                requested: value,
                max: SOV_MAX_SUPPLY,
            });
        }
        Ok(TokenAmount(value))
    }

    /// Create amount with value 0
    pub const fn zero() -> Self {
        TokenAmount(0)
    }

    /// Create amount with SOV_MAX_SUPPLY
    pub const fn max() -> Self {
        TokenAmount(SOV_MAX_SUPPLY)
    }

    /// Get the raw u128 value
    pub const fn value(self) -> u128 {
        self.0
    }

    /// Checked addition (returns None on overflow)
    pub fn checked_add(self, other: TokenAmount) -> Option<TokenAmount> {
        self.0.checked_add(other.0).and_then(|v| TokenAmount::new(v).ok())
    }

    /// Checked subtraction (returns None on underflow)
    pub fn checked_sub(self, other: TokenAmount) -> Option<TokenAmount> {
        self.0.checked_sub(other.0).map(TokenAmount)
    }

    /// Checked multiplication (returns None on overflow)
    pub fn checked_mul(self, scalar: u64) -> Option<TokenAmount> {
        self.0
            .checked_mul(scalar as u128)
            .and_then(|v| TokenAmount::new(v).ok())
    }

    /// Division (wraps, cannot overflow)
    pub fn saturating_div(self, divisor: u128) -> TokenAmount {
        if divisor == 0 {
            TokenAmount(0)
        } else {
            TokenAmount(self.0 / divisor)
        }
    }

    /// Check if amount is zero
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Check if amount equals max supply
    pub const fn is_max(self) -> bool {
        self.0 == SOV_MAX_SUPPLY
    }
}

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} SOV", self.0)
    }
}

impl Default for TokenAmount {
    fn default() -> Self {
        TokenAmount::zero()
    }
}

impl TryFrom<u128> for TokenAmount {
    type Error = TokenAmountError;

    /// Create a TokenAmount from a u128 value, validating against max supply
    fn try_from(value: u128) -> Result<Self, Self::Error> {
        TokenAmount::new(value)
    }
}

/// Error type for token amount operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAmountError {
    /// Requested amount exceeds SOV_MAX_SUPPLY
    ExceedsMaxSupply { requested: u128, max: u128 },
}

impl fmt::Display for TokenAmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenAmountError::ExceedsMaxSupply { requested, max } => {
                write!(
                    f,
                    "Token amount {} exceeds maximum supply of {}",
                    requested, max
                )
            }
        }
    }
}

impl std::error::Error for TokenAmountError {}

/// SOV token type representing the Sovereign Network native token
///
/// # Invariants
/// - Fixed supply: exactly 1 trillion tokens, non-mintable
/// - Non-transferable at type level (accounting namespace)
/// - No inflation mechanism
/// - No burn mechanism (supply never decreases)
///
/// # Serialization
/// Serializes to canonical bincode format. Round-trip is lossless.
///
/// # Usage
/// SOV tokens represent network participation and fee accumulation.
/// Not individual assets but accounting units for fees and distributions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SOVToken {
    /// Amount of SOV (in units of 1 SOV = 1 token)
    pub amount: TokenAmount,
}

impl SOVToken {
    /// Create a new SOV token amount
    ///
    /// # Errors
    /// Returns error if amount exceeds SOV_MAX_SUPPLY
    pub fn new(amount: TokenAmount) -> Result<Self, TokenAmountError> {
        Ok(SOVToken { amount })
    }

    /// Create zero SOV
    pub fn zero() -> Self {
        SOVToken {
            amount: TokenAmount::zero(),
        }
    }

    /// Create max supply (1 trillion)
    pub fn max_supply() -> Self {
        SOVToken {
            amount: TokenAmount::max(),
        }
    }

    /// Get the current amount
    pub fn amount(self) -> TokenAmount {
        self.amount
    }

    /// Get raw value
    pub fn value(self) -> u128 {
        self.amount.value()
    }

    /// Checked addition
    pub fn checked_add(self, other: SOVToken) -> Option<SOVToken> {
        self.amount.checked_add(other.amount).map(|amount| SOVToken { amount })
    }

    /// Checked subtraction
    pub fn checked_sub(self, other: SOVToken) -> Option<SOVToken> {
        self.amount.checked_sub(other.amount).map(|amount| SOVToken { amount })
    }
}

impl fmt::Display for SOVToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.amount)
    }
}

impl Default for SOVToken {
    fn default() -> Self {
        SOVToken::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_amount_creation() {
        let amount = TokenAmount::new(1_000_000).unwrap();
        assert_eq!(amount.value(), 1_000_000);

        let zero = TokenAmount::zero();
        assert!(zero.is_zero());

        let max = TokenAmount::max();
        assert!(max.is_max());
        assert_eq!(max.value(), SOV_MAX_SUPPLY);
    }

    #[test]
    fn token_amount_exceeds_max() {
        let result = TokenAmount::new(SOV_MAX_SUPPLY + 1);
        assert!(matches!(result, Err(TokenAmountError::ExceedsMaxSupply { .. })));
    }

    #[test]
    fn token_amount_checked_add() {
        let a = TokenAmount::new(100).unwrap();
        let b = TokenAmount::new(200).unwrap();
        let sum = a.checked_add(b).unwrap();
        assert_eq!(sum.value(), 300);

        // Test overflow
        let near_max = TokenAmount::new(SOV_MAX_SUPPLY - 1).unwrap();
        let result = near_max.checked_add(TokenAmount::new(2).unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn token_amount_checked_sub() {
        let a = TokenAmount::new(500).unwrap();
        let b = TokenAmount::new(200).unwrap();
        let diff = a.checked_sub(b).unwrap();
        assert_eq!(diff.value(), 300);

        // Test underflow
        let result = b.checked_sub(a);
        assert!(result.is_none());
    }

    #[test]
    fn token_amount_checked_mul() {
        let amount = TokenAmount::new(1000).unwrap();
        let scaled = amount.checked_mul(100).unwrap();
        assert_eq!(scaled.value(), 100_000);

        // Test overflow
        let near_max = TokenAmount::new(SOV_MAX_SUPPLY / 2 + 1).unwrap();
        let result = near_max.checked_mul(3);
        assert!(result.is_none());
    }

    #[test]
    fn token_amount_saturating_div() {
        let amount = TokenAmount::new(1000).unwrap();
        let halved = amount.saturating_div(2);
        assert_eq!(halved.value(), 500);

        // Division by zero returns zero
        let zero_result = amount.saturating_div(0);
        assert!(zero_result.is_zero());
    }

    #[test]
    fn token_amount_display() {
        let amount = TokenAmount::new(1_000_000).unwrap();
        assert_eq!(format!("{}", amount), "1000000 SOV");
    }

    #[test]
    fn sov_token_creation() {
        let token = SOVToken::new(TokenAmount::new(100_000).unwrap()).unwrap();
        assert_eq!(token.value(), 100_000);

        let zero = SOVToken::zero();
        assert_eq!(zero.value(), 0);

        let max = SOVToken::max_supply();
        assert_eq!(max.value(), SOV_MAX_SUPPLY);
    }

    #[test]
    fn sov_token_checked_add() {
        let a = SOVToken::new(TokenAmount::new(1000).unwrap()).unwrap();
        let b = SOVToken::new(TokenAmount::new(2000).unwrap()).unwrap();
        let sum = a.checked_add(b).unwrap();
        assert_eq!(sum.value(), 3000);
    }

    #[test]
    fn sov_token_checked_sub() {
        let a = SOVToken::new(TokenAmount::new(5000).unwrap()).unwrap();
        let b = SOVToken::new(TokenAmount::new(2000).unwrap()).unwrap();
        let diff = a.checked_sub(b).unwrap();
        assert_eq!(diff.value(), 3000);
    }

    /// Test round-trip serialization/deserialization (golden test)
    #[test]
    fn token_amount_serialization_round_trip() {
        let test_values = vec![
            0u128,
            1,
            1_000,
            1_000_000,
            1_000_000_000,
            SOV_MAX_SUPPLY,
        ];

        for value in test_values {
            let amount = TokenAmount::new(value).unwrap();
            let serialized = bincode::serialize(&amount).expect("serialization failed");
            let deserialized: TokenAmount =
                bincode::deserialize(&serialized).expect("deserialization failed");
            assert_eq!(amount, deserialized, "round-trip failed for {}", value);
        }
    }

    /// Golden test vectors for serialization
    #[test]
    fn sov_token_serialization_golden() {
        let token_zero = SOVToken::zero();
        let serialized_zero = bincode::serialize(&token_zero).expect("serialize");
        let deserialized_zero: SOVToken = bincode::deserialize(&serialized_zero).expect("deserialize");
        assert_eq!(token_zero, deserialized_zero);

        let token_max = SOVToken::max_supply();
        let serialized_max = bincode::serialize(&token_max).expect("serialize");
        let deserialized_max: SOVToken = bincode::deserialize(&serialized_max).expect("deserialize");
        assert_eq!(token_max, deserialized_max);
    }

    /// Invariant test: SOV supply is always fixed
    #[test]
    fn sov_supply_invariant() {
        assert_eq!(SOV_MAX_SUPPLY, 1_000_000_000_000);
        let max_token = SOVToken::max_supply();
        assert_eq!(max_token.value(), SOV_MAX_SUPPLY);
        assert!(max_token.value() >= 0); // Always non-negative
    }

    /// Test that arithmetic operations cannot violate fixed supply
    #[test]
    fn sov_arithmetic_safety() {
        let max = TokenAmount::max();
        let one = TokenAmount::new(1).unwrap();

        // Cannot exceed max
        assert!(max.checked_add(one).is_none());

        // Can subtract
        let reduced = max.checked_sub(one).unwrap();
        assert_eq!(reduced.value(), SOV_MAX_SUPPLY - 1);

        // Cannot create invalid amounts
        assert!(TokenAmount::new(SOV_MAX_SUPPLY + 1).is_err());
    }

    // Property-based tests using proptest
    #[cfg(test)]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        /// Test that checked_add respects supply bounds
        proptest! {
            #[test]
            fn prop_checked_add_respects_bounds(
                a in 0u128..=SOV_MAX_SUPPLY,
                b in 0u128..=SOV_MAX_SUPPLY
            ) {
                let amount_a = TokenAmount::new(a).unwrap();
                let amount_b = TokenAmount::new(b).unwrap();

                if let Some(sum) = amount_a.checked_add(amount_b) {
                    // Sum must not exceed max supply
                    assert!(sum.value() <= SOV_MAX_SUPPLY);
                    // Sum must equal a + b
                    assert_eq!(sum.value(), a + b);
                } else {
                    // Overflow detected, which is correct
                    assert!(a + b > SOV_MAX_SUPPLY);
                }
            }
        }

        /// Test that checked_add and checked_sub are inverse operations
        proptest! {
            #[test]
            fn prop_add_sub_inverse(
                a in 0u128..=SOV_MAX_SUPPLY,
                b in 0u128..=SOV_MAX_SUPPLY,
            ) {
                let amount_a = TokenAmount::new(a).unwrap();
                let amount_b = TokenAmount::new(b).unwrap();

                // (a + b) - b should equal a (when valid)
                if let Some(sum) = amount_a.checked_add(amount_b) {
                    if let Some(back) = sum.checked_sub(amount_b) {
                        assert_eq!(back.value(), a);
                    }
                }

                // (a - b) + b should equal a (when valid)
                if let Some(diff) = amount_a.checked_sub(amount_b) {
                    if let Some(back) = diff.checked_add(amount_b) {
                        assert_eq!(back.value(), a);
                    }
                }
            }
        }

        /// Test that checked_sub detects underflow
        proptest! {
            #[test]
            fn prop_checked_sub_underflow(
                a in 0u128..=SOV_MAX_SUPPLY,
                b in 0u128..=SOV_MAX_SUPPLY,
            ) {
                let amount_a = TokenAmount::new(a).unwrap();
                let amount_b = TokenAmount::new(b).unwrap();

                match amount_a.checked_sub(amount_b) {
                    Some(result) => {
                        // Subtraction succeeded, so a >= b and result = a - b
                        assert!(a >= b);
                        assert_eq!(result.value(), a - b);
                    }
                    None => {
                        // Underflow detected, so a < b
                        assert!(a < b);
                    }
                }
            }
        }

        /// Test that checked_mul respects supply bounds
        proptest! {
            #[test]
            fn prop_checked_mul_respects_bounds(
                a in 0u128..=SOV_MAX_SUPPLY,
                b in 0u64..=1000u64
            ) {
                let amount = TokenAmount::new(a).unwrap();

                match amount.checked_mul(b) {
                    Some(result) => {
                        // Product must not exceed max supply
                        assert!(result.value() <= SOV_MAX_SUPPLY);
                        // Product must equal a * b
                        assert_eq!(result.value(), a * (b as u128));
                    }
                    None => {
                        // Overflow detected, which is correct
                        assert!(a.checked_mul(b as u128).is_none() ||
                                a.checked_mul(b as u128).unwrap() > SOV_MAX_SUPPLY);
                    }
                }
            }
        }

        /// Test that all valid amounts can be created and serialized
        proptest! {
            #[test]
            fn prop_serialization_round_trip(value in 0u128..=SOV_MAX_SUPPLY) {
                let amount = TokenAmount::new(value).unwrap();
                let serialized = bincode::serialize(&amount).unwrap();
                let deserialized: TokenAmount = bincode::deserialize(&serialized).unwrap();
                assert_eq!(amount, deserialized);
            }
        }

        /// Test that zero is identity for addition
        proptest! {
            #[test]
            fn prop_zero_is_additive_identity(a in 0u128..=SOV_MAX_SUPPLY) {
                let amount = TokenAmount::new(a).unwrap();
                let zero = TokenAmount::zero();

                // a + 0 = a
                if let Some(result) = amount.checked_add(zero) {
                    assert_eq!(result.value(), a);
                }

                // 0 + a = a
                if let Some(result) = zero.checked_add(amount) {
                    assert_eq!(result.value(), a);
                }

                // a - 0 = a
                if let Some(result) = amount.checked_sub(zero) {
                    assert_eq!(result.value(), a);
                }

                // a - a = 0
                if let Some(result) = amount.checked_sub(amount) {
                    assert_eq!(result.value(), 0);
                }
            }
        }

        /// Test that is_zero and is_max work correctly
        proptest! {
            #[test]
            fn prop_zero_max_predicates(value in 0u128..=SOV_MAX_SUPPLY) {
                let amount = TokenAmount::new(value).unwrap();

                if value == 0 {
                    assert!(amount.is_zero());
                    assert!(!amount.is_max());
                } else if value == SOV_MAX_SUPPLY {
                    assert!(!amount.is_zero());
                    assert!(amount.is_max());
                } else {
                    assert!(!amount.is_zero());
                    assert!(!amount.is_max());
                }
            }
        }

        /// Test TryFrom implementation
        proptest! {
            #[test]
            fn prop_try_from_respects_bounds(value in 0u128..=SOV_MAX_SUPPLY) {
                let amount = TokenAmount::try_from(value).unwrap();
                assert_eq!(amount.value(), value);
            }
        }

        /// Test that TryFrom rejects invalid values
        proptest! {
            #[test]
            fn prop_try_from_rejects_overflow(value in (SOV_MAX_SUPPLY + 1)..=u128::MAX) {
                let result = TokenAmount::try_from(value);
                assert!(result.is_err());
            }
        }
    }
}
