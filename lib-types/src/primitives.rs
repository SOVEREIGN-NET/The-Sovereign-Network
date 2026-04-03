//! Canonical Primitive Types for ZHTP Consensus
//!
//! Rule: No String identifiers in consensus state. Ever.
//!
//! These types are the foundational building blocks for all consensus-critical
//! data structures. They are designed to be:
//! - Fixed-size (no dynamic allocation)
//! - Deterministically serializable
//! - Efficient to copy and compare

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// TYPE ALIASES
// ============================================================================

/// Block height in the chain (0-indexed)
pub type BlockHeight = u64;

/// Token amounts (supports up to ~340 undecillion units)
pub type Amount = u128;

/// Basis points for percentage calculations (10000 = 100%)
pub type Bps = u16;

// ============================================================================
// HASH TYPES
// ============================================================================

/// 32-byte block hash
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct BlockHash(pub [u8; 32]);

impl BlockHash {
    /// Create a new BlockHash from raw bytes
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a zeroed BlockHash
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if this is the zero hash
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHash({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<[u8; 32]> for BlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for BlockHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 32-byte transaction hash
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct TxHash(pub [u8; 32]);

impl TxHash {
    /// Create a new TxHash from raw bytes
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a zeroed TxHash
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if this is the zero hash
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxHash({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<[u8; 32]> for TxHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// IDENTITY TYPES
// ============================================================================

/// 32-byte address (derived from public key)
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Create a new Address from raw bytes
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a zeroed Address
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if this is the zero address
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// TOKEN TYPES
// ============================================================================

/// 32-byte token identifier
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct TokenId(pub [u8; 32]);

impl TokenId {
    /// Create a new TokenId from raw bytes
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a zeroed TokenId (represents native SOV token)
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Native SOV token ID (all zeros)
    pub const NATIVE: Self = Self([0u8; 32]);

    /// Get the underlying bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if this is the native token
    pub fn is_native(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_native() {
            write!(f, "TokenId(NATIVE)")
        } else {
            write!(f, "TokenId({})", hex::encode(&self.0[..8]))
        }
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_native() {
            write!(f, "SOV")
        } else {
            write!(f, "{}", hex::encode(&self.0))
        }
    }
}

impl From<[u8; 32]> for TokenId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TokenId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_hash_basics() {
        let hash = BlockHash::new([1u8; 32]);
        assert!(!hash.is_zero());
        assert_eq!(hash.as_bytes(), &[1u8; 32]);

        let zero = BlockHash::zero();
        assert!(zero.is_zero());
    }

    #[test]
    fn test_tx_hash_basics() {
        let hash = TxHash::new([2u8; 32]);
        assert!(!hash.is_zero());
        assert_eq!(hash.as_bytes(), &[2u8; 32]);
    }

    #[test]
    fn test_address_basics() {
        let addr = Address::new([3u8; 32]);
        assert!(!addr.is_zero());
        assert_eq!(addr.as_bytes(), &[3u8; 32]);
    }

    #[test]
    fn test_token_id_native() {
        let native = TokenId::NATIVE;
        assert!(native.is_native());
        assert_eq!(format!("{}", native), "SOV");

        let custom = TokenId::new([1u8; 32]);
        assert!(!custom.is_native());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let hash = BlockHash::new([42u8; 32]);
        let serialized = bincode::serialize(&hash).unwrap();
        let deserialized: BlockHash = bincode::deserialize(&serialized).unwrap();
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_from_array() {
        let bytes = [5u8; 32];
        let hash: BlockHash = bytes.into();
        assert_eq!(hash.0, bytes);

        let addr: Address = bytes.into();
        assert_eq!(addr.0, bytes);
    }
}
