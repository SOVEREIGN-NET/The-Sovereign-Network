//! Hash utilities for blockchain
//!
//! Provides hash computation and verification utilities used throughout
//! the blockchain implementation. Integrates with lib-crypto for hashing.

use serde::{Serialize, Deserialize};
use anyhow::Result;

/// Hash wrapper type for ZHTP blockchain
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Create a new hash from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create a hash from a slice (truncate or pad to 32 bytes)
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        let len = std::cmp::min(bytes.len(), 32);
        hash[..len].copy_from_slice(&bytes[..len]);
        Hash(hash)
    }

    /// Get hash as bytes slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get hash as array
    pub fn as_array(&self) -> [u8; 32] {
        self.0
    }

    /// Create hash from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, anyhow::Error> {
        let hex_str = hex_str.trim_start_matches("0x");
        if hex_str.len() != 64 {
            return Err(anyhow::anyhow!("Invalid hex string length"));
        }
        
        match hex::decode(hex_str) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(anyhow::anyhow!("Invalid hash length"));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok(Hash(hash))
            }
            Err(_) => Err(anyhow::anyhow!("Invalid hex string")),
        }
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Check if this is the zero hash
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Create zero hash
    pub fn zero() -> Self {
        Hash([0u8; 32])
    }
}

impl Default for Hash {
    fn default() -> Self {
        Hash::zero()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> [u8; 32] {
        hash.0
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Hash a byte slice using Blake3 (via lib-crypto integration)
pub fn blake3_hash(data: &[u8]) -> Hash {
    // This integrates with lib-crypto package
    let hash_bytes = crate::integration::crypto_integration::hash_data(data);
    Hash::new(hash_bytes)
}

/// Convert a hash to hexadecimal string representation
pub fn hash_to_hex(hash: &Hash) -> String {
    hash.to_hex()
}

/// Parse a hexadecimal string into a hash
pub fn hex_to_hash(hex_str: &str) -> Result<Hash, anyhow::Error> {
    Hash::from_hex(hex_str)
}

/// Zero hash constant
pub fn zero_hash() -> Hash {
    Hash::zero()
}

/// Check if a hash is the zero hash
pub fn is_zero_hash(hash: &Hash) -> bool {
    hash.is_zero()
}

/// Trait for types that can be hashed
pub trait Hashable {
    fn hash(&self) -> Hash;
}

/// Implement Hashable for common types
impl Hashable for Vec<u8> {
    fn hash(&self) -> Hash {
        blake3_hash(self)
    }
}

impl Hashable for &[u8] {
    fn hash(&self) -> Hash {
        blake3_hash(self)
    }
}

impl Hashable for String {
    fn hash(&self) -> Hash {
        blake3_hash(self.as_bytes())
    }
}

impl Hashable for &str {
    fn hash(&self) -> Hash {
        blake3_hash(self.as_bytes())
    }
}
