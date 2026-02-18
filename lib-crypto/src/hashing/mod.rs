//! Hashing module for ZHTP cryptography
//!
//! Provides Blake3 and SHA3-256 hashing functionality used throughout the system.
//!
//! # Canonical Consensus Hash (BFT-I, Issue #1010)
//!
//! **BLAKE3 is the canonical hash function for all consensus-critical data.**
//!
//! This includes block headers, state roots, vote IDs, and proposal IDs.
//! SHA-3 is available for non-consensus purposes but MUST NOT be used for
//! consensus commitments.  Using an alternate hash for consensus-critical
//! objects causes mismatched commitments and breaks BFT finality.
//!
//! See [`CONSENSUS_HASH_FUNCTION`] and [`canonical_consensus_hash`].

use blake3;
pub mod sha3;

pub use sha3::hash_sha3_256;

// ============================================================================
// CANONICAL CONSENSUS HASH (BFT-I, Issue #1010)
// ============================================================================

/// The canonical hash function for all consensus-critical data.
///
/// All block headers, state roots, and vote IDs MUST be hashed with BLAKE3.
pub const CONSENSUS_HASH_FUNCTION: &str = "BLAKE3";

/// Computes the canonical consensus hash of `data` using BLAKE3.
///
/// Use this for any data that enters a consensus-critical path.
pub fn canonical_consensus_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

#[cfg(test)]
mod canonical_hash_tests {
    use super::*;

    #[test]
    fn test_canonical_consensus_hash_is_deterministic() {
        let data = b"consensus-critical block header";
        assert_eq!(canonical_consensus_hash(data), canonical_consensus_hash(data));
    }

    #[test]
    fn test_canonical_consensus_hash_matches_blake3() {
        let data = b"state root commitment";
        let expected: [u8; 32] = blake3::hash(data).into();
        assert_eq!(canonical_consensus_hash(data), expected);
    }
}

/// Blake3 hash function - primary hash function for ZHTP
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    hash.into()
}

/// Hash multiple data segments
pub fn hash_blake3_multiple(data_segments: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for segment in data_segments {
        hasher.update(segment);
    }
    hasher.finalize().into()
}

/// Hash with custom key for keyed hashing
pub fn hash_blake3_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let hash = blake3::keyed_hash(key, data);
    hash.into()
}

/// Derive key using Blake3 KDF
pub fn derive_key_blake3(context: &str, key_material: &[u8]) -> [u8; 32] {
    let hash = blake3::derive_key(context, key_material);
    hash.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let data = b"hello world";
        let hash = hash_blake3(data);
        assert_eq!(hash.len(), 32);
        
        // Test consistency
        let hash2 = hash_blake3(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake3_multiple() {
        let data1 = b"hello";
        let data2 = b" ";
        let data3 = b"world";
        
        let hash1 = hash_blake3_multiple(&[data1, data2, data3]);
        let hash2 = hash_blake3(b"hello world");
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [42u8; 32];
        let data = b"test data";
        let hash = hash_blake3_keyed(&key, data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_derive() {
        let context = "ZHTP key derivation";
        let material = b"secret key material";
        let derived = derive_key_blake3(context, material);
        assert_eq!(derived.len(), 32);
    }
}