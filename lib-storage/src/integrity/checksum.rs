//! Checksum management

use serde::{Deserialize, Serialize};
use lib_crypto::hashing::hash_blake3;
use std::collections::HashMap;

/// Checksum algorithm type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    /// Blake3 hashing (default, fastest)
    Blake3,
    /// SHA-256 (for compatibility)
    Sha256,
}

/// Checksum wrapper
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum {
    pub algorithm: ChecksumAlgorithm,
    pub hash: [u8; 32],
}

impl Checksum {
    /// Create new checksum
    pub fn new(algorithm: ChecksumAlgorithm, data: &[u8]) -> Self {
        let hash = match algorithm {
            ChecksumAlgorithm::Blake3 => hash_blake3(data),
            ChecksumAlgorithm::Sha256 => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().into()
            }
        };

        Self { algorithm, hash }
    }

    /// Verify data against this checksum
    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = Self::new(self.algorithm, data);
        self.hash == computed.hash
    }
}

/// Checksum manager for efficient checksum operations
pub struct ChecksumManager {
    /// Cached checksums
    cache: HashMap<String, Checksum>,
    /// Default algorithm
    default_algorithm: ChecksumAlgorithm,
}

impl ChecksumManager {
    /// Create new checksum manager
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            default_algorithm: ChecksumAlgorithm::Blake3,
        }
    }

    /// Compute and cache checksum
    pub fn compute(&mut self, key: String, data: &[u8]) -> Checksum {
        let checksum = Checksum::new(self.default_algorithm, data);
        self.cache.insert(key, checksum.clone());
        checksum
    }

    /// Get cached checksum
    pub fn get_cached(&self, key: &str) -> Option<&Checksum> {
        self.cache.get(key)
    }

    /// Verify data against cached checksum
    pub fn verify_cached(&self, key: &str, data: &[u8]) -> Option<bool> {
        self.cache.get(key).map(|checksum| checksum.verify(data))
    }

    /// Clear cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Set default algorithm
    pub fn set_default_algorithm(&mut self, algorithm: ChecksumAlgorithm) {
        self.default_algorithm = algorithm;
    }
}

impl Default for ChecksumManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_creation() {
        let data = b"test data";
        let checksum = Checksum::new(ChecksumAlgorithm::Blake3, data);
        assert_eq!(checksum.algorithm, ChecksumAlgorithm::Blake3);
        assert!(checksum.verify(data));
    }

    #[test]
    fn test_checksum_verification() {
        let data = b"test data";
        let checksum = Checksum::new(ChecksumAlgorithm::Blake3, data);
        
        assert!(checksum.verify(data));
        assert!(!checksum.verify(b"wrong data"));
    }

    #[test]
    fn test_checksum_manager() {
        let mut manager = ChecksumManager::new();
        let data = b"test data";
        
        let checksum = manager.compute("key1".to_string(), data);
        assert!(checksum.verify(data));
        
        assert!(manager.verify_cached("key1", data).unwrap());
        assert!(!manager.verify_cached("key1", b"wrong").unwrap());
    }
}
