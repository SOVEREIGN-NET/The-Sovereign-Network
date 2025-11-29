//! Hashing module for ZHTP cryptography
//! 
//! Provides Blake3 hashing functionality used throughout the system

use blake3;

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