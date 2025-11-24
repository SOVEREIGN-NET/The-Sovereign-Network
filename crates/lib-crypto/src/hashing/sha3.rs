//! SHA-3 hashing - preserving ZHTP secure hashing
//! 
//! implementation from crypto.rs, lines 646-655

use sha3::{Digest, Sha3_256};

/// Secure cryptographic hash using SHA-3 (NIST standard)
pub fn hash_sha3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-3 256-bit hash (alias for compatibility)
pub fn hash_sha3_256(data: &[u8]) -> [u8; 32] {
    hash_sha3(data)
}
