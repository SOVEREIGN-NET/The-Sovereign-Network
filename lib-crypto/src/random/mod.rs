//! Random number generation module for ZHTP cryptography
//! 
//! Provides secure random number generation for cryptographic operations

use rand::{CryptoRng, RngCore};
use rand::rngs::OsRng;

/// Secure random number generator wrapper
pub struct SecureRng {
    rng: OsRng,
}

impl SecureRng {
    /// Create a new secure RNG instance
    pub fn new() -> Self {
        Self {
            rng: OsRng,
        }
    }

    /// Generate random bytes into the provided buffer
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    /// Generate a random u32
    pub fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    /// Generate a random u64
    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// Generate random bytes and return as Vec
    pub fn generate_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        self.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a random 32-byte array (common for keys)
    pub fn generate_key(&mut self) -> [u8; 32] {
        let mut key = [0u8; 32];
        self.fill_bytes(&mut key);
        key
    }

    /// Generate a random 64-byte array (common for seeds)
    pub fn generate_seed(&mut self) -> [u8; 64] {
        let mut seed = [0u8; 64];
        self.fill_bytes(&mut seed);
        seed
    }

    /// Generate key material for cryptographic operations
    pub fn generate_key_material(&mut self) -> [u8; 32] {
        self.generate_key()
    }

    /// Generate a random u64 value
    pub fn generate_u64(&mut self) -> u64 {
        self.next_u64()
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRng {}

/// Convenience function to generate random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = SecureRng::new();
    rng.generate_bytes(len)
}

/// Convenience function to generate a random key
pub fn generate_random_key() -> [u8; 32] {
    let mut rng = SecureRng::new();
    rng.generate_key()
}

/// Convenience function to generate a random seed
pub fn generate_random_seed() -> [u8; 64] {
    let mut rng = SecureRng::new();
    rng.generate_seed()
}

/// Generate a nonce for cryptographic operations
pub fn generate_nonce() -> [u8; 12] {
    let mut rng = SecureRng::new();
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Generate a 24-byte nonce for XChaCha20
pub fn generate_xchacha20_nonce() -> [u8; 24] {
    let mut rng = SecureRng::new();
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rng_creation() {
        let _rng = SecureRng::new();
        // If we get here without panic, creation succeeded
    }

    #[test]
    fn test_random_bytes_generation() {
        let mut rng = SecureRng::new();
        let bytes1 = rng.generate_bytes(32);
        let bytes2 = rng.generate_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_random_key_generation() {
        let mut rng = SecureRng::new();
        let key1 = rng.generate_key();
        let key2 = rng.generate_key();
        
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2); // Should be different
    }

    #[test]
    fn test_convenience_functions() {
        let bytes = generate_random_bytes(16);
        let key = generate_random_key();
        let seed = generate_random_seed();
        
        assert_eq!(bytes.len(), 16);
        assert_eq!(key.len(), 32);
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_rng_core_implementation() {
        let mut rng = SecureRng::new();
        let _u32_val = rng.next_u32();
        let _u64_val = rng.next_u64();
        
        let mut buffer = [0u8; 16];
        rng.fill_bytes(&mut buffer);
        
        // Check that buffer was modified
        assert_ne!(buffer, [0u8; 16]);
    }
}