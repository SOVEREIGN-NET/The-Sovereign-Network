//! Secure random number generator - preserving ZHTP entropy
//! 
//! implementation from crypto.rs, lines 720-742

use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure random number generator with automatic zeroization
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecureRng {
    buffer: Vec<u8>,
}

impl SecureRng {
    pub fn new() -> Self {
        SecureRng {
            buffer: Vec::new(),
        }
    }

    pub fn generate_bytes(&mut self, len: usize) -> Vec<u8> {
        self.buffer.clear();
        self.buffer.resize(len, 0);
        OsRng.fill_bytes(&mut self.buffer);
        self.buffer.clone()
    }

    pub fn generate_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    pub fn generate_key_material(&mut self) -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
}
