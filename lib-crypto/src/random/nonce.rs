//! Nonce generation - preserving ZHTP nonce security
//! 
//! implementation from crypto.rs, lines 703-707

use rand::{RngCore, rngs::OsRng};

/// Generate a secure random nonce for encryption
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
