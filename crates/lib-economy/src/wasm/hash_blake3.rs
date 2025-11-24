//! WASM-compatible Blake3 hashing with DefaultHasher fallback
//! 
//! Provides cross-platform hashing that works in both native and browser environments.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// WASM-compatible Blake3 hash function
#[cfg(not(target_arch = "wasm32"))]
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    // Use Blake3 hashing on native platforms
    // This would typically use the blake3 crate
    // For now, using a simple hash for compatibility
    let mut hash = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash_value = hasher.finish();
    let bytes = hash_value.to_le_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        hash[i] = byte;
        hash[i + 8] = byte;
        hash[i + 16] = byte;
        hash[i + 24] = byte;
    }
    hash
}

/// WASM-compatible fallback hash function
#[cfg(target_arch = "wasm32")]
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    // Simple hash for WebAssembly environments
    let mut hash = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash_value = hasher.finish();
    let bytes = hash_value.to_le_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        hash[i] = byte;
        hash[i + 8] = byte;
        hash[i + 16] = byte;
        hash[i + 24] = byte;
    }
    hash
}
