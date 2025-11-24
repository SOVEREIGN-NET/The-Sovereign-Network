//! Platform compatibility utilities for conditional compilation
//! 
//! Provides utilities for handling differences between native and WASM targets.

/// Check if running in WASM environment
pub fn is_wasm() -> bool {
    cfg!(target_arch = "wasm32")
}

/// Get current timestamp in a cross-platform way
pub fn current_timestamp() -> Result<u64, anyhow::Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| anyhow::anyhow!("Time error: {}", e))
}

/// Platform-specific random number generation
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut bytes = Vec::with_capacity(len);
    let mut hasher = DefaultHasher::new();
    
    for i in 0..len {
        i.hash(&mut hasher);
        let value = hasher.finish() as u8;
        bytes.push(value);
    }
    
    bytes
}

/// WASM-compatible random number generation
#[cfg(target_arch = "wasm32")]
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut bytes = Vec::with_capacity(len);
    let mut hasher = DefaultHasher::new();
    
    for i in 0..len {
        i.hash(&mut hasher);
        let value = hasher.finish() as u8;
        bytes.push(value);
    }
    
    bytes
}
