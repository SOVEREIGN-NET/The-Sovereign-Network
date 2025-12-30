//! Hash wrapper type implementation - preserving ZHTP Hash functionality
//! 
//! implementation from crypto.rs, line 22-50

use anyhow::Result;
use serde::{Serialize, Deserialize};

/// Hash wrapper type for ZHTP - implementation from production codebase
///
/// CRITICAL: Includes Ord and PartialOrd derives to support BTreeMap usage
/// in consensus message structures. This ensures canonical ordering for
/// deterministic serialization (CM-3, CM-4). Must NOT use HashMap for
/// any consensus-critical data structures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Create a hash from bytes (truncate or pad to 32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        let len = std::cmp::min(bytes.len(), 32);
        hash[..len].copy_from_slice(&bytes[..len]);
        Hash(hash)
    }

    /// Get hash as bytes slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create hash from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| anyhow::anyhow!("Invalid hex string: {}", e))?;
        Ok(Hash::from_bytes(&bytes))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
