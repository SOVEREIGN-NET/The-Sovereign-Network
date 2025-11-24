//! WASM-compatible identity implementation
//! 
//! Provides IdentityId implementation that works in browser environments.

use serde::{Serialize, Deserialize};

/// WASM-compatible IdentityId implementation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityId(pub [u8; 32]);

impl IdentityId {
    /// Create new IdentityId from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        IdentityId(bytes)
    }
    
    /// Get the inner bytes array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Create IdentityId from slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice);
            Some(IdentityId(bytes))
        } else {
            None
        }
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        Self::from_slice(&bytes).ok_or(hex::FromHexError::InvalidStringLength)
    }
}
