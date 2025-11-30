//! Session token management for authenticated users
//! 
//! Provides secure session tokens for authenticated identities

use lib_crypto::hash_blake3;
use crate::types::IdentityId;
use anyhow::Result;

/// Session token for authenticated users
#[derive(Debug, Clone)]
pub struct SessionToken {
    pub token: String,
    pub identity_id: IdentityId,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used: u64,
}

impl SessionToken {
    /// Check if session token is still valid
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        now < self.expires_at
    }

    /// Update last used timestamp
    pub fn touch(&mut self) {
        self.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Generate a new session token
    pub fn new(identity_id: IdentityId, duration_seconds: u64) -> Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Generate secure random token using identity and timestamp
        let token_material = [
            identity_id.0.as_slice(),
            &now.to_le_bytes(),
            &rand::random::<[u8; 32]>(),
            b"ZHTP_session_token_v1"
        ].concat();
        
        let token_hash = hash_blake3(&token_material);
        let token = hex::encode(token_hash);
        
        Ok(SessionToken {
            token,
            identity_id,
            created_at: now,
            expires_at: now + duration_seconds,
            last_used: now,
        })
    }
}