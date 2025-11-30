//! Recovery key management for ZHTP Identity
//! 
//! Manages multiple recovery keys that can be used to restore identity access
//! if the primary key is lost or compromised.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::Hash;
use crate::types::IdentityId;

/// Recovery key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKey {
    /// Recovery key ID
    pub id: Hash,
    /// The actual recovery key (encrypted)
    pub encrypted_key: Vec<u8>,
    /// Key derivation path
    pub derivation_path: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used: Option<u64>,
    /// Whether this key is still valid
    pub is_active: bool,
    /// Human-readable label
    pub label: String,
}

/// Recovery key manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKeyManager {
    /// Identity this belongs to
    pub identity_id: IdentityId,
    /// List of recovery keys
    pub recovery_keys: Vec<RecoveryKey>,
    /// Maximum number of recovery keys allowed
    pub max_keys: usize,
}

impl RecoveryKey {
    /// Create a new recovery key
    pub fn new(
        encrypted_key: Vec<u8>,
        derivation_path: String,
        label: String,
    ) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let key_data = [
            &encrypted_key,
            derivation_path.as_bytes(),
            &current_time.to_le_bytes(),
        ].concat();
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(&key_data));
        
        Self {
            id,
            encrypted_key,
            derivation_path,
            created_at: current_time,
            last_used: None,
            is_active: true,
            label,
        }
    }
    
    /// Mark recovery key as used
    pub fn mark_used(&mut self) {
        self.last_used = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }
    
    /// Deactivate recovery key
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
    
    /// Check if key is expired (older than 1 year unused)
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let last_activity = self.last_used.unwrap_or(self.created_at);
        now - last_activity > 365 * 24 * 3600 // 1 year
    }
}

impl RecoveryKeyManager {
    /// Create a new recovery key manager
    pub fn new(identity_id: IdentityId) -> Self {
        Self {
            identity_id,
            recovery_keys: Vec::new(),
            max_keys: 5, // Maximum 5 recovery keys
        }
    }
    
    /// Add a recovery key
    pub fn add_recovery_key(&mut self, recovery_key: RecoveryKey) -> Result<()> {
        if self.recovery_keys.len() >= self.max_keys {
            return Err(anyhow::anyhow!("Maximum number of recovery keys reached"));
        }
        
        // Check for duplicate labels
        if self.recovery_keys.iter().any(|k| k.label == recovery_key.label) {
            return Err(anyhow::anyhow!("Recovery key with label '{}' already exists", recovery_key.label));
        }
        
        self.recovery_keys.push(recovery_key);
        Ok(())
    }
    
    /// Remove a recovery key by ID
    pub fn remove_recovery_key(&mut self, key_id: &Hash) -> Result<()> {
        let initial_len = self.recovery_keys.len();
        self.recovery_keys.retain(|k| &k.id != key_id);
        
        if self.recovery_keys.len() == initial_len {
            return Err(anyhow::anyhow!("Recovery key not found"));
        }
        
        Ok(())
    }
    
    /// Get recovery key by ID
    pub fn get_recovery_key(&self, key_id: &Hash) -> Option<&RecoveryKey> {
        self.recovery_keys.iter().find(|k| &k.id == key_id)
    }
    
    /// Get active recovery keys
    pub fn get_active_keys(&self) -> Vec<&RecoveryKey> {
        self.recovery_keys.iter()
            .filter(|k| k.is_active && !k.is_expired())
            .collect()
    }
    
    /// Clean up expired keys
    pub fn cleanup_expired_keys(&mut self) {
        self.recovery_keys.retain(|k| !k.is_expired());
    }
    
    /// Validate recovery key format
    pub fn validate_recovery_key(&self, encrypted_key: &[u8]) -> bool {
        encrypted_key.len() >= 32 && encrypted_key.len() <= 128
    }
}
