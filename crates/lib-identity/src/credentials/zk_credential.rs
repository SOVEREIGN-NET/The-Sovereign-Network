//! Zero-knowledge credential implementation from the original identity.rs

use serde::{Deserialize, Serialize};
use lib_crypto::Hash;
use lib_proofs::ZeroKnowledgeProof;
use crate::types::{IdentityId, CredentialType};

/// Zero-knowledge credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkCredential {
    /// Credential identifier
    pub id: Hash,
    /// Type of credential
    pub credential_type: CredentialType,
    /// Issuer identity
    pub issuer: IdentityId,
    /// Subject identity
    pub subject: IdentityId,
    /// ZK proof of credential validity
    pub proof: ZeroKnowledgeProof,
    /// Expiration timestamp
    pub expires_at: Option<u64>,
    /// Creation timestamp
    pub issued_at: u64,
    /// Credential metadata (encrypted)
    pub metadata: Vec<u8>,
}

impl ZkCredential {
    /// Create a new ZK credential
    pub fn new(
        credential_type: CredentialType,
        issuer: IdentityId,
        subject: IdentityId,
        proof: ZeroKnowledgeProof,
        expires_at: Option<u64>,
        metadata: Vec<u8>,
    ) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate credential ID from contents
        let id_data = [
            issuer.as_bytes(),
            subject.as_bytes(),
            &current_time.to_le_bytes(),
            &serde_json::to_vec(&credential_type).unwrap_or_default()
        ].concat();
        
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(&id_data));
        
        Self {
            id,
            credential_type,
            issuer,
            subject,
            proof,
            expires_at,
            issued_at: current_time,
            metadata,
        }
    }
    
    /// Check if credential has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            expires_at <= now
        } else {
            false
        }
    }
    
    /// Check if credential is valid (not expired and has valid proof structure)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && 
        !self.proof.proof_data.is_empty() && 
        !self.proof.public_inputs.is_empty()
    }
    
    /// Get credential age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.issued_at)
    }
    
    /// Get time until expiration in seconds (None if no expiration)
    pub fn time_until_expiration(&self) -> Option<u64> {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if expires_at > now {
                Some(expires_at - now)
            } else {
                Some(0) // Already expired
            }
        } else {
            None // Never expires
        }
    }
}
