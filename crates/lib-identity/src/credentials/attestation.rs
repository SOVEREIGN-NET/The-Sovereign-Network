//! Identity attestation implementation from the original identity.rs

use serde::{Deserialize, Serialize};
use lib_crypto::Hash;
use lib_proofs::ZeroKnowledgeProof;
use crate::types::{IdentityId, AttestationType};

/// Identity attestation from trusted parties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAttestation {
    /// Attestation identifier
    pub id: Hash,
    /// Attester identity
    pub attester: IdentityId,
    /// Attestation type
    pub attestation_type: AttestationType,
    /// Zero-knowledge proof of attestation
    pub proof: ZeroKnowledgeProof,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Attestation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: Option<u64>,
}

impl IdentityAttestation {
    /// Create a new identity attestation
    pub fn new(
        attester: IdentityId,
        attestation_type: AttestationType,
        proof: ZeroKnowledgeProof,
        confidence: u8,
        expires_at: Option<u64>,
    ) -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Generate attestation ID
        let id_data = [
            attester.as_bytes(),
            &current_time.to_le_bytes(),
            &confidence.to_le_bytes(),
            &serde_json::to_vec(&attestation_type).unwrap_or_default()
        ].concat();
        
        let id = Hash::from_bytes(&lib_crypto::hash_blake3(&id_data));
        
        Self {
            id,
            attester,
            attestation_type,
            proof,
            confidence: std::cmp::min(confidence, 100), // Cap at 100
            created_at: current_time,
            expires_at,
        }
    }
    
    /// Check if attestation has expired
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
    
    /// Check if attestation is valid (not expired, valid confidence, and valid proof)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && 
        self.confidence <= 100 &&
        !self.proof.proof_data.is_empty() && 
        !self.proof.public_inputs.is_empty()
    }
    
    /// Get attestation age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.created_at)
    }
    
    /// Get confidence level as a normalized value (0.0 to 1.0)
    pub fn confidence_normalized(&self) -> f64 {
        self.confidence as f64 / 100.0
    }
    
    /// Check if confidence meets minimum threshold
    pub fn meets_confidence_threshold(&self, threshold: u8) -> bool {
        self.confidence >= threshold
    }
}
