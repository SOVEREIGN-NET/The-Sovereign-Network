//! Storage proof implementation for Proof of Storage consensus

use anyhow::Result;
use lib_crypto::Hash;
use serde::{Deserialize, Serialize};

/// Storage challenge for proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChallenge {
    /// Challenge identifier
    pub id: Hash,
    /// Content hash being challenged
    pub content_hash: Hash,
    /// Challenge data
    pub challenge: Vec<u8>,
    /// Response to challenge
    pub response: Vec<u8>,
    /// Challenge timestamp
    pub timestamp: u64,
}

/// Proof of Storage for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    /// Validator providing storage
    pub validator: Hash,
    /// Total storage capacity in bytes
    pub storage_capacity: u64,
    /// Storage utilization percentage (0-100)
    pub utilization: u64,
    /// Successfully passed storage challenges
    pub challenges_passed: Vec<StorageChallenge>,
    /// Merkle proof of stored data
    pub merkle_proof: Vec<Hash>,
}

impl StorageProof {
    /// Create a new storage proof
    pub fn new(
        validator: Hash,
        storage_capacity: u64,
        utilization: u64,
        challenges_passed: Vec<StorageChallenge>,
        merkle_proof: Vec<Hash>,
    ) -> Result<Self> {
        // Validate utilization percentage
        if utilization > 100 {
            return Err(anyhow::anyhow!("Storage utilization cannot exceed 100%"));
        }

        Ok(StorageProof {
            validator,
            storage_capacity,
            utilization,
            challenges_passed,
            merkle_proof,
        })
    }

    /// Verify the storage proof is valid
    pub fn verify(&self) -> Result<bool> {
        // Verify all challenges were properly responded to
        for challenge in &self.challenges_passed {
            if !self.verify_challenge_response(challenge)? {
                return Ok(false);
            }
        }

        // Verify merkle proof integrity
        if !self.verify_merkle_proof()? {
            return Ok(false);
        }

        // Verify utilization is reasonable
        if self.utilization > 100 {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify a single challenge response
    fn verify_challenge_response(&self, challenge: &StorageChallenge) -> Result<bool> {
        // In a implementation, this would verify the cryptographic challenge-response
        // For now, just check that response is not empty
        Ok(!challenge.response.is_empty() && challenge.response.len() >= challenge.challenge.len())
    }

    /// Verify merkle proof of stored data
    fn verify_merkle_proof(&self) -> Result<bool> {
        // In a implementation, this would verify the Merkle tree proof
        // For now, just check that proof exists
        Ok(!self.merkle_proof.is_empty())
    }

    /// Calculate storage score based on capacity and utilization
    pub fn calculate_storage_score(&self) -> f64 {
        let capacity_score = (self.storage_capacity as f64).sqrt();
        let utilization_factor = self.utilization as f64 / 100.0;
        let challenge_bonus = (self.challenges_passed.len() as f64) * 0.1;

        capacity_score * utilization_factor + challenge_bonus
    }

    /// Get effective storage provided (capacity * utilization)
    pub fn effective_storage(&self) -> u64 {
        self.storage_capacity * self.utilization / 100
    }
}
