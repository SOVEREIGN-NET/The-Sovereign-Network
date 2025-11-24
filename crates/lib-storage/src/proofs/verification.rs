//! Proof verification module

use anyhow::{Result};
use serde::{Deserialize, Serialize};
use lib_proofs::merkle::tree::hash_merkle_pair;
use crate::proofs::{StorageProof, RetrievalProof};
use crate::proofs::challenge::{StorageChallenge, ChallengeType};

/// Result of proof verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Proof is valid
    Valid,
    /// Proof is invalid with reason
    Invalid(String),
    /// Challenge expired before proof was verified
    ChallengeExpired,
    /// Proof expired
    ProofExpired,
    /// Wrong proof type for challenge
    ProofTypeMismatch,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        !self.is_valid()
    }
}

/// Proof verifier for storage and retrieval proofs
pub struct ProofVerifier {
    /// Maximum proof age in seconds before considering expired
    max_proof_age: u64,
}

impl ProofVerifier {
    /// Create a new proof verifier
    pub fn new(max_proof_age: u64) -> Self {
        Self { max_proof_age }
    }

    /// Verify a storage proof against a challenge
    pub fn verify_storage_proof(
        &self,
        proof: &StorageProof,
        challenge: &StorageChallenge,
    ) -> VerificationResult {
        // Check challenge expiration
        if challenge.is_expired() {
            return VerificationResult::ChallengeExpired;
        }

        // Check proof expiration
        if proof.is_expired(self.max_proof_age) {
            return VerificationResult::ProofExpired;
        }

        // Verify content hash matches
        if proof.content_hash != challenge.content_hash {
            return VerificationResult::Invalid(
                "Content hash mismatch".to_string()
            );
        }

        // Verify nonce matches
        if proof.challenge_nonce != challenge.nonce {
            return VerificationResult::Invalid(
                "Challenge nonce mismatch".to_string()
            );
        }

        // Verify block index matches
        if let Some(expected_index) = challenge.block_index {
            if proof.block_index != expected_index {
                return VerificationResult::Invalid(
                    format!(
                        "Block index mismatch: expected {}, got {}",
                        expected_index, proof.block_index
                    )
                );
            }
        }

        // Verify Merkle proof
        match self.verify_merkle_proof(proof) {
            Ok(true) => VerificationResult::Valid,
            Ok(false) => VerificationResult::Invalid(
                "Merkle proof verification failed".to_string()
            ),
            Err(e) => VerificationResult::Invalid(
                format!("Merkle proof error: {}", e)
            ),
        }
    }

    /// Verify a retrieval proof against a challenge
    pub fn verify_retrieval_proof(
        &self,
        proof: &RetrievalProof,
        challenge: &StorageChallenge,
    ) -> VerificationResult {
        // Check challenge expiration
        if challenge.is_expired() {
            return VerificationResult::ChallengeExpired;
        }

        // Check proof type matches
        if challenge.challenge_type != ChallengeType::ProofOfRetrieval {
            return VerificationResult::ProofTypeMismatch;
        }

        // Check proof expiration
        if proof.is_expired(self.max_proof_age) {
            return VerificationResult::ProofExpired;
        }

        // Verify content hash matches
        if proof.content_hash != challenge.content_hash {
            return VerificationResult::Invalid(
                "Content hash mismatch".to_string()
            );
        }

        // Verify sample count matches
        if let Some(expected_samples) = challenge.sample_count {
            if proof.sample_indices.len() != expected_samples {
                return VerificationResult::Invalid(
                    format!(
                        "Sample count mismatch: expected {}, got {}",
                        expected_samples, proof.sample_indices.len()
                    )
                );
            }
        }

        // Verify combined hash
        if !proof.verify_combined_hash() {
            return VerificationResult::Invalid(
                "Combined hash verification failed".to_string()
            );
        }

        VerificationResult::Valid
    }

    /// Verify Merkle proof for storage proof
    fn verify_merkle_proof(&self, proof: &StorageProof) -> Result<bool> {
        // Hash the challenged block
        let mut current_hash = proof.block_hash();
        let mut index = proof.block_index;

        // Traverse up the Merkle tree
        for sibling_hash in &proof.merkle_path {
            current_hash = if index % 2 == 0 {
                // Current is left child
                hash_merkle_pair(current_hash, *sibling_hash)
            } else {
                // Current is right child
                hash_merkle_pair(*sibling_hash, current_hash)
            };
            index /= 2;
        }

        // Final hash should match the Merkle root
        Ok(current_hash == proof.merkle_root)
    }

    /// Batch verify multiple proofs
    pub fn batch_verify_storage_proofs(
        &self,
        proofs: &[(StorageProof, StorageChallenge)],
    ) -> Vec<VerificationResult> {
        proofs
            .iter()
            .map(|(proof, challenge)| self.verify_storage_proof(proof, challenge))
            .collect()
    }

    /// Batch verify retrieval proofs
    pub fn batch_verify_retrieval_proofs(
        &self,
        proofs: &[(RetrievalProof, StorageChallenge)],
    ) -> Vec<VerificationResult> {
        proofs
            .iter()
            .map(|(proof, challenge)| self.verify_retrieval_proof(proof, challenge))
            .collect()
    }
}

impl Default for ProofVerifier {
    fn default() -> Self {
        Self::new(3600) // 1 hour default max proof age
    }
}

/// Verification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    pub total_verified: usize,
    pub valid_proofs: usize,
    pub invalid_proofs: usize,
    pub expired_proofs: usize,
    pub challenge_expired: usize,
    pub type_mismatches: usize,
}

impl VerificationStats {
    pub fn new() -> Self {
        Self {
            total_verified: 0,
            valid_proofs: 0,
            invalid_proofs: 0,
            expired_proofs: 0,
            challenge_expired: 0,
            type_mismatches: 0,
        }
    }

    pub fn record_result(&mut self, result: &VerificationResult) {
        self.total_verified += 1;
        match result {
            VerificationResult::Valid => self.valid_proofs += 1,
            VerificationResult::Invalid(_) => self.invalid_proofs += 1,
            VerificationResult::ProofExpired => self.expired_proofs += 1,
            VerificationResult::ChallengeExpired => self.challenge_expired += 1,
            VerificationResult::ProofTypeMismatch => self.type_mismatches += 1,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_verified == 0 {
            0.0
        } else {
            (self.valid_proofs as f64 / self.total_verified as f64) * 100.0
        }
    }
}

impl Default for VerificationStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::storage_types::ContentHash;

    #[test]
    fn test_verification_result() {
        assert!(VerificationResult::Valid.is_valid());
        assert!(!VerificationResult::Invalid("test".to_string()).is_valid());
        assert!(VerificationResult::ChallengeExpired.is_invalid());
    }

    #[test]
    fn test_verification_stats() {
        let mut stats = VerificationStats::new();
        
        stats.record_result(&VerificationResult::Valid);
        stats.record_result(&VerificationResult::Valid);
        stats.record_result(&VerificationResult::Invalid("test".to_string()));
        
        assert_eq!(stats.total_verified, 3);
        assert_eq!(stats.valid_proofs, 2);
        assert_eq!(stats.invalid_proofs, 1);
        assert_eq!(stats.success_rate(), 66.66666666666666);
    }

    #[test]
    fn test_proof_verifier_creation() {
        let verifier = ProofVerifier::new(3600);
        assert_eq!(verifier.max_proof_age, 3600);

        let default_verifier = ProofVerifier::default();
        assert_eq!(default_verifier.max_proof_age, 3600);
    }

    #[test]
    fn test_storage_proof_verification_content_mismatch() {
        let verifier = ProofVerifier::default();
        
        let content_hash1 = ContentHash::from("content1".to_string());
        let content_hash2 = ContentHash::from("content2".to_string());
        
        let proof = StorageProof::new(
            content_hash1,
            [0u8; 32],
            123,
            vec![],
            vec![1, 2, 3],
            0,
            "node1".to_string(),
        );
        
        let challenge = StorageChallenge::new_storage_challenge(
            content_hash2,
            0,
            "challenger".to_string(),
            300,
        );
        
        let result = verifier.verify_storage_proof(&proof, &challenge);
        assert!(result.is_invalid());
        match result {
            VerificationResult::Invalid(msg) => {
                assert_eq!(msg, "Content hash mismatch");
            }
            _ => panic!("Expected Invalid result"),
        }
    }

    #[test]
    fn test_retrieval_proof_combined_hash() {
        let content_hash = ContentHash::from("test".to_string());
        let sample_blocks = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
        ];
        
        let proof = RetrievalProof::new(
            content_hash,
            vec![0, 1],
            sample_blocks,
            "node1".to_string(),
        );
        
        assert!(proof.verify_combined_hash());
    }
}
