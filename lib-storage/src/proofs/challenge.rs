//! Challenge generation and management for storage proofs

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::ContentHash;

// Convert nonce bytes to u64 for challenge ID
fn nonce_to_u64(nonce: [u8; 12]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&nonce[..8]);
    u64::from_le_bytes(bytes)
}

/// Type of storage challenge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    /// Proof of storage - prove a specific block exists
    ProofOfStorage,
    /// Proof of retrieval - prove multiple random blocks exist
    ProofOfRetrieval,
    /// Periodic audit challenge
    PeriodicAudit,
}

/// Challenge issued to storage nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChallenge {
    /// Unique challenge ID
    pub challenge_id: String,
    /// Content to verify
    pub content_hash: ContentHash,
    /// Type of challenge
    pub challenge_type: ChallengeType,
    /// Random nonce for this challenge
    pub nonce: u64,
    /// Block index to prove (for ProofOfStorage)
    pub block_index: Option<usize>,
    /// Number of samples (for ProofOfRetrieval)
    pub sample_count: Option<usize>,
    /// Challenge creation timestamp
    pub created_at: u64,
    /// Challenge expiration timestamp
    pub expires_at: u64,
    /// Challenger node ID
    pub challenger_id: String,
}

impl StorageChallenge {
    /// Create a new proof-of-storage challenge
    pub fn new_storage_challenge(
        content_hash: ContentHash,
        block_index: usize,
        challenger_id: String,
        timeout_seconds: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nonce = lib_crypto::random::generate_nonce();
        let nonce_u64 = nonce_to_u64(nonce);
        let challenge_id = format!("pos_{}_{}", now, nonce_u64);

        Self {
            challenge_id,
            content_hash,
            challenge_type: ChallengeType::ProofOfStorage,
            nonce: nonce_u64,
            block_index: Some(block_index),
            sample_count: None,
            created_at: now,
            expires_at: now + timeout_seconds,
            challenger_id,
        }
    }

    /// Create a new proof-of-retrieval challenge
    pub fn new_retrieval_challenge(
        content_hash: ContentHash,
        sample_count: usize,
        challenger_id: String,
        timeout_seconds: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nonce = lib_crypto::random::generate_nonce();
        let nonce_u64 = nonce_to_u64(nonce);
        let challenge_id = format!("por_{}_{}", now, nonce_u64);

        Self {
            challenge_id,
            content_hash,
            challenge_type: ChallengeType::ProofOfRetrieval,
            nonce: nonce_u64,
            block_index: None,
            sample_count: Some(sample_count),
            created_at: now,
            expires_at: now + timeout_seconds,
            challenger_id,
        }
    }

    /// Create a periodic audit challenge
    pub fn new_audit_challenge(
        content_hash: ContentHash,
        block_index: usize,
        challenger_id: String,
        timeout_seconds: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let nonce = lib_crypto::random::generate_nonce();
        let nonce_u64 = nonce_to_u64(nonce);
        let challenge_id = format!("audit_{}_{}", now, nonce_u64);

        Self {
            challenge_id,
            content_hash,
            challenge_type: ChallengeType::PeriodicAudit,
            nonce: nonce_u64,
            block_index: Some(block_index),
            sample_count: None,
            created_at: now,
            expires_at: now + timeout_seconds,
            challenger_id,
        }
    }

    /// Check if the challenge has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }

    /// Get time remaining in seconds
    pub fn time_remaining(&self) -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (self.expires_at as i64) - (now as i64)
    }

    /// Validate challenge parameters
    pub fn validate(&self) -> Result<()> {
        match self.challenge_type {
            ChallengeType::ProofOfStorage | ChallengeType::PeriodicAudit => {
                if self.block_index.is_none() {
                    return Err(anyhow!("Block index required for storage challenges"));
                }
            }
            ChallengeType::ProofOfRetrieval => {
                if self.sample_count.is_none() {
                    return Err(anyhow!("Sample count required for retrieval challenges"));
                }
                if let Some(count) = self.sample_count {
                    if count == 0 {
                        return Err(anyhow!("Sample count must be greater than 0"));
                    }
                }
            }
        }

        if self.is_expired() {
            return Err(anyhow!("Challenge has expired"));
        }

        Ok(())
    }
}

/// Challenge generator for creating various types of challenges
pub struct ChallengeGenerator {
    /// Default challenge timeout in seconds
    default_timeout: u64,
    /// Default sample count for retrieval proofs
    default_sample_count: usize,
}

impl ChallengeGenerator {
    /// Create a new challenge generator
    pub fn new(default_timeout: u64, default_sample_count: usize) -> Self {
        Self {
            default_timeout,
            default_sample_count,
        }
    }

    /// Generate a random storage challenge for content
    pub fn generate_storage_challenge(
        &self,
        content_hash: ContentHash,
        total_blocks: usize,
        challenger_id: String,
    ) -> Result<StorageChallenge> {
        if total_blocks == 0 {
            return Err(anyhow!("Cannot generate challenge for empty content"));
        }

        // Select random block index
        let nonce = lib_crypto::random::generate_nonce();
        let nonce_u64 = nonce_to_u64(nonce);
        let block_index = (nonce_u64 as usize) % total_blocks;

        Ok(StorageChallenge::new_storage_challenge(
            content_hash,
            block_index,
            challenger_id,
            self.default_timeout,
        ))
    }

    /// Generate a retrieval challenge with random sampling
    pub fn generate_retrieval_challenge(
        &self,
        content_hash: ContentHash,
        total_blocks: usize,
        challenger_id: String,
    ) -> Result<StorageChallenge> {
        if total_blocks == 0 {
            return Err(anyhow!("Cannot generate challenge for empty content"));
        }

        // Use default sample count or limit to total blocks
        let sample_count = self.default_sample_count.min(total_blocks);

        Ok(StorageChallenge::new_retrieval_challenge(
            content_hash,
            sample_count,
            challenger_id,
            self.default_timeout,
        ))
    }

    /// Generate an audit challenge
    pub fn generate_audit_challenge(
        &self,
        content_hash: ContentHash,
        block_index: usize,
        challenger_id: String,
    ) -> StorageChallenge {
        StorageChallenge::new_audit_challenge(
            content_hash,
            block_index,
            challenger_id,
            self.default_timeout,
        )
    }

    /// Generate multiple challenges for a content
    pub fn generate_batch_challenges(
        &self,
        content_hash: ContentHash,
        total_blocks: usize,
        count: usize,
        challenger_id: String,
    ) -> Result<Vec<StorageChallenge>> {
        if total_blocks == 0 {
            return Err(anyhow!("Cannot generate challenges for empty content"));
        }

        let mut challenges = Vec::new();
        for _ in 0..count {
            let challenge = self.generate_storage_challenge(
                content_hash.clone(),
                total_blocks,
                challenger_id.clone(),
            )?;
            challenges.push(challenge);
        }

        Ok(challenges)
    }
}

impl Default for ChallengeGenerator {
    fn default() -> Self {
        Self::new(300, 10) // 5 minutes timeout, 10 samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::hash_blake3;

    fn content_hash(label: &str) -> ContentHash {
        ContentHash::from_bytes(&hash_blake3(label.as_bytes()))
    }

    #[test]
    fn test_storage_challenge_creation() {
        let content_hash = content_hash("test_content");
        let challenge = StorageChallenge::new_storage_challenge(
            content_hash,
            5,
            "challenger1".to_string(),
            300,
        );

        assert_eq!(challenge.challenge_type, ChallengeType::ProofOfStorage);
        assert_eq!(challenge.block_index, Some(5));
        assert!(challenge.sample_count.is_none());
        assert!(!challenge.is_expired());
        assert!(challenge.validate().is_ok());
    }

    #[test]
    fn test_retrieval_challenge_creation() {
        let content_hash = content_hash("test_content");
        let challenge = StorageChallenge::new_retrieval_challenge(
            content_hash,
            10,
            "challenger1".to_string(),
            300,
        );

        assert_eq!(challenge.challenge_type, ChallengeType::ProofOfRetrieval);
        assert!(challenge.block_index.is_none());
        assert_eq!(challenge.sample_count, Some(10));
        assert!(!challenge.is_expired());
        assert!(challenge.validate().is_ok());
    }

    #[test]
    fn test_audit_challenge_creation() {
        let content_hash = content_hash("test_content");
        let challenge = StorageChallenge::new_audit_challenge(
            content_hash,
            3,
            "auditor1".to_string(),
            600,
        );

        assert_eq!(challenge.challenge_type, ChallengeType::PeriodicAudit);
        assert_eq!(challenge.block_index, Some(3));
        assert!(challenge.time_remaining() > 0);
    }

    #[test]
    fn test_challenge_generator() {
        let generator = ChallengeGenerator::new(300, 5);
        let content_hash = content_hash("test_content");

        let storage_challenge = generator.generate_storage_challenge(
            content_hash.clone(),
            20,
            "node1".to_string(),
        );
        assert!(storage_challenge.is_ok());

        let retrieval_challenge = generator.generate_retrieval_challenge(
            content_hash.clone(),
            20,
            "node1".to_string(),
        );
        assert!(retrieval_challenge.is_ok());
    }

    #[test]
    fn test_batch_challenge_generation() {
        let generator = ChallengeGenerator::default();
        let content_hash = content_hash("test_content");

        let challenges = generator.generate_batch_challenges(
            content_hash,
            50,
            5,
            "node1".to_string(),
        );

        assert!(challenges.is_ok());
        let challenges = challenges.unwrap();
        assert_eq!(challenges.len(), 5);
    }

    #[test]
    fn test_challenge_validation() {
        let content_hash = content_hash("test");
        
        // Valid storage challenge
        let valid_challenge = StorageChallenge::new_storage_challenge(
            content_hash.clone(),
            0,
            "node1".to_string(),
            300,
        );
        assert!(valid_challenge.validate().is_ok());

        // Invalid retrieval challenge (no sample count)
        let mut invalid_challenge = StorageChallenge::new_retrieval_challenge(
            content_hash,
            10,
            "node1".to_string(),
            300,
        );
        invalid_challenge.sample_count = None;
        assert!(invalid_challenge.validate().is_err());
    }
}
