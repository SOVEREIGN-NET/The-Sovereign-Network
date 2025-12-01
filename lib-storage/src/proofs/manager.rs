//! Proof management and coordination

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::proofs::{StorageProof, RetrievalProof};
use crate::proofs::challenge::{StorageChallenge, ChallengeType, ChallengeGenerator};
use crate::proofs::verification::{ProofVerifier, VerificationResult, VerificationStats};
use crate::types::ContentHash;

/// Proof manager coordinates challenges and verification
pub struct ProofManager {
    /// Challenge generator
    challenge_generator: ChallengeGenerator,
    /// Proof verifier
    verifier: ProofVerifier,
    /// Active challenges indexed by content hash
    active_challenges: HashMap<ContentHash, Vec<StorageChallenge>>,
    /// Completed storage proofs
    storage_proof_history: HashMap<ContentHash, Vec<(StorageProof, VerificationResult)>>,
    /// Completed retrieval proofs
    retrieval_proof_history: HashMap<ContentHash, Vec<(RetrievalProof, VerificationResult)>>,
    /// Verification statistics
    stats: VerificationStats,
    /// Challenge cleanup interval (remove expired challenges)
    cleanup_interval: u64,
    /// Last cleanup timestamp
    last_cleanup: u64,
}

impl ProofManager {
    /// Create a new proof manager
    pub fn new(
        challenge_timeout: u64,
        sample_count: usize,
        max_proof_age: u64,
    ) -> Self {
        Self {
            challenge_generator: ChallengeGenerator::new(challenge_timeout, sample_count),
            verifier: ProofVerifier::new(max_proof_age),
            active_challenges: HashMap::new(),
            storage_proof_history: HashMap::new(),
            retrieval_proof_history: HashMap::new(),
            stats: VerificationStats::new(),
            cleanup_interval: 3600, // 1 hour
            last_cleanup: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Generate a storage challenge
    pub fn generate_storage_challenge(
        &mut self,
        content_hash: ContentHash,
        total_blocks: usize,
        challenger_id: String,
    ) -> Result<StorageChallenge> {
        let challenge = self.challenge_generator.generate_storage_challenge(
            content_hash.clone(),
            total_blocks,
            challenger_id,
        )?;

        self.active_challenges
            .entry(content_hash)
            .or_insert_with(Vec::new)
            .push(challenge.clone());

        Ok(challenge)
    }

    /// Generate a retrieval challenge
    pub fn generate_retrieval_challenge(
        &mut self,
        content_hash: ContentHash,
        total_blocks: usize,
        challenger_id: String,
    ) -> Result<StorageChallenge> {
        let challenge = self.challenge_generator.generate_retrieval_challenge(
            content_hash.clone(),
            total_blocks,
            challenger_id,
        )?;

        self.active_challenges
            .entry(content_hash)
            .or_insert_with(Vec::new)
            .push(challenge.clone());

        Ok(challenge)
    }

    /// Generate an audit challenge
    pub fn generate_audit_challenge(
        &mut self,
        content_hash: ContentHash,
        block_index: usize,
        challenger_id: String,
    ) -> StorageChallenge {
        let challenge = self.challenge_generator.generate_audit_challenge(
            content_hash.clone(),
            block_index,
            challenger_id,
        );

        self.active_challenges
            .entry(content_hash)
            .or_insert_with(Vec::new)
            .push(challenge.clone());

        challenge
    }

    /// Submit and verify a storage proof
    pub fn submit_storage_proof(
        &mut self,
        proof: StorageProof,
        challenge_id: String,
    ) -> Result<VerificationResult> {
        // Find the matching challenge
        let challenge = self.find_challenge(&proof.content_hash, &challenge_id)?;

        // Verify the proof
        let result = self.verifier.verify_storage_proof(&proof, &challenge);

        // Record statistics
        self.stats.record_result(&result);

        // Store proof in history
        self.storage_proof_history
            .entry(proof.content_hash.clone())
            .or_insert_with(Vec::new)
            .push((proof, result.clone()));

        // Remove challenge if verified successfully
        if result.is_valid() {
            self.remove_challenge(&challenge.content_hash, &challenge_id);
        }

        Ok(result)
    }

    /// Submit and verify a retrieval proof
    pub fn submit_retrieval_proof(
        &mut self,
        proof: RetrievalProof,
        challenge_id: String,
    ) -> Result<VerificationResult> {
        // Find the matching challenge
        let challenge = self.find_challenge(&proof.content_hash, &challenge_id)?;

        // Verify the proof
        let result = self.verifier.verify_retrieval_proof(&proof, &challenge);

        // Record statistics
        self.stats.record_result(&result);

        // Store proof in history
        self.retrieval_proof_history
            .entry(proof.content_hash.clone())
            .or_insert_with(Vec::new)
            .push((proof, result.clone()));

        // Remove challenge if verified successfully
        if result.is_valid() {
            self.remove_challenge(&challenge.content_hash, &challenge_id);
        }

        Ok(result)
    }

    /// Find a challenge by content hash and challenge ID
    fn find_challenge(
        &self,
        content_hash: &ContentHash,
        challenge_id: &str,
    ) -> Result<StorageChallenge> {
        let challenges = self.active_challenges
            .get(content_hash)
            .ok_or_else(|| anyhow!("No challenges found for content"))?;

        challenges
            .iter()
            .find(|c| c.challenge_id == challenge_id)
            .cloned()
            .ok_or_else(|| anyhow!("Challenge not found"))
    }

    /// Remove a challenge
    fn remove_challenge(&mut self, content_hash: &ContentHash, challenge_id: &str) {
        if let Some(challenges) = self.active_challenges.get_mut(content_hash) {
            challenges.retain(|c: &StorageChallenge| c.challenge_id != challenge_id);
            if challenges.is_empty() {
                self.active_challenges.remove(content_hash);
            }
        }
    }

    /// Get active challenges for content
    pub fn get_active_challenges(&self, content_hash: &ContentHash) -> Vec<StorageChallenge> {
        self.active_challenges
            .get(content_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Get all active challenges
    pub fn get_all_active_challenges(&self) -> Vec<StorageChallenge> {
        self.active_challenges
            .values()
            .flat_map(|v: &Vec<StorageChallenge>| v.clone())
            .collect()
    }

    /// Get proof history for content
    pub fn get_storage_proof_history(
        &self,
        content_hash: &ContentHash,
    ) -> Vec<(StorageProof, VerificationResult)> {
        self.storage_proof_history
            .get(content_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Get retrieval proof history
    pub fn get_retrieval_proof_history(
        &self,
        content_hash: &ContentHash,
    ) -> Vec<(RetrievalProof, VerificationResult)> {
        self.retrieval_proof_history
            .get(content_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Get verification statistics
    pub fn get_stats(&self) -> &VerificationStats {
        &self.stats
    }

    /// Clean up expired challenges
    pub fn cleanup_expired_challenges(&mut self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if cleanup is needed
        if now < self.last_cleanup + self.cleanup_interval {
            return 0;
        }

        let mut removed_count = 0;

        // Remove expired challenges
        let mut empty_keys: Vec<ContentHash> = Vec::new();
        for (content_hash, challenges) in self.active_challenges.iter_mut() {
            let before_len = challenges.len();
            challenges.retain(|c: &StorageChallenge| !c.is_expired());
            removed_count += before_len - challenges.len();

            if challenges.is_empty() {
                empty_keys.push(content_hash.clone());
            }
        }

        // Remove empty entries
        for key in empty_keys {
            self.active_challenges.remove(&key);
        }

        self.last_cleanup = now;
        removed_count
    }

    /// Generate periodic audit challenges for stored content
    pub fn generate_audit_batch(
        &mut self,
        content_hashes: Vec<(ContentHash, usize)>, // (content_hash, total_blocks)
        auditor_id: String,
    ) -> Vec<StorageChallenge> {
        let mut challenges = Vec::new();

        for (content_hash, total_blocks) in content_hashes {
            if total_blocks > 0 {
                // Pick random block index
                let nonce = lib_crypto::random::generate_nonce();
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&nonce[..8]);
                let nonce_u64 = u64::from_le_bytes(bytes);
                let block_index = (nonce_u64 as usize) % total_blocks;
                let challenge = self.generate_audit_challenge(
                    content_hash,
                    block_index,
                    auditor_id.clone(),
                );
                challenges.push(challenge);
            }
        }

        challenges
    }

    /// Get challenge statistics
    pub fn get_challenge_stats(&self) -> ChallengeStats {
        let mut total_challenges = 0;
        let mut storage_challenges = 0;
        let mut retrieval_challenges = 0;
        let mut audit_challenges = 0;

        for challenges in self.active_challenges.values() {
            for challenge in challenges {
                total_challenges += 1;
                match challenge.challenge_type {
                    ChallengeType::ProofOfStorage => storage_challenges += 1,
                    ChallengeType::ProofOfRetrieval => retrieval_challenges += 1,
                    ChallengeType::PeriodicAudit => audit_challenges += 1,
                }
            }
        }

        ChallengeStats {
            total_challenges,
            storage_challenges,
            retrieval_challenges,
            audit_challenges,
            content_with_challenges: self.active_challenges.len(),
        }
    }
}

impl Default for ProofManager {
    fn default() -> Self {
        Self::new(300, 10, 3600) // 5 min timeout, 10 samples, 1 hour max proof age
    }
}

/// Challenge statistics
#[derive(Debug, Clone)]
pub struct ChallengeStats {
    pub total_challenges: usize,
    pub storage_challenges: usize,
    pub retrieval_challenges: usize,
    pub audit_challenges: usize,
    pub content_with_challenges: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::hash_blake3;

    fn content_hash(label: &str) -> ContentHash {
        ContentHash::from_bytes(&hash_blake3(label.as_bytes()))
    }

    #[test]
    fn test_proof_manager_creation() {
        let manager = ProofManager::new(300, 10, 3600);
        assert_eq!(manager.get_stats().total_verified, 0);
    }

    #[test]
    fn test_generate_storage_challenge() {
        let mut manager = ProofManager::default();
        let content_hash = content_hash("test_content");

        let challenge = manager.generate_storage_challenge(
            content_hash.clone(),
            10,
            "challenger1".to_string(),
        );

        assert!(challenge.is_ok());
        
        let active_challenges = manager.get_active_challenges(&content_hash);
        assert_eq!(active_challenges.len(), 1);
    }

    #[test]
    fn test_generate_retrieval_challenge() {
        let mut manager = ProofManager::default();
        let content_hash = content_hash("test_content");

        let challenge = manager.generate_retrieval_challenge(
            content_hash.clone(),
            20,
            "challenger1".to_string(),
        );

        assert!(challenge.is_ok());
        
        let active_challenges = manager.get_active_challenges(&content_hash);
        assert_eq!(active_challenges.len(), 1);
    }

    #[test]
    fn test_challenge_stats() {
        let mut manager = ProofManager::default();
        let content_hash = content_hash("test");

        manager.generate_storage_challenge(
            content_hash.clone(),
            10,
            "node1".to_string(),
        ).unwrap();

        manager.generate_retrieval_challenge(
            content_hash.clone(),
            10,
            "node1".to_string(),
        ).unwrap();

        let stats = manager.get_challenge_stats();
        assert_eq!(stats.total_challenges, 2);
        assert_eq!(stats.storage_challenges, 1);
        assert_eq!(stats.retrieval_challenges, 1);
        assert_eq!(stats.content_with_challenges, 1);
    }

    #[test]
    fn test_audit_batch_generation() {
        let mut manager = ProofManager::default();
        let content_list = vec![
            (content_hash("content1"), 10),
            (content_hash("content2"), 20),
            (content_hash("content3"), 15),
        ];

        let challenges = manager.generate_audit_batch(
            content_list,
            "auditor".to_string(),
        );

        assert_eq!(challenges.len(), 3);
        for challenge in challenges {
            assert_eq!(challenge.challenge_type, ChallengeType::PeriodicAudit);
        }
    }
}
