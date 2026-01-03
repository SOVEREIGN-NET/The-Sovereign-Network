//! Storage proof implementation for Proof of Storage consensus

use anyhow::Result;
use lib_crypto::{hash_blake3, Hash};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const MIN_STORAGE_CAPACITY: u64 = 100 * 1024 * 1024 * 1024;
const MAX_CHALLENGE_AGE_SECS: u64 = 24 * 60 * 60;

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

impl StorageChallenge {
    /// Create a new storage challenge with derived id and response.
    pub fn new(
        content_hash: Hash,
        challenge: Vec<u8>,
        validator: Hash,
        timestamp: u64,
    ) -> Result<Self> {
        if challenge.is_empty() {
            return Err(anyhow::anyhow!("Challenge payload cannot be empty"));
        }

        let id = Self::derive_id(&content_hash, &challenge, timestamp);
        let response = Self::derive_response(&content_hash, &challenge, &validator, timestamp);

        Ok(Self {
            id,
            content_hash,
            challenge,
            response,
            timestamp,
        })
    }

    /// Derive a deterministic challenge identifier.
    pub fn derive_id(content_hash: &Hash, challenge: &[u8], timestamp: u64) -> Hash {
        let payload = [
            content_hash.as_bytes(),
            challenge,
            &timestamp.to_le_bytes(),
        ]
        .concat();
        Hash::from_bytes(&hash_blake3(&payload))
    }

    /// Derive the expected response for a challenge.
    pub fn derive_response(
        content_hash: &Hash,
        challenge: &[u8],
        validator: &Hash,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = [
            validator.as_bytes(),
            content_hash.as_bytes(),
            challenge,
            &timestamp.to_le_bytes(),
        ]
        .concat();
        hash_blake3(&payload).to_vec()
    }
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
        if self.storage_capacity < MIN_STORAGE_CAPACITY {
            return Ok(false);
        }

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
        if challenge.challenge.is_empty() {
            return Ok(false);
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if challenge.timestamp > now {
            return Ok(false);
        }
        if now.saturating_sub(challenge.timestamp) > MAX_CHALLENGE_AGE_SECS {
            return Ok(false);
        }

        let expected_id =
            StorageChallenge::derive_id(&challenge.content_hash, &challenge.challenge, challenge.timestamp);
        if expected_id != challenge.id {
            return Ok(false);
        }

        let expected_response = StorageChallenge::derive_response(
            &challenge.content_hash,
            &challenge.challenge,
            &self.validator,
            challenge.timestamp,
        );

        Ok(challenge.response == expected_response)
    }

    /// Verify merkle proof of stored data
    fn verify_merkle_proof(&self) -> Result<bool> {
        if self.merkle_proof.is_empty() {
            return Ok(false);
        }

        let root = match Self::compute_merkle_root(
            &self
                .challenges_passed
                .iter()
                .map(|challenge| challenge.content_hash.clone())
                .collect::<Vec<_>>(),
        ) {
            Some(root) => root,
            None => return Ok(false),
        };

        Ok(self.merkle_proof.iter().any(|hash| hash == &root))
    }

    pub fn compute_merkle_root(leaves: &[Hash]) -> Option<Hash> {
        if leaves.is_empty() {
            return None;
        }

        let mut level: Vec<Hash> = leaves.to_vec();
        level.sort();

        while level.len() > 1 {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                let left = &level[i];
                let right = if i + 1 < level.len() {
                    &level[i + 1]
                } else {
                    &level[i]
                };

                let pair = if left.as_bytes() <= right.as_bytes() {
                    [left.as_bytes(), right.as_bytes()].concat()
                } else {
                    [right.as_bytes(), left.as_bytes()].concat()
                };
                next.push(Hash::from_bytes(&hash_blake3(&pair)));
                i += 2;
            }
            level = next;
        }

        level.pop()
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
