//! Storage Proof System
//!
//! Implements proof-of-storage and proof-of-retrieval mechanisms for the DHT.
//! Integrates with lib-proofs for Merkle tree functionality and lib-crypto for hashing.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use lib_crypto::hashing::hash_blake3;
use lib_proofs::merkle::tree::ZkMerkleTree;
use crate::types::ContentHash;

pub mod challenge;
pub mod verification;
pub mod manager;

// Re-export key types
pub use challenge::{StorageChallenge, ChallengeType};
pub use verification::{ProofVerifier, VerificationResult};
pub use manager::ProofManager;

/// Proof of storage using Merkle tree verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    /// Content hash being proven
    pub content_hash: ContentHash,
    /// Merkle root of the stored data
    pub merkle_root: [u8; 32],
    /// Challenge nonce
    pub challenge_nonce: u64,
    /// Merkle proof path for challenged block
    pub merkle_path: Vec<[u8; 32]>,
    /// The actual block data that was challenged
    pub challenged_block: Vec<u8>,
    /// Block index that was challenged
    pub block_index: usize,
    /// Timestamp of proof generation
    pub timestamp: u64,
    /// Node ID that generated this proof
    pub prover_id: String,
}

impl StorageProof {
    /// Create a new storage proof
    pub fn new(
        content_hash: ContentHash,
        merkle_root: [u8; 32],
        challenge_nonce: u64,
        merkle_path: Vec<[u8; 32]>,
        challenged_block: Vec<u8>,
        block_index: usize,
        prover_id: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            content_hash,
            merkle_root,
            challenge_nonce,
            merkle_path,
            challenged_block,
            block_index,
            timestamp,
            prover_id,
        }
    }

    /// Get the hash of the challenged block
    pub fn block_hash(&self) -> [u8; 32] {
        hash_blake3(&self.challenged_block)
    }

    /// Check if proof is expired (older than expiry_seconds)
    pub fn is_expired(&self, expiry_seconds: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.timestamp + expiry_seconds
    }
}

/// Proof of retrieval with random sampling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalProof {
    /// Content hash
    pub content_hash: ContentHash,
    /// Random sample indices
    pub sample_indices: Vec<usize>,
    /// Hash of sampled blocks
    pub sample_hashes: Vec<[u8; 32]>,
    /// Combined hash of all samples
    pub combined_hash: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Prover node ID
    pub prover_id: String,
}

impl RetrievalProof {
    /// Create a new retrieval proof
    pub fn new(
        content_hash: ContentHash,
        sample_indices: Vec<usize>,
        sample_blocks: Vec<Vec<u8>>,
        prover_id: String,
    ) -> Self {
        let sample_hashes: Vec<[u8; 32]> = sample_blocks
            .iter()
            .map(|block| hash_blake3(block))
            .collect();

        // Create combined hash of all samples
        let mut combined_data = Vec::new();
        for hash in &sample_hashes {
            combined_data.extend_from_slice(hash);
        }
        let combined_hash = hash_blake3(&combined_data);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            content_hash,
            sample_indices,
            sample_hashes,
            combined_hash,
            timestamp,
            prover_id,
        }
    }

    /// Verify the combined hash
    pub fn verify_combined_hash(&self) -> bool {
        let mut combined_data = Vec::new();
        for hash in &self.sample_hashes {
            combined_data.extend_from_slice(hash);
        }
        let computed_hash = hash_blake3(&combined_data);
        computed_hash == self.combined_hash
    }

    /// Check if proof is expired
    pub fn is_expired(&self, expiry_seconds: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.timestamp + expiry_seconds
    }
}

/// Generate a storage proof for content
pub fn generate_storage_proof(
    content_hash: ContentHash,
    content_blocks: &[Vec<u8>],
    challenge_nonce: u64,
    block_index: usize,
    prover_id: String,
) -> Result<StorageProof> {
    if block_index >= content_blocks.len() {
        return Err(anyhow!("Block index out of range"));
    }

    // Build Merkle tree from content blocks
    let block_hashes: Vec<[u8; 32]> = content_blocks
        .iter()
        .map(|block| hash_blake3(block))
        .collect();

    let mut merkle_tree = ZkMerkleTree::with_leaves(
        calculate_tree_height(block_hashes.len()),
        block_hashes,
    )?;

    // Generate Merkle proof for the challenged block
    let merkle_path = generate_merkle_path(&merkle_tree, block_index)?;

    Ok(StorageProof::new(
        content_hash,
        merkle_tree.root,
        challenge_nonce,
        merkle_path,
        content_blocks[block_index].clone(),
        block_index,
        prover_id,
    ))
}

/// Generate a retrieval proof with random sampling
pub fn generate_retrieval_proof(
    content_hash: ContentHash,
    content_blocks: &[Vec<u8>],
    sample_count: usize,
    seed: u64,
    prover_id: String,
) -> Result<RetrievalProof> {
    if sample_count == 0 || sample_count > content_blocks.len() {
        return Err(anyhow!("Invalid sample count"));
    }

    // Generate random sample indices using seed
    let sample_indices = generate_random_indices(content_blocks.len(), sample_count, seed);

    // Collect sampled blocks
    let sample_blocks: Vec<Vec<u8>> = sample_indices
        .iter()
        .map(|&idx| content_blocks[idx].clone())
        .collect();

    Ok(RetrievalProof::new(
        content_hash,
        sample_indices,
        sample_blocks,
        prover_id,
    ))
}

/// Calculate required tree height for given number of leaves
fn calculate_tree_height(leaf_count: usize) -> u8 {
    if leaf_count == 0 {
        return 0;
    }
    let mut height = 0;
    let mut capacity = 1;
    while capacity < leaf_count {
        capacity *= 2;
        height += 1;
    }
    height
}

/// Generate Merkle path for a leaf index
fn generate_merkle_path(tree: &ZkMerkleTree, leaf_index: usize) -> Result<Vec<[u8; 32]>> {
    // For now, return a placeholder implementation
    // In a full implementation, this would traverse the tree and collect sibling nodes
    let mut path = Vec::new();
    let mut current_index = leaf_index;
    
    for _ in 0..tree.height {
        // Get sibling index
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };
        
        // Get sibling hash (placeholder - would need tree internals)
        if let Some(leaf) = tree.get_leaf(sibling_index) {
            path.push(leaf);
        } else {
            path.push([0u8; 32]); // Empty node
        }
        
        current_index /= 2;
    }
    
    Ok(path)
}

/// Generate random indices for sampling
fn generate_random_indices(max: usize, count: usize, seed: u64) -> Vec<usize> {
    use std::collections::HashSet;
    
    let mut indices = HashSet::new();
    let mut rng_state = seed;
    
    while indices.len() < count {
        // Simple LCG random number generator
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let index = (rng_state as usize) % max;
        indices.insert(index);
    }
    
    let mut result: Vec<usize> = indices.into_iter().collect();
    result.sort_unstable();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::hash_blake3;

    fn content_hash(label: &str) -> ContentHash {
        ContentHash::from_bytes(&hash_blake3(label.as_bytes()))
    }

    #[test]
    fn test_storage_proof_creation() {
        let content_hash = content_hash("test_content");
        let blocks = vec![
            b"block0".to_vec(),
            b"block1".to_vec(),
            b"block2".to_vec(),
        ];

        let proof = generate_storage_proof(
            content_hash,
            &blocks,
            12345,
            1,
            "node1".to_string(),
        );

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert_eq!(proof.block_index, 1);
        assert_eq!(proof.challenged_block, b"block1");
    }

    #[test]
    fn test_retrieval_proof_creation() {
        let content_hash = content_hash("test_content");
        let blocks = vec![
            b"block0".to_vec(),
            b"block1".to_vec(),
            b"block2".to_vec(),
            b"block3".to_vec(),
        ];

        let proof = generate_retrieval_proof(
            content_hash,
            &blocks,
            2,
            54321,
            "node1".to_string(),
        );

        assert!(proof.is_ok());
        let proof = proof.unwrap();
        assert_eq!(proof.sample_indices.len(), 2);
        assert_eq!(proof.sample_hashes.len(), 2);
        assert!(proof.verify_combined_hash());
    }

    #[test]
    fn test_calculate_tree_height() {
        assert_eq!(calculate_tree_height(1), 0);
        assert_eq!(calculate_tree_height(2), 1);
        assert_eq!(calculate_tree_height(3), 2);
        assert_eq!(calculate_tree_height(4), 2);
        assert_eq!(calculate_tree_height(5), 3);
        assert_eq!(calculate_tree_height(8), 3);
        assert_eq!(calculate_tree_height(9), 4);
    }

    #[test]
    fn test_random_indices_generation() {
        let indices = generate_random_indices(100, 10, 42);
        assert_eq!(indices.len(), 10);
        
        // Check all indices are unique
        let unique_count: std::collections::HashSet<_> = indices.iter().collect();
        assert_eq!(unique_count.len(), 10);
        
        // Check all indices are in range
        for &idx in &indices {
            assert!(idx < 100);
        }
    }

    #[test]
    fn test_proof_expiration() {
        let content_hash = content_hash("test");
        let proof = StorageProof::new(
            content_hash,
            [0u8; 32],
            123,
            vec![],
            vec![1, 2, 3],
            0,
            "node1".to_string(),
        );

        assert!(!proof.is_expired(3600)); // Not expired within 1 hour
    }
}
