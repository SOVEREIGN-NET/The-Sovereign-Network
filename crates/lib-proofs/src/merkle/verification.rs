//! Merkle proof verification
//! 
//! Provides comprehensive verification functions for Merkle inclusion proofs,
//! ensuring data membership validation without revealing tree structure.

use anyhow::Result;
use crate::types::{MerkleProof, VerificationResult};
use crate::merkle::tree::{ZkMerkleTree, hash_merkle_pair};
use crate::merkle::proof_generation::compute_root_from_proof;

impl ZkMerkleTree {
    /// Verify a Merkle inclusion proof
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf;

        for (i, &sibling) in proof.path.iter().enumerate() {
            current_hash = if proof.indices[i] {
                hash_merkle_pair(sibling, current_hash)
            } else {
                hash_merkle_pair(current_hash, sibling)
            };
        }

        current_hash == self.root
    }

    /// Verify a proof with detailed error information
    pub fn verify_proof_detailed(&self, proof: &MerkleProof) -> VerificationResult {
        // Check proof structure validity
        if !proof.is_valid_structure() {
            return VerificationResult::Invalid("Invalid proof format".to_string());
        }

        // Check if proof depth matches expected tree structure
        let expected_depth = self.height as usize;
        if proof.depth() > expected_depth {
            return VerificationResult::Invalid("Invalid proof format".to_string());
        }

        // Verify the actual proof
        match self.verify_proof(proof) {
            true => VerificationResult::Valid {
                circuit_id: "merkle_proof".to_string(),
                verification_time_ms: 0,
                public_inputs: vec![],
            },
            false => VerificationResult::Invalid("Merkle verification failed".to_string()),
        }
    }

    /// Batch verify multiple proofs
    pub fn batch_verify_proofs(&self, proofs: &[MerkleProof]) -> Vec<bool> {
        proofs.iter().map(|proof| self.verify_proof(proof)).collect()
    }

    /// Verify that a proof is for a leaf that exists in this tree
    pub fn verify_proof_for_existing_leaf(&self, proof: &MerkleProof) -> bool {
        self.contains_leaf(proof.leaf) && self.verify_proof(proof)
    }
}

/// Verify a Merkle proof against a known root hash
pub fn verify_proof_against_root(
    proof: &MerkleProof,
    expected_root: [u8; 32],
) -> Result<bool> {
    if !proof.is_valid_structure() {
        return Ok(false);
    }

    let computed_root = compute_root_from_proof(
        proof.leaf,
        &proof.path,
        &proof.indices,
    )?;

    Ok(computed_root == expected_root)
}

/// Verify a proof against a root with detailed results
pub fn verify_proof_against_root_detailed(
    proof: &MerkleProof,
    expected_root: [u8; 32],
) -> VerificationResult {
    match verify_proof_against_root(proof, expected_root) {
        Ok(true) => VerificationResult::Valid {
            circuit_id: "merkle_proof".to_string(),
            verification_time_ms: 0,
            public_inputs: vec![],
        },
        Ok(false) => VerificationResult::Invalid("Merkle verification failed".to_string()),
        Err(e) => VerificationResult::Error(e.to_string()),
    }
}

/// Batch verify proofs against a known root
pub fn batch_verify_against_root(
    proofs: &[MerkleProof],
    expected_root: [u8; 32],
) -> Result<Vec<bool>> {
    let mut results = Vec::with_capacity(proofs.len());
    
    for proof in proofs {
        results.push(verify_proof_against_root(proof, expected_root)?);
    }
    
    Ok(results)
}

/// Verify a proof efficiently without rebuilding intermediate hashes
pub fn verify_proof_optimized(
    leaf: [u8; 32],
    siblings: &[[u8; 32]],
    indices: &[bool],
    expected_root: [u8; 32],
) -> bool {
    if siblings.len() != indices.len() {
        return false;
    }

    let mut current_hash = leaf;
    
    for (i, &sibling) in siblings.iter().enumerate() {
        current_hash = if indices[i] {
            hash_merkle_pair(sibling, current_hash)
        } else {
            hash_merkle_pair(current_hash, sibling)
        };
    }
    
    current_hash == expected_root
}

/// Verify multiple proofs with the same root efficiently
pub fn batch_verify_optimized(
    proofs: &[(Vec<[u8; 32]>, Vec<bool>)], // (siblings, indices) pairs
    leaves: &[[u8; 32]],
    expected_root: [u8; 32],
) -> Vec<bool> {
    if proofs.len() != leaves.len() {
        return vec![false; proofs.len()];
    }

    proofs
        .iter()
        .enumerate()
        .map(|(i, (siblings, indices))| {
            verify_proof_optimized(leaves[i], siblings, indices, expected_root)
        })
        .collect()
}

/// Verify proof membership in a set of valid roots (useful for multiple tree versions)
pub fn verify_proof_in_root_set(
    proof: &MerkleProof,
    valid_roots: &[[u8; 32]],
) -> Result<bool> {
    for &root in valid_roots {
        if verify_proof_against_root(proof, root)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Advanced verification with custom validation logic
pub fn verify_proof_with_validator<F>(
    proof: &MerkleProof,
    expected_root: [u8; 32],
    validator: F,
) -> Result<bool>
where
    F: Fn([u8; 32]) -> bool, // Custom leaf validator
{
    // First verify the leaf meets custom criteria
    if !validator(proof.leaf) {
        return Ok(false);
    }

    // Then verify the Merkle proof
    verify_proof_against_root(proof, expected_root)
}

/// Verification statistics for performance monitoring
#[derive(Debug, Clone)]
pub struct VerificationStats {
    pub total_proofs: usize,
    pub valid_proofs: usize,
    pub invalid_proofs: usize,
    pub error_count: usize,
    pub average_depth: f64,
    pub success_rate: f64,
}

impl VerificationStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self {
            total_proofs: 0,
            valid_proofs: 0,
            invalid_proofs: 0,
            error_count: 0,
            average_depth: 0.0,
            success_rate: 0.0,
        }
    }

    /// Update stats with a verification result
    pub fn update(&mut self, result: &VerificationResult, depth: usize) {
        self.total_proofs += 1;
        
        match result {
            VerificationResult::Valid { .. } => self.valid_proofs += 1,
            VerificationResult::Invalid(_) => self.invalid_proofs += 1,
            VerificationResult::Error(_) => self.error_count += 1,
        }
        
        // Update running average of depth
        self.average_depth = (self.average_depth * (self.total_proofs - 1) as f64 + depth as f64) / self.total_proofs as f64;
        
        // Update success rate
        self.success_rate = (self.valid_proofs as f64 / self.total_proofs as f64) * 100.0;
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
    use lib_crypto::hashing::hash_blake3;

    #[test]
    fn test_verify_valid_proof() {
        let mut tree = ZkMerkleTree::new(4);
        
        let leaf1 = hash_blake3(b"leaf1");
        let leaf2 = hash_blake3(b"leaf2");
        
        tree.add_leaf(leaf1).unwrap();
        tree.add_leaf(leaf2).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        assert!(tree.verify_proof(&proof));
    }

    #[test]
    fn test_verify_invalid_proof() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"leaf");
        tree.add_leaf(leaf).unwrap();
        
        let mut proof = tree.generate_proof(0).unwrap();
        // Corrupt the proof
        proof.leaf = hash_blake3(b"different_leaf");
        
        assert!(!tree.verify_proof(&proof));
    }

    #[test]
    fn test_verify_proof_detailed() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"leaf");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        let result = tree.verify_proof_detailed(&proof);
        
        assert!(result.is_valid());
    }

    #[test]
    fn test_verify_against_root() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"leaf");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        let is_valid = verify_proof_against_root(&proof, tree.root).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_verify_against_wrong_root() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"leaf");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        let wrong_root = [0u8; 32];
        let is_valid = verify_proof_against_root(&proof, wrong_root).unwrap();
        
        assert!(!is_valid);
    }

    #[test]
    fn test_batch_verification() {
        let mut tree = ZkMerkleTree::new(4);
        
        for i in 0..3 {
            let leaf = hash_blake3(&[i]);
            tree.add_leaf(leaf).unwrap();
        }
        
        let proofs = tree.generate_all_proofs().unwrap();
        let results = tree.batch_verify_proofs(&proofs);
        
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&r| r));
    }

    #[test]
    fn test_verify_proof_optimized() {
        let mut tree = ZkMerkleTree::new(3);
        let leaf = hash_blake3(b"test");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        let is_valid = verify_proof_optimized(
            proof.leaf,
            &proof.path,
            &proof.indices,
            tree.root,
        );
        
        assert!(is_valid);
    }

    #[test]
    fn test_verify_in_root_set() {
        let mut tree1 = ZkMerkleTree::new(3);
        let mut tree2 = ZkMerkleTree::new(3);
        let leaf = hash_blake3(b"test");
        
        tree1.add_leaf(leaf).unwrap();
        tree2.add_leaf(leaf).unwrap();
        tree2.add_leaf(hash_blake3(b"extra")).unwrap();
        
        let proof = tree1.generate_proof(0).unwrap();
        let valid_roots = vec![tree1.root, tree2.root];
        
        let is_valid = verify_proof_in_root_set(&proof, &valid_roots).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_with_validator() {
        let mut tree = ZkMerkleTree::new(3);
        let leaf = hash_blake3(b"valid_prefix_data");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        
        // Validator that checks if leaf starts with specific bytes
        let validator = |leaf_hash: [u8; 32]| {
            // Just check that it's not all zeros (simple validation)
            leaf_hash != [0u8; 32]
        };
        
        let is_valid = verify_proof_with_validator(&proof, tree.root, validator).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verification_stats() {
        let mut stats = VerificationStats::new();
        
        stats.update(&VerificationResult::Valid {
            circuit_id: "test".to_string(),
            verification_time_ms: 0,
            public_inputs: vec![],
        }, 3);
        stats.update(&VerificationResult::Invalid("Merkle verification failed".to_string()), 2);
        stats.update(&VerificationResult::Valid {
            circuit_id: "test".to_string(),
            verification_time_ms: 0,
            public_inputs: vec![],
        }, 4);
        
        assert_eq!(stats.total_proofs, 3);
        assert_eq!(stats.valid_proofs, 2);
        assert_eq!(stats.invalid_proofs, 1);
        assert_eq!(stats.error_count, 0);
        assert!((stats.average_depth - 3.0).abs() < 0.1);
        assert!((stats.success_rate - 66.666_66).abs() < 0.1);
    }
}
