//! Merkle proof verifier
//! 
//! Provides verification functions for Merkle tree inclusion proofs.

use anyhow::Result;
use crate::types::{MerkleProof, VerificationResult};
use crate::merkle::ZkMerkleTree;

/// Verify a Merkle proof against a known root
pub fn verify_merkle_proof(
    proof: &MerkleProof,
    expected_root: [u8; 32],
) -> Result<bool> {
    crate::merkle::verification::verify_proof_against_root(proof, expected_root)
}

/// Verify a Merkle proof with detailed results
pub fn verify_merkle_proof_detailed(
    proof: &MerkleProof,
    expected_root: [u8; 32],
) -> VerificationResult {
    crate::merkle::verification::verify_proof_against_root_detailed(proof, expected_root)
}

/// Batch verify multiple Merkle proofs
pub fn batch_verify_merkle_proofs(
    proofs: &[MerkleProof],
    expected_root: [u8; 32],
) -> Result<Vec<bool>> {
    crate::merkle::verification::batch_verify_against_root(proofs, expected_root)
}

/// Verify a proof using a Merkle tree
pub fn verify_with_tree(
    tree: &ZkMerkleTree,
    proof: &MerkleProof,
) -> bool {
    tree.verify_proof(proof)
}

/// Verify a proof with detailed results using a tree
pub fn verify_with_tree_detailed(
    tree: &ZkMerkleTree,
    proof: &MerkleProof,
) -> VerificationResult {
    tree.verify_proof_detailed(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::hashing::hash_blake3;

    #[test]
    fn test_merkle_verification() {
        let mut tree = ZkMerkleTree::new(3);
        let leaf = hash_blake3(b"test_leaf");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        
        assert!(verify_merkle_proof(&proof, tree.root).unwrap());
        assert!(verify_with_tree(&tree, &proof));
    }

    #[test]
    fn test_detailed_verification() {
        let mut tree = ZkMerkleTree::new(3);
        let leaf = hash_blake3(b"test_leaf");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        
        let result = verify_merkle_proof_detailed(&proof, tree.root);
        assert!(result.is_valid());
        
        let tree_result = verify_with_tree_detailed(&tree, &proof);
        assert!(tree_result.is_valid());
    }
}
