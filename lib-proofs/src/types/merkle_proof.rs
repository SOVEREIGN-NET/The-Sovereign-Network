//! Merkle proof structures and verification types
//! 
//! Provides types for Merkle tree inclusion proofs, enabling zero-knowledge
//! verification of data membership without revealing the entire tree structure.

use serde::{Serialize, Deserialize};

/// Merkle inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf data being proven
    pub leaf: [u8; 32],
    /// Path of sibling hashes from leaf to root
    pub path: Vec<[u8; 32]>,
    /// Boolean flags indicating left/right positions (true = right, false = left)
    pub indices: Vec<bool>,
}

impl MerkleProof {
    /// Create a new Merkle proof
    pub fn new(leaf: [u8; 32], path: Vec<[u8; 32]>, indices: Vec<bool>) -> Self {
        Self { leaf, path, indices }
    }

    /// Get the depth of this proof (number of levels)
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Check if the proof structure is valid
    pub fn is_valid_structure(&self) -> bool {
        self.path.len() == self.indices.len()
    }

    /// Get the size of this proof in bytes
    pub fn size(&self) -> usize {
        32 + (self.path.len() * 32) + self.indices.len()
    }
}

/// Merkle tree root hash type
pub type MerkleRoot = [u8; 32];

/// Merkle tree leaf hash type  
pub type MerkleLeaf = [u8; 32];

/// Merkle tree node hash type
pub type MerkleNode = [u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_proof_creation() {
        let leaf = [1u8; 32];
        let path = vec![[2u8; 32], [3u8; 32]];
        let indices = vec![false, true];
        
        let proof = MerkleProof::new(leaf, path, indices);
        
        assert_eq!(proof.leaf, [1u8; 32]);
        assert_eq!(proof.depth(), 2);
        assert!(proof.is_valid_structure());
        assert_eq!(proof.size(), 32 + 64 + 2);
    }

    #[test]
    fn test_invalid_merkle_proof() {
        let leaf = [1u8; 32];
        let path = vec![[2u8; 32], [3u8; 32]];
        let indices = vec![false]; // Wrong length
        
        let proof = MerkleProof::new(leaf, path, indices);
        assert!(!proof.is_valid_structure());
    }
}
