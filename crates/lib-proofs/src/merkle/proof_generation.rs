//! Merkle proof generation
//! 
//! Implements the generation of cryptographic inclusion proofs for Merkle trees,
//! allowing verification of data membership without revealing tree structure.

use anyhow::Result;
use crate::types::MerkleProof;
use crate::merkle::tree::{ZkMerkleTree, hash_merkle_pair};

impl ZkMerkleTree {
    /// Generate a Merkle inclusion proof
    pub fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(anyhow::anyhow!("Leaf index out of bounds"));
        }

        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut current_level = self.leaves.clone();
        let mut current_index = leaf_index;

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                [0u8; 32]
            };

            path.push(sibling);
            indices.push(current_index % 2 == 1);

            // Build next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_merkle_pair(chunk[0], chunk[1])
                } else {
                    hash_merkle_pair(chunk[0], [0u8; 32])
                };
                next_level.push(hash);
            }

            current_level = next_level;
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf: self.leaves[leaf_index],
            path,
            indices,
        })
    }

    /// Generate proof for a specific leaf value
    pub fn generate_proof_for_leaf(&self, leaf: [u8; 32]) -> Result<MerkleProof> {
        let index = self.find_leaf_index(leaf)
            .ok_or_else(|| anyhow::anyhow!("Leaf not found in tree"))?;
        self.generate_proof(index)
    }

    /// Generate multiple proofs at once
    pub fn generate_batch_proofs(&self, indices: Vec<usize>) -> Result<Vec<MerkleProof>> {
        let mut proofs = Vec::with_capacity(indices.len());
        
        for index in indices {
            proofs.push(self.generate_proof(index)?);
        }
        
        Ok(proofs)
    }

    /// Generate proofs for all leaves
    pub fn generate_all_proofs(&self) -> Result<Vec<MerkleProof>> {
        let indices: Vec<usize> = (0..self.leaves.len()).collect();
        self.generate_batch_proofs(indices)
    }
}

/// Generate a proof for a leaf without building the full tree
/// Useful for streaming scenarios where you don't want to store all leaves
pub fn generate_streaming_proof(
    leaf: [u8; 32],
    leaf_index: usize,
    siblings: Vec<[u8; 32]>,
    tree_height: u8,
) -> Result<MerkleProof> {
    if siblings.len() != tree_height as usize {
        return Err(anyhow::anyhow!("Incorrect number of siblings for tree height"));
    }

    let mut indices = Vec::new();
    let mut current_index = leaf_index;
    
    for _ in 0..tree_height {
        indices.push(current_index % 2 == 1);
        current_index /= 2;
    }

    Ok(MerkleProof {
        leaf,
        path: siblings,
        indices,
    })
}

/// Compute the expected root from a leaf and its siblings
/// This is used internally for proof verification
pub fn compute_root_from_proof(
    leaf: [u8; 32],
    siblings: &[[u8; 32]],
    indices: &[bool],
) -> Result<[u8; 32]> {
    if siblings.len() != indices.len() {
        return Err(anyhow::anyhow!("Siblings and indices length mismatch"));
    }

    let mut current_hash = leaf;

    for (i, &sibling) in siblings.iter().enumerate() {
        current_hash = if indices[i] {
            hash_merkle_pair(sibling, current_hash)
        } else {
            hash_merkle_pair(current_hash, sibling)
        };
    }

    Ok(current_hash)
}

/// Proof generation statistics
#[derive(Debug, Clone)]
pub struct ProofStats {
    pub proof_size: usize,
    pub depth: usize,
    pub leaf_index: usize,
    pub verification_complexity: usize, // Number of hash operations needed
}

impl MerkleProof {
    /// Get statistics about this proof
    pub fn stats(&self, leaf_index: usize) -> ProofStats {
        ProofStats {
            proof_size: self.size(),
            depth: self.depth(),
            leaf_index,
            verification_complexity: self.path.len(),
        }
    }

    /// Optimize proof by removing unnecessary padding
    pub fn optimize(&mut self) {
        // Remove trailing zero siblings (padding)
        while let Some(&last_sibling) = self.path.last() {
            if last_sibling == [0u8; 32] && self.indices.last() == Some(&false) {
                self.path.pop();
                self.indices.pop();
            } else {
                break;
            }
        }
    }

    /// Create a compact representation of the proof
    pub fn to_compact(&self) -> CompactMerkleProof {
        CompactMerkleProof {
            leaf: self.leaf,
            path: self.path.clone(),
            indices_packed: pack_indices(&self.indices),
        }
    }
}

/// Compact representation of a Merkle proof with packed boolean indices
#[derive(Debug, Clone)]
pub struct CompactMerkleProof {
    pub leaf: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub indices_packed: u64, // Packed boolean flags
}

impl CompactMerkleProof {
    /// Convert back to standard MerkleProof
    pub fn to_standard(&self) -> MerkleProof {
        MerkleProof {
            leaf: self.leaf,
            path: self.path.clone(),
            indices: unpack_indices(self.indices_packed, self.path.len()),
        }
    }
}

/// Pack boolean indices into a u64
fn pack_indices(indices: &[bool]) -> u64 {
    let mut packed = 0u64;
    for (i, &flag) in indices.iter().enumerate() {
        if flag && i < 64 {
            packed |= 1u64 << i;
        }
    }
    packed
}

/// Unpack boolean indices from a u64
fn unpack_indices(packed: u64, count: usize) -> Vec<bool> {
    let mut indices = Vec::with_capacity(count);
    for i in 0..count {
        indices.push((packed & (1u64 << i)) != 0);
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::hashing::hash_blake3;

    #[test]
    fn test_generate_proof() {
        let mut tree = ZkMerkleTree::new(4);
        
        // Add some leaves
        let leaf1 = hash_blake3(b"leaf1");
        let leaf2 = hash_blake3(b"leaf2");
        let leaf3 = hash_blake3(b"leaf3");
        
        tree.add_leaf(leaf1).unwrap();
        tree.add_leaf(leaf2).unwrap();
        tree.add_leaf(leaf3).unwrap();
        
        // Generate proof for leaf1
        let proof = tree.generate_proof(0).unwrap();
        assert_eq!(proof.leaf, leaf1);
        assert!(proof.is_valid_structure());
        
        // Generate proof for leaf2
        let proof = tree.generate_proof(1).unwrap();
        assert_eq!(proof.leaf, leaf2);
        assert!(proof.is_valid_structure());
    }

    #[test]
    fn test_generate_proof_for_leaf() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"test_leaf");
        
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof_for_leaf(leaf).unwrap();
        assert_eq!(proof.leaf, leaf);
    }

    #[test]
    fn test_generate_proof_nonexistent_leaf() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"test_leaf");
        let nonexistent = hash_blake3(b"nonexistent");
        
        tree.add_leaf(leaf).unwrap();
        
        let result = tree.generate_proof_for_leaf(nonexistent);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_proof_generation() {
        let mut tree = ZkMerkleTree::new(4);
        
        for i in 0..5 {
            let leaf = hash_blake3(&[i]);
            tree.add_leaf(leaf).unwrap();
        }
        
        let proofs = tree.generate_batch_proofs(vec![0, 2, 4]).unwrap();
        assert_eq!(proofs.len(), 3);
        
        for (i, proof) in proofs.iter().enumerate() {
            let expected_leaf = hash_blake3(&[i as u8 * 2]);
            assert_eq!(proof.leaf, expected_leaf);
        }
    }

    #[test]
    fn test_generate_all_proofs() {
        let mut tree = ZkMerkleTree::new(3);
        
        for i in 0..3 {
            let leaf = hash_blake3(&[i]);
            tree.add_leaf(leaf).unwrap();
        }
        
        let proofs = tree.generate_all_proofs().unwrap();
        assert_eq!(proofs.len(), 3);
    }

    #[test]
    fn test_compute_root_from_proof() {
        let mut tree = ZkMerkleTree::new(3);
        let leaf = hash_blake3(b"test");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        let computed_root = compute_root_from_proof(
            proof.leaf, 
            &proof.path, 
            &proof.indices
        ).unwrap();
        
        assert_eq!(computed_root, tree.root);
    }

    #[test]
    fn test_proof_optimization() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"test");
        tree.add_leaf(leaf).unwrap();
        
        let mut proof = tree.generate_proof(0).unwrap();
        let original_size = proof.size();
        
        proof.optimize();
        
        // Size should be same or smaller after optimization
        assert!(proof.size() <= original_size);
    }

    #[test]
    fn test_compact_proof() {
        let mut tree = ZkMerkleTree::new(3);
        let leaf = hash_blake3(b"test");
        tree.add_leaf(leaf).unwrap();
        
        let proof = tree.generate_proof(0).unwrap();
        let compact = proof.to_compact();
        let restored = compact.to_standard();
        
        assert_eq!(proof.leaf, restored.leaf);
        assert_eq!(proof.path, restored.path);
        assert_eq!(proof.indices, restored.indices);
    }

    #[test]
    fn test_pack_unpack_indices() {
        let indices = vec![true, false, true, true, false];
        let packed = pack_indices(&indices);
        let unpacked = unpack_indices(packed, indices.len());
        
        assert_eq!(indices, unpacked);
    }
}
