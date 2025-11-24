// Merkle prover implementation
use crate::types::MerkleProof;
use crate::merkle::ZkMerkleTree;
use anyhow::Result;

/// Merkle prover for generating merkle inclusion proofs
pub struct MerkleProver {
    pub tree: ZkMerkleTree,
}

impl MerkleProver {
    pub fn new(tree: ZkMerkleTree) -> Self {
        Self { tree }
    }

    pub fn prove_inclusion(&self, leaf: [u8; 32], index: usize) -> Result<MerkleProof> {
        // Validate that the leaf at the given index matches the provided leaf
        let tree_leaf = self.tree.get_leaf(index);
        if let Some(actual_leaf) = tree_leaf {
            if actual_leaf != leaf {
                return Err(anyhow::anyhow!("Leaf mismatch: provided leaf does not match leaf at index {}", index));
            }
        }
        
        self.tree.generate_proof(index)
    }
}
