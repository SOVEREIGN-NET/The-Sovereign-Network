// Merkle proof circuit implementation
use crate::types::VerificationResult;
use anyhow::Result;

/// Merkle circuit for proving inclusion in a tree
pub struct MerkleCircuit {
    pub tree_height: u32,
    pub root: [u8; 32],
}

impl MerkleCircuit {
    pub fn new(tree_height: u32, root: [u8; 32]) -> Self {
        Self {
            tree_height,
            root,
        }
    }

    pub fn prove(&self, leaf: [u8; 32], path: &[[u8; 32]]) -> Result<VerificationResult> {
        // Validate the Merkle path length
        if path.len() as u32 != self.tree_height {
            return Ok(VerificationResult::Invalid("Invalid path length".to_string()));
        }
        
        // Compute root from leaf and path to verify inclusion
        let mut current_hash = leaf;
        for sibling in path {
            let combined = [current_hash.as_slice(), sibling.as_slice()].concat();
            current_hash = lib_crypto::hashing::hash_blake3(&combined);
        }
        
        // Check if computed root matches expected root
        if current_hash == self.root {
            Ok(VerificationResult::Valid {
                circuit_id: "merkle_circuit".to_string(),
                verification_time_ms: 1,
                public_inputs: vec![self.tree_height as u64, u64::from_le_bytes(leaf[0..8].try_into().unwrap_or([0; 8]))],
            })
        } else {
            Ok(VerificationResult::Invalid("Invalid merkle path".to_string()))
        }
    }
}
