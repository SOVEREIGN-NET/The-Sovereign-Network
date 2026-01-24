//! State root computation for consensus validation
//!
//! Computes Merkle roots of contract state for inclusion in block headers,
//! enabling validators to verify state consistency across the network.

use super::errors::StorageResult;
use super::persistent::PersistentStorage;

/// State root computation for consensus validation
///
/// Computes a Merkle root over all contract state at a block height,
/// creating a cryptographic commitment to the entire state that can be
/// included in block headers for cross-validator verification.
pub struct StateRootComputation {
    storage: PersistentStorage,
}

impl StateRootComputation {
    /// Create a new state root computation instance
    pub fn new(storage: PersistentStorage) -> Self {
        StateRootComputation { storage }
    }

    /// Compute state root for a specific block height
    ///
    /// # Algorithm
    /// 1. Collect all state entries at block height
    /// 2. Sort keys lexicographically
    /// 3. Build Merkle tree from blake3::hash(key || value)
    /// 4. Return root hash
    ///
    /// # Returns
    /// 32-byte blake3 hash of the state root
    pub fn compute_state_root(&self, block_height: u64) -> StorageResult<[u8; 32]> {
        // Scan all versioned entries for this block height
        let prefix = format!("state:{}:", block_height);
        let mut entries = self
            .storage
            .scan_prefix(prefix.as_bytes())?;

        if entries.is_empty() {
            // Empty state has a specific root
            return Ok(Self::empty_root());
        }

        // Sort entries by key for deterministic ordering
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Build leaf hashes: hash(key || value)
        let mut leaf_hashes = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&key);
            hasher.update(&value);
            let hash = hasher.finalize();
            leaf_hashes.push(hash.as_bytes().to_vec());
        }

        // Build Merkle tree bottom-up
        Ok(Self::merkle_root(&leaf_hashes))
    }

    /// Build Merkle tree from leaf hashes
    fn merkle_root(leaf_hashes: &[Vec<u8>]) -> [u8; 32] {
        if leaf_hashes.is_empty() {
            return Self::empty_root();
        }

        if leaf_hashes.len() == 1 {
            let mut result = [0u8; 32];
            result.copy_from_slice(&leaf_hashes[0]);
            return result;
        }

        let mut nodes = leaf_hashes.to_vec();

        // Build tree level by level
        while nodes.len() > 1 {
            let mut next_level = Vec::new();

            // Process pairs of nodes
            for i in (0..nodes.len()).step_by(2) {
                let left = &nodes[i];
                let right = if i + 1 < nodes.len() {
                    &nodes[i + 1]
                } else {
                    left // Hash single node with itself
                };

                let mut hasher = blake3::Hasher::new();
                hasher.update(left);
                hasher.update(right);
                let hash = hasher.finalize();
                next_level.push(hash.as_bytes().to_vec());
            }

            nodes = next_level;
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&nodes[0]);
        result
    }

    /// Hash of empty state
    fn empty_root() -> [u8; 32] {
        let hash = blake3::hash(b"EMPTY_STATE_ROOT");
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_bytes());
        result
    }

    /// Verify that a given state root matches computed root
    pub fn verify_state_root(
        &self,
        block_height: u64,
        expected_root: &[u8; 32],
    ) -> StorageResult<bool> {
        let computed = self.compute_state_root(block_height)?;
        Ok(computed == *expected_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_empty_state_root() {
        let root = StateRootComputation::empty_root();
        assert_eq!(root.len(), 32);

        // Empty root should be deterministic
        let root2 = StateRootComputation::empty_root();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_root_single_entry() {
        let entries = vec![b"test".to_vec()];
        let root = StateRootComputation::merkle_root(&entries);
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_merkle_root_multiple_entries() {
        let entries = vec![
            b"entry1".to_vec(),
            b"entry2".to_vec(),
            b"entry3".to_vec(),
        ];
        let root = StateRootComputation::merkle_root(&entries);
        assert_eq!(root.len(), 32);

        // Same entries should produce same root (deterministic)
        let root2 = StateRootComputation::merkle_root(&entries);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_root_determinism() {
        let entries = vec![
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"gamma".to_vec(),
        ];

        let root1 = StateRootComputation::merkle_root(&entries);
        let root2 = StateRootComputation::merkle_root(&entries);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_state_root() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let computer = StateRootComputation::new(storage.clone());

        // Store versioned state
        let versioned_key = format!("state:{}:{}", 100, "contract1");
        storage
            .set(versioned_key.as_bytes(), b"state_value")
            .unwrap();

        // Compute root
        let root = computer.compute_state_root(100).unwrap();
        assert_eq!(root.len(), 32);

        // Should be deterministic
        let root2 = computer.compute_state_root(100).unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_verify_state_root() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let computer = StateRootComputation::new(storage.clone());

        // Store versioned state
        let versioned_key = format!("state:{}:{}", 100, "contract1");
        storage
            .set(versioned_key.as_bytes(), b"state_value")
            .unwrap();

        // Compute root
        let computed_root = computer.compute_state_root(100).unwrap();

        // Verify with correct root
        assert!(computer
            .verify_state_root(100, &computed_root)
            .unwrap());

        // Verify fails with wrong root
        let wrong_root = [0u8; 32];
        assert!(!computer.verify_state_root(100, &wrong_root).unwrap());
    }
}
