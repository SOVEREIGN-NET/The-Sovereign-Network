//! Zero-knowledge Merkle tree implementation
//! 
//! Implements a cryptographic Merkle tree that supports zero-knowledge
//! inclusion proofs, allowing verification of data membership without
//! revealing the entire tree structure.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::hashing::hash_blake3;

/// Merkle tree for ZK inclusion proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMerkleTree {
    /// Root hash of the tree
    pub root: [u8; 32],
    /// Maximum height of the tree
    pub height: u8,
    /// Current leaves in the tree
    pub leaves: Vec<[u8; 32]>,
}

impl ZkMerkleTree {
    /// Create a new empty Merkle tree
    pub fn new(height: u8) -> Self {
        ZkMerkleTree {
            root: [0u8; 32],
            height,
            leaves: Vec::new(),
        }
    }

    /// Create a new Merkle tree with initial leaves
    pub fn with_leaves(height: u8, leaves: Vec<[u8; 32]>) -> Result<Self> {
        let max_leaves = 1 << height;
        if leaves.len() > max_leaves {
            return Err(anyhow::anyhow!("Too many leaves for tree height"));
        }

        let mut tree = Self::new(height);
        for leaf in leaves {
            tree.add_leaf(leaf)?;
        }
        Ok(tree)
    }

    /// Add a leaf to the tree
    pub fn add_leaf(&mut self, leaf: [u8; 32]) -> Result<()> {
        if self.leaves.len() >= (1 << self.height) {
            return Err(anyhow::anyhow!("Tree is full"));
        }

        self.leaves.push(leaf);
        self.update_root()?;
        Ok(())
    }

    /// Add multiple leaves at once
    pub fn add_leaves(&mut self, leaves: Vec<[u8; 32]>) -> Result<()> {
        if self.leaves.len() + leaves.len() > (1 << self.height) {
            return Err(anyhow::anyhow!("Too many leaves for tree capacity"));
        }

        for leaf in leaves {
            self.leaves.push(leaf);
        }
        self.update_root()?;
        Ok(())
    }

    /// Update the root hash
    fn update_root(&mut self) -> Result<()> {
        if self.leaves.is_empty() {
            self.root = [0u8; 32];
            return Ok(());
        }

        let mut level = self.leaves.clone();
        
        while level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_merkle_pair(chunk[0], chunk[1])
                } else {
                    hash_merkle_pair(chunk[0], [0u8; 32])
                };
                next_level.push(hash);
            }
            
            level = next_level;
        }
        
        self.root = level[0];
        Ok(())
    }

    /// Get the current number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get the maximum capacity of the tree
    pub fn capacity(&self) -> usize {
        1 << self.height
    }

    /// Check if the tree is full
    pub fn is_full(&self) -> bool {
        self.leaves.len() >= self.capacity()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get a leaf by index
    pub fn get_leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.leaves.get(index).copied()
    }

    /// Check if a leaf exists in the tree
    pub fn contains_leaf(&self, leaf: [u8; 32]) -> bool {
        self.leaves.contains(&leaf)
    }

    /// Get the index of a leaf if it exists
    pub fn find_leaf_index(&self, leaf: [u8; 32]) -> Option<usize> {
        self.leaves.iter().position(|&l| l == leaf)
    }

    /// Rebuild the tree root (useful after deserialization)
    pub fn rebuild_root(&mut self) -> Result<()> {
        self.update_root()
    }

    /// Get tree statistics
    pub fn stats(&self) -> TreeStats {
        TreeStats {
            height: self.height,
            leaf_count: self.leaves.len(),
            capacity: self.capacity(),
            utilization: (self.leaves.len() as f64 / self.capacity() as f64) * 100.0,
            root: self.root,
        }
    }
}

/// Tree statistics structure
#[derive(Debug, Clone)]
pub struct TreeStats {
    pub height: u8,
    pub leaf_count: usize,
    pub capacity: usize,
    pub utilization: f64, // Percentage
    pub root: [u8; 32],
}

/// Hash two Merkle tree nodes
pub fn hash_merkle_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&left);
    combined[32..].copy_from_slice(&right);
    hash_blake3(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = ZkMerkleTree::new(4);
        assert_eq!(tree.height, 4);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.capacity(), 16);
        assert!(tree.is_empty());
        assert!(!tree.is_full());
    }

    #[test]
    fn test_add_single_leaf() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf = hash_blake3(b"test_leaf");
        
        tree.add_leaf(leaf).unwrap();
        
        assert_eq!(tree.leaf_count(), 1);
        assert!(!tree.is_empty());
        assert!(tree.contains_leaf(leaf));
        assert_eq!(tree.find_leaf_index(leaf), Some(0));
    }

    #[test]
    fn test_add_multiple_leaves() {
        let mut tree = ZkMerkleTree::new(4);
        let leaf1 = hash_blake3(b"leaf1");
        let leaf2 = hash_blake3(b"leaf2");
        let leaf3 = hash_blake3(b"leaf3");
        
        tree.add_leaf(leaf1).unwrap();
        tree.add_leaf(leaf2).unwrap();
        tree.add_leaf(leaf3).unwrap();
        
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.get_leaf(0), Some(leaf1));
        assert_eq!(tree.get_leaf(1), Some(leaf2));
        assert_eq!(tree.get_leaf(2), Some(leaf3));
    }

    #[test]
    fn test_tree_capacity() {
        let mut tree = ZkMerkleTree::new(2); // Capacity = 4
        
        for i in 0..4 {
            let leaf = hash_blake3(&[i as u8]);
            tree.add_leaf(leaf).unwrap();
        }
        
        assert!(tree.is_full());
        
        // Adding one more should fail
        let extra_leaf = hash_blake3(b"extra");
        assert!(tree.add_leaf(extra_leaf).is_err());
    }

    #[test]
    fn test_with_leaves_constructor() {
        let leaf1 = hash_blake3(b"leaf1");
        let leaf2 = hash_blake3(b"leaf2");
        let leaves = vec![leaf1, leaf2];
        
        let tree = ZkMerkleTree::with_leaves(4, leaves).unwrap();
        
        assert_eq!(tree.leaf_count(), 2);
        assert!(tree.contains_leaf(leaf1));
        assert!(tree.contains_leaf(leaf2));
    }

    #[test]
    fn test_tree_stats() {
        let mut tree = ZkMerkleTree::new(3); // Capacity = 8
        
        for i in 0..3 {
            let leaf = hash_blake3(&[i as u8]);
            tree.add_leaf(leaf).unwrap();
        }
        
        let stats = tree.stats();
        assert_eq!(stats.height, 3);
        assert_eq!(stats.leaf_count, 3);
        assert_eq!(stats.capacity, 8);
        assert_eq!(stats.utilization, 37.5); // 3/8 * 100
    }

    #[test]
    fn test_hash_merkle_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        
        let hash1 = hash_merkle_pair(left, right);
        let hash2 = hash_merkle_pair(left, right);
        
        // Should be deterministic
        assert_eq!(hash1, hash2);
        
        // Should be different with different inputs
        let hash3 = hash_merkle_pair(right, left);
        assert_ne!(hash1, hash3);
    }
}
