//! Quorum-based consistency

use crate::consistency::vector_clock::NodeId;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Quorum configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumConfig {
    /// Total number of replicas
    pub n: usize,
    /// Read quorum size
    pub r: usize,
    /// Write quorum size
    pub w: usize,
}

impl QuorumConfig {
    /// Create a new quorum configuration
    pub fn new(n: usize, r: usize, w: usize) -> Result<Self> {
        if r + w <= n {
            return Err(anyhow!("Invalid quorum: r + w must be > n for strong consistency"));
        }
        if r == 0 || w == 0 {
            return Err(anyhow!("Quorum sizes must be positive"));
        }
        if r > n || w > n {
            return Err(anyhow!("Quorum sizes cannot exceed replica count"));
        }

        Ok(Self { n, r, w })
    }

    /// Create a strict majority quorum (n/2 + 1)
    pub fn majority(n: usize) -> Result<Self> {
        let quorum_size = n / 2 + 1;
        Self::new(n, quorum_size, quorum_size)
    }

    /// Create a quorum optimized for reads (small r, large w)
    pub fn read_heavy(n: usize) -> Result<Self> {
        let r = n / 3 + 1;
        let w = n - r + 1;
        Self::new(n, r, w)
    }

    /// Create a quorum optimized for writes (large r, small w)
    pub fn write_heavy(n: usize) -> Result<Self> {
        let w = n / 3 + 1;
        let r = n - w + 1;
        Self::new(n, r, w)
    }

    /// Validate if the configuration provides strong consistency
    pub fn is_strongly_consistent(&self) -> bool {
        self.r + self.w > self.n
    }
}

/// Quorum manager
pub struct QuorumManager {
    config: QuorumConfig,
    nodes: HashSet<NodeId>,
}

impl QuorumManager {
    /// Create a new quorum manager
    pub fn new(config: QuorumConfig, nodes: Vec<NodeId>) -> Result<Self> {
        if nodes.len() != config.n {
            return Err(anyhow!("Number of nodes must match quorum configuration"));
        }

        Ok(Self {
            config,
            nodes: nodes.into_iter().collect(),
        })
    }

    /// Check if read quorum is met
    pub fn check_read_quorum(&self, responding_nodes: &[NodeId]) -> QuorumResult {
        let valid_responses: HashSet<_> = responding_nodes
            .iter()
            .filter(|n| self.nodes.contains(*n))
            .collect();

        if valid_responses.len() >= self.config.r {
            QuorumResult::Met {
                required: self.config.r,
                actual: valid_responses.len(),
            }
        } else {
            QuorumResult::NotMet {
                required: self.config.r,
                actual: valid_responses.len(),
            }
        }
    }

    /// Check if write quorum is met
    pub fn check_write_quorum(&self, responding_nodes: &[NodeId]) -> QuorumResult {
        let valid_responses: HashSet<_> = responding_nodes
            .iter()
            .filter(|n| self.nodes.contains(*n))
            .collect();

        if valid_responses.len() >= self.config.w {
            QuorumResult::Met {
                required: self.config.w,
                actual: valid_responses.len(),
            }
        } else {
            QuorumResult::NotMet {
                required: self.config.w,
                actual: valid_responses.len(),
            }
        }
    }

    /// Get the quorum configuration
    pub fn config(&self) -> &QuorumConfig {
        &self.config
    }

    /// Get all nodes
    pub fn nodes(&self) -> Vec<NodeId> {
        self.nodes.iter().cloned().collect()
    }

    /// Add a node to the quorum
    pub fn add_node(&mut self, node_id: NodeId) {
        self.nodes.insert(node_id);
    }

    /// Remove a node from the quorum
    pub fn remove_node(&mut self, node_id: &NodeId) -> bool {
        self.nodes.remove(node_id)
    }

    /// Check if node is in quorum
    pub fn contains_node(&self, node_id: &NodeId) -> bool {
        self.nodes.contains(node_id)
    }

    /// Get number of nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

/// Quorum check result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuorumResult {
    /// Quorum met
    Met { required: usize, actual: usize },
    /// Quorum not met
    NotMet { required: usize, actual: usize },
}

impl QuorumResult {
    /// Check if quorum is met
    pub fn is_met(&self) -> bool {
        matches!(self, QuorumResult::Met { .. })
    }

    /// Get the required quorum size
    pub fn required(&self) -> usize {
        match self {
            QuorumResult::Met { required, .. } | QuorumResult::NotMet { required, .. } => {
                *required
            }
        }
    }

    /// Get the actual response count
    pub fn actual(&self) -> usize {
        match self {
            QuorumResult::Met { actual, .. } | QuorumResult::NotMet { actual, .. } => *actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_config() {
        let config = QuorumConfig::new(5, 3, 3).unwrap();
        assert!(config.is_strongly_consistent());

        let config = QuorumConfig::new(5, 2, 2);
        assert!(config.is_err()); // r + w <= n
    }

    #[test]
    fn test_majority_quorum() {
        let config = QuorumConfig::majority(5).unwrap();
        assert_eq!(config.r, 3);
        assert_eq!(config.w, 3);
        assert!(config.is_strongly_consistent());
    }

    #[test]
    fn test_read_quorum() {
        let config = QuorumConfig::new(5, 3, 3).unwrap();
        let nodes = vec![
            "node1".to_string(),
            "node2".to_string(),
            "node3".to_string(),
            "node4".to_string(),
            "node5".to_string(),
        ];
        let manager = QuorumManager::new(config, nodes).unwrap();

        let responding = vec!["node1".to_string(), "node2".to_string(), "node3".to_string()];
        assert!(manager.check_read_quorum(&responding).is_met());

        let responding = vec!["node1".to_string(), "node2".to_string()];
        assert!(!manager.check_read_quorum(&responding).is_met());
    }

    #[test]
    fn test_write_quorum() {
        let config = QuorumConfig::new(5, 3, 3).unwrap();
        let nodes = vec![
            "node1".to_string(),
            "node2".to_string(),
            "node3".to_string(),
            "node4".to_string(),
            "node5".to_string(),
        ];
        let manager = QuorumManager::new(config, nodes).unwrap();

        let responding = vec![
            "node1".to_string(),
            "node2".to_string(),
            "node3".to_string(),
            "node4".to_string(),
        ];
        assert!(manager.check_write_quorum(&responding).is_met());
    }
}
