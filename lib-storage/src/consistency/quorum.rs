//! Quorum-based consistency

use crate::types::NodeId;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use lib_crypto::types::{PublicKey, Signature};

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

/// Signed quorum response binding a node to a payload
#[derive(Clone, Debug)]
pub struct SignedQuorumResponse {
    pub node_id: NodeId,
    pub payload: Vec<u8>,
    pub signature: Signature,
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

    /// Add a node to the quorum (validates quorum invariants)
    pub fn add_node(&mut self, node_id: NodeId) -> Result<()> {
        if self.nodes.contains(&node_id) {
            return Err(anyhow!("Node already present"));
        }
        self.nodes.insert(node_id);
        let n = self.nodes.len();
        if self.config.r > n || self.config.w > n {
            self.nodes.remove(&node_id);
            return Err(anyhow!(
                "Adding node would violate quorum invariants: r={}, w={}, n={}",
                self.config.r, self.config.w, n
            ));
        }
        self.config.n = n;
        Ok(())
    }

    /// Remove a node from the quorum (validates quorum invariants)
    pub fn remove_node(&mut self, node_id: &NodeId) -> Result<bool> {
        if !self.nodes.contains(node_id) {
            return Ok(false);
        }
        let n_after = self.nodes.len().saturating_sub(1);
        if self.config.r > n_after || self.config.w > n_after {
            return Err(anyhow!(
                "Removing node would violate quorum invariants: r={}, w={}, remaining={}",
                self.config.r, self.config.w, n_after
            ));
        }
        let removed = self.nodes.remove(node_id);
        self.config.n = n_after;
        Ok(removed)
    }

    /// Reconfigure quorum parameters while keeping membership constant
    pub fn reconfigure(&mut self, new_config: QuorumConfig) -> Result<()> {
        let current_n = self.nodes.len();
        if new_config.n != current_n {
            return Err(anyhow!(
                "Config node count mismatch: config.n={}, members={}",
                new_config.n, current_n
            ));
        }
        if new_config.r > current_n || new_config.w > current_n {
            return Err(anyhow!(
                "Quorum sizes exceed member count: r={}, w={}, n={}",
                new_config.r, new_config.w, current_n
            ));
        }
        if !new_config.is_strongly_consistent() {
            return Err(anyhow!("Invalid quorum: r + w must be > n"));
        }

        self.config = new_config;
        Ok(())
    }

    /// Check read quorum with signature verification
    pub fn check_signed_read_quorum(
        &self,
        responses: &[SignedQuorumResponse],
        allowed_skew_secs: u64,
        public_keys: &HashMap<NodeId, PublicKey>,
    ) -> QuorumResult {
        let valid = self.count_verified(responses, allowed_skew_secs, public_keys);
        if valid >= self.config.r {
            QuorumResult::Met {
                required: self.config.r,
                actual: valid,
            }
        } else {
            QuorumResult::NotMet {
                required: self.config.r,
                actual: valid,
            }
        }
    }

    /// Check write quorum with signature verification
    pub fn check_signed_write_quorum(
        &self,
        responses: &[SignedQuorumResponse],
        allowed_skew_secs: u64,
        public_keys: &HashMap<NodeId, PublicKey>,
    ) -> QuorumResult {
        let valid = self.count_verified(responses, allowed_skew_secs, public_keys);
        if valid >= self.config.w {
            QuorumResult::Met {
                required: self.config.w,
                actual: valid,
            }
        } else {
            QuorumResult::NotMet {
                required: self.config.w,
                actual: valid,
            }
        }
    }

    fn count_verified(
        &self,
        responses: &[SignedQuorumResponse],
        allowed_skew_secs: u64,
        public_keys: &HashMap<NodeId, PublicKey>,
    ) -> usize {
        responses
            .iter()
            .filter(|resp| self.verify_response(resp, allowed_skew_secs, public_keys))
            .count()
    }

    fn verify_response(
        &self,
        resp: &SignedQuorumResponse,
        allowed_skew_secs: u64,
        public_keys: &HashMap<NodeId, PublicKey>,
    ) -> bool {
        // Node must be in quorum
        if !self.nodes.contains(&resp.node_id) {
            return false;
        }

        // Timestamp drift check (reject signatures too far in the future)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if resp.signature.timestamp > now.saturating_add(allowed_skew_secs) {
            return false;
        }

        // Public key must match registry for this node
        let expected_pk = match public_keys.get(&resp.node_id) {
            Some(pk) => pk,
            None => return false,
        };
        if expected_pk.key_id != resp.signature.public_key.key_id {
            return false;
        }

        // Verify signature on payload
        match expected_pk.verify(&resp.payload, &resp.signature) {
            Ok(valid) => valid,
            Err(_) => false,
        }
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
    use std::collections::HashMap;
    use lib_crypto::keypair::KeyPair;
    use lib_identity::NodeId as IdentityNodeId;

    fn node(id: u8) -> IdentityNodeId {
        IdentityNodeId::from_bytes([id; 32])
    }

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
            node(1),
            node(2),
            node(3),
            node(4),
            node(5),
        ];
        let manager = QuorumManager::new(config, nodes).unwrap();

        let responding = vec![node(1), node(2), node(3)];
        assert!(manager.check_read_quorum(&responding).is_met());

        let responding = vec![node(1), node(2)];
        assert!(!manager.check_read_quorum(&responding).is_met());
    }

    #[test]
    fn test_write_quorum() {
        let config = QuorumConfig::new(5, 3, 3).unwrap();
        let nodes = vec![
            node(1),
            node(2),
            node(3),
            node(4),
            node(5),
        ];
        let manager = QuorumManager::new(config, nodes).unwrap();

        let responding = vec![
            node(1),
            node(2),
            node(3),
            node(4),
        ];
        assert!(manager.check_write_quorum(&responding).is_met());
    }

    fn signed_response(keypair: &KeyPair, payload: &[u8]) -> SignedQuorumResponse {
        let signature = keypair.sign(payload).expect("signing should succeed");
        let node_id = IdentityNodeId::from_bytes(keypair.public_key.key_id);
        SignedQuorumResponse {
            node_id,
            payload: payload.to_vec(),
            signature,
        }
    }

    #[test]
    fn test_signed_quorum_checks_signatures_and_membership() {
        let kp1 = KeyPair::generate().unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let kp3 = KeyPair::generate().unwrap();

        let node1 = IdentityNodeId::from_bytes(kp1.public_key.key_id);
        let node2 = IdentityNodeId::from_bytes(kp2.public_key.key_id);
        let node3 = IdentityNodeId::from_bytes(kp3.public_key.key_id);

        let mut pk_map = HashMap::new();
        pk_map.insert(node1, kp1.public_key.clone());
        pk_map.insert(node2, kp2.public_key.clone());
        pk_map.insert(node3, kp3.public_key.clone());

        let config = QuorumConfig::new(3, 2, 2).unwrap();
        let mut manager = QuorumManager::new(config, vec![node1, node2, node3]).unwrap();

        let payload = b"replication-ack";
        let responses = vec![
            signed_response(&kp1, payload),
            signed_response(&kp2, payload),
        ];

        let result = manager.check_signed_read_quorum(&responses, 300, &pk_map);
        assert!(result.is_met());

        // Tamper: wrong payload should fail verification
        let mut bad = responses[0].clone();
        bad.payload = b"tampered".to_vec();
        let result = manager.check_signed_read_quorum(&[bad], 300, &pk_map);
        assert!(!result.is_met());

        // Remove a node and ensure membership validation applies
        manager.remove_node(&node2).unwrap();
        let result = manager.check_signed_write_quorum(&responses, 300, &pk_map);
        assert!(!result.is_met());
    }

    #[test]
    fn test_signed_quorum_rejects_future_timestamp() {
        let kp1 = KeyPair::generate().unwrap();
        let node1 = IdentityNodeId::from_bytes(kp1.public_key.key_id);
        let mut pk_map = HashMap::new();
        pk_map.insert(node1, kp1.public_key.clone());

        let config = QuorumConfig::new(1, 1, 1).unwrap();
        let manager = QuorumManager::new(config, vec![node1]).unwrap();

        let payload = b"time-check";
        let mut resp = signed_response(&kp1, payload);
        resp.signature.timestamp = resp.signature.timestamp.saturating_add(10_000);

        let result = manager.check_signed_read_quorum(&[resp], 300, &pk_map);
        assert!(!result.is_met());
    }

    #[test]
    fn test_add_node_updates_config_and_prevents_duplicates() {
        let config = QuorumConfig::new(3, 2, 2).unwrap();
        let nodes = vec![node(1), node(2), node(3)];
        let mut manager = QuorumManager::new(config, nodes).unwrap();

        // Add new node updates config.n
        manager.add_node(node(4)).unwrap();
        assert_eq!(manager.node_count(), 4);
        assert_eq!(manager.config().n, 4);

        // Duplicate add is rejected
        let err = manager.add_node(node(4)).unwrap_err();
        assert!(err.to_string().contains("already"));
    }

    #[test]
    fn test_remove_node_validates_quorum_invariants() {
        let config = QuorumConfig::new(3, 2, 2).unwrap();
        let nodes = vec![node(1), node(2), node(3)];
        let mut manager = QuorumManager::new(config, nodes).unwrap();

        // First removal is allowed
        assert!(manager.remove_node(&node(3)).unwrap());
        assert_eq!(manager.node_count(), 2);
        assert_eq!(manager.config().n, 2);

        // Next removal would violate r/w vs remaining nodes
        let result = manager.remove_node(&node(2));
        assert!(result.is_err());
    }

    #[test]
    fn test_reconfigure_validates_node_count_and_invariants() {
        let config = QuorumConfig::new(3, 2, 2).unwrap();
        let nodes = vec![node(1), node(2), node(3)];
        let mut manager = QuorumManager::new(config, nodes).unwrap();

        // Valid reconfigure with same node count
        let new_config = QuorumConfig::new(3, 2, 2).unwrap();
        manager.reconfigure(new_config).unwrap();

        // Invalid: n does not match membership
        let invalid_config = QuorumConfig::new(4, 3, 3).unwrap();
        let err = manager.reconfigure(invalid_config).unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }
}
