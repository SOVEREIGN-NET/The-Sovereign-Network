//! DHT Replication
//! 
//! Handles data replication, consistency, and fault tolerance in the DHT network.

use crate::types::dht_types::{DhtNode, ReplicationPolicy, ReplicationStatus};
use crate::types::NodeId;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// DHT replication manager
///
/// ## Sequence Counter Behavior
///
/// The sequence counter starts at 0 on every node initialization and increments monotonically
/// with each outgoing replication message. This provides replay protection for the current session.
///
/// **Important**: After a node restart, the sequence counter resets to 0. This means:
/// - Replication messages from a restarted node will have low sequence numbers
/// - Remote peers that still have high last_sequence values will reject these messages
/// - The wraparound window (1024) provides some tolerance for this scenario
/// - If a node frequently restarts, legitimate replication operations may fail
///
/// **Mitigation strategies** (not yet implemented):
/// 1. Persist sequence counters across restarts
/// 2. Add a connection reset protocol to signal sequence counter reset
/// 3. Use timestamp-based validation in addition to sequence numbers
/// 4. Implement session tokens that change on restart
#[derive(Debug)]
pub struct DhtReplication {
    /// Local node ID
    local_id: NodeId,
    /// Replication policies for different data types
    policies: HashMap<String, ReplicationPolicy>,
    /// Current replication status for stored data
    replication_status: HashMap<String, ReplicationStatus>,
    /// Default replication factor
    default_replication_factor: usize,
    /// Monotonic sequence counter for outgoing replication messages
    sequence_counter: u64,
}

impl DhtReplication {
    /// Create a new replication manager
    pub fn new(local_id: NodeId, default_replication_factor: usize) -> Self {
        Self {
            local_id,
            policies: HashMap::new(),
            replication_status: HashMap::new(),
            default_replication_factor,
            sequence_counter: 0,
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.sequence_counter;
        self.sequence_counter = self.sequence_counter.wrapping_add(1);
        sequence
    }
    
    /// Set replication policy for a data type
    pub fn set_policy(&mut self, data_type: String, policy: ReplicationPolicy) {
        self.policies.insert(data_type, policy);
    }
    
    /// Get replication policy for a data type
    pub fn get_policy(&self, data_type: &str) -> ReplicationPolicy {
        self.policies.get(data_type).cloned().unwrap_or_else(|| {
            ReplicationPolicy {
                replication_factor: self.default_replication_factor,
                consistency_level: crate::types::dht_types::ConsistencyLevel::Eventual,
                repair_threshold: self.default_replication_factor / 2,
                max_repair_attempts: 3,
            }
        })
    }
    
    /// Initiate replication for a key-value pair
    pub async fn replicate_data(&mut self, key: String, value: Vec<u8>, target_nodes: Vec<DhtNode>) -> Result<()> {
        let policy = self.get_policy("default");
        
        if target_nodes.len() < policy.replication_factor {
            return Err(anyhow!("Insufficient target nodes for replication: {} < {}", 
                target_nodes.len(), policy.replication_factor));
        }
        
        let replica_nodes = target_nodes.into_iter()
            .take(policy.replication_factor)
            .collect::<Vec<_>>();
        
        let mut successful_replicas = Vec::new();
        let mut failed_replicas = Vec::new();
        
        // Attempt to replicate to each target node
        for node in replica_nodes {
            match self.replicate_to_node(&key, &value, &node).await {
                Ok(_) => successful_replicas.push(node.peer.node_id().clone()),
                Err(_) => failed_replicas.push(node.peer.node_id().clone()),
            }
        }
        
        // Update replication status
        let status = ReplicationStatus {
            key: key.clone(),
            total_replicas: successful_replicas.len(),
            required_replicas: policy.replication_factor,
            replica_nodes: successful_replicas.clone(),
            failed_nodes: failed_replicas,
            last_update: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            repair_needed: successful_replicas.len() < policy.repair_threshold,
        };
        
        self.replication_status.insert(key, status);
        
        if successful_replicas.len() < policy.repair_threshold {
            return Err(anyhow!("Replication failed: only {} out of {} replicas created", 
                successful_replicas.len(), policy.replication_factor));
        }
        
        Ok(())
    }
    
    /// Replicate data to a specific node
    async fn replicate_to_node(&mut self, key: &str, value: &[u8], target_node: &DhtNode) -> Result<()> {
        // Check node reputation before attempting replication
        if target_node.reputation < 500 {
            return Err(anyhow!("Target node reputation too low: {}", target_node.reputation));
        }

        // Create DHT store message for replication
        // SECURITY: Includes nonce and sequence_number for replay protection
        // Issue #676: Message should be signed by caller using MessageSigner
        let _message = crate::types::dht_types::DhtMessage {
            message_id: hex::encode(&blake3::hash(&[key.as_bytes(), value, target_node.peer.node_id().as_bytes()].concat()).as_bytes()[..8]),
            message_type: crate::types::dht_types::DhtMessageType::Store,
            sender_id: self.local_id.clone(),
            target_id: Some(target_node.peer.node_id().clone()),
            key: Some(key.to_string()),
            value: Some(value.to_vec()),
            nodes: None, // Not needed for store operation
            contract_data: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: {
                // Generate nonce from timestamp and key hash
                let mut nonce = [0u8; 32];
                let hash = blake3::hash(&[key.as_bytes(), &std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_le_bytes()].concat());
                nonce.copy_from_slice(&hash.as_bytes()[..32]);
                nonce
            },
            sequence_number: self.next_sequence(),
            signature: None, // TODO (HIGH-5): Sign message
        };

        // Send replication message to target node
        // In a implementation, this would use the network layer
        // For now, we'll log the replication attempt and simulate success
        println!(" Replicating key '{}' ({} bytes) to node {}", 
                key, 
                value.len(), 
                hex::encode(&target_node.peer.node_id().as_bytes()[..4]));

        // Log successful replication (metrics would be handled by a separate metrics system)
        println!("Replication message created for key '{}'", key);
        
        // Simulate realistic network delay based on data size
        let delay_ms = (value.len() / 1024).max(10).min(1000); // 10ms to 1s based on size
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms as u64)).await;
        
        // Simulate realistic success rate based on node reputation
        let success_rate = (target_node.reputation as f64 / 1000.0).min(1.0);
        if rand::random::<f64>() < success_rate {
            Ok(())
        } else {
            Err(anyhow!("Network error during replication to node with reputation {}", target_node.reputation))
        }
    }
    
    /// Check and repair under-replicated data
    pub async fn repair_replicas(&mut self, available_nodes: &[DhtNode]) -> Result<RepairStats> {
        let mut repairs_attempted = 0;
        let mut repairs_successful = 0;
        let mut repairs_failed = 0;
        
        let keys_needing_repair: Vec<String> = self.replication_status.iter()
            .filter_map(|(key, status)| {
                if status.repair_needed {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();
        
        for key in keys_needing_repair {
            repairs_attempted += 1;
            
            match self.repair_single_key(&key, available_nodes).await {
                Ok(_) => repairs_successful += 1,
                Err(_) => repairs_failed += 1,
            }
        }
        
        Ok(RepairStats {
            repairs_attempted,
            repairs_successful,
            repairs_failed,
        })
    }
    
    /// Repair replication for a single key
    async fn repair_single_key(&mut self, key: &str, available_nodes: &[DhtNode]) -> Result<()> {
        let status = self.replication_status.get(key)
            .ok_or_else(|| anyhow!("Key not found in replication status"))?;
        
        let policy = self.get_policy("default");
        let needed_replicas = policy.replication_factor.saturating_sub(status.total_replicas);
        
        if needed_replicas == 0 {
            return Ok(());
        }
        
        // Find nodes that don't already have this replica
        // **MIGRATION (Ticket #145):** Uses `node.peer.node_id()` for comparison
        let candidate_nodes: Vec<&DhtNode> = available_nodes.iter()
            .filter(|node| !status.replica_nodes.contains(node.peer.node_id()) && *node.peer.node_id() != self.local_id)
            .take(needed_replicas)
            .collect();
        
        if candidate_nodes.is_empty() {
            return Err(anyhow!("No candidate nodes available for repair"));
        }
        
        // Retrieve the data (in practice, this would come from local storage or another replica)
        let value = self.retrieve_data_for_repair(key).await?;
        
        let mut new_replicas = Vec::new();
        for node in candidate_nodes {
            if let Ok(_) = self.replicate_to_node(key, &value, node).await {
                new_replicas.push(node.peer.node_id().clone());
            }
        }
        
        // Update replication status
        if let Some(status) = self.replication_status.get_mut(key) {
            status.replica_nodes.extend(new_replicas);
            status.total_replicas = status.replica_nodes.len();
            status.repair_needed = status.total_replicas < policy.repair_threshold;
            status.last_update = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        }
        
        Ok(())
    }
    
    /// Retrieve data for repair (simulation)
    async fn retrieve_data_for_repair(&self, key: &str) -> Result<Vec<u8>> {
        // In a implementation, this would:
        // 1. Check local storage first
        // 2. Query existing replicas if not found locally
        // 3. Reconstruct from erasure codes if available
        
        // Try to reconstruct from available replicas
        if let Some(status) = self.replication_status.get(key) {
            if !status.replica_nodes.is_empty() {
                // In production, this would fetch from the first available replica
                // For now, generate a deterministic response based on the key
                let key_hash = blake3::hash(key.as_bytes());
                return Ok(format!("repaired_data_for_{}_hash_{}", key, hex::encode(&key_hash.as_bytes()[..8])).into_bytes());
            }
        }
        
        // If no replicas available, return error
        Err(anyhow::anyhow!("No replicas available for key: {}", key))
    }
    
    /// Get replication status for a key
    pub fn get_replication_status(&self, key: &str) -> Option<&ReplicationStatus> {
        self.replication_status.get(key)
    }
    
    /// List all keys that need repair
    pub fn list_keys_needing_repair(&self) -> Vec<String> {
        self.replication_status.iter()
            .filter_map(|(key, status)| {
                if status.repair_needed {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Remove replication tracking for a key
    pub fn remove_replication_tracking(&mut self, key: &str) -> Option<ReplicationStatus> {
        self.replication_status.remove(key)
    }
    
    /// Get overall replication statistics
    pub fn get_replication_stats(&self) -> OverallReplicationStats {
        let total_keys = self.replication_status.len();
        let under_replicated = self.replication_status.values()
            .filter(|status| status.repair_needed)
            .count();
        let properly_replicated = total_keys - under_replicated;
        
        let avg_replication_factor = if total_keys > 0 {
            let total_replicas: usize = self.replication_status.values()
                .map(|status| status.total_replicas)
                .sum();
            total_replicas as f64 / total_keys as f64
        } else {
            0.0
        };
        
        OverallReplicationStats {
            total_keys,
            properly_replicated,
            under_replicated,
            avg_replication_factor,
        }
    }
}

/// Repair operation statistics
#[derive(Debug)]
pub struct RepairStats {
    pub repairs_attempted: usize,
    pub repairs_successful: usize,
    pub repairs_failed: usize,
}

/// Overall replication statistics
#[derive(Debug)]
pub struct OverallReplicationStats {
    pub total_keys: usize,
    pub properly_replicated: usize,
    pub under_replicated: usize,
    pub avg_replication_factor: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_replication_creation() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let replication = DhtReplication::new(local_id, 3);
        
        assert_eq!(replication.default_replication_factor, 3);
        assert_eq!(replication.policies.len(), 0);
        assert_eq!(replication.replication_status.len(), 0);
    }
    
    #[test]
    fn test_policy_management() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut replication = DhtReplication::new(local_id, 3);
        
        let policy = ReplicationPolicy {
            replication_factor: 5,
            consistency_level: crate::types::dht_types::ConsistencyLevel::Strong,
            repair_threshold: 3,
            max_repair_attempts: 5,
        };
        
        replication.set_policy("critical_data".to_string(), policy.clone());
        
        let retrieved_policy = replication.get_policy("critical_data");
        assert_eq!(retrieved_policy.replication_factor, 5);
        assert_eq!(retrieved_policy.repair_threshold, 3);
    }
    
    #[tokio::test]
    async fn test_replicate_data_insufficient_nodes() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut replication = DhtReplication::new(local_id, 3);
        
        let key = "test_key".to_string();
        let value = b"test_value".to_vec();
        let nodes = vec![]; // Empty nodes list
        
        let result = replication.replicate_data(key, value, nodes).await;
        assert!(result.is_err());
    }
    
    #[test]
    fn test_replication_stats() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let replication = DhtReplication::new(local_id, 3);
        
        let stats = replication.get_replication_stats();
        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.properly_replicated, 0);
        assert_eq!(stats.under_replicated, 0);
        assert_eq!(stats.avg_replication_factor, 0.0);
    }
    
    #[test]
    fn test_keys_needing_repair() {
        let local_id = NodeId::from_bytes([1u8; 32]);
        let mut replication = DhtReplication::new(local_id, 3);
        
        // Manually add a status that needs repair
        let status = ReplicationStatus {
            key: "test_key".to_string(),
            total_replicas: 1,
            required_replicas: 3,
            replica_nodes: vec![NodeId::from_bytes([2u8; 32])],
            failed_nodes: vec![],
            last_update: 12345,
            repair_needed: true,
        };
        
        replication.replication_status.insert("test_key".to_string(), status);
        
        let keys_needing_repair = replication.list_keys_needing_repair();
        assert_eq!(keys_needing_repair.len(), 1);
        assert_eq!(keys_needing_repair[0], "test_key");
    }
}
