//! Core state proof structures and types
//! 
//! Defines the fundamental data structures for aggregated state proofs
//! that enable efficient blockchain bootstrapping and mesh integration.

use crate::types::ZkProof;
use crate::plonky2::Plonky2Proof;
use serde::{Deserialize, Serialize};
use anyhow::Result;

/// Unique identifier for a network segment (simplified from MeshId)
pub type NetworkId = [u8; 32];

/// Basic network metadata - minimal info needed for state proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateInfo {
    pub network_id: NetworkId,
    pub node_count: u32,
    pub last_updated: u64, // Block height
}

/// State commitment representing the current state of all accounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCommitment {
    pub merkle_root: [u8; 32],        // Root of account state tree
    pub validator_set_hash: [u8; 32], // Hash of current validator set
    pub total_supply: u64,            // Total token supply
    pub block_height: u64,            // Block at which this state is valid
    pub timestamp: u64,               // Unix timestamp
}

/// Aggregated state proof - core blockchain state proof without complex mesh features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedStateProof {
    /// Current state commitment
    pub state: StateCommitment,
    
    /// ZKP proving genesis state → current state transition
    pub transition_proof: ZkProof,
    
    /// Recent transaction batch proofs for incremental verification
    pub batch_proofs: Vec<ZkProof>,
    
    /// Child proofs for hierarchical aggregation (optional)
    pub child_proofs: Vec<AggregatedStateProof>,
    
    /// Basic network metadata (simplified)
    pub network_metadata: NetworkStateInfo,
    
    /// Efficient recursive proof using Plonky2
    pub plonky2_proof: Plonky2Proof,
    
    /// Proof generation timestamp
    pub generated_at: u64,
}

impl AggregatedStateProof {
    /// Create a new aggregated state proof for a single network (no children)
    pub fn new_single_network(
        state: StateCommitment,
        transition_proof: ZkProof,
        network_metadata: NetworkStateInfo,
        plonky2_proof: Plonky2Proof,
    ) -> Self {
        Self {
            state,
            transition_proof,
            batch_proofs: Vec::new(),
            child_proofs: Vec::new(),
            network_metadata,
            plonky2_proof,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Create an aggregated proof that combines multiple child network proofs
    pub fn new_aggregated(
        combined_state: StateCommitment,
        child_proofs: Vec<AggregatedStateProof>,
        network_metadata: NetworkStateInfo,
        plonky2_proof: Plonky2Proof,
    ) -> Self {
        Self {
            state: combined_state,
            transition_proof: ZkProof::empty(), // Aggregated proofs don't need individual transitions
            batch_proofs: Vec::new(),
            child_proofs,
            network_metadata,
            plonky2_proof,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Get the total number of nodes covered by this proof (recursive)
    pub fn total_node_count(&self) -> u32 {
        let child_count: u32 = self.child_proofs
            .iter()
            .map(|child| child.total_node_count())
            .sum();
        
        self.network_metadata.node_count + child_count
    }
    
    /// Get the depth of the proof hierarchy
    pub fn proof_depth(&self) -> u32 {
        if self.child_proofs.is_empty() {
            1
        } else {
            1 + self.child_proofs
                .iter()
                .map(|child| child.proof_depth())
                .max()
                .unwrap_or(0)
        }
    }
    
    /// Check if this is a leaf proof (no children)
    pub fn is_leaf_proof(&self) -> bool {
        self.child_proofs.is_empty()
    }
    
    /// Get all network IDs covered by this proof (recursive)
    pub fn covered_networks(&self) -> Vec<NetworkId> {
        let mut networks = vec![self.network_metadata.network_id];
        
        for child in &self.child_proofs {
            networks.extend(child.covered_networks());
        }
        
        networks
    }

    /// Check if this proof is valid (simplified validation)
    pub fn is_valid(&self) -> Result<bool> {
        // Basic validity checks for standalone state proof
        if self.state.block_height == 0 {
            return Ok(false); // Invalid block height
        }
        
        if self.transition_proof.is_empty() && self.child_proofs.is_empty() {
            return Ok(false); // No proof content
        }
        
        // In a implementation, would verify the plonky2_proof
        // For now, assume valid if basic structure checks pass
        Ok(true)
    }
}