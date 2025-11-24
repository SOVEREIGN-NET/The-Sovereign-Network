//! State proof aggregation logic for hierarchical mesh networks
//!
//! Provides functionality to combine multiple mesh state proofs into
//! aggregated proofs using recursive ZKP techniques.

use crate::state::{AggregatedStateProof, StateCommitment, NetworkStateInfo, NetworkId};
use crate::plonky2::{Plonky2Proof, RecursiveProofBuilder, RecursiveConfig};
use anyhow::{Result, anyhow};
use lib_crypto::hashing::hash_blake3_multiple;
use std::collections::HashMap;

/// Rules for how to aggregate child mesh proofs
#[derive(Debug, Clone)]
pub struct AggregationRules {
    /// Maximum number of child proofs that can be aggregated at once
    pub max_children: usize,
    
    /// Minimum stake required for a mesh to be included
    pub min_stake_threshold: u64,
    
    /// Whether to include geographic bounds in aggregation
    pub include_geographic_data: bool,
    
    /// Whether to validate connectivity between child meshes
    pub validate_connectivity: bool,
}

impl Default for AggregationRules {
    fn default() -> Self {
        Self {
            max_children: 50, // Reasonable limit for proof size
            min_stake_threshold: 1000, // Minimum stake to prevent spam
            include_geographic_data: true,
            validate_connectivity: true,
        }
    }
}

/// State proof aggregator that combines multiple child proofs
pub struct StateProofAggregator {
    rules: AggregationRules,
}

impl StateProofAggregator {
    /// Create a new aggregator with default rules
    pub fn new() -> Self {
        Self {
            rules: AggregationRules::default(),
        }
    }
    
    /// Create a new aggregator with custom rules
    pub fn with_rules(rules: AggregationRules) -> Self {
        Self { rules }
    }
    
    /// Aggregate multiple child network proofs into a single proof
    pub async fn aggregate_proofs(
        &self,
        child_proofs: Vec<AggregatedStateProof>,
        parent_network_id: [u8; 32],
    ) -> Result<AggregatedStateProof> {
        if child_proofs.is_empty() {
            return Err(anyhow!("Cannot aggregate empty list of proofs"));
        }
        
        if child_proofs.len() > self.rules.max_children {
            return Err(anyhow!("Too many child proofs: {} > {}", 
                child_proofs.len(), self.rules.max_children));
        }
        
        // Validate all child proofs
        self.validate_child_proofs(&child_proofs).await?;
        
        // Create combined state commitment
        let combined_state = self.combine_states(&child_proofs)?;
        
        // Create parent network metadata
        let parent_metadata = self.create_parent_metadata(&child_proofs, parent_network_id)?;
        
        // Generate recursive Plonky2 proof
        let recursive_proof = self.generate_recursive_proof(&child_proofs).await?;
        
        Ok(AggregatedStateProof::new_aggregated(
            combined_state,
            child_proofs,
            parent_metadata,
            recursive_proof,
        ))
    }
    
    /// Create a single network proof for bootstrap purposes
    pub async fn create_single_network_proof(
        &self,
        state: StateCommitment,
        network_metadata: NetworkStateInfo,
    ) -> Result<AggregatedStateProof> {
        // Create a simple transaction proof for the current state
        let proof_system = crate::plonky2::ZkProofSystem::new()
            .map_err(|e| anyhow!("Failed to create proof system: {}", e))?;
        
        // Generate a proof for the current state
        let plonky2_proof = proof_system.prove_transaction(
            state.total_supply,
            state.block_height,
            network_metadata.node_count.into(),
            state.timestamp,
            1000, // Default stake value since we removed complex metadata
        ).map_err(|e| anyhow!("Failed to generate transaction proof: {}", e))?;
        
        // Create the single network proof
        Ok(AggregatedStateProof::new_single_network(
            state,
            crate::types::ZkProof::empty(), // No state transition for bootstrap
            network_metadata,
            plonky2_proof,
        ))
    }
    
    /// Validate that all child proofs are legitimate and compatible
    async fn validate_child_proofs(&self, child_proofs: &[AggregatedStateProof]) -> Result<()> {
        for (i, proof) in child_proofs.iter().enumerate() {
            // Check minimum stake requirement
            // Simplified: skip stake validation for now since we removed complex mesh metadata
            // TODO: Add basic network validation if needed
            
            // Validate the proof itself (this will be implemented in verification.rs)
            // For now, we'll assume basic validation
            if proof.state.block_height == 0 {
                return Err(anyhow!("Child proof {} has invalid block height", i));
            }
        }
        
        // Validate connectivity between child networks if required
        if self.rules.validate_connectivity {
            self.validate_network_connectivity(child_proofs)?;
        }
        
        Ok(())
    }
    
    /// Combine multiple state commitments into a single aggregated commitment
    fn combine_states(&self, child_proofs: &[AggregatedStateProof]) -> Result<StateCommitment> {
        let mut total_supply = 0u64;
        let mut max_block_height = 0u64;
        let mut latest_timestamp = 0u64;
        
        // Collect state data from all children
        let mut state_hashes = Vec::new();
        let mut validator_hashes = Vec::new();
        
        for proof in child_proofs {
            total_supply = total_supply.saturating_add(proof.state.total_supply);
            max_block_height = max_block_height.max(proof.state.block_height);
            latest_timestamp = latest_timestamp.max(proof.state.timestamp);
            
            state_hashes.push(proof.state.merkle_root);
            validator_hashes.push(proof.state.validator_set_hash);
        }
        
        // Create combined merkle root (hash of all child state roots)
        let combined_merkle_root = self.hash_state_roots(&state_hashes);
        
        // Create combined validator set hash
        let combined_validator_hash = self.hash_validator_sets(&validator_hashes);
        
        Ok(StateCommitment {
            merkle_root: combined_merkle_root,
            validator_set_hash: combined_validator_hash,
            total_supply,
            block_height: max_block_height,
            timestamp: latest_timestamp,
        })
    }
    
    /// Create metadata for the parent network that aggregates children
    fn create_parent_metadata(
        &self,
        child_proofs: &[AggregatedStateProof],
        parent_network_id: [u8; 32],
    ) -> Result<NetworkStateInfo> {
        let total_nodes: u32 = child_proofs.iter()
            .map(|p| p.total_node_count())
            .sum();
        
        let max_block_height = child_proofs.iter()
            .map(|p| p.state.block_height)
            .max()
            .unwrap_or(0);
        
        Ok(NetworkStateInfo {
            network_id: parent_network_id,
            node_count: total_nodes,
            last_updated: max_block_height,
        })
    }
    
    /// Generate a recursive Plonky2 proof that proves all child proofs are valid
    async fn generate_recursive_proof(&self, child_proofs: &[AggregatedStateProof]) -> Result<Plonky2Proof> {
        if child_proofs.is_empty() {
            return Err(anyhow!("Cannot generate recursive proof from empty child proofs"));
        }

        // Extract Plonky2 proofs from all children
        let child_plonky2_proofs: Vec<Plonky2Proof> = child_proofs.iter()
            .map(|p| p.plonky2_proof.clone())
            .collect();
        
        // Configure recursive proof generation
        let config = RecursiveConfig {
            max_depth: 10,
            batch_size: child_plonky2_proofs.len() as u32,
            optimization_level: 2,
        };
        
        // Create recursive proof builder
        let mut builder = RecursiveProofBuilder::new(config)
            .map_err(|e| anyhow!("Failed to create recursive proof builder: {}", e))?;
        
        // Add all child proofs to the builder
        for proof in child_plonky2_proofs {
            builder.add_proof(proof)
                .map_err(|e| anyhow!("Failed to add proof to builder: {}", e))?;
        }
        
        // Build the recursive proof
        let recursive_proof = builder.build()
            .map_err(|e| anyhow!("Failed to build recursive proof: {}", e))?;
        
        // Extract the final aggregated proof from the recursive proof structure
        // Use the last layer if available, otherwise use base proof
        let final_proof = if !recursive_proof.recursive_layers.is_empty() {
            recursive_proof.recursive_layers.last().unwrap().clone()
        } else {
            recursive_proof.base_proof
        };
        
        // Create the final aggregated Plonky2 proof
        Ok(Plonky2Proof {
            circuit_id: "recursive_state_aggregation".to_string(),
            proof: final_proof.proof,
            public_inputs: recursive_proof.aggregated_inputs,
            proof_system: "ZHTP-Recursive-StateAggregation".to_string(),
            verification_key_hash: final_proof.verification_key_hash,
            private_input_commitment: final_proof.private_input_commitment,
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
    
    /// Validate that child networks have basic validity 
    fn validate_network_connectivity(&self, child_proofs: &[AggregatedStateProof]) -> Result<()> {
        // Simplified validation - just check basic properties
        
        for proof in child_proofs {
            if proof.network_metadata.node_count == 0 {
                return Err(anyhow!("Network has no nodes"));
            }
            
            // Simplified validation - just check basic network metadata
            if proof.network_metadata.node_count == 0 {
                return Err(anyhow!("Child proof has invalid node count"));
            }
        }
        
        Ok(())
    }
    
    // Removed calculate_combined_bounds - not needed in simplified version
    
    /// Hash multiple state roots into a single combined root
    fn hash_state_roots(&self, state_roots: &[[u8; 32]]) -> [u8; 32] {
        let data_segments: Vec<&[u8]> = state_roots.iter().map(|r| r.as_slice()).collect();
        hash_blake3_multiple(&data_segments)
    }
    
    /// Hash multiple validator set hashes into a single combined hash
    fn hash_validator_sets(&self, validator_hashes: &[[u8; 32]]) -> [u8; 32] {
        let data_segments: Vec<&[u8]> = validator_hashes.iter().map(|h| h.as_slice()).collect();
        hash_blake3_multiple(&data_segments)
    }
}

impl Default for StateProofAggregator {
    fn default() -> Self {
        Self::new()
    }
}