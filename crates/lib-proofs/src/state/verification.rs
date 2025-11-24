//! State proof verification types and utilities
//!
//! Provides supporting types and utility functions for state proof verification.
//! The main verifier is located in verifiers/state_verifier.rs following the
//! established pattern.

use crate::state::{AggregatedStateProof, BootstrapProof};
use crate::types::VerificationResult;
use anyhow::Result;

/// Verification configuration for state proofs
#[derive(Debug, Clone)]
pub struct StateVerificationConfig {
    /// Whether to verify all child proofs recursively
    pub verify_children_recursive: bool,
    
    /// Whether to validate mesh connectivity claims
    pub validate_mesh_connectivity: bool,
    
    /// Whether to check geographic bounds consistency
    pub validate_geographic_bounds: bool,
    
    /// Maximum allowed proof age in seconds
    pub max_proof_age_seconds: u64,
    
    /// Whether to require multiple proof sources for validation
    pub require_multiple_sources: bool,
    
    /// Minimum number of confirming sources if multiple sources required
    pub min_confirming_sources: usize,
}

impl Default for StateVerificationConfig {
    fn default() -> Self {
        Self {
            verify_children_recursive: true,
            validate_mesh_connectivity: true,
            validate_geographic_bounds: false, // Optional
            max_proof_age_seconds: 7200, // 2 hours
            require_multiple_sources: false, // For single mesh bootstrapping
            min_confirming_sources: 2,
        }
    }
}

/// Result of state proof verification with detailed information
#[derive(Debug, Clone)]
pub struct StateVerificationResult {
    /// Overall verification result
    pub result: VerificationResult,
    
    /// Number of child proofs verified
    pub children_verified: usize,
    
    /// Total nodes covered by the proof
    pub total_nodes_covered: u32,
    
    /// Proof hierarchy depth
    pub proof_depth: u32,
    
    /// Any warnings or issues found
    pub warnings: Vec<String>,
    
    /// Verification timing information
    pub verification_time_ms: u64,
}

// Supporting utility functions for basic verification
// These provide simple proof validation without complex logic

/// Convenience function for quick state proof verification
pub async fn verify_state_proof(proof: &AggregatedStateProof) -> Result<VerificationResult> {
    // Basic structural validation
    if proof.state.block_height == 0 && !proof.child_proofs.is_empty() {
        return Ok(VerificationResult::Invalid("Genesis state cannot have child proofs".to_string()));
    }
    
    // Check that the proof has required components  
    if proof.plonky2_proof.proof.is_empty() {
        return Ok(VerificationResult::Invalid("Empty plonky2 proof".to_string()));
    }
    
    // For now, return Valid for well-formed proofs
    // In a full implementation, this would verify the cryptographic proof
    Ok(VerificationResult::Valid {
        circuit_id: "state_proof".to_string(),
        verification_time_ms: 1,
        public_inputs: vec![proof.state.block_height],
    })
}

/// Convenience function for quick bootstrap proof verification
pub async fn verify_bootstrap_proof(proof: &BootstrapProof) -> Result<VerificationResult> {
    // Verify the main state proof first
    let state_result = verify_state_proof(&proof.state_proof).await?;
    if !state_result.is_valid() {
        return Ok(state_result);
    }
    
    // Basic bootstrap-specific validation
    if proof.genesis_state.block_height > proof.state_proof.state.block_height {
        return Ok(VerificationResult::Invalid("Genesis state is ahead of current state".to_string()));
    }
    
    // Check topology is reasonable
    if proof.mesh_topology.total_meshes == 0 {
        return Ok(VerificationResult::Invalid("Mesh topology reports zero meshes".to_string()));
    }
    
    Ok(VerificationResult::Valid {
        circuit_id: "bootstrap_proof".to_string(),
        verification_time_ms: 2,
        public_inputs: vec![proof.state_proof.state.block_height, proof.genesis_state.block_height],
    })
}