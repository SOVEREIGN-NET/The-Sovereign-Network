//! State proof verifier following the established verifier pattern
//!
//! Provides verification of aggregated state proofs for blockchain bootstrapping
//! and mesh integration, following the same interface as other verifiers.

use crate::state::{AggregatedStateProof, BootstrapProof};
use crate::state::verification::{StateVerificationConfig, StateVerificationResult, verify_state_proof, verify_bootstrap_proof};
use crate::types::VerificationResult;
use anyhow::Result;

/// State proof verifier that handles aggregated proofs following the standard verifier interface
pub struct StateVerifier {
    config: StateVerificationConfig,
}

impl StateVerifier {
    /// Create a new state proof verifier
    pub fn new() -> Self {
        Self {
            config: StateVerificationConfig::default(),
        }
    }
    
    /// Create a new verifier with custom configuration
    pub fn with_config(config: StateVerificationConfig) -> Self {
        Self {
            config,
        }
    }
    
    /// Verify an aggregated state proof with basic result
    pub async fn verify_proof(&self, proof: &AggregatedStateProof) -> Result<VerificationResult> {
        verify_state_proof(proof).await
    }
    
    /// Verify an aggregated state proof with detailed results
    pub async fn verify_aggregated_proof(&self, proof: &AggregatedStateProof) -> Result<StateVerificationResult> {
        // Create a detailed result from the basic verification
        let start_time = std::time::Instant::now();
        let basic_result = verify_state_proof(proof).await?;
        
        Ok(StateVerificationResult {
            result: basic_result,
            children_verified: proof.child_proofs.len(),
            total_nodes_covered: proof.total_node_count(),
            proof_depth: proof.proof_depth(),
            warnings: Vec::new(),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        })
    }
    
    /// Verify a bootstrap proof for a new node
    pub async fn verify_bootstrap_proof(&self, bootstrap_proof: &BootstrapProof) -> Result<StateVerificationResult> {
        // Use the verification function from state::verification
        let start_time = std::time::Instant::now();
        let basic_result = verify_bootstrap_proof(bootstrap_proof).await?;
        
        Ok(StateVerificationResult {
            result: basic_result,
            children_verified: bootstrap_proof.state_proof.child_proofs.len(),
            total_nodes_covered: bootstrap_proof.state_proof.total_node_count(),
            proof_depth: bootstrap_proof.state_proof.proof_depth(),
            warnings: Vec::new(),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        })
    }
    
    /// Get current configuration
    pub fn get_config(&self) -> &StateVerificationConfig {
        &self.config
    }
    
    /// Update configuration
    pub fn set_config(&mut self, config: StateVerificationConfig) {
        self.config = config;
    }
}

impl Default for StateVerifier {
    fn default() -> Self {
        Self::new()
    }
}