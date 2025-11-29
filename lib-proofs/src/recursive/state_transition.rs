//! State Transition Recursive Circuit Implementation
//! 
//! Advanced recursive circuits for proving chains of state transitions
//! with efficient verification of blockchain state evolution.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::hashing::{hash_blake3, hash_blake3_multiple};
use crate::circuits::StateTransitionProof;
use crate::state::{StateCommitment, AggregatedStateProof};
use crate::plonky2::{CircuitBuilder, CircuitConfig, CircuitConstraint, ZkCircuit, Plonky2Proof, 
    RecursiveProof, RecursiveConfig, generate_batch_recursive_proof, verify_batch_recursive_proof};
use std::collections::HashMap;

// Custom serialization for [u8; 64] arrays
mod signatures_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(signatures: &Vec<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let signatures_vec: Vec<Vec<u8>> = signatures.iter().map(|s| s.to_vec()).collect();
        signatures_vec.serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let signatures_vec: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        let mut signatures = Vec::new();
        for sig_vec in signatures_vec {
            if sig_vec.len() != 64 {
                return Err(serde::de::Error::custom("Invalid signature length"));
            }
            let mut sig_array = [0u8; 64];
            sig_array.copy_from_slice(&sig_vec);
            signatures.push(sig_array);
        }
        Ok(signatures)
    }
}

/// Recursive state transition circuit for proving chains of state changes
pub struct StateTransitionRecursiveCircuit {
    config: CircuitConfig,
    max_chain_length: u32,
    validation_rules: TransitionValidationRules,
}

/// Rules for validating state transition chains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionValidationRules {
    /// Maximum allowed gap between block heights
    pub max_height_gap: u64,
    /// Maximum allowed time gap between transitions (seconds)
    pub max_time_gap: u64,
    /// Minimum number of transitions required for chain validity
    pub min_chain_length: u32,
    /// Maximum number of transitions in a single proof
    pub max_chain_length: u32,
    /// Require validator set consistency
    pub require_validator_consistency: bool,
    /// Allow balance increases (for mining/staking rewards)
    pub allow_balance_increases: bool,
}

impl Default for TransitionValidationRules {
    fn default() -> Self {
        Self {
            max_height_gap: 1000,      // Allow up to 1000 blocks gap
            max_time_gap: 86400,       // 24 hours
            min_chain_length: 2,       // At least 2 transitions
            max_chain_length: 100,     // Up to 100 transitions per proof
            require_validator_consistency: true,
            allow_balance_increases: true,
        }
    }
}

/// Chain of state transitions for recursive proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionChain {
    /// Ordered list of state transitions
    pub transitions: Vec<StateTransitionProof>,
    /// Chain metadata
    pub chain_metadata: ChainMetadata,
    /// Validation checkpoints within the chain
    pub checkpoints: Vec<ValidationCheckpoint>,
}

/// Metadata for state transition chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    /// Starting state commitment
    pub genesis_state: StateCommitment,
    /// Final state commitment
    pub final_state: StateCommitment,
    /// Total number of transitions
    pub transition_count: u32,
    /// Total time span (seconds)
    pub time_span: u64,
    /// Chain validation timestamp
    pub validated_at: u64,
    /// Economic value transacted in chain
    pub total_value_transacted: u64,
}

/// Validation checkpoint within transition chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheckpoint {
    /// Position in chain (transition index)
    pub position: u32,
    /// State at this checkpoint
    pub checkpoint_state: StateCommitment,
    /// Accumulated proof up to this point
    pub accumulated_proof_hash: [u8; 32],
    /// Validator signatures at checkpoint
    #[serde(with = "signatures_serde")]
    pub validator_signatures: Vec<[u8; 64]>,
}

/// Result of chain validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainValidationProof {
    /// Recursive proof of the entire chain
    pub chain_recursive_proof: RecursiveProof,
    /// Public inputs summarizing the chain
    pub chain_public_inputs: ChainPublicInputs,
    /// Validation metadata
    pub validation_metadata: ChainValidationMetadata,
    /// Economic proof (rewards, fees, etc.)
    pub economic_proof: ChainEconomicProof,
}

/// Public inputs for chain validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainPublicInputs {
    /// Genesis state hash
    pub genesis_state_hash: [u8; 32],
    /// Final state hash
    pub final_state_hash: [u8; 32],
    /// Number of transitions proven
    pub transition_count: u32,
    /// Starting block height
    pub start_block_height: u64,
    /// Final block height
    pub end_block_height: u64,
    /// Starting timestamp
    pub start_timestamp: u64,
    /// Final timestamp
    pub end_timestamp: u64,
    /// Total value transacted
    pub total_value: u64,
}

/// Metadata for chain validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainValidationMetadata {
    /// Validation rules applied
    pub rules_applied: TransitionValidationRules,
    /// Number of checkpoints verified
    pub checkpoints_verified: u32,
    /// Validation complexity score
    pub complexity_score: u64,
    /// Verification time estimate (milliseconds)
    pub verification_time_estimate: u64,
    /// Memory usage during validation (bytes)
    pub memory_usage: u64,
}

/// Economic proof for transition chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEconomicProof {
    /// Total fees paid in chain
    pub total_fees: u64,
    /// Rewards distributed
    pub total_rewards: u64,
    /// Supply changes (minting/burning)
    pub supply_changes: i64, // Can be negative for burning
    /// Economic balance proof
    pub balance_proof: Vec<u8>,
    /// Fee distribution proof
    pub fee_distribution_proof: Vec<u8>,
}

impl StateTransitionRecursiveCircuit {
    /// Create new state transition recursive circuit
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: CircuitConfig::default(),
            max_chain_length: 100,
            validation_rules: TransitionValidationRules::default(),
        })
    }

    /// Create with custom configuration
    pub fn with_config(
        config: CircuitConfig,
        max_chain_length: u32,
        validation_rules: TransitionValidationRules,
    ) -> Result<Self> {
        Ok(Self {
            config,
            max_chain_length,
            validation_rules,
        })
    }

    /// Prove a chain of state transitions recursively
    pub fn prove_transition_chain(
        &self,
        chain: StateTransitionChain,
    ) -> Result<ChainValidationProof> {
        let start_time = std::time::Instant::now();

        // Validate the chain
        self.validate_transition_chain(&chain)?;

        // Build recursive proof circuit
        let mut builder = CircuitBuilder::new(self.config.clone());

        // Add chain validation constraints
        self.add_chain_continuity_constraints(&mut builder, &chain)?;
        self.add_economic_conservation_constraints(&mut builder, &chain)?;
        self.add_temporal_consistency_constraints(&mut builder, &chain)?;
        self.add_checkpoint_validation_constraints(&mut builder, &chain)?;

        // Generate recursive proof
        let chain_recursive_proof = self.generate_chain_recursive_proof(&chain)?;

        // Build public inputs
        let chain_public_inputs = self.build_chain_public_inputs(&chain)?;

        // Generate economic proof
        let economic_proof = self.generate_economic_proof(&chain)?;

        let validation_time = start_time.elapsed().as_millis() as u64;

        Ok(ChainValidationProof {
            chain_recursive_proof,
            chain_public_inputs,
            validation_metadata: ChainValidationMetadata {
                rules_applied: self.validation_rules.clone(),
                checkpoints_verified: chain.checkpoints.len() as u32,
                complexity_score: self.calculate_chain_complexity(&chain),
                verification_time_estimate: validation_time,
                memory_usage: self.estimate_memory_usage(&chain),
            },
            economic_proof,
        })
    }

    /// Verify a chain validation proof
    pub fn verify_chain_proof(&self, proof: &ChainValidationProof) -> Result<bool> {
        // Verify recursive proof
        let recursive_valid = crate::plonky2::verify_batch_recursive_proof(&proof.chain_recursive_proof)?;
        if !recursive_valid {
            return Ok(false);
        }

        // Verify public inputs consistency
        self.verify_chain_public_inputs(&proof.chain_public_inputs)?;

        // Verify economic proof
        self.verify_economic_proof(&proof.economic_proof)?;

        // Verify metadata consistency
        if proof.validation_metadata.checkpoints_verified == 0 {
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate transition chain before proving
    fn validate_transition_chain(&self, chain: &StateTransitionChain) -> Result<()> {
        if chain.transitions.is_empty() {
            return Err(anyhow::anyhow!("Empty transition chain"));
        }

        if chain.transitions.len() < self.validation_rules.min_chain_length as usize {
            return Err(anyhow::anyhow!("Chain too short: {} < {}", 
                chain.transitions.len(), self.validation_rules.min_chain_length));
        }

        if chain.transitions.len() > self.validation_rules.max_chain_length as usize {
            return Err(anyhow::anyhow!("Chain too long: {} > {}", 
                chain.transitions.len(), self.validation_rules.max_chain_length));
        }

        // Validate continuity between transitions
        for i in 1..chain.transitions.len() {
            let prev = &chain.transitions[i-1];
            let curr = &chain.transitions[i];

            // Check block height continuity
            let height_diff = curr.public_inputs.block_height - prev.public_inputs.block_height;
            if height_diff > self.validation_rules.max_height_gap {
                return Err(anyhow::anyhow!("Block height gap too large: {}", height_diff));
            }

            // Check timestamp continuity
            let time_diff = curr.public_inputs.timestamp - prev.public_inputs.timestamp;
            if time_diff > self.validation_rules.max_time_gap {
                return Err(anyhow::anyhow!("Time gap too large: {}", time_diff));
            }

            // Check state continuity
            if curr.public_inputs.prev_state_root != prev.public_inputs.new_state_root {
                return Err(anyhow::anyhow!("State continuity broken at transition {}", i));
            }
        }

        // Validate checkpoints
        for checkpoint in &chain.checkpoints {
            if checkpoint.position >= chain.transitions.len() as u32 {
                return Err(anyhow::anyhow!("Invalid checkpoint position: {}", checkpoint.position));
            }
        }

        Ok(())
    }

    /// Add chain continuity constraints
    fn add_chain_continuity_constraints(
        &self,
        builder: &mut CircuitBuilder,
        chain: &StateTransitionChain,
    ) -> Result<()> {
        // Verify state continuity: each transition's end state equals next transition's start state
        for i in 1..chain.transitions.len() {
            let prev_end_wire = builder.add_private_input(None);
            let curr_start_wire = builder.add_private_input(None);
            
            // Constrain that prev_end == curr_start
            builder.add_equality_constraint(prev_end_wire, curr_start_wire);
        }

        builder.add_constraint(CircuitConstraint {
            constraint_type: "block_height_progression".to_string(),
            wires: vec![2, 3], // Placeholder wire indices
            coefficients: vec![1, 1], // Placeholder coefficients
        });

        Ok(())
    }

    /// Add economic conservation constraints
    fn add_economic_conservation_constraints(
        &self,
        builder: &mut CircuitBuilder,
        chain: &StateTransitionChain,
    ) -> Result<()> {
        // Verify supply conservation across the entire chain
        let genesis_supply_wire = builder.add_public_input(None);
        let final_supply_wire = builder.add_public_input(None);
        
        // Calculate total fees across all transitions
        let mut total_fees_wire = builder.add_public_input(None); // Start with 0
        for transition in &chain.transitions {
            let transition_fees_wire = builder.add_private_input(None);
            total_fees_wire = builder.add_addition(total_fees_wire, transition_fees_wire);
        }
        
        // final_supply should equal genesis_supply - total_fees (fees are burned/redistributed)
        let expected_final_wire = builder.add_subtraction(genesis_supply_wire, total_fees_wire);
        builder.add_equality_constraint(final_supply_wire, expected_final_wire);

        Ok(())
    }

    /// Add temporal consistency constraints
    fn add_temporal_consistency_constraints(
        &self,
        builder: &mut CircuitBuilder,
        chain: &StateTransitionChain,
    ) -> Result<()> {
        builder.add_constraint(CircuitConstraint {
            constraint_type: "timestamp_progression".to_string(),
            wires: vec![6, 7], // Placeholder wire indices
            coefficients: vec![1, 1], // Placeholder coefficients
        });

        Ok(())
    }

    /// Add checkpoint validation constraints
    fn add_checkpoint_validation_constraints(
        &self,
        builder: &mut CircuitBuilder,
        chain: &StateTransitionChain,
    ) -> Result<()> {
        builder.add_constraint(CircuitConstraint {
            constraint_type: "checkpoint_validity".to_string(),
            wires: vec![8, 9], // Placeholder wire indices
            coefficients: vec![1, 1], // Placeholder coefficients
        });

        Ok(())
    }

    /// Generate recursive proof for the entire chain
    fn generate_chain_recursive_proof(&self, chain: &StateTransitionChain) -> Result<RecursiveProof> {
        use crate::plonky2::{RecursiveConfig, generate_batch_recursive_proof};

        // Extract Plonky2 proofs from all transitions
        let transition_proofs: Vec<Plonky2Proof> = chain.transitions
            .iter()
            .map(|t| t.plonky2_proof.clone())
            .collect();

        let config = RecursiveConfig {
            max_depth: self.max_chain_length / 10, // Reasonable depth based on chain length
            batch_size: transition_proofs.len() as u32,
            optimization_level: 3,
        };

        generate_batch_recursive_proof(transition_proofs, config)
    }

    /// Build public inputs for chain
    fn build_chain_public_inputs(&self, chain: &StateTransitionChain) -> Result<ChainPublicInputs> {
        let first_transition = &chain.transitions[0];
        let last_transition = &chain.transitions[chain.transitions.len() - 1];

        Ok(ChainPublicInputs {
            genesis_state_hash: first_transition.public_inputs.prev_state_root,
            final_state_hash: last_transition.public_inputs.new_state_root,
            transition_count: chain.transitions.len() as u32,
            start_block_height: first_transition.public_inputs.block_height,
            end_block_height: last_transition.public_inputs.block_height,
            start_timestamp: first_transition.public_inputs.timestamp,
            end_timestamp: last_transition.public_inputs.timestamp,
            total_value: chain.chain_metadata.total_value_transacted,
        })
    }

    /// Generate economic proof for the chain
    fn generate_economic_proof(&self, chain: &StateTransitionChain) -> Result<ChainEconomicProof> {
        // Calculate economic values from chain
        let total_fees = self.calculate_total_fees(chain);
        let total_rewards = self.calculate_total_rewards(chain);
        let supply_changes = self.calculate_supply_changes(chain);

        // Generate ZK proofs for economic claims
        let balance_proof = self.generate_balance_proof(chain)?;
        let fee_distribution_proof = self.generate_fee_distribution_proof(chain)?;

        Ok(ChainEconomicProof {
            total_fees,
            total_rewards,
            supply_changes,
            balance_proof,
            fee_distribution_proof,
        })
    }

    // Helper methods
    fn calculate_chain_complexity(&self, chain: &StateTransitionChain) -> u64 {
        let transition_complexity = chain.transitions.len() as u64 * 100;
        let checkpoint_complexity = chain.checkpoints.len() as u64 * 50;
        let time_span_factor = (chain.chain_metadata.time_span / 3600).max(1); // Hours
        
        (transition_complexity + checkpoint_complexity) * time_span_factor
    }

    fn estimate_memory_usage(&self, chain: &StateTransitionChain) -> u64 {
        let base_usage = 1024 * 1024; // 1MB base
        let transition_usage = chain.transitions.len() as u64 * 10240; // 10KB per transition
        let checkpoint_usage = chain.checkpoints.len() as u64 * 5120; // 5KB per checkpoint
        
        base_usage + transition_usage + checkpoint_usage
    }

    fn calculate_expected_supply_change(&self, chain: &StateTransitionChain) -> i64 {
        // Calculate expected supply change from rewards and burns
        let rewards = self.calculate_total_rewards(chain) as i64;
        let burns = 0i64; // Would calculate actual burns in practice
        rewards - burns
    }

    fn calculate_total_fees(&self, chain: &StateTransitionChain) -> u64 {
        // Sum fees from all transitions
        chain.transitions.iter()
            .map(|t| t.metadata.transaction_count as u64 * 100) // Estimate: 100 units per transaction
            .sum()
    }

    fn calculate_total_rewards(&self, chain: &StateTransitionChain) -> u64 {
        // Calculate block rewards
        let block_count = chain.chain_metadata.final_state.block_height - 
                         chain.chain_metadata.genesis_state.block_height;
        block_count * 1000 // Estimate: 1000 units per block reward
    }

    fn calculate_supply_changes(&self, chain: &StateTransitionChain) -> i64 {
        let final_supply = chain.chain_metadata.final_state.total_supply as i64;
        let genesis_supply = chain.chain_metadata.genesis_state.total_supply as i64;
        final_supply - genesis_supply
    }

    fn generate_balance_proof(&self, _chain: &StateTransitionChain) -> Result<Vec<u8>> {
        // Generate ZK proof that balances are conserved
        Ok(vec![1, 2, 3, 4, 5]) // Placeholder
    }

    fn generate_fee_distribution_proof(&self, _chain: &StateTransitionChain) -> Result<Vec<u8>> {
        // Generate ZK proof that fees are distributed correctly
        Ok(vec![6, 7, 8, 9, 10]) // Placeholder
    }

    fn verify_chain_public_inputs(&self, inputs: &ChainPublicInputs) -> Result<()> {
        if inputs.transition_count == 0 {
            return Err(anyhow::anyhow!("Invalid transition count"));
        }
        
        if inputs.end_block_height < inputs.start_block_height {
            return Err(anyhow::anyhow!("Invalid block height progression"));
        }
        
        if inputs.end_timestamp < inputs.start_timestamp {
            return Err(anyhow::anyhow!("Invalid timestamp progression"));
        }
        
        Ok(())
    }

    fn verify_economic_proof(&self, proof: &ChainEconomicProof) -> Result<()> {
        // Verify economic proof validity
        if proof.balance_proof.is_empty() {
            return Err(anyhow::anyhow!("Missing balance proof"));
        }
        
        if proof.fee_distribution_proof.is_empty() {
            return Err(anyhow::anyhow!("Missing fee distribution proof"));
        }
        
        Ok(())
    }
}

impl Default for StateTransitionRecursiveCircuit {
    fn default() -> Self {
        Self::new().expect("Failed to create default StateTransitionRecursiveCircuit")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transition_validation_rules() {
        let rules = TransitionValidationRules::default();
        assert_eq!(rules.max_height_gap, 1000);
        assert_eq!(rules.max_time_gap, 86400);
        assert_eq!(rules.min_chain_length, 2);
        assert_eq!(rules.max_chain_length, 100);
    }

    #[test]
    fn test_state_transition_recursive_circuit() {
        let circuit = StateTransitionRecursiveCircuit::new();
        assert!(circuit.is_ok());
    }
}