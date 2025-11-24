//! State Transition Circuit Implementation
//! 
//! Implements zero-knowledge circuits for proving state transitions
//! between blockchain states using transaction proofs as building blocks.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::hashing::{hash_blake3, hash_blake3_multiple};
use crate::circuits::TransactionCircuit;
use crate::state::{StateCommitment, NetworkStateInfo};
use crate::plonky2::{CircuitBuilder, CircuitConfig, CircuitConstraint, ZkCircuit, Plonky2Proof};
use std::collections::HashMap;

/// State transition witness containing all data needed to prove a state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionWitness {
    /// Previous state commitment
    pub prev_state: StateCommitment,
    /// New state commitment after transitions
    pub new_state: StateCommitment,
    /// List of transaction hashes included in this transition
    pub transaction_hashes: Vec<[u8; 32]>,
    /// Merkle proof showing transaction inclusion
    pub merkle_proof: Vec<[u8; 32]>,
    /// State tree update witness
    pub state_updates: Vec<StateUpdateWitness>,
    /// Block metadata
    pub block_metadata: BlockMetadata,
}

/// Individual state update within a transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdateWitness {
    /// Account being updated
    pub account_id: [u8; 32],
    /// Previous balance
    pub prev_balance: u64,
    /// New balance after update
    pub new_balance: u64,
    /// Balance blinding factor
    pub balance_blinding: [u8; 32],
    /// Merkle path for this account in state tree
    pub merkle_path: Vec<[u8; 32]>,
}

/// Block metadata for state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetadata {
    /// Block height
    pub height: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Validator set hash
    pub validator_set_hash: [u8; 32],
    /// Previous block hash
    pub prev_block_hash: [u8; 32],
    /// Transaction count
    pub transaction_count: u32,
}

/// State transition proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionProof {
    /// The underlying Plonky2 proof
    pub plonky2_proof: Plonky2Proof,
    /// Public inputs (state commitments)
    pub public_inputs: StateTransitionPublicInputs,
    /// Proof metadata
    pub metadata: StateTransitionMetadata,
}

/// Public inputs for state transition proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionPublicInputs {
    /// Previous state root
    pub prev_state_root: [u8; 32],
    /// New state root
    pub new_state_root: [u8; 32],
    /// Transaction root (Merkle root of all transactions)
    pub transaction_root: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Total supply after transition
    pub total_supply: u64,
}

/// Metadata for state transition proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionMetadata {
    /// Number of transactions processed
    pub transaction_count: u32,
    /// Number of state updates
    pub state_update_count: u32,
    /// Proof generation time (milliseconds)
    pub generation_time_ms: u64,
    /// Circuit complexity score
    pub complexity_score: u32,
}

/// State transition circuit implementation
#[derive(Debug)]
pub struct StateTransitionCircuit {
    config: CircuitConfig,
    transaction_circuit: TransactionCircuit,
}

impl StateTransitionCircuit {
    /// Create a new state transition circuit
    pub fn new() -> Result<Self> {
        let config = CircuitConfig::default();
        let transaction_circuit = TransactionCircuit::new(config.clone());
        
        Ok(Self {
            config,
            transaction_circuit,
        })
    }

    /// Create circuit with custom configuration
    pub fn with_config(config: CircuitConfig) -> Result<Self> {
        let transaction_circuit = TransactionCircuit::new(config.clone());
        
        Ok(Self {
            config,
            transaction_circuit,
        })
    }

    /// Generate proof for a state transition
    pub fn prove_transition(
        &self,
        witness: StateTransitionWitness,
    ) -> Result<StateTransitionProof> {
        let start_time = std::time::Instant::now();
        
        // Validate witness
        self.validate_witness(&witness)?;
        
        // Build the circuit
        let mut builder = CircuitBuilder::new(self.config.clone());
        
        // Add state transition constraints
        self.add_state_consistency_constraints(&mut builder, &witness)?;
        self.add_transaction_validity_constraints(&mut builder, &witness)?;
        self.add_balance_conservation_constraints(&mut builder, &witness)?;
        self.add_merkle_proof_constraints(&mut builder, &witness)?;
        
        // Build public inputs
        let public_inputs = self.build_public_inputs(&witness)?;
        
        // Generate the proof
        let circuit = builder.build()?;
        let private_inputs = self.witness_to_private_inputs(&witness)?;
        let plonky2_proof = circuit.prove(&self.witness_to_circuit_inputs(&witness)?, &private_inputs)?;
        
        let generation_time = start_time.elapsed().as_millis() as u64;
        
        Ok(StateTransitionProof {
            plonky2_proof,
            public_inputs,
            metadata: StateTransitionMetadata {
                transaction_count: witness.transaction_hashes.len() as u32,
                state_update_count: witness.state_updates.len() as u32,
                generation_time_ms: generation_time,
                complexity_score: self.calculate_complexity_score(&witness),
            },
        })
    }

    /// Verify a state transition proof
    pub fn verify_proof(&self, proof: &StateTransitionProof) -> Result<bool> {
        // Verify the underlying Plonky2 proof
        let plonky2_valid = crate::plonky2::verify_plonky2_proof(&proof.plonky2_proof)?;
        
        if !plonky2_valid.is_valid() {
            return Ok(false);
        }
        
        // Verify public inputs consistency
        self.verify_public_inputs_consistency(&proof.public_inputs)?;
        
        // Verify metadata consistency
        self.verify_metadata_consistency(&proof.metadata)?;
        
        Ok(true)
    }

    /// Validate the witness data
    fn validate_witness(&self, witness: &StateTransitionWitness) -> Result<()> {
        // Check state progression
        if witness.new_state.block_height != witness.prev_state.block_height + 1 {
            return Err(anyhow::anyhow!("Invalid block height progression"));
        }
        
        // Check timestamp progression
        if witness.new_state.timestamp <= witness.prev_state.timestamp {
            return Err(anyhow::anyhow!("Invalid timestamp progression"));
        }
        
        // Validate state updates
        for update in &witness.state_updates {
            if update.prev_balance == update.new_balance {
                return Err(anyhow::anyhow!("No-op state update detected"));
            }
        }
        
        // Check transaction count consistency
        if witness.transaction_hashes.len() != witness.block_metadata.transaction_count as usize {
            return Err(anyhow::anyhow!("Transaction count mismatch"));
        }
        
        Ok(())
    }

    /// Add state consistency constraints to the circuit
    fn add_state_consistency_constraints(
        &self,
        builder: &mut CircuitBuilder,
        witness: &StateTransitionWitness,
    ) -> Result<()> {
        // Add constraints ensuring proper state root transitions
        builder.add_constraint(CircuitConstraint {
            constraint_type: "state_root_transition".to_string(),
            wires: vec![6, 7], // Placeholder wire indices
            coefficients: vec![1, 1], // Placeholder coefficients
        });
        
        // Add validator set consistency constraints
        builder.add_constraint(CircuitConstraint {
            constraint_type: "validator_set_consistency".to_string(),
            wires: vec![8, 9], // Placeholder wire indices
            coefficients: vec![1, 1], // Placeholder coefficients
        });
        
        Ok(())
    }

    /// Add transaction validity constraints
    fn add_transaction_validity_constraints(
        &self,
        builder: &mut CircuitBuilder,
        witness: &StateTransitionWitness,
    ) -> Result<()> {
        // Add constraint that all transactions are valid
        builder.add_constraint(CircuitConstraint {
            constraint_type: "transaction_validity".to_string(),
            wires: vec![10, 11], // Placeholder wire indices
            coefficients: vec![1, 1], // Placeholder coefficients
        });
        
        // Add Merkle proof constraints for transaction inclusion
        let tx_root_wire = self.compute_transaction_merkle_root_wire(builder, &witness.transaction_hashes);
        let prev_block_hash_wire = builder.add_public_input(None);
        builder.add_equality_constraint(tx_root_wire, prev_block_hash_wire);
        
        Ok(())
    }

    /// Add balance conservation constraints
    fn add_balance_conservation_constraints(
        &self,
        builder: &mut CircuitBuilder,
        witness: &StateTransitionWitness,
    ) -> Result<()> {
        // Balance conservation: new_supply = prev_supply - total_fees
        let prev_supply_wire = builder.add_public_input(None);
        let new_supply_wire = builder.add_public_input(None);
        let total_fees_wire = self.calculate_total_fees_wire(builder, &witness.transaction_hashes);
        let expected_new_supply_wire = builder.add_subtraction(prev_supply_wire, total_fees_wire);
        builder.add_equality_constraint(new_supply_wire, expected_new_supply_wire);
        
        Ok(())
    }

    /// Add Merkle proof constraints for state updates
    fn add_merkle_proof_constraints(
        &self,
        builder: &mut CircuitBuilder,
        witness: &StateTransitionWitness,
    ) -> Result<()> {
        // Verify Merkle proofs for all state updates
        for update in &witness.state_updates {
            let account_id_wire = builder.add_private_input(None);
            let old_balance_wire = builder.add_private_input(None);
            let new_balance_wire = builder.add_private_input(None);
            
            // Verify the Merkle path from old state to new state
            let computed_old_root = self.verify_merkle_path_circuit(
                builder,
                account_id_wire,
                old_balance_wire,
                &update.merkle_path,
            );
            
            let prev_state_root_wire = builder.add_public_input(None);
            builder.add_equality_constraint(computed_old_root, prev_state_root_wire);
            
            // Verify the new state root after update
            let computed_new_root = self.verify_merkle_path_circuit(
                builder,
                account_id_wire,
                new_balance_wire,
                &update.merkle_path,
            );
            
            let new_state_root_wire = builder.add_public_input(None);
            builder.add_equality_constraint(computed_new_root, new_state_root_wire);
        }
        
        Ok(())
    }

    /// Build public inputs for the circuit
    fn build_public_inputs(&self, witness: &StateTransitionWitness) -> Result<StateTransitionPublicInputs> {
        let transaction_root = self.compute_transaction_merkle_root(&witness.transaction_hashes);
        
        Ok(StateTransitionPublicInputs {
            prev_state_root: witness.prev_state.merkle_root,
            new_state_root: witness.new_state.merkle_root,
            transaction_root,
            block_height: witness.new_state.block_height,
            timestamp: witness.new_state.timestamp,
            total_supply: witness.new_state.total_supply,
        })
    }

    /// Convert witness to circuit inputs
    fn witness_to_circuit_inputs(&self, witness: &StateTransitionWitness) -> Result<Vec<u64>> {
        let mut inputs = Vec::new();
        
        // Add state commitments as inputs
        inputs.extend_from_slice(&self.commitment_to_field_elements(&witness.prev_state));
        inputs.extend_from_slice(&self.commitment_to_field_elements(&witness.new_state));
        
        // Add transaction data
        for tx_hash in &witness.transaction_hashes {
            inputs.extend_from_slice(&self.hash_to_field_elements(tx_hash));
        }
        
        // Add state updates
        for update in &witness.state_updates {
            inputs.push(update.prev_balance);
            inputs.push(update.new_balance);
            inputs.extend_from_slice(&self.hash_to_field_elements(&update.account_id));
        }
        
        Ok(inputs)
    }

    /// Convert witness to private inputs for the circuit
    fn witness_to_private_inputs(&self, witness: &StateTransitionWitness) -> Result<Vec<u64>> {
        let mut private_inputs = Vec::new();
        
        // Add private witness data (e.g., Merkle proof elements)
        for proof_element in &witness.merkle_proof {
            private_inputs.extend_from_slice(&self.hash_to_field_elements(proof_element));
        }
        
        // Add signature data as private inputs
        for update in &witness.state_updates {
            private_inputs.extend_from_slice(&self.hash_to_field_elements(&update.merkle_path[0]));
        }
        
        Ok(private_inputs)
    }

    /// Calculate complexity score for the proof
    fn calculate_complexity_score(&self, witness: &StateTransitionWitness) -> u32 {
        let tx_complexity = witness.transaction_hashes.len() as u32 * 10;
        let state_complexity = witness.state_updates.len() as u32 * 5;
        let merkle_complexity = witness.merkle_proof.len() as u32 * 2;
        
        tx_complexity + state_complexity + merkle_complexity
    }

    /// Helper functions for circuit constraints
    fn compute_new_state_root(&self, prev_state: &StateCommitment, updates: &[StateUpdateWitness]) -> [u8; 32] {
        // Simplified state root computation - in practice this would be more complex
        let mut data = Vec::new();
        data.extend_from_slice(&prev_state.merkle_root);
        
        for update in updates {
            data.extend_from_slice(&update.account_id);
            data.extend_from_slice(&update.new_balance.to_le_bytes());
        }
        
        hash_blake3(&data)
    }

    fn compute_transaction_merkle_root(&self, tx_hashes: &[[u8; 32]]) -> [u8; 32] {
        if tx_hashes.is_empty() {
            return [0; 32];
        }
        
        // Convert fixed-size arrays to slices
        let hash_slices: Vec<&[u8]> = tx_hashes.iter().map(|h| h.as_slice()).collect();
        hash_blake3_multiple(&hash_slices)
    }

    /// Compute transaction merkle root as a circuit wire
    fn compute_transaction_merkle_root_wire(&self, builder: &mut CircuitBuilder, tx_hashes: &[[u8; 32]]) -> usize {
        if tx_hashes.is_empty() {
            return builder.add_public_input(None);
        }

        // Add each transaction hash as a wire
        let mut hash_wires: Vec<usize> = tx_hashes.iter()
            .map(|hash| {
                let wire = builder.add_private_input(None);
                // In a implementation, we'd constrain this wire to equal the hash
                wire
            })
            .collect();

        // Build Merkle tree bottom-up
        while hash_wires.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hash_wires.chunks(2) {
                let parent_wire = if chunk.len() == 2 {
                    builder.add_hash(vec![chunk[0], chunk[1]])
                } else {
                    chunk[0] // Odd number of leaves
                };
                next_level.push(parent_wire);
            }
            hash_wires = next_level;
        }

        hash_wires[0]
    }

    /// Calculate total fees as a circuit wire
    fn calculate_total_fees_wire(&self, builder: &mut CircuitBuilder, transaction_hashes: &[[u8; 32]]) -> usize {
        let num_transactions = transaction_hashes.len() as u64;
        let fee_per_tx = 1000u64; // Fixed fee per transaction
        
        // Create a constant wire for the fee per transaction
        let fee_per_tx_wire = builder.add_public_input(None);
        
        // Create a constant wire for the number of transactions
        let num_tx_wire = builder.add_public_input(None);
        
        // Multiply: total_fees = num_transactions * fee_per_tx
        builder.add_multiplication(num_tx_wire, fee_per_tx_wire)
    }

    /// Verify a Merkle path in circuit 
    fn verify_merkle_path_circuit(
        &self,
        builder: &mut CircuitBuilder,
        leaf_wire: usize,
        value_wire: usize,
        merkle_path: &[[u8; 32]],
    ) -> usize {
        // Start with the leaf hash (account_id + value)
        let mut current_hash = builder.add_hash(vec![leaf_wire, value_wire]);
        
        // Process each level of the Merkle path
        for path_element in merkle_path {
            let sibling_wire = builder.add_private_input(None);
            // In a implementation, we'd need to handle left/right positioning
            current_hash = builder.add_hash(vec![current_hash, sibling_wire]);
        }
        
        current_hash
    }

    fn calculate_total_fees(&self, _tx_hashes: &[[u8; 32]]) -> u64 {
        // Placeholder - would calculate actual fees from transaction data
        0
    }

    fn verify_merkle_path(&self, _account_id: &[u8; 32], _balance: &u64, _path: &[[u8; 32]], _root: &[u8; 32]) -> bool {
        // Placeholder - would verify actual Merkle path
        true
    }

    fn commitment_to_field_elements(&self, commitment: &StateCommitment) -> Vec<u64> {
        vec![
            commitment.block_height,
            commitment.timestamp,
            commitment.total_supply,
        ]
    }

    fn hash_to_field_elements(&self, hash: &[u8; 32]) -> Vec<u64> {
        // Convert hash to field elements (simplified)
        hash.chunks(8).map(|chunk| {
            u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]))
        }).collect()
    }

    fn verify_public_inputs_consistency(&self, inputs: &StateTransitionPublicInputs) -> Result<()> {
        if inputs.block_height == 0 {
            return Err(anyhow::anyhow!("Invalid block height"));
        }
        
        if inputs.timestamp == 0 {
            return Err(anyhow::anyhow!("Invalid timestamp"));
        }
        
        Ok(())
    }

    fn verify_metadata_consistency(&self, metadata: &StateTransitionMetadata) -> Result<()> {
        if metadata.transaction_count == 0 && metadata.state_update_count == 0 {
            return Err(anyhow::anyhow!("Empty state transition"));
        }
        
        Ok(())
    }
}

impl Default for StateTransitionCircuit {
    fn default() -> Self {
        Self::new().expect("Failed to create default StateTransitionCircuit")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transition_circuit_creation() {
        let circuit = StateTransitionCircuit::new();
        assert!(circuit.is_ok());
    }

    #[test]
    fn test_witness_validation() {
        let circuit = StateTransitionCircuit::new().unwrap();
        
        let witness = StateTransitionWitness {
            prev_state: StateCommitment {
                merkle_root: [1; 32],
                validator_set_hash: [2; 32],
                total_supply: 1000,
                block_height: 100,
                timestamp: 1000000,
            },
            new_state: StateCommitment {
                merkle_root: [3; 32],
                validator_set_hash: [2; 32],
                total_supply: 1000,
                block_height: 101,
                timestamp: 1000001,
            },
            transaction_hashes: vec![[4; 32]],
            merkle_proof: vec![[5; 32]],
            state_updates: vec![StateUpdateWitness {
                account_id: [6; 32],
                prev_balance: 100,
                new_balance: 90,
                balance_blinding: [7; 32],
                merkle_path: vec![[8; 32]],
            }],
            block_metadata: BlockMetadata {
                height: 101,
                timestamp: 1000001,
                validator_set_hash: [2; 32],
                prev_block_hash: [9; 32],
                transaction_count: 1,
            },
        };
        
        assert!(circuit.validate_witness(&witness).is_ok());
    }
}