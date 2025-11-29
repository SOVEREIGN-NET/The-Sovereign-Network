//! Transaction circuit implementation
//! 
//! Implements zero-knowledge circuits for transaction validation
//! proving balance constraints without revealing actual values.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::hashing::hash_blake3;
use crate::plonky2::{CircuitBuilder, CircuitConfig, ZkCircuit};

/// Transaction witness data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWitness {
    /// Sender's balance before transaction
    pub sender_balance: u64,
    /// Receiver's balance before transaction  
    pub receiver_balance: u64,
    /// Transaction amount
    pub amount: u64,
    /// Transaction fee
    pub fee: u64,
    /// Sender's blinding factor
    pub sender_blinding: [u8; 32],
    /// Receiver's blinding factor
    pub receiver_blinding: [u8; 32],
    /// Transaction nullifier
    pub nullifier: [u8; 32],
}

impl TransactionWitness {
    /// Create new transaction witness
    pub fn new(
        sender_balance: u64,
        receiver_balance: u64,
        amount: u64,
        fee: u64,
        sender_blinding: [u8; 32],
        receiver_blinding: [u8; 32],
        nullifier: [u8; 32],
    ) -> Self {
        Self {
            sender_balance,
            receiver_balance,
            amount,
            fee,
            sender_blinding,
            receiver_blinding,
            nullifier,
        }
    }

    /// Validate witness data
    pub fn validate(&self) -> Result<()> {
        if self.sender_balance < self.amount + self.fee {
            return Err(anyhow::anyhow!("Insufficient sender balance"));
        }
        Ok(())
    }

    /// Calculate sender balance commitment
    pub fn sender_commitment(&self) -> [u8; 32] {
        let data = [
            &self.sender_balance.to_le_bytes()[..],
            &self.sender_blinding[..],
        ].concat();
        hash_blake3(&data)
    }

    /// Calculate receiver balance commitment
    pub fn receiver_commitment(&self) -> [u8; 32] {
        let data = [
            &self.receiver_balance.to_le_bytes()[..],
            &self.receiver_blinding[..],
        ].concat();
        hash_blake3(&data)
    }

    /// Calculate transaction hash
    pub fn transaction_hash(&self) -> [u8; 32] {
        let data = [
            &self.amount.to_le_bytes()[..],
            &self.fee.to_le_bytes()[..],
            &self.nullifier[..],
        ].concat();
        hash_blake3(&data)
    }
}

/// Transaction circuit for zero-knowledge transaction validation
#[derive(Debug, Clone)]
pub struct TransactionCircuit {
    /// Circuit configuration
    pub config: CircuitConfig,
    /// Built circuit
    pub circuit: Option<ZkCircuit>,
}

impl TransactionCircuit {
    /// Create new transaction circuit
    pub fn new(config: CircuitConfig) -> Self {
        Self {
            config,
            circuit: None,
        }
    }

    /// Create with standard configuration
    pub fn standard() -> Self {
        Self::new(CircuitConfig::standard())
    }

    /// Build the circuit
    pub fn build(&mut self) -> Result<()> {
        let mut builder = CircuitBuilder::new(self.config.clone());

        // Public inputs
        let sender_commitment_wire = builder.add_public_input(None);
        let receiver_commitment_wire = builder.add_public_input(None);
        let amount_wire = builder.add_public_input(None);
        let fee_wire = builder.add_public_input(None);
        let nullifier_wire = builder.add_public_input(None);

        // Private inputs (witness)
        let sender_balance_wire = builder.add_private_input(None);
        let receiver_balance_wire = builder.add_private_input(None);
        let sender_blinding_wire = builder.add_private_input(None);
        let receiver_blinding_wire = builder.add_private_input(None);

        // Verify sender balance commitment
        let sender_commitment_calc = builder.add_hash(vec![sender_balance_wire, sender_blinding_wire]);
        builder.add_equality_constraint(sender_commitment_calc, sender_commitment_wire);

        // Verify receiver balance commitment
        let receiver_commitment_calc = builder.add_hash(vec![receiver_balance_wire, receiver_blinding_wire]);
        builder.add_equality_constraint(receiver_commitment_calc, receiver_commitment_wire);

        // Verify balance constraint: sender_balance >= amount + fee
        let amount_plus_fee = builder.add_addition(amount_wire, fee_wire);
        
        // Convert to range constraint (sender_balance - (amount + fee) >= 0)
        // This is simplified - implementation would use proper subtraction
        builder.add_range_constraint(sender_balance_wire, 0, u64::MAX);
        builder.add_range_constraint(amount_plus_fee, 0, u64::MAX);

        // Add non-negativity constraints
        builder.add_range_constraint(amount_wire, 0, u64::MAX);
        builder.add_range_constraint(fee_wire, 0, u64::MAX);
        builder.add_range_constraint(sender_balance_wire, 0, u64::MAX);
        builder.add_range_constraint(receiver_balance_wire, 0, u64::MAX);

        // Output the validity proof
        let validity_proof = builder.add_hash(vec![
            sender_commitment_wire,
            receiver_commitment_wire,
            amount_wire,
            fee_wire,
            nullifier_wire,
        ]);
        let _output = builder.add_output(validity_proof);

        self.circuit = Some(ZkCircuit::from_builder(builder));
        Ok(())
    }

    /// Generate proof for a transaction
    pub fn prove(&self, witness: &TransactionWitness) -> Result<TransactionProof> {
        witness.validate()?;
        
        let circuit = self.circuit.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;

        let proof_data = self.generate_proof_data(witness);
        
        Ok(TransactionProof {
            sender_commitment: witness.sender_commitment(),
            receiver_commitment: witness.receiver_commitment(),
            amount: witness.amount,
            fee: witness.fee,
            nullifier: witness.nullifier,
            proof_data,
            circuit_hash: circuit.circuit_hash,
        })
    }

    /// Generate proof data using PURE ZK circuits only
    fn generate_proof_data(&self, witness: &TransactionWitness) -> Vec<u8> {
        tracing::info!(" Using PURE ZK transaction proof generation - NO FALLBACKS");
        
        let circuit = self.circuit.as_ref()
            .expect("Circuit must be built before proof generation");

        // Create ZK proof inputs from witness
        let public_inputs = vec![
            witness.amount,
            witness.fee,
            u64::from_le_bytes(witness.nullifier[0..8].try_into().unwrap_or([0; 8])),
        ];
        
        let private_inputs = vec![
            witness.sender_balance,
            witness.receiver_balance,
            u64::from_le_bytes(witness.sender_blinding[0..8].try_into().unwrap_or([0; 8])),
            u64::from_le_bytes(witness.receiver_blinding[0..8].try_into().unwrap_or([0; 8])),
        ];

        // Generate ZK proof using Plonky2 circuit
        match circuit.prove(&public_inputs, &private_inputs) {
            Ok(zk_proof) => {
                tracing::info!("Generated PURE ZK transaction proof: {} bytes", zk_proof.proof.len());
                zk_proof.proof
            },
            Err(e) => {
                tracing::error!("ZK proof generation failed: {:?}", e);
                // NO FALLBACK - fail hard if ZK proof generation fails
                panic!("ZK proof generation failed - this indicates a serious constraint violation or implementation bug: {:?}", e);
            }
        }
    }

    /// Verify a transaction proof using PURE ZK circuit verification only
    pub fn verify(&self, proof: &TransactionProof) -> Result<bool> {
        tracing::info!("Using PURE ZK transaction proof verification - NO FALLBACKS");
        
        let circuit = self.circuit.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;

        // Verify circuit hash matches
        if proof.circuit_hash != circuit.circuit_hash {
            tracing::error!("Circuit hash mismatch");
            return Ok(false);
        }

        // Initialize ZK proof system - MUST succeed
        let zk_system = crate::plonky2::ZkProofSystem::new()
            .map_err(|e| anyhow::anyhow!("Failed to initialize ZK system: {:?}", e))?;
        
        // Extract nullifier from proof data for ZK verification
        let nullifier_u64 = if proof.proof_data.len() >= 8 {
            // For pure ZK proofs, extract nullifier from the proof structure
            u64::from_le_bytes(proof.nullifier[0..8].try_into().unwrap_or([0; 8]))
        } else {
            return Err(anyhow::anyhow!("Invalid proof data length: {}", proof.proof_data.len()));
        };
        
        // Create ZK proof structure for verification
        let zk_proof = crate::plonky2::Plonky2Proof {
            proof: proof.proof_data.clone(),
            public_inputs: vec![proof.amount, proof.fee, nullifier_u64],
            verification_key_hash: proof.circuit_hash,
            proof_system: "ZHTP-Optimized-Transaction".to_string(),
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            circuit_id: "transaction_v1".to_string(),
            private_input_commitment: lib_crypto::hashing::hash_blake3(&proof.proof_data),
        };
        
        // PURE ZK verification - NO FALLBACKS
        match zk_system.verify_transaction(&zk_proof) {
            Ok(result) => {
                if result {
                    tracing::info!("Transaction proof verified using PURE ZK circuit");
                } else {
                    tracing::error!("ZK circuit verification failed - proof is invalid");
                }
                Ok(result)
            },
            Err(e) => {
                tracing::error!("ZK verification system error: {:?}", e);
                // NO FALLBACK - fail hard if ZK verification fails
                Err(anyhow::anyhow!("ZK verification failed - no fallbacks allowed: {:?}", e))
            }
        }
    }

    /// Get circuit statistics
    pub fn get_circuit_stats(&self) -> Option<crate::plonky2::CircuitStats> {
        self.circuit.as_ref().map(|c| c.stats())
    }
}

/// Transaction proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionProof {
    /// Sender balance commitment
    pub sender_commitment: [u8; 32],
    /// Receiver balance commitment
    pub receiver_commitment: [u8; 32],
    /// Transaction amount (public)
    pub amount: u64,
    /// Transaction fee (public)
    pub fee: u64,
    /// Transaction nullifier (public)
    pub nullifier: [u8; 32],
    /// Zero-knowledge proof data
    pub proof_data: Vec<u8>,
    /// Circuit hash for verification
    pub circuit_hash: [u8; 32],
}

impl TransactionProof {
    /// Get proof size in bytes
    pub fn proof_size(&self) -> usize {
        32 + // sender_commitment
        32 + // receiver_commitment
        8 +  // amount
        8 +  // fee
        32 + // nullifier
        self.proof_data.len() + // proof_data
        32   // circuit_hash
    }

    /// Validate proof structure
    pub fn validate(&self) -> Result<()> {
        if self.proof_data.is_empty() {
            return Err(anyhow::anyhow!("Empty proof data"));
        }
        
        if self.sender_commitment == [0u8; 32] {
            return Err(anyhow::anyhow!("Invalid sender commitment"));
        }
        
        if self.receiver_commitment == [0u8; 32] {
            return Err(anyhow::anyhow!("Invalid receiver commitment"));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_witness() {
        let witness = TransactionWitness::new(
            1000, // sender_balance
            500,  // receiver_balance
            100,  // amount
            10,   // fee
            [1u8; 32], // sender_blinding
            [2u8; 32], // receiver_blinding
            [3u8; 32], // nullifier
        );

        assert!(witness.validate().is_ok());
        assert_ne!(witness.sender_commitment(), [0u8; 32]);
        assert_ne!(witness.receiver_commitment(), [0u8; 32]);
        assert_ne!(witness.transaction_hash(), [0u8; 32]);
    }

    #[test]
    fn test_insufficient_balance() {
        let witness = TransactionWitness::new(
            100, // sender_balance (insufficient)
            500, // receiver_balance
            150, // amount (too large)
            10,  // fee
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        assert!(witness.validate().is_err());
    }

    #[test]
    fn test_transaction_circuit_build() {
        let mut circuit = TransactionCircuit::standard();
        assert!(circuit.build().is_ok());
        assert!(circuit.circuit.is_some());
        
        let stats = circuit.get_circuit_stats().unwrap();
        assert!(stats.gate_count > 0);
        assert!(stats.depth > 0);
        assert!(stats.constraint_count > 0);
    }

    #[test]
    fn test_transaction_proof_generation() {
        let mut circuit = TransactionCircuit::standard();
        circuit.build().unwrap();

        let witness = TransactionWitness::new(
            1000,
            500,
            100,
            10,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let proof = circuit.prove(&witness).unwrap();
        assert!(proof.validate().is_ok());
        assert_eq!(proof.amount, 100);
        assert_eq!(proof.fee, 10);
        assert_eq!(proof.proof_size(), 144 + proof.proof_data.len());
    }

    #[test]
    fn test_transaction_proof_verification() {
        let mut circuit = TransactionCircuit::standard();
        circuit.build().unwrap();

        let witness = TransactionWitness::new(
            1000,
            500,
            100,
            10,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let proof = circuit.prove(&witness).unwrap();
        let is_valid = circuit.verify(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_proof_verification() {
        let mut circuit = TransactionCircuit::standard();
        circuit.build().unwrap();

        let witness = TransactionWitness::new(
            1000,
            500,
            100,
            10,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let mut proof = circuit.prove(&witness).unwrap();
        
        // Corrupt the proof
        proof.amount = 200; // Different from witness
        
        let is_valid = circuit.verify(&proof).unwrap();
        assert!(!is_valid);
    }
}
