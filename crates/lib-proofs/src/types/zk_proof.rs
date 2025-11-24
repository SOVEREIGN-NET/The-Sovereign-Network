//! Zero-knowledge proof structures and types
//! 
//! Unified ZK proof system matching ZHTPDEV-main65 architecture.
//! All proof types use the same underlying ZkProof structure with Plonky2 backend.

use serde::{Serialize, Deserialize};
use crate::plonky2::Plonky2Proof;

/// Zero-knowledge proof (unified approach matching ZHTPDEV-main65)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Proof system identifier (always "Plonky2" for unified system)
    pub proof_system: String,
    /// Proof data (contains actual cryptographic proof)
    pub proof_data: Vec<u8>,
    /// Public inputs (circuit inputs visible to verifier)
    pub public_inputs: Vec<u8>,
    /// Verification key (for circuit binding)
    pub verification_key: Vec<u8>,
    /// Plonky2 proof data (primary proof mechanism)
    pub plonky2_proof: Option<Plonky2Proof>,
    /// Deprecated proof format (kept for data structure compatibility only)
    pub proof: Vec<u8>,
}

impl ZkProof {
    /// Create a new ZK proof using unified Plonky2 backend (ZHTPDEV-main65 style)
    pub fn new(
        proof_system: String,
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
        verification_key: Vec<u8>,
        plonky2_proof: Option<Plonky2Proof>,
    ) -> Self {
        Self {
            proof_system, // Use the provided proof system identifier
            proof_data: proof_data.clone(),
            public_inputs,
            verification_key,
            plonky2_proof,
            proof: proof_data, // Legacy compatibility
        }
    }

    /// Create from Plonky2 proof directly (preferred method)
    pub fn from_plonky2(plonky2_proof: Plonky2Proof) -> Self {
        Self {
            proof_system: "Plonky2".to_string(),
            proof_data: plonky2_proof.proof.clone(),
            public_inputs: plonky2_proof.public_inputs.iter()
                .flat_map(|&x| x.to_le_bytes().to_vec())
                .collect(),
            verification_key: plonky2_proof.verification_key_hash.to_vec(),
            plonky2_proof: Some(plonky2_proof),
            proof: vec![],
        }
    }

    /// Create a ZkProof from public inputs (generates proof internally)
    pub fn from_public_inputs(public_inputs: Vec<u64>) -> anyhow::Result<Self> {
        // Try to create a Plonky2 proof
        match crate::plonky2::ZkProofSystem::new() {
            Ok(zk_system) => {
                // Use the ZK system to generate a proof from public inputs
                match zk_system.prove_transaction(
                    public_inputs.get(0).copied().unwrap_or(0),
                    public_inputs.get(1).copied().unwrap_or(0),
                    public_inputs.get(2).copied().unwrap_or(0),
                    public_inputs.get(3).copied().unwrap_or(0),
                    public_inputs.get(4).copied().unwrap_or(0),
                ) {
                    Ok(plonky2_proof) => Ok(Self::from_plonky2(plonky2_proof)),
                    Err(e) => {
                        // NO FALLBACK - fail hard if Plonky2 proof creation fails
                        Err(anyhow::anyhow!("Plonky2 proof creation failed - no fallbacks allowed: {:?}", e))
                    }
                }
            },
            Err(e) => {
                // NO FALLBACK - fail hard if ZK system initialization fails
                Err(anyhow::anyhow!("ZK system initialization failed - no fallbacks allowed: {:?}", e))
            }
        }
    }

    /// Create a default/empty proof (always Plonky2)
    pub fn empty() -> Self {
        Self {
            proof_system: "Plonky2".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
        }
    }

    /// Check if this proof uses Plonky2 (always true in unified system)
    pub fn is_plonky2(&self) -> bool {
        true // Always true in unified system
    }

    /// Get the proof size in bytes
    pub fn size(&self) -> usize {
        if let Some(ref plonky2) = self.plonky2_proof {
            plonky2.proof.len() + plonky2.public_inputs.len()
        } else {
            self.proof_data.len() + self.public_inputs.len() + self.verification_key.len()
        }
    }

    /// Check if the proof is empty/uninitialized
    pub fn is_empty(&self) -> bool {
        self.plonky2_proof.is_none() && 
        self.proof_data.is_empty() && 
        self.public_inputs.is_empty() && 
        self.verification_key.is_empty()
    }

    /// Verify this proof using unified ZK system
    pub fn verify(&self) -> anyhow::Result<bool> {
        if let Some(ref plonky2_proof) = self.plonky2_proof {
            // Use ZkProofSystem for verification (unified approach)
            let zk_system = crate::plonky2::ZkProofSystem::new()?;
            
            // Determine proof type and verify accordingly
            match plonky2_proof.proof_system.as_str() {
                "ZHTP-Optimized-Transaction" => zk_system.verify_transaction(plonky2_proof),
                "ZHTP-Optimized-Identity" => zk_system.verify_identity(plonky2_proof),
                "ZHTP-Optimized-Range" => zk_system.verify_range(plonky2_proof),
                "ZHTP-Optimized-StorageAccess" => zk_system.verify_storage_access(plonky2_proof),
                "ZHTP-Optimized-Routing" => zk_system.verify_routing(plonky2_proof),
                "ZHTP-Optimized-DataIntegrity" => zk_system.verify_data_integrity(plonky2_proof),
                _ => Ok(false), // Unknown proof type
            }
        } else {
            // NO FALLBACK - all proofs must use Plonky2
            Err(anyhow::anyhow!("Proof must use Plonky2 - no fallbacks allowed"))
        }
    }
}

impl Default for ZkProof {
    fn default() -> Self {
        Self::empty()
    }
}

/// Type alias for backward compatibility with other modules
pub type ZeroKnowledgeProof = ZkProof;

/// Zero-knowledge proof type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkProofType {
    /// Transaction proof (amount, balance, nullifier)
    Transaction,
    /// Identity proof with selective disclosure
    Identity,
    /// Range proof for values within bounds
    Range,
    /// Merkle inclusion proof
    Merkle,
    /// Storage access proof
    Storage,
    /// Routing privacy proof
    Routing,
    /// Data integrity proof
    DataIntegrity,
    /// Custom proof type
    Custom(String),
}

impl ZkProofType {
    /// Get the string representation of the proof type
    pub fn as_str(&self) -> &str {
        match self {
            ZkProofType::Transaction => "transaction",
            ZkProofType::Identity => "identity", 
            ZkProofType::Range => "range",
            ZkProofType::Merkle => "merkle",
            ZkProofType::Storage => "storage",
            ZkProofType::Routing => "routing",
            ZkProofType::DataIntegrity => "data_integrity",
            ZkProofType::Custom(name) => name,
        }
    }

    /// Parse proof type from string
    pub fn from_str(s: &str) -> Self {
        match s {
            "transaction" => ZkProofType::Transaction,
            "identity" => ZkProofType::Identity,
            "range" => ZkProofType::Range,
            "merkle" => ZkProofType::Merkle,
            "storage" => ZkProofType::Storage,
            "routing" => ZkProofType::Routing,
            "data_integrity" => ZkProofType::DataIntegrity,
            custom => ZkProofType::Custom(custom.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_proof_creation() {
        use crate::plonky2::Plonky2Proof;
        
        // Create a valid Plonky2Proof
        let plonky2 = Plonky2Proof {
            proof: vec![1, 2, 3],
            public_inputs: vec![4, 5, 6],
            verification_key_hash: [7; 32],
            proof_system: "Plonky2".to_string(),
            generated_at: 1234567890,
            circuit_id: "test_circuit".to_string(),
            private_input_commitment: [8; 32],
        };
        
        let proof = ZkProof::new(
            "Plonky2".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            Some(plonky2),
        );

        assert_eq!(proof.proof_system, "Plonky2");
        assert!(proof.is_plonky2());
        assert_eq!(proof.size(), 6); // 3 (proof) + 3 (public_inputs) = 6
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_zk_proof_type() {
        let tx_type = ZkProofType::Transaction;
        assert_eq!(tx_type.as_str(), "transaction");

        let parsed = ZkProofType::from_str("identity");
        assert_eq!(parsed, ZkProofType::Identity);

        let custom = ZkProofType::Custom("my_proof".to_string());
        assert_eq!(custom.as_str(), "my_proof");
    }

    #[test]
    fn test_default_proof() {
        let proof = ZkProof::default();
        assert!(proof.is_empty());
        assert!(proof.is_plonky2());
    }
}
