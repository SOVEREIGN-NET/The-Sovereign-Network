//! Zero-knowledge proof structures and types
//!
//! Unified ZK proof system matching ZHTPDEV-main65 architecture.
//! All proof types use the same underlying ZkProof structure with Plonky2 backend.

use crate::plonky2::Plonky2Proof;
use serde::{Deserialize, Serialize};

fn default_version() -> String {
    "v0".to_string()
}

fn default_circuit_version() -> u32 {
    1
}

/// Runtime guard: reject mock proofs outside of tests or fake-proofs builds.
#[inline]
pub fn ensure_mock_allowed() -> anyhow::Result<()> {
    #[cfg(not(any(test, feature = "fake-proofs")))]
    {
        return Err(anyhow::anyhow!(
            "Mock/placeholder proofs are disabled in production builds. \
             Enable feature 'fake-proofs' for testing only."
        ));
    }
    #[cfg(any(test, feature = "fake-proofs"))]
    {
        Ok(())
    }
}

/// Zero-knowledge proof (unified approach matching ZHTPDEV-main65)
#[derive(Debug, Clone)]
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
    /// Circuit identifier for strict verification matching
    pub circuit_id: String,
    /// Circuit version for strict verification matching
    pub circuit_version: u32,
    /// True if this proof is a mock, stub, or placeholder.
    /// Mock proofs are rejected in production builds.
    pub is_mock: bool,
}

impl Serialize for ZkProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ZkProof", 10)?;
        state.serialize_field("version", &default_version())?;
        state.serialize_field("proof_system", &self.proof_system)?;
        state.serialize_field("proof_data", &self.proof_data)?;
        state.serialize_field("public_inputs", &self.public_inputs)?;
        state.serialize_field("verification_key", &self.verification_key)?;
        state.serialize_field("plonky2_proof", &self.plonky2_proof)?;
        state.serialize_field("proof", &self.proof)?;
        state.serialize_field("circuit_id", &self.circuit_id)?;
        state.serialize_field("circuit_version", &self.circuit_version)?;
        state.serialize_field("is_mock", &self.is_mock)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ZkProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct MaybeVersionedProof {
            version: Option<String>,
            proof_system: String,
            proof_data: Vec<u8>,
            public_inputs: Vec<u8>,
            verification_key: Vec<u8>,
            plonky2_proof: Option<Plonky2Proof>,
            proof: Vec<u8>,
            #[serde(default)]
            circuit_id: String,
            #[serde(default = "default_circuit_version")]
            circuit_version: u32,
            #[serde(default)]
            is_mock: bool,
        }

        let mv: MaybeVersionedProof = MaybeVersionedProof::deserialize(deserializer)?;
        let version = mv.version.unwrap_or_else(|| {
            tracing::warn!("Missing version field in proof; assuming v0");
            default_version()
        });
        if version != "v0" {
            tracing::warn!("ZkProof version mismatch: {}", version);
        }

        // Backward compat: legacy proofs without explicit is_mock are considered mock
        // if they look like placeholders or empty proofs.
        let is_mock = if mv.is_mock {
            true
        } else if mv.proof_data.is_empty()
            && mv.public_inputs.is_empty()
            && mv.verification_key.is_empty()
            && mv.plonky2_proof.is_none()
        {
            tracing::warn!(
                "Deserialized ZkProof has no proof data and no is_mock flag; \
                 treating as mock for safety"
            );
            true
        } else {
            false
        };

        Ok(ZkProof {
            proof_system: mv.proof_system,
            proof_data: mv.proof_data,
            public_inputs: mv.public_inputs,
            verification_key: mv.verification_key,
            plonky2_proof: mv.plonky2_proof,
            proof: mv.proof,
            circuit_id: mv.circuit_id,
            circuit_version: mv.circuit_version,
            is_mock,
        })
    }
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
            proof_system,
            proof_data: proof_data.clone(),
            public_inputs,
            verification_key,
            plonky2_proof,
            proof: proof_data,
            circuit_id: String::new(),
            circuit_version: 1,
            is_mock: false,
        }
    }

    /// Create a placeholder proof for cases where actual proof is not needed.
    ///
    /// **TEST / FAKE-PROOFS ONLY.** This is unavailable in production builds.
    #[cfg(any(test, feature = "fake-proofs"))]
    pub fn placeholder() -> Self {
        Self {
            proof_system: "placeholder".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
            circuit_id: "placeholder".to_string(),
            circuit_version: 0,
            is_mock: true,
        }
    }

    /// Create from Plonky2 proof directly (preferred method)
    pub fn from_plonky2(plonky2_proof: Plonky2Proof) -> Self {
        Self {
            proof_system: "Plonky2".to_string(),
            proof_data: plonky2_proof.proof.clone(),
            public_inputs: plonky2_proof
                .public_inputs
                .iter()
                .flat_map(|&x| x.to_le_bytes().to_vec())
                .collect(),
            verification_key: plonky2_proof.verification_key_hash.to_vec(),
            plonky2_proof: Some(plonky2_proof),
            proof: vec![],
            circuit_id: String::new(),
            circuit_version: 1,
            is_mock: false,
        }
    }

    /// Create a ZkProof from public inputs (generates proof internally)
    pub fn from_public_inputs(public_inputs: Vec<u64>) -> anyhow::Result<Self> {
        match crate::plonky2::ZkProofSystem::new() {
            Ok(zk_system) => {
                match zk_system.prove_transaction(
                    public_inputs.get(0).copied().unwrap_or(0),
                    public_inputs.get(1).copied().unwrap_or(0),
                    public_inputs.get(2).copied().unwrap_or(0),
                    public_inputs.get(3).copied().unwrap_or(0),
                    public_inputs.get(4).copied().unwrap_or(0),
                ) {
                    Ok(plonky2_proof) => Ok(Self::from_plonky2(plonky2_proof)),
                    Err(e) => Err(anyhow::anyhow!(
                        "Plonky2 proof creation failed - no fallbacks allowed: {:?}",
                        e
                    )),
                }
            }
            Err(e) => Err(anyhow::anyhow!(
                "ZK system initialization failed - no fallbacks allowed: {:?}",
                e
            )),
        }
    }

    /// Create a default/empty proof.
    ///
    /// Note: empty proofs are marked `is_mock = true` and will be rejected
    /// by `verify()` in production builds.
    pub fn empty() -> Self {
        Self {
            proof_system: "Plonky2".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
            circuit_id: String::new(),
            circuit_version: 0,
            is_mock: true,
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
        self.plonky2_proof.is_none()
            && self.proof_data.is_empty()
            && self.public_inputs.is_empty()
            && self.verification_key.is_empty()
    }

    /// Reject mock proofs outside of tests or fake-proofs builds.
    pub fn ensure_not_mock(&self) -> anyhow::Result<()> {
        if self.is_mock {
            ensure_mock_allowed()?;
        }
        Ok(())
    }

    /// Verify this proof using unified ZK system.
    ///
    /// In production builds, mock/placeholder/empty proofs will fail verification.
    pub fn verify(&self) -> anyhow::Result<bool> {
        self.ensure_not_mock()?;

        if let Some(ref plonky2_proof) = self.plonky2_proof {
            let zk_system = crate::plonky2::ZkProofSystem::new()?;

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
            Err(anyhow::anyhow!(
                "Proof must use Plonky2 - no fallbacks allowed"
            ))
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
    use serde_json;

    #[test]
    fn test_zk_proof_creation() {
        use crate::plonky2::Plonky2Proof;

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
        assert_eq!(proof.size(), 6);
        assert!(!proof.is_empty());
        assert!(!proof.is_mock);
    }

    #[test]
    fn test_placeholder_is_mock() {
        let proof = ZkProof::placeholder();
        assert!(proof.is_mock);
        assert_eq!(proof.circuit_id, "placeholder");
    }

    #[test]
    fn test_empty_is_mock() {
        let proof = ZkProof::empty();
        assert!(proof.is_mock);
    }

    #[test]
    fn test_default_is_mock() {
        let proof: ZkProof = Default::default();
        assert!(proof.is_mock);
    }

    #[test]
    fn test_mock_allowed_in_tests() {
        let proof = ZkProof::placeholder();
        assert!(proof.ensure_not_mock().is_ok());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let plonky2 = crate::plonky2::Plonky2Proof {
            proof: vec![1, 2, 3],
            public_inputs: vec![4, 5, 6],
            verification_key_hash: [7; 32],
            proof_system: "Plonky2".to_string(),
            generated_at: 1234567890,
            circuit_id: "test_circuit".to_string(),
            private_input_commitment: [8; 32],
        };

        let original = ZkProof {
            proof_system: "Plonky2".to_string(),
            proof_data: vec![1, 2, 3],
            public_inputs: vec![4, 5, 6],
            verification_key: vec![7, 8, 9],
            plonky2_proof: Some(plonky2),
            proof: vec![1, 2, 3],
            circuit_id: "cid".to_string(),
            circuit_version: 2,
            is_mock: false,
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: ZkProof = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.proof_system, original.proof_system);
        assert_eq!(decoded.circuit_id, original.circuit_id);
        assert_eq!(decoded.circuit_version, original.circuit_version);
        assert_eq!(decoded.is_mock, original.is_mock);
    }

    #[test]
    fn test_deserialize_legacy_empty_as_mock() {
        let legacy_json = r#"{
            "version": "v0",
            "proof_system": "Plonky2",
            "proof_data": [],
            "public_inputs": [],
            "verification_key": [],
            "plonky2_proof": null,
            "proof": []
        }"#;

        let decoded: ZkProof = serde_json::from_str(legacy_json).unwrap();
        assert!(decoded.is_mock);
    }
}
