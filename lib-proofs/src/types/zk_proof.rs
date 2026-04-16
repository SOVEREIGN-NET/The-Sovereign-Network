//! Zero-knowledge proof structures and types
//!
//! Unified ZK proof system matching ZHTPDEV-main65 architecture.
//! All proof types use the same underlying ZkProof structure with a swappable backend.

use crate::backend::BackendProof;
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
    /// Proof system identifier (e.g. "Plonky2", "fake")
    pub proof_system: String,
    /// Proof data (contains actual cryptographic proof)
    pub proof_data: Vec<u8>,
    /// Public inputs (circuit inputs visible to verifier)
    pub public_inputs: Vec<u8>,
    /// Verification key (for circuit binding)
    pub verification_key: Vec<u8>,
    /// Opaque backend-specific proof data.
    /// This field is the only backend-specific state; downstream crates must not inspect it.
    pub backend_proof: Option<BackendProof>,
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
        state.serialize_field("backend_proof", &self.backend_proof)?;
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
            backend_proof: Option<BackendProof>,
            /// Legacy field: old serialized proofs may still contain a Plonky2Proof object.
            /// We keep it here so deserialization does not fail, but we do not use it.
            #[serde(default)]
            plonky2_proof: Option<serde_json::Value>,
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
            && mv.backend_proof.is_none()
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
            backend_proof: mv.backend_proof,
            proof: mv.proof,
            circuit_id: mv.circuit_id,
            circuit_version: mv.circuit_version,
            is_mock,
        })
    }
}

impl ZkProof {
    /// Create a new ZK proof using unified backend (ZHTPDEV-main65 style)
    pub fn new(
        proof_system: String,
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
        verification_key: Vec<u8>,
        backend_proof: Option<BackendProof>,
    ) -> Self {
        Self {
            proof_system,
            proof_data: proof_data.clone(),
            public_inputs,
            verification_key,
            backend_proof,
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
            backend_proof: None,
            proof: vec![],
            circuit_id: "placeholder".to_string(),
            circuit_version: 0,
            is_mock: true,
        }
    }

    /// Create from opaque backend proof directly (preferred method for backend code)
    pub fn from_backend_proof(backend_proof: BackendProof) -> Self {
        Self {
            proof_system: backend_proof.proof_system.clone(),
            proof_data: backend_proof.data.clone(),
            public_inputs: vec![],
            verification_key: vec![],
            backend_proof: Some(backend_proof),
            proof: vec![],
            circuit_id: String::new(),
            circuit_version: 1,
            is_mock: false,
        }
    }

    /// Create from opaque backend proof, attempting to extract rich fields when
    /// the backend data is a recognizable Plonky2 proof.
    pub fn from_backend_proof_rich(backend_proof: BackendProof) -> Self {
        if let Ok(plonky2_proof) =
            bincode::deserialize::<crate::plonky2::Plonky2Proof>(&backend_proof.data)
        {
            Self::from_plonky2(plonky2_proof)
        } else {
            Self::from_backend_proof(backend_proof)
        }
    }

    /// Create from Plonky2 proof directly (internal compatibility shim)
    #[doc(hidden)]
    pub fn from_plonky2(plonky2_proof: crate::plonky2::Plonky2Proof) -> Self {
        let backend = BackendProof {
            proof_system: plonky2_proof.proof_system.clone(),
            data: match bincode::serialize(&plonky2_proof) {
                Ok(v) => v,
                Err(_) => vec![],
            },
        };
        let public_inputs_bytes = match bincode::serialize(&plonky2_proof.public_inputs) {
            Ok(v) => v,
            Err(_) => vec![],
        };
        Self {
            proof_system: plonky2_proof.proof_system.clone(),
            proof_data: plonky2_proof.proof.clone(),
            public_inputs: public_inputs_bytes,
            verification_key: plonky2_proof.verification_key_hash.to_vec(),
            backend_proof: Some(backend),
            proof: plonky2_proof.proof.clone(),
            circuit_id: plonky2_proof.circuit_id.clone(),
            circuit_version: 1,
            is_mock: false,
        }
    }

    /// Attempt to extract public inputs as `Vec<u64>` from a Plonky2 backend proof.
    pub fn public_inputs_as_u64(&self) -> anyhow::Result<Vec<u64>> {
        if let Some(ref backend_proof) = self.backend_proof {
            if let Ok(plonky2_proof) =
                bincode::deserialize::<crate::plonky2::Plonky2Proof>(&backend_proof.data)
            {
                return Ok(plonky2_proof.public_inputs);
            }
        }
        if !self.public_inputs.is_empty() {
            if let Ok(v) = bincode::deserialize::<Vec<u64>>(&self.public_inputs) {
                return Ok(v);
            }
        }
        Err(anyhow::anyhow!("Could not extract public inputs as u64"))
    }

    /// Create a ZkProof from public inputs (generates proof internally)
    pub fn from_public_inputs(public_inputs: Vec<u64>) -> anyhow::Result<Self> {
        let backend = crate::backend::get_backend();
        let sender_balance = public_inputs.get(0).copied().unwrap_or(0);
        let amount = public_inputs.get(1).copied().unwrap_or(0);
        let fee = public_inputs.get(2).copied().unwrap_or(0);
        let sender_secret = public_inputs.get(3).copied().unwrap_or(0);
        let nullifier_seed = public_inputs.get(4).copied().unwrap_or(0);

        let leaf_hash = crate::transaction::circuit::real::compute_leaf_commitment(
            nullifier_seed,
            sender_secret,
            sender_balance,
        );
        let (merkle_root, merkle_siblings) = crate::transaction::circuit::real::
            build_sparse_merkle_tree_from_hashes(&[(0, leaf_hash)], 0)?;

        let bp = backend.prove_transaction(
            sender_balance,
            amount,
            fee,
            sender_secret,
            nullifier_seed,
            merkle_root,
            0,
            &merkle_siblings,
        )?;
        Ok(Self::from_backend_proof(bp))
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
            backend_proof: None,
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
        if let Some(ref bp) = self.backend_proof {
            bp.data.len()
        } else {
            self.proof_data.len() + self.public_inputs.len() + self.verification_key.len()
        }
    }

    /// Check if the proof is empty/uninitialized
    pub fn is_empty(&self) -> bool {
        self.backend_proof.is_none()
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

    /// Verify this proof using the active backend.
    ///
    /// In production builds, mock/placeholder/empty proofs will fail verification.
    pub fn verify(&self) -> anyhow::Result<bool> {
        self.ensure_not_mock()?;

        // Direct dispatch for real identity proofs that bypass the backend envelope.
        if self.proof_system == "plonky2-real-identity" {
            #[cfg(feature = "real-proofs")]
            {
                return crate::identity::circuit::real::verify_identity(&self.proof_data)
                    .map(|_| true)
                    .or_else(|_| Ok(false));
            }
            #[cfg(not(feature = "real-proofs"))]
            {
                return Ok(false);
            }
        }

        if let Some(ref backend_proof) = self.backend_proof {
            let backend = crate::backend::get_backend();
            match backend_proof.proof_system.as_str() {
                "ZHTP-Optimized-Transaction" | "plonky2-real-transaction" => {
                    backend.verify_transaction(backend_proof)
                }
                "ZHTP-Optimized-Identity" => backend.verify_identity(backend_proof),
                "ZHTP-Optimized-Range" | "Bulletproofs" => backend.verify_range(backend_proof),
                "ZHTP-Optimized-StorageAccess" => backend.verify_storage_access(backend_proof),
                "ZHTP-Optimized-Merkle" => backend.verify_merkle(backend_proof, [0u8; 32]),
                "ZHTP-Optimized-Routing" => Ok(true), // stub
                "ZHTP-Optimized-DataIntegrity" => Ok(true), // stub
                "fake" => Ok(true),
                _ => Ok(false), // Unknown proof type
            }
        } else {
            // No backend data means the proof is structurally incomplete.
            // This is a verification failure, not a system error.
            Ok(false)
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
        let backend = BackendProof {
            proof_system: "Plonky2".to_string(),
            data: vec![1, 2, 3],
        };

        let proof = ZkProof::new(
            "Plonky2".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            Some(backend),
        );

        assert_eq!(proof.proof_system, "Plonky2");
        assert!(proof.is_plonky2());
        assert_eq!(proof.size(), 3);
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
        let backend = BackendProof {
            proof_system: "Plonky2".to_string(),
            data: vec![1, 2, 3],
        };

        let original = ZkProof {
            proof_system: "Plonky2".to_string(),
            proof_data: vec![1, 2, 3],
            public_inputs: vec![4, 5, 6],
            verification_key: vec![7, 8, 9],
            backend_proof: Some(backend),
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
        assert!(decoded.backend_proof.is_some());
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
