//! V1 Proof Envelope and Governance Registry
//!
//! This module defines the canonical `ProofEnvelope` container, the `ProofType`
//! enum for governed proof variants, and registry metadata used to validate
//! envelopes in a structured, append-only way.

use serde::{Deserialize, Serialize};

/// Algorithm identifiers used for proofs and verification keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmId {
    /// CRYSTALS-Dilithium2 post-quantum signature
    Dilithium2,
    /// CRYSTALS-Dilithium3 post-quantum signature
    Dilithium3,
    /// Ed25519 (classical, only for dev/compat if governance allows)
    Ed25519,
    /// Plonky2 zero-knowledge proof system
    Plonky2,
}

/// High-level proof type classification (append-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    // Identity / capabilities
    SignaturePopV1,
    IdentityAttributeZkV1,
    CredentialProofV1,
    DeviceDelegationV1,

    // Proximity / sessions
    ProximityHandshakeV1,
    SessionKeyProofV1,

    // Network / transport / storage
    StorageProofV1,
    RoutingProofV1,
    TransportProofV1,

    // SID economy
    SidTransactionV1,

    // Governance / DAO
    DaoTransactionV1,
    VotingV1,
    StateTransitionV1,

    // Optional / fringe extensions
    CredentialRevocationProofV1,
    KeyCompromiseProofV1,
    UsageRateProofV1,
    SybilResistanceProofV1,
    JurisdictionComplianceProofV1,
}

/// Implementation status for a proof type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofImplementationStatus {
    /// Fully implemented prover/verifier with tests.
    Implemented,
    /// Structurally defined, but verifier returns a typed NotImplementedYet error.
    Experimental,
}

/// Registry metadata for a proof type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    pub proof_type: ProofType,
    pub version: &'static str,
    pub is_public: bool,
    pub requires_circuit_hash: bool,
    pub requires_verification_key: bool,
    pub requires_public_inputs: bool,
    pub requires_proof_data: bool,
    pub status: ProofImplementationStatus,
    #[serde(skip_serializing, skip_deserializing)]
    pub allowed_algorithms: &'static [AlgorithmId],
}

/// Canonical V1 proof envelope used across the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEnvelope {
    /// Envelope version ("v1" for this proposal).
    pub version: String,
    /// DID schema/version ("v1" for ADR-0001 identities).
    pub did_version: String,
    /// Type of proof (governed enum, no free-form strings).
    pub proof_type: ProofType,
    /// Optional hash of the circuit or proving system.
    pub circuit_hash: Option<Vec<u8>>,
    /// Optional verification key bytes (circuit VK or public key).
    pub verification_key: Option<Vec<u8>>,
    /// Public inputs to the proof/circuit.
    pub public_inputs: Vec<u8>,
    /// Raw proof artifact (signature or ZK proof bytes).
    pub proof_data: Vec<u8>,
}

impl ProofEnvelope {
    /// Convenience constructor for a minimal V1 envelope.
    pub fn new(
        proof_type: ProofType,
        circuit_hash: Option<Vec<u8>>,
        verification_key: Option<Vec<u8>>,
        public_inputs: Vec<u8>,
        proof_data: Vec<u8>,
    ) -> Self {
        Self {
            version: "v1".to_string(),
            did_version: "v1".to_string(),
            proof_type,
            circuit_hash,
            verification_key,
            public_inputs,
            proof_data,
        }
    }

    /// Temporary adapter for legacy call sites that referenced ad-hoc proof_system strings.
    pub fn from_legacy_label(
        label: &str,
        verification_key: Option<Vec<u8>>,
        public_inputs: Vec<u8>,
        proof_data: Vec<u8>,
    ) -> Self {
        Self::new(
            Self::map_legacy_label(label),
            None,
            verification_key,
            public_inputs,
            proof_data,
        )
    }

    fn map_legacy_label(label: &str) -> ProofType {
        match label {
            "NodeIdentity" | "lib-OwnershipProof" | "ownership_proof" | "dilithium-pop-placeholder-v0" => {
                ProofType::SignaturePopV1
            }
            "wallet_upload" | "StorageProof" | "dht_service" | "test" => ProofType::StorageProofV1,
            "Ring-Signature-Response" => ProofType::SessionKeyProofV1,
            "lib-AgeProof" | "lib-PlonkyCommit" | "Plonky2" => ProofType::IdentityAttributeZkV1,
            _ => ProofType::CredentialProofV1,
        }
    }
}

/// Static registry describing all proof types.
///
/// NOTE: This is an initial, minimal table to get the structure in place.
/// Details (e.g. bounds per type) should be refined to match priovac-3.md.
pub fn proof_type_registry() -> &'static [ProofTypeMetadata] {
    use AlgorithmId::*;
    use ProofImplementationStatus::*;
    use ProofType::*;

    static REGISTRY: &[ProofTypeMetadata] = &[
        // Identity / capabilities
        ProofTypeMetadata {
            proof_type: SignaturePopV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: false,
            requires_verification_key: true,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Dilithium2],
        },
        ProofTypeMetadata {
            proof_type: IdentityAttributeZkV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: CredentialProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2, Ed25519],
        },
        ProofTypeMetadata {
            proof_type: DeviceDelegationV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: false,
            requires_verification_key: true,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Ed25519, Dilithium2],
        },
        // Proximity / sessions
        ProofTypeMetadata {
            proof_type: ProximityHandshakeV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: false,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: SessionKeyProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: false,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        // Network / transport / storage
        ProofTypeMetadata {
            proof_type: StorageProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: RoutingProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: TransportProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        // SID economy
        ProofTypeMetadata {
            proof_type: SidTransactionV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        // Governance / DAO
        ProofTypeMetadata {
            proof_type: DaoTransactionV1,
            version: "v1",
            is_public: true,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: VotingV1,
            version: "v1",
            is_public: true,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: StateTransitionV1,
            version: "v1",
            is_public: true,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        // Fringe / extensions
        ProofTypeMetadata {
            proof_type: CredentialRevocationProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: KeyCompromiseProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: false,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Ed25519, Dilithium2],
        },
        ProofTypeMetadata {
            proof_type: UsageRateProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: SybilResistanceProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
        ProofTypeMetadata {
            proof_type: JurisdictionComplianceProofV1,
            version: "v1",
            is_public: false,
            requires_circuit_hash: true,
            requires_verification_key: false,
            requires_public_inputs: true,
            requires_proof_data: true,
            status: Experimental,
            allowed_algorithms: &[Plonky2],
        },
    ];

    REGISTRY
}

impl Default for ProofEnvelope {
    fn default() -> Self {
        Self::new(
            ProofType::SignaturePopV1,
            None,
            None,
            Vec::new(),
            Vec::new(),
        )
    }
}
