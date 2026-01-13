//! Approval Verifier Traits (Issue #658)
//!
//! Core trait definitions for verifying DAO approval of welfare subdomain issuance.
//! Different DAOs may use different approval mechanisms (governance votes,
//! multisig, delegated verifiers).

use serde::{Deserialize, Serialize};

/// 32-byte address type
pub type Address = [u8; 32];

/// Issuance request submitted for DAO approval
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    /// The label being requested (e.g., "farm" for "farm.food.dao.sov")
    pub label: String,
    /// The sector ID this request is for
    pub sector_id: u8,
    /// Recipient's public key
    pub recipient: [u8; 32],
    /// Recipient's verification level (as u8)
    pub recipient_verification_level: u8,
    /// Who submitted this request (public key)
    pub requester: [u8; 32],
    /// Current block height at time of request
    pub current_block: u64,
}

impl IssuanceRequest {
    /// Compute a hash of this request for verification
    pub fn compute_hash(&self) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"ISSUANCE_REQUEST_V1");
        hasher.update(self.label.as_bytes());
        hasher.update(&[self.sector_id]);
        hasher.update(&self.recipient);
        hasher.update(&[self.recipient_verification_level]);
        hasher.update(&self.requester);
        hasher.update(&self.current_block.to_le_bytes());
        let hash = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

/// 64-byte signature wrapper for serde compatibility
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

impl Signature64 {
    /// Create a new signature from bytes
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the inner bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl serde::Serialize for Signature64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature64(arr))
    }
}

/// Proof of DAO approval for an issuance request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalProof {
    /// Governance vote approval
    GovernanceVote {
        /// Proposal ID in the DAO governance system
        proposal_id: [u8; 32],
        /// Block height when the vote concluded
        vote_concluded_at: u64,
        /// Total votes in favor
        votes_for: u64,
        /// Total votes against
        votes_against: u64,
        /// Merkle proof linking proposal to vote outcome
        merkle_proof: Vec<[u8; 32]>,
    },
    /// Multisig approval
    Multisig {
        /// Signatures from multisig signers
        signatures: Vec<Signature64>,
        /// Public keys of signers
        signers: Vec<[u8; 32]>,
        /// Required threshold
        threshold: u8,
        /// Hash of the message being signed
        message_hash: [u8; 32],
    },
    /// Delegated verifier approval
    Delegated {
        /// Address of the delegated verifier contract
        verifier_contract: Address,
        /// Attestation data from the verifier
        attestation: Vec<u8>,
        /// When the attestation was issued
        attestation_timestamp: u64,
    },
}

impl ApprovalProof {
    /// Get the proof type as a string
    pub fn proof_type(&self) -> &'static str {
        match self {
            ApprovalProof::GovernanceVote { .. } => "governance_vote",
            ApprovalProof::Multisig { .. } => "multisig",
            ApprovalProof::Delegated { .. } => "delegated",
        }
    }
}

/// Result of verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,
    /// The DAO that approved this issuance
    pub approving_dao: [u8; 32],
    /// Block height when approval was granted
    pub approved_at: u64,
    /// Optional expiration of the approval
    pub expires_at: Option<u64>,
    /// Optional context information
    pub context: Option<String>,
}

/// Verification error types
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationError {
    /// Proof type doesn't match verifier
    ProofTypeMismatch {
        expected: String,
        found: String,
    },
    /// Invalid governance vote proof
    InvalidGovernanceVote {
        reason: String,
    },
    /// Proposal not found
    ProposalNotFound {
        proposal_id: [u8; 32],
    },
    /// Vote did not pass (required_ratio_percent is 0-100 instead of f64)
    VoteDidNotPass {
        votes_for: u64,
        votes_against: u64,
        required_ratio_percent: u8,
    },
    /// Invalid merkle proof
    InvalidMerkleProof {
        reason: String,
    },
    /// Invalid multisig
    InvalidMultisig {
        reason: String,
    },
    /// Insufficient signatures
    InsufficientSignatures {
        provided: usize,
        required: u8,
    },
    /// Invalid signature
    InvalidSignature {
        signer_index: usize,
        reason: String,
    },
    /// Signer not authorized
    SignerNotAuthorized {
        signer: [u8; 32],
    },
    /// Invalid attestation
    InvalidAttestation {
        reason: String,
    },
    /// Delegated verifier error
    DelegatedVerifierError {
        verifier: Address,
        error: String,
    },
    /// Approval expired
    ApprovalExpired {
        expired_at: u64,
        current_block: u64,
    },
    /// DAO not authorized for this sector
    DaoNotAuthorizedForSector {
        dao_id: [u8; 32],
        sector_id: u8,
    },
    /// Generic verification error
    Other {
        message: String,
    },
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::ProofTypeMismatch { expected, found } => {
                write!(f, "Proof type mismatch: expected {}, found {}", expected, found)
            }
            VerificationError::InvalidGovernanceVote { reason } => {
                write!(f, "Invalid governance vote: {}", reason)
            }
            VerificationError::ProposalNotFound { proposal_id } => {
                write!(f, "Proposal not found: {:?}", &proposal_id[..8])
            }
            VerificationError::VoteDidNotPass { votes_for, votes_against, required_ratio_percent } => {
                write!(
                    f,
                    "Vote did not pass: {} for, {} against (required: {}%)",
                    votes_for, votes_against, required_ratio_percent
                )
            }
            VerificationError::InvalidMerkleProof { reason } => {
                write!(f, "Invalid merkle proof: {}", reason)
            }
            VerificationError::InvalidMultisig { reason } => {
                write!(f, "Invalid multisig: {}", reason)
            }
            VerificationError::InsufficientSignatures { provided, required } => {
                write!(
                    f,
                    "Insufficient signatures: {} provided, {} required",
                    provided, required
                )
            }
            VerificationError::InvalidSignature { signer_index, reason } => {
                write!(f, "Invalid signature at index {}: {}", signer_index, reason)
            }
            VerificationError::SignerNotAuthorized { signer } => {
                write!(f, "Signer not authorized: {:?}", &signer[..8])
            }
            VerificationError::InvalidAttestation { reason } => {
                write!(f, "Invalid attestation: {}", reason)
            }
            VerificationError::DelegatedVerifierError { verifier, error } => {
                write!(f, "Delegated verifier {:?} error: {}", &verifier[..8], error)
            }
            VerificationError::ApprovalExpired { expired_at, current_block } => {
                write!(
                    f,
                    "Approval expired at block {}, current block {}",
                    expired_at, current_block
                )
            }
            VerificationError::DaoNotAuthorizedForSector { dao_id, sector_id } => {
                write!(
                    f,
                    "DAO {:?} not authorized for sector {}",
                    &dao_id[..8],
                    sector_id
                )
            }
            VerificationError::Other { message } => {
                write!(f, "Verification error: {}", message)
            }
        }
    }
}

impl std::error::Error for VerificationError {}

/// Trait for verifying DAO approval of welfare subdomain issuance
///
/// Implementations of this trait verify different types of approval proofs
/// (governance votes, multisig, delegated verifiers).
pub trait IssuanceApprovalVerifier: Send + Sync {
    /// Verify that an issuance request has been approved by the given DAO
    ///
    /// # Arguments
    /// * `request` - The issuance request to verify
    /// * `proof` - The proof of approval
    /// * `dao_id` - The DAO ID that should have approved this
    ///
    /// # Returns
    /// * `Ok(VerificationResult)` - If verification succeeds
    /// * `Err(VerificationError)` - If verification fails
    fn verify_issuance_approval(
        &self,
        request: &IssuanceRequest,
        proof: &ApprovalProof,
        dao_id: [u8; 32],
    ) -> Result<VerificationResult, VerificationError>;

    /// Get the expected proof type for this verifier
    fn expected_proof_type(&self) -> &'static str;

    /// Check if this verifier supports the given proof type
    fn supports_proof(&self, proof: &ApprovalProof) -> bool {
        proof.proof_type() == self.expected_proof_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuance_request_hash() {
        let request = IssuanceRequest {
            label: "farm".to_string(),
            sector_id: 5,
            recipient: [1u8; 32],
            recipient_verification_level: 1,
            requester: [2u8; 32],
            current_block: 1000,
        };

        let hash1 = request.compute_hash();
        let hash2 = request.compute_hash();
        assert_eq!(hash1, hash2, "Hash should be deterministic");

        let mut request2 = request.clone();
        request2.label = "store".to_string();
        let hash3 = request2.compute_hash();
        assert_ne!(hash1, hash3, "Different requests should have different hashes");
    }

    #[test]
    fn test_proof_types() {
        let gov_proof = ApprovalProof::GovernanceVote {
            proposal_id: [0u8; 32],
            vote_concluded_at: 100,
            votes_for: 100,
            votes_against: 10,
            merkle_proof: vec![],
        };
        assert_eq!(gov_proof.proof_type(), "governance_vote");

        let multisig_proof = ApprovalProof::Multisig {
            signatures: vec![],
            signers: vec![],
            threshold: 2,
            message_hash: [0u8; 32],
        };
        assert_eq!(multisig_proof.proof_type(), "multisig");

        let delegated_proof = ApprovalProof::Delegated {
            verifier_contract: [3u8; 32],
            attestation: vec![0u8; 64],
            attestation_timestamp: 1000,
        };
        assert_eq!(delegated_proof.proof_type(), "delegated");
    }
}
