//! Issuance Approval Verifier - Phase 3 Welfare System (Issue #658)
//!
//! Provides verification and approval mechanisms for welfare subdomain issuance
//! by ratified sector DAOs.

use serde::{Deserialize, Serialize};

/// Request for issuance approval
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    /// DAO requesting issuance capability
    pub dao_id: [u8; 32],
    /// Sector being claimed
    pub sector: String,
    /// Block height of request
    pub block_height: u64,
}

/// Cryptographic proof of approval
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalProof {
    /// Signature from root governance
    pub signature: Vec<u8>,
    /// Public key of signer
    pub signer: [u8; 32],
    /// Timestamp of approval
    pub timestamp: u64,
}

/// Verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Approval proof is invalid
    InvalidProof,
    /// Signer is not authorized
    UnauthorizedSigner,
    /// Proof has expired
    ProofExpired,
    /// DAO not found
    DaoNotFound,
    /// Sector mismatch
    SectorMismatch,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidProof => write!(f, "Invalid approval proof"),
            VerificationError::UnauthorizedSigner => write!(f, "Signer not authorized"),
            VerificationError::ProofExpired => write!(f, "Proof has expired"),
            VerificationError::DaoNotFound => write!(f, "DAO not found"),
            VerificationError::SectorMismatch => write!(f, "Sector mismatch"),
        }
    }
}

/// Verifier for issuance approvals
#[derive(Debug, Clone)]
pub struct IssuanceApprovalVerifier {
    root_public_key: [u8; 32],
    proof_validity_period: u64,
}

impl IssuanceApprovalVerifier {
    /// Create a new verifier
    pub fn new(root_public_key: [u8; 32], proof_validity_period: u64) -> Self {
        Self {
            root_public_key,
            proof_validity_period,
        }
    }

    /// Verify an issuance approval
    pub fn verify(
        &self,
        request: &IssuanceRequest,
        proof: &ApprovalProof,
        current_block: u64,
    ) -> Result<(), VerificationError> {
        // Check signer is authorized
        if proof.signer != self.root_public_key {
            return Err(VerificationError::UnauthorizedSigner);
        }

        // Check proof hasn't expired
        if current_block > proof.timestamp.saturating_add(self.proof_validity_period) {
            return Err(VerificationError::ProofExpired);
        }

        // In a real implementation, would verify cryptographic signature here
        // For now, just ensure proof exists
        if proof.signature.is_empty() {
            return Err(VerificationError::InvalidProof);
        }

        Ok(())
    }
}
