// Identity verifier implementation
use crate::types::VerificationResult;
use crate::identity::{ZkIdentityProof, ZkCredentialProof, CredentialSchema, IdentityVerificationResult};
use crate::identity::verification::{verify_identity_proof, verify_credential_proof, verify_batch_identity_proofs, verify_batch_credential_proofs};
use crate::identity::identity_proof::BatchIdentityProof;
use crate::identity::credential_proof::BatchCredentialProof;
use anyhow::Result;

/// Identity verifier for verifying identity proofs
pub struct IdentityVerifier;

impl IdentityVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Verify a zero-knowledge identity proof with detailed results
    pub fn verify_identity(&self, proof: &ZkIdentityProof) -> Result<VerificationResult> {
        let result = verify_identity_proof(proof)?;
        Ok(result.basic_result)
    }

    /// Verify a zero-knowledge identity proof with detailed identity context
    pub fn verify_identity_detailed(&self, proof: &ZkIdentityProof) -> Result<IdentityVerificationResult> {
        verify_identity_proof(proof)
    }

    /// REMOVED: Fast identity verification - NO SHORTCUTS ALLOWED
    /// All verifications must use full cryptographic proof validation
    pub fn verify_identity_fast(&self, proof: &ZkIdentityProof) -> Result<bool> {
        // NO FAST MODE - use full verification always
        match self.verify_identity_detailed(proof) {
            Ok(result) => Ok(result.basic_result.is_valid()),
            Err(_) => Ok(false),
        }
    }

    /// Verify a credential proof
    pub fn verify_credential(&self, proof: &ZkCredentialProof, schema: &CredentialSchema) -> Result<VerificationResult> {
        verify_credential_proof(proof, schema)
    }

    /// Verify a batch of identity proofs
    pub fn verify_batch_identities(&self, batch: &BatchIdentityProof) -> Result<Vec<IdentityVerificationResult>> {
        verify_batch_identity_proofs(batch)
    }

    /// Verify a batch of credential proofs
    pub fn verify_batch_credentials(&self, batch: &BatchCredentialProof, schemas: &[CredentialSchema]) -> Result<Vec<VerificationResult>> {
        verify_batch_credential_proofs(batch, schemas)
    }

    /// Check if an identity proof is expired
    pub fn is_proof_expired(&self, proof: &ZkIdentityProof) -> bool {
        proof.is_expired()
    }

    /// Get proof age in seconds
    pub fn get_proof_age(&self, proof: &ZkIdentityProof) -> u64 {
        proof.age_seconds()
    }

    /// Verify identity nullifier for double-spending prevention
    pub fn verify_nullifier(&self, proof: &ZkIdentityProof, known_nullifiers: &[[u8; 32]]) -> bool {
        !known_nullifiers.contains(&proof.commitment.nullifier)
    }

    /// Extract verified attributes from an identity proof
    pub fn extract_verified_attributes(&self, proof: &ZkIdentityProof) -> Result<Vec<String>> {
        let result = verify_identity_proof(proof)?;
        Ok(result.verified_attributes)
    }
}
