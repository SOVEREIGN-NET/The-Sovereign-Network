//! Multisig Verifier (Issue #658)
//!
//! Verifies DAO approval via threshold signature verification.
//! Used by DAOs that use multisig wallets for approval decisions.

use super::traits::{
    ApprovalProof, IssuanceApprovalVerifier, IssuanceRequest, Signature64, VerificationError,
    VerificationResult,
};
use std::collections::HashSet;

/// Configuration for multisig verification
#[derive(Debug, Clone)]
pub struct MultisigConfig {
    /// Minimum required signers (override threshold in proof if higher)
    pub min_signers: Option<u8>,
    /// Maximum allowed signers
    pub max_signers: u8,
}

impl Default for MultisigConfig {
    fn default() -> Self {
        Self {
            min_signers: None,
            max_signers: 10,
        }
    }
}

/// Verifier for multisig-based approvals
///
/// Validates that:
/// 1. Sufficient signatures are provided
/// 2. All signatures are valid
/// 3. All signers are authorized for this DAO
/// 4. No duplicate signers
#[derive(Debug, Clone)]
pub struct MultisigVerifier {
    config: MultisigConfig,
    /// Authorized signers per DAO (dao_id -> set of authorized public keys)
    authorized_signers: std::collections::HashMap<[u8; 32], HashSet<[u8; 32]>>,
}

impl MultisigVerifier {
    /// Create a new verifier with default config
    pub fn new() -> Self {
        Self {
            config: MultisigConfig::default(),
            authorized_signers: std::collections::HashMap::new(),
        }
    }

    /// Create a new verifier with custom config
    pub fn with_config(config: MultisigConfig) -> Self {
        Self {
            config,
            authorized_signers: std::collections::HashMap::new(),
        }
    }

    /// Register authorized signers for a DAO
    pub fn register_signers(&mut self, dao_id: [u8; 32], signers: Vec<[u8; 32]>) {
        let signer_set: HashSet<[u8; 32]> = signers.into_iter().collect();
        self.authorized_signers.insert(dao_id, signer_set);
    }

    /// Verify a single signature
    ///
    /// In production, this would use ed25519 or similar
    fn verify_signature(
        &self,
        message_hash: &[u8; 32],
        signature: &Signature64,
        public_key: &[u8; 32],
    ) -> Result<(), String> {
        // Placeholder verification
        // In production: use ed25519_dalek or similar
        let sig_bytes = signature.as_bytes();

        // Basic sanity checks
        if sig_bytes.iter().all(|&b| b == 0) {
            return Err("Invalid signature: all zeros".to_string());
        }

        if public_key.iter().all(|&b| b == 0) {
            return Err("Invalid public key: all zeros".to_string());
        }

        // Simple placeholder validation:
        // Verify the signature "references" the message (mock verification)
        let mut expected_prefix = [0u8; 4];
        expected_prefix.copy_from_slice(&message_hash[..4]);

        // In a real implementation, this would be cryptographic verification
        let _ = (expected_prefix, sig_bytes, public_key);

        Ok(())
    }

    /// Check if a signer is authorized for a DAO
    fn is_authorized_signer(&self, dao_id: &[u8; 32], signer: &[u8; 32]) -> bool {
        // If no signers registered, allow any signer (permissive mode)
        if self.authorized_signers.is_empty() {
            return true;
        }

        self.authorized_signers
            .get(dao_id)
            .map(|signers| signers.contains(signer))
            .unwrap_or(false)
    }
}

impl Default for MultisigVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuanceApprovalVerifier for MultisigVerifier {
    fn verify_issuance_approval(
        &self,
        request: &IssuanceRequest,
        proof: &ApprovalProof,
        dao_id: [u8; 32],
    ) -> Result<VerificationResult, VerificationError> {
        // Extract multisig proof
        let (signatures, signers, threshold, message_hash) = match proof {
            ApprovalProof::Multisig {
                signatures,
                signers,
                threshold,
                message_hash,
            } => (signatures, signers, *threshold, message_hash),
            _ => {
                return Err(VerificationError::ProofTypeMismatch {
                    expected: "multisig".to_string(),
                    found: proof.proof_type().to_string(),
                })
            }
        };

        // Verify signature/signer count matches
        if signatures.len() != signers.len() {
            return Err(VerificationError::InvalidMultisig {
                reason: format!(
                    "Signature count ({}) doesn't match signer count ({})",
                    signatures.len(),
                    signers.len()
                ),
            });
        }

        // Check signer count against limits
        if signers.len() > self.config.max_signers as usize {
            return Err(VerificationError::InvalidMultisig {
                reason: format!(
                    "Too many signers: {} (max {})",
                    signers.len(),
                    self.config.max_signers
                ),
            });
        }

        // Determine effective threshold
        let effective_threshold = self
            .config
            .min_signers
            .map(|min| min.max(threshold))
            .unwrap_or(threshold);

        // Check sufficient signatures
        if signatures.len() < effective_threshold as usize {
            return Err(VerificationError::InsufficientSignatures {
                provided: signatures.len(),
                required: effective_threshold,
            });
        }

        // Check for duplicate signers
        let mut seen_signers: HashSet<[u8; 32]> = HashSet::new();
        for signer in signers {
            if !seen_signers.insert(*signer) {
                return Err(VerificationError::InvalidMultisig {
                    reason: "Duplicate signer detected".to_string(),
                });
            }
        }

        // Verify each signature and signer authorization
        for (i, (signature, signer)) in signatures.iter().zip(signers.iter()).enumerate() {
            // Verify signature
            self.verify_signature(message_hash, signature, signer)
                .map_err(|reason| VerificationError::InvalidSignature {
                    signer_index: i,
                    reason,
                })?;

            // Verify signer is authorized
            if !self.is_authorized_signer(&dao_id, signer) {
                return Err(VerificationError::SignerNotAuthorized { signer: *signer });
            }
        }

        // Verify message hash matches the request
        let expected_hash = request.compute_hash();
        if *message_hash != expected_hash {
            return Err(VerificationError::InvalidMultisig {
                reason: "Message hash doesn't match issuance request".to_string(),
            });
        }

        Ok(VerificationResult {
            is_valid: true,
            approving_dao: dao_id,
            approved_at: request.current_block,
            expires_at: None, // Multisig approvals don't expire by default
            context: Some(format!(
                "Multisig approval: {}/{} signatures",
                signatures.len(),
                threshold
            )),
        })
    }

    fn expected_proof_type(&self) -> &'static str {
        "multisig"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_request() -> IssuanceRequest {
        IssuanceRequest {
            label: "farm".to_string(),
            sector_id: 5, // Food
            recipient: [1u8; 32],
            recipient_verification_level: 1, // L1
            requester: [2u8; 32],
            current_block: 10000,
        }
    }

    #[test]
    fn test_proof_type_mismatch() {
        let verifier = MultisigVerifier::new();
        let request = make_test_request();
        let wrong_proof = ApprovalProof::GovernanceVote {
            proposal_id: [0u8; 32],
            vote_concluded_at: 100,
            votes_for: 100,
            votes_against: 10,
            merkle_proof: vec![],
        };

        let result = verifier.verify_issuance_approval(&request, &wrong_proof, [3u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::ProofTypeMismatch { .. })
        ));
    }

    #[test]
    fn test_insufficient_signatures() {
        let verifier = MultisigVerifier::new();
        let request = make_test_request();
        let proof = ApprovalProof::Multisig {
            signatures: vec![Signature64::new([1u8; 64])], // Only 1 signature
            signers: vec![[1u8; 32]],
            threshold: 3, // But needs 3
            message_hash: request.compute_hash(),
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [3u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::InsufficientSignatures { .. })
        ));
    }

    #[test]
    fn test_duplicate_signers() {
        let verifier = MultisigVerifier::new();
        let request = make_test_request();
        let signer = [1u8; 32];
        let proof = ApprovalProof::Multisig {
            signatures: vec![Signature64::new([1u8; 64]), Signature64::new([2u8; 64])],
            signers: vec![signer, signer], // Duplicate!
            threshold: 2,
            message_hash: request.compute_hash(),
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [3u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidMultisig { .. })
        ));
    }

    #[test]
    fn test_valid_multisig() {
        let verifier = MultisigVerifier::new();
        let request = make_test_request();
        let proof = ApprovalProof::Multisig {
            signatures: vec![Signature64::new([1u8; 64]), Signature64::new([2u8; 64])],
            signers: vec![[1u8; 32], [2u8; 32]],
            threshold: 2,
            message_hash: request.compute_hash(),
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [3u8; 32]);
        assert!(result.is_ok());
        let verification = result.unwrap();
        assert!(verification.is_valid);
    }

    #[test]
    fn test_unauthorized_signer() {
        let mut verifier = MultisigVerifier::new();
        let dao_id = [3u8; 32];

        // Only [1u8; 32] is authorized
        verifier.register_signers(dao_id, vec![[1u8; 32]]);

        let request = make_test_request();
        let proof = ApprovalProof::Multisig {
            signatures: vec![Signature64::new([1u8; 64]), Signature64::new([2u8; 64])],
            signers: vec![[1u8; 32], [2u8; 32]], // [2u8; 32] not authorized
            threshold: 2,
            message_hash: request.compute_hash(),
        };

        let result = verifier.verify_issuance_approval(&request, &proof, dao_id);
        assert!(matches!(
            result,
            Err(VerificationError::SignerNotAuthorized { .. })
        ));
    }

    #[test]
    fn test_message_hash_mismatch() {
        let verifier = MultisigVerifier::new();
        let request = make_test_request();
        let proof = ApprovalProof::Multisig {
            signatures: vec![Signature64::new([1u8; 64]), Signature64::new([2u8; 64])],
            signers: vec![[1u8; 32], [2u8; 32]],
            threshold: 2,
            message_hash: [0u8; 32], // Wrong hash!
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [3u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidMultisig { .. })
        ));
    }
}
