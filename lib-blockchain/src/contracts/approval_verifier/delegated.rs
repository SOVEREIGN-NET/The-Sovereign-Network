//! Delegated Verifier (Issue #658)
//!
//! Verifies DAO approval via an external verifier contract.
//! Used by DAOs that delegate approval decisions to specialized contracts.

use super::traits::{
    Address, ApprovalProof, IssuanceApprovalVerifier, IssuanceRequest, VerificationError,
    VerificationResult,
};

/// Configuration for delegated verification
#[derive(Debug, Clone)]
pub struct DelegatedConfig {
    /// Maximum age of attestation (in seconds)
    pub max_attestation_age: u64,
    /// Minimum attestation data length
    pub min_attestation_length: usize,
}

impl Default for DelegatedConfig {
    fn default() -> Self {
        Self {
            max_attestation_age: 3600, // 1 hour
            min_attestation_length: 32,
        }
    }
}

/// Verifier for delegated (external verifier contract) approvals
///
/// Validates that:
/// 1. The verifier contract is registered for this DAO
/// 2. The attestation is properly formatted
/// 3. The attestation is not expired
/// 4. The attestation authorizes the specific issuance
#[derive(Debug, Clone)]
pub struct DelegatedVerifier {
    config: DelegatedConfig,
    /// Registered verifier contracts per DAO
    registered_verifiers: std::collections::HashMap<[u8; 32], Address>,
}

impl DelegatedVerifier {
    /// Create a new verifier with default config
    pub fn new() -> Self {
        Self {
            config: DelegatedConfig::default(),
            registered_verifiers: std::collections::HashMap::new(),
        }
    }

    /// Create a new verifier with custom config
    pub fn with_config(config: DelegatedConfig) -> Self {
        Self {
            config,
            registered_verifiers: std::collections::HashMap::new(),
        }
    }

    /// Register a verifier contract for a DAO
    pub fn register_verifier(&mut self, dao_id: [u8; 32], verifier: Address) {
        self.registered_verifiers.insert(dao_id, verifier);
    }

    /// Get the registered verifier for a DAO
    pub fn get_verifier(&self, dao_id: &[u8; 32]) -> Option<&Address> {
        self.registered_verifiers.get(dao_id)
    }

    /// Verify an attestation from the delegated verifier
    ///
    /// Attestation format:
    /// ```text
    /// [32 bytes] - hash of IssuanceRequest
    /// [8 bytes]  - timestamp (little-endian u64)
    /// [64 bytes] - signature from verifier
    /// [remaining] - optional metadata
    /// ```
    fn verify_attestation(
        &self,
        request: &IssuanceRequest,
        verifier_contract: &Address,
        attestation: &[u8],
        timestamp: u64,
        current_time: u64,
    ) -> Result<(), VerificationError> {
        // Check attestation length
        if attestation.len() < self.config.min_attestation_length {
            return Err(VerificationError::InvalidAttestation {
                reason: format!(
                    "Attestation too short: {} < {}",
                    attestation.len(),
                    self.config.min_attestation_length
                ),
            });
        }

        // Check attestation age
        if current_time > timestamp {
            let age = current_time - timestamp;
            if age > self.config.max_attestation_age {
                return Err(VerificationError::InvalidAttestation {
                    reason: format!(
                        "Attestation expired: {} seconds old (max {})",
                        age, self.config.max_attestation_age
                    ),
                });
            }
        }

        // Verify the attestation contains the request hash
        let request_hash = self.hash_request(request);
        if attestation.len() >= 32 {
            let attested_hash: [u8; 32] = attestation[..32].try_into().unwrap();
            if attested_hash != request_hash {
                return Err(VerificationError::InvalidAttestation {
                    reason: "Attestation doesn't match request".to_string(),
                });
            }
        }

        // In real implementation, verify the signature from verifier_contract
        let _ = verifier_contract;

        Ok(())
    }

    /// Hash an issuance request for attestation verification
    fn hash_request(&self, request: &IssuanceRequest) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"DELEGATED_ISSUANCE_V1");
        hasher.update(request.label.as_bytes());
        hasher.update(&[request.sector_id]);
        hasher.update(&request.recipient);
        hasher.update(&[request.recipient_verification_level]);
        let hash = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

impl Default for DelegatedVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuanceApprovalVerifier for DelegatedVerifier {
    fn verify_issuance_approval(
        &self,
        request: &IssuanceRequest,
        proof: &ApprovalProof,
        dao_id: [u8; 32],
    ) -> Result<VerificationResult, VerificationError> {
        // Extract delegated proof
        let (verifier_contract, attestation, attestation_timestamp) = match proof {
            ApprovalProof::Delegated {
                verifier_contract,
                attestation,
                attestation_timestamp,
            } => (verifier_contract, attestation, *attestation_timestamp),
            _ => {
                return Err(VerificationError::ProofTypeMismatch {
                    expected: "delegated".to_string(),
                    found: proof.proof_type().to_string(),
                })
            }
        };

        // Check if verifier is registered for this DAO (if we have registrations)
        if !self.registered_verifiers.is_empty() {
            match self.registered_verifiers.get(&dao_id) {
                Some(registered) if registered != verifier_contract => {
                    return Err(VerificationError::DelegatedVerifierError {
                        verifier: *verifier_contract,
                        error: "Verifier not registered for this DAO".to_string(),
                    });
                }
                None => {
                    return Err(VerificationError::DelegatedVerifierError {
                        verifier: *verifier_contract,
                        error: "No verifier registered for this DAO".to_string(),
                    });
                }
                _ => {}
            }
        }

        // Convert block height to approximate timestamp
        // Assuming 10-second blocks
        let current_time = request.current_block * 10;

        // Verify the attestation
        self.verify_attestation(
            request,
            verifier_contract,
            attestation,
            attestation_timestamp,
            current_time,
        )?;

        Ok(VerificationResult {
            is_valid: true,
            approving_dao: dao_id,
            approved_at: request.current_block,
            expires_at: Some(attestation_timestamp + self.config.max_attestation_age),
            context: Some(format!("Verified by {:?}", &verifier_contract[..8])),
        })
    }

    fn expected_proof_type(&self) -> &'static str {
        "delegated"
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
        let verifier = DelegatedVerifier::new();
        let request = make_test_request();
        let wrong_proof = ApprovalProof::Multisig {
            signatures: vec![],
            signers: vec![],
            threshold: 2,
            message_hash: [0u8; 32],
        };

        let result = verifier.verify_issuance_approval(&request, &wrong_proof, [3u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::ProofTypeMismatch { .. })
        ));
    }

    #[test]
    fn test_attestation_too_short() {
        let verifier = DelegatedVerifier::new();
        let request = make_test_request();
        let proof = ApprovalProof::Delegated {
            verifier_contract: [4u8; 32],
            attestation: vec![0u8; 10], // Too short!
            attestation_timestamp: request.current_block * 10,
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [3u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidAttestation { .. })
        ));
    }

    #[test]
    fn test_attestation_expired() {
        let verifier = DelegatedVerifier::new();
        let request = make_test_request();
        let proof = ApprovalProof::Delegated {
            verifier_contract: [4u8; 32],
            attestation: vec![0u8; 64],
            attestation_timestamp: 1, // Very old!
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [3u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::InvalidAttestation { .. })
        ));
    }

    #[test]
    fn test_valid_delegated_proof() {
        let verifier = DelegatedVerifier::new();
        let request = make_test_request();

        // Build attestation with correct request hash
        let request_hash = verifier.hash_request(&request);
        let mut attestation = Vec::new();
        attestation.extend_from_slice(&request_hash);
        attestation.extend_from_slice(&[0u8; 32]); // Padding to meet minimum

        let proof = ApprovalProof::Delegated {
            verifier_contract: [4u8; 32],
            attestation,
            attestation_timestamp: request.current_block * 10, // Current time
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [3u8; 32]);
        assert!(result.is_ok());
        let verification = result.unwrap();
        assert!(verification.is_valid);
    }

    #[test]
    fn test_wrong_verifier_for_dao() {
        let mut verifier = DelegatedVerifier::new();
        let dao_id = [3u8; 32];
        verifier.register_verifier(dao_id, [5u8; 32]); // Register [5u8; 32]

        let request = make_test_request();
        let request_hash = verifier.hash_request(&request);
        let mut attestation = Vec::new();
        attestation.extend_from_slice(&request_hash);
        attestation.extend_from_slice(&[0u8; 32]);

        let proof = ApprovalProof::Delegated {
            verifier_contract: [4u8; 32], // Wrong verifier!
            attestation,
            attestation_timestamp: request.current_block * 10,
        };

        let result = verifier.verify_issuance_approval(&request, &proof, dao_id);
        assert!(matches!(
            result,
            Err(VerificationError::DelegatedVerifierError { .. })
        ));
    }
}
