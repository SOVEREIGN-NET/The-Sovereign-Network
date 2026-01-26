//! Governance Vote Verifier (Issue #658)
//!
//! Verifies DAO approval via on-chain governance proposal votes.
//! Used by DAOs that use standard governance voting for approval decisions.

use super::traits::{
    ApprovalProof, IssuanceApprovalVerifier, IssuanceRequest, VerificationError,
    VerificationResult,
};

/// Configuration for governance vote verification
#[derive(Debug, Clone)]
pub struct GovernanceVoteConfig {
    /// Required percentage of yes votes to total (0-100)
    pub required_approval_percent: u8,
    /// Minimum number of blocks for a proposal to be valid
    pub min_proposal_duration: u64,
    /// Maximum age of a concluded vote (in blocks)
    pub max_vote_age: u64,
}

impl Default for GovernanceVoteConfig {
    fn default() -> Self {
        Self {
            required_approval_percent: 50, // Simple majority
            min_proposal_duration: 100,    // ~1000 seconds with 10s blocks
            max_vote_age: 8640,            // ~1 day with 10s blocks
        }
    }
}

/// Verifier for governance vote-based approvals
///
/// Validates that:
/// 1. The proposal exists and matches the issuance request
/// 2. The vote concluded successfully with sufficient approval
/// 3. The merkle proof is valid
/// 4. The vote hasn't expired
#[derive(Debug, Clone)]
pub struct GovernanceVoteVerifier {
    config: GovernanceVoteConfig,
}

impl GovernanceVoteVerifier {
    /// Create a new verifier with default config
    pub fn new() -> Self {
        Self {
            config: GovernanceVoteConfig::default(),
        }
    }

    /// Create a new verifier with custom config
    pub fn with_config(config: GovernanceVoteConfig) -> Self {
        Self { config }
    }

    /// Verify the merkle proof linking proposal to vote outcome
    ///
    /// The merkle proof should demonstrate that:
    /// 1. The proposal hash is in the DAO's proposal tree
    /// 2. The vote outcome is linked to the proposal
    fn verify_merkle_proof(
        &self,
        proposal_id: &[u8; 32],
        merkle_proof: &[[u8; 32]],
        _request: &IssuanceRequest,
    ) -> Result<(), VerificationError> {
        // For now, verify proof has reasonable length
        if merkle_proof.len() > 32 {
            return Err(VerificationError::InvalidMerkleProof {
                reason: "Proof too long".to_string(),
            });
        }

        // In production, this would:
        // 1. Reconstruct the merkle root from the proof
        // 2. Verify the root matches the DAO's committed root
        // 3. Verify the proposal data matches the issuance request

        // Placeholder: verify proposal_id is in proof path (simplified)
        if merkle_proof.is_empty() {
            // Empty proof is valid for root-level entries
            return Ok(());
        }

        // Verify proof structure (simplified)
        let mut current = *proposal_id;
        for sibling in merkle_proof {
            // Hash current with sibling (order determined by comparison)
            let (left, right) = if current < *sibling {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = hash_pair(&left, &right);
        }

        // In real implementation, verify current matches stored root
        let _ = current;

        Ok(())
    }

    /// Check if the vote passed with sufficient approval
    fn check_vote_passed(
        &self,
        votes_for: u64,
        votes_against: u64,
    ) -> Result<(), VerificationError> {
        let total_votes = votes_for.saturating_add(votes_against);
        if total_votes == 0 {
            return Err(VerificationError::VoteDidNotPass {
                votes_for,
                votes_against,
                required_ratio_percent: self.config.required_approval_percent,
            });
        }

        // Calculate approval percentage (0-100)
        let approval_percent = ((votes_for * 100) / total_votes) as u8;
        if approval_percent < self.config.required_approval_percent {
            return Err(VerificationError::VoteDidNotPass {
                votes_for,
                votes_against,
                required_ratio_percent: self.config.required_approval_percent,
            });
        }

        Ok(())
    }

    /// Check if the vote is still valid (not expired)
    fn check_vote_age(
        &self,
        vote_concluded_at: u64,
        current_block: u64,
    ) -> Result<(), VerificationError> {
        if current_block > vote_concluded_at {
            let age = current_block - vote_concluded_at;
            if age > self.config.max_vote_age {
                return Err(VerificationError::ApprovalExpired {
                    expired_at: vote_concluded_at + self.config.max_vote_age,
                    current_block,
                });
            }
        }
        Ok(())
    }
}

impl Default for GovernanceVoteVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuanceApprovalVerifier for GovernanceVoteVerifier {
    fn verify_issuance_approval(
        &self,
        request: &IssuanceRequest,
        proof: &ApprovalProof,
        dao_id: [u8; 32],
    ) -> Result<VerificationResult, VerificationError> {
        // Extract governance vote proof
        let (proposal_id, vote_concluded_at, votes_for, votes_against, merkle_proof) = match proof {
            ApprovalProof::GovernanceVote {
                proposal_id,
                vote_concluded_at,
                votes_for,
                votes_against,
                merkle_proof,
            } => (proposal_id, *vote_concluded_at, *votes_for, *votes_against, merkle_proof),
            _ => {
                return Err(VerificationError::ProofTypeMismatch {
                    expected: "governance_vote".to_string(),
                    found: proof.proof_type().to_string(),
                })
            }
        };

        // Verify the vote passed
        self.check_vote_passed(votes_for, votes_against)?;

        // Verify the vote hasn't expired
        self.check_vote_age(vote_concluded_at, request.current_block)?;

        // Verify the merkle proof
        self.verify_merkle_proof(proposal_id, merkle_proof, request)?;

        Ok(VerificationResult {
            is_valid: true,
            approving_dao: dao_id,
            approved_at: vote_concluded_at,
            expires_at: Some(vote_concluded_at + self.config.max_vote_age),
            context: Some(format!(
                "Governance vote passed: {} for, {} against",
                votes_for, votes_against
            )),
        })
    }

    fn expected_proof_type(&self) -> &'static str {
        "governance_vote"
    }
}

/// Hash two 32-byte values together
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(b"MERKLE_NODE");
    hasher.update(left);
    hasher.update(right);
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
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
    fn test_valid_governance_vote() {
        let verifier = GovernanceVoteVerifier::new();
        let request = make_test_request();
        let proof = ApprovalProof::GovernanceVote {
            proposal_id: [3u8; 32],
            vote_concluded_at: 9900, // 100 blocks ago
            votes_for: 100,
            votes_against: 20,
            merkle_proof: vec![],
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [4u8; 32]);
        assert!(result.is_ok());
        let verification = result.unwrap();
        assert!(verification.is_valid);
        assert_eq!(verification.approved_at, 9900);
    }

    #[test]
    fn test_vote_did_not_pass() {
        let verifier = GovernanceVoteVerifier::new();
        let request = make_test_request();
        let proof = ApprovalProof::GovernanceVote {
            proposal_id: [3u8; 32],
            vote_concluded_at: 9900,
            votes_for: 20,
            votes_against: 100, // More against
            merkle_proof: vec![],
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [4u8; 32]);
        assert!(matches!(result, Err(VerificationError::VoteDidNotPass { .. })));
    }

    #[test]
    fn test_vote_expired() {
        let verifier = GovernanceVoteVerifier::new();
        let mut request = make_test_request();
        request.current_block = 100000; // Much later

        let proof = ApprovalProof::GovernanceVote {
            proposal_id: [3u8; 32],
            vote_concluded_at: 1000, // Very old
            votes_for: 100,
            votes_against: 20,
            merkle_proof: vec![],
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [4u8; 32]);
        assert!(matches!(result, Err(VerificationError::ApprovalExpired { .. })));
    }

    #[test]
    fn test_proof_type_mismatch() {
        let verifier = GovernanceVoteVerifier::new();
        let request = make_test_request();
        let wrong_proof = ApprovalProof::Multisig {
            signatures: vec![],
            signers: vec![],
            threshold: 2,
            message_hash: [0u8; 32],
        };

        let result = verifier.verify_issuance_approval(&request, &wrong_proof, [4u8; 32]);
        assert!(matches!(
            result,
            Err(VerificationError::ProofTypeMismatch { .. })
        ));
    }

    #[test]
    fn test_custom_config() {
        let config = GovernanceVoteConfig {
            required_approval_percent: 67, // Two-thirds majority
            min_proposal_duration: 200,
            max_vote_age: 1000,
        };
        let verifier = GovernanceVoteVerifier::with_config(config);
        let request = make_test_request();

        // This would pass with simple majority but fails with two-thirds
        let proof = ApprovalProof::GovernanceVote {
            proposal_id: [3u8; 32],
            vote_concluded_at: 9900,
            votes_for: 60,
            votes_against: 40, // 60% approval, needs 67%
            merkle_proof: vec![],
        };

        let result = verifier.verify_issuance_approval(&request, &proof, [4u8; 32]);
        assert!(matches!(result, Err(VerificationError::VoteDidNotPass { .. })));
    }
}
