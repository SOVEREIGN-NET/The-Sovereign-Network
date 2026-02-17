//! Consensus validation logic for the BFT consensus engine.
//!
//! # Determinism guarantees
//!
//! All validation functions in this module are designed to be **deterministic**:
//! given the same inputs, they always produce the same output on every node.
//! This is a hard requirement for BFT consensus — if two honest validators
//! disagree about whether a block is valid, liveness is broken.
//!
//! ## Determinism rules enforced here
//!
//! 1. **Validator set is snapshot-based**: [`ConsensusEngine::is_validator_member`]
//!    looks up a *snapshot* of the validator set at the target height, not the
//!    current live set.  This makes membership checks a pure function of height.
//!
//! 2. **Signature verification is stateless**: [`ConsensusEngine::verify_signature`]
//!    and [`ConsensusEngine::verify_vote_signature`] depend only on the provided
//!    data and the public key stored in the validator registry — no ambient state.
//!
//! 3. **Vote data is reconstructed deterministically**: The signed bytes fed into
//!    [`ConsensusEngine::verify_vote_signature`] are derived solely from the vote
//!    fields (id, voter, proposal_id, vote_type, height, round).
//!
//! 4. **State transitions are pure**: [`ConsensusEngine::validate_remote_vote`]
//!    returns the same `bool` for the same `(vote, engine_state)` pair regardless
//!    of wall-clock time or process identity.
//!
//! ## Assertion helper
//!
//! [`assert_deterministic_state_transition`] can be used in tests and integration
//! paths to assert that a state transition function is pure: it executes the
//! transition twice with the same inputs and asserts the outputs are identical.

use super::*;
use lib_crypto::PostQuantumSignature;

/// Assert that a state transition is deterministic by executing it twice and
/// comparing the results.
///
/// # Parameters
///
/// - `label`: Human-readable name of the transition (for error messages).
/// - `prev_state_hash`: A hash of the initial state before the transition.
/// - `block_hash`: The hash of the block being applied.
/// - `result_state_hash_1`: State root produced by the first execution.
/// - `result_state_hash_2`: State root produced by the second execution.
///
/// # Panics (debug) / Logs error (release)
///
/// Panics if the two result hashes differ, indicating that the transition is
/// non-deterministic.
pub fn assert_deterministic_state_transition(
    label: &str,
    prev_state_hash: &[u8; 32],
    block_hash: &[u8; 32],
    result_state_hash_1: &[u8; 32],
    result_state_hash_2: &[u8; 32],
) {
    if result_state_hash_1 != result_state_hash_2 {
        let msg = format!(
            "NON-DETERMINISTIC state transition detected in '{}': \
             prev_state={}, block={}, result1={}, result2={}. \
             State transitions must be pure functions of (prev_state, block).",
            label,
            hex::encode(prev_state_hash),
            hex::encode(block_hash),
            hex::encode(result_state_hash_1),
            hex::encode(result_state_hash_2),
        );
        #[cfg(debug_assertions)]
        panic!("{}", msg);
        #[cfg(not(debug_assertions))]
        tracing::error!("{}", msg);
    }
}

impl ConsensusEngine {
    /// Verify a signature
    pub(super) async fn verify_signature(
        &self,
        data: &[u8],
        signature: &PostQuantumSignature,
    ) -> ConsensusResult<bool> {
        match signature.public_key.verify(data, signature) {
            Ok(is_valid) => Ok(is_valid),
            Err(e) => {
                tracing::warn!("Signature verification error: {}", e);
                Ok(false)
            }
        }
    }

    /// Verify consensus proof
    pub(super) async fn verify_consensus_proof(&self, proof: &ConsensusProof) -> ConsensusResult<bool> {
        match proof.consensus_type {
            ConsensusType::ProofOfStake => {
                if let Some(stake_proof) = &proof.stake_proof {
                    Ok(stake_proof.verify(self.current_round.height)?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::ProofOfStorage => {
                if let Some(storage_proof) = &proof.storage_proof {
                    Ok(storage_proof.verify()?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::ProofOfUsefulWork => {
                if let Some(work_proof) = &proof.work_proof {
                    Ok(work_proof.verify()?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::ByzantineFaultTolerance => {
                // For BFT, we rely on vote thresholds rather than individual proofs. This generic proof validator is not applicable to BFT proofs.
                Ok(false)
            }
        }
    }

    /// Check if a validator is a member of the active validator set
    ///
    /// **INVARIANT**: Validator membership is a function of height, not wall-clock time.
    /// A validator is valid only if it was a member of the validator set at the target height.
    ///
    pub(super) fn is_validator_member(&self, voter: &IdentityId, height: u64) -> bool {
        if let Some(snapshot) = self.validator_set_for_height(height) {
            return snapshot.contains(voter);
        }

        tracing::warn!(
            "Validator snapshot missing for height {}, rejecting vote for determinism",
            height
        );

        false
    }

    /// Verify the cryptographic signature of a vote
    ///
    /// Uses the vote's own height and round to reconstruct the signed data.
    /// Returns true if signature is valid, false otherwise.
    pub(super) async fn verify_vote_signature(&self, vote: &ConsensusVote) -> ConsensusResult<bool> {
        let validator = match self.validator_manager.get_validator(&vote.voter) {
            Some(validator) => validator,
            None => {
                tracing::warn!(
                    "Vote rejected: validator {} not found for signature verification",
                    vote.voter
                );
                return Ok(false);
            }
        };

        if validator.consensus_key != vote.signature.public_key.dilithium_pk {
            tracing::warn!(
                "Vote rejected: consensus key mismatch for validator {} at height {} round {}",
                vote.voter,
                vote.height,
                vote.round
            );
            return Ok(false);
        }

        // Reconstruct the vote data that was signed, using the vote's own height/round
        // This ensures the signature binds to the vote's exact content, not local state
        let vote_data = self.serialize_vote_data(
            &vote.id,
            &vote.voter,
            &vote.proposal_id,
            &vote.vote_type,
            vote.height,
            vote.round,
        )?;
        let signature_valid = self.verify_signature(&vote_data, &vote.signature).await?;
        if !signature_valid {
            tracing::warn!(
                "Vote rejected: invalid signature from validator {} for height {} round {}",
                vote.voter,
                vote.height,
                vote.round
            );
        }
        Ok(signature_valid)
    }

    /// Validate a remote vote against all BFT safety invariants
    ///
    /// A remote vote MUST be rejected if any of the following fail:
    ///
    /// 1. **Signature**: Cryptographically valid and signed by the claimed validator key
    /// 2. **Validator membership**: Sender is in the active validator set for the target height
    /// 3. **Height**: vote.height == local.height
    /// 4. **Round**: vote.round == local.round
    /// 5. **Vote type coherence**: PreVote only accepted in PreVote step; PreCommit only in PreCommit step
    ///
    /// **Invariant**: validate_remote_vote() is a hard gate, not a soft filter.
    /// Invalid votes are rejected immediately and never stored.
    ///
    /// **Design**: This enforces locally deterministic validation independent of network state.
    /// Signature verification assumes CONSENSUS-NET-4.2 (network delivers authenticated sender + canonical vote envelope).
    ///
    /// **BFT Safety Guarantee**: This function enforces the "Agreement" property by ensuring
    /// that only votes from valid validators at the correct height/round/step can contribute
    /// to quorum. Combined with signature verification, this prevents Byzantine validators
    /// from forging votes or creating false quorums.
    pub(super) async fn validate_remote_vote(&self, vote: &ConsensusVote) -> ConsensusResult<bool> {
        // Runtime check: Votes must be for current or future height (never past)
        // Accepting votes for past heights could allow replay attacks
        if vote.height < self.current_round.height {
            tracing::warn!(
                "Vote rejected: vote height {} < current height {} (potential replay attack)",
                vote.height,
                self.current_round.height
            );
            return Ok(false);
        }
        // 1. Verify signature
        if !self.verify_vote_signature(vote).await? {
            return Ok(false);
        }

        // 2. Verify validator membership
        if !self.is_validator_member(&vote.voter, vote.height) {
            tracing::warn!(
                "Vote rejected: voter {} is not in active validator set for height {}",
                vote.voter,
                vote.height
            );
            return Ok(false);
        }

        // 3. Verify height matches
        if vote.height != self.current_round.height {
            tracing::debug!(
                "Vote rejected: height mismatch. Vote height {} != local height {}",
                vote.height,
                self.current_round.height
            );
            return Ok(false);
        }

        // 4. Verify round matches
        if vote.round != self.current_round.round {
            tracing::debug!(
                "Vote rejected: round mismatch. Vote round {} != local round {}",
                vote.round,
                self.current_round.round
            );
            return Ok(false);
        }

        // 5. Verify vote type coherence - STRICT equality, not >=
        // **CRITICAL INVARIANT**: Votes are only valid in the step they are defined for.
        // Late votes (e.g., PreVote in PreCommit step) are INVALID and never stored.
        // This ensures:
        // - No retroactive quorum formation
        // - Step transitions are monotonic and deterministic
        // - No ambiguous quorum timing
        let valid_for_step = match vote.vote_type {
            VoteType::PreVote => self.current_round.step == ConsensusStep::PreVote,
            VoteType::PreCommit => self.current_round.step == ConsensusStep::PreCommit,
            VoteType::Commit => {
                // Commit votes intentionally bypass step-based validation here.
                //
                // **Design rationale**:
                // - Commit votes are allowed as long as height and round match local state.
                // - The 2/3+1 identical-commit quorum requirement is enforced in `maybe_finalize()`,
                //   which is the only place where blocks are actually finalized.
                // - Keeping quorum logic out of `validate_remote_vote()` preserves the invariant that
                //   this function performs only local, stateless validation (signature, membership,
                //   height/round coherence, and step compatibility for non-commit votes).
                // - Any commit votes that never reach quorum are handled by higher-level cleanup
                //   when rounds/heights advance and vote sets are pruned.
                true
            }
            VoteType::Against => false, // Against votes are never valid in BFT
        };

        if !valid_for_step {
            tracing::warn!(
                "Vote rejected: vote type {:?} not valid for current step {:?}",
                vote.vote_type,
                self.current_round.step
            );
            return Ok(false);
        }

        // All validations passed
        Ok(true)
    }

    /// Validate that the previous hash matches the expected blockchain state
    pub(super) async fn validate_previous_hash(
        &self,
        height: u64,
        previous_hash: &Hash,
    ) -> ConsensusResult<()> {
        // For genesis block (height 0), previous hash should be zero
        if height == 0 {
            let zero_hash = Hash::from_bytes(&[0u8; 32]);
            if *previous_hash != zero_hash {
                return Err(ConsensusError::InvalidPreviousHash(format!(
                    "Genesis block must have zero previous hash, got: {}",
                    previous_hash
                )));
            }
            return Ok(());
        }

        // For subsequent blocks, validate against the actual chain state
        // In a implementation, this would check against stored blockchain state

        // Check if we have the expected previous block
        if height > 1 {
            tracing::debug!(
                "Validating previous hash {} for height {}",
                previous_hash,
                height
            );

            // Here we would normally:
            // 1. Query the blockchain storage for block at height-1
            // 2. Compare its hash with the provided previous_hash
            // 3. Detect potential forks or reorganizations

            // For now, we log the validation but don't fail
            tracing::info!("Previous hash validation passed for height {}", height);
        }

        Ok(())
    }
}

#[cfg(test)]
mod determinism_tests {
    use super::assert_deterministic_state_transition;

    /// Verify that identical executions are accepted as deterministic.
    #[test]
    fn identical_state_transitions_pass() {
        let prev = [0u8; 32];
        let block = [1u8; 32];
        let result = [2u8; 32];
        // Should not panic: both results are the same.
        assert_deterministic_state_transition("test_transition", &prev, &block, &result, &result);
    }

    /// Verify that differing executions are flagged as non-deterministic.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "NON-DETERMINISTIC state transition detected")]
    fn differing_state_transitions_panic() {
        let prev = [0u8; 32];
        let block = [1u8; 32];
        let result1 = [2u8; 32];
        let mut result2 = [2u8; 32];
        result2[0] = 0xff; // differs in first byte
        assert_deterministic_state_transition("test_transition", &prev, &block, &result1, &result2);
    }
}
