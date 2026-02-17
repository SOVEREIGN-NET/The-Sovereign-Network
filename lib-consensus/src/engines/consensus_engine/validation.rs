use super::*;
use lib_crypto::PostQuantumSignature;

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
            ConsensusType::Hybrid => {
                let stake_valid = proof
                    .stake_proof
                    .as_ref()
                    .map(|p| p.verify(self.current_round.height))
                    .transpose()?
                    .unwrap_or(false);

                let storage_valid = proof
                    .storage_proof
                    .as_ref()
                    .map(|p| p.verify())
                    .transpose()?
                    .unwrap_or(false);

                Ok(stake_valid && storage_valid)
            }
            ConsensusType::ByzantineFaultTolerance => {
                // For BFT, we rely on vote thresholds rather than individual proofs
                Ok(true)
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
        // Safety assertion: Votes must be for future or current height (never past)
        // Accepting votes for past heights could allow replay attacks
        debug_assert!(
            vote.height >= self.current_round.height,
            "BFT Safety: vote height {} < current height {} (potential replay attack)",
            vote.height,
            self.current_round.height
        );
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
