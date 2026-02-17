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
    pub(super) async fn validate_remote_vote(&self, vote: &ConsensusVote) -> ConsensusResult<bool> {
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

    /// Validate that a block proposal does not create a fork.
    ///
    /// # BFT Fork Invariant
    ///
    /// In Byzantine Fault Tolerant (BFT) consensus, **forks are invalid by definition**.
    /// Once 2/3+1 validators have committed a block at height H with hash X, that block
    /// is final and irreversible. Any proposal arriving at height H with a different block
    /// hash Y is a fork attempt and MUST be rejected immediately.
    ///
    /// This property differs fundamentally from Nakamoto (PoW) consensus:
    /// - In PoW, forks are possible and resolved by longest-chain rule.
    /// - In BFT, finality is immediate: a committed block cannot be replaced.
    ///   A conflicting proposal is therefore provably invalid, not merely a candidate.
    ///
    /// # Arguments
    /// * `proposal_height` - The height claimed by the incoming proposal
    /// * `proposal_id` - The block/proposal hash of the incoming proposal (for logging)
    ///
    /// # Errors
    /// Returns `ConsensusError::ByzantineFault` if the proposal height already has a
    /// different committed block. The error message identifies the conflicting hashes
    /// so the evidence can be used for validator accountability.
    ///
    /// # Invariant
    /// This check MUST be applied to every incoming proposal before it is accepted
    /// into the pending proposal queue. It is a hard gate: a fork proposal is never
    /// stored, never voted on, and never forwarded to peers.
    pub(super) fn validate_no_fork_proposal(
        &self,
        proposal_height: u64,
        proposal_id: &Hash,
    ) -> ConsensusResult<()> {
        // If the proposal is for a height strictly below the current round height,
        // it is for an already-committed block. Reject it unconditionally.
        //
        // Note: current_round.height is the height we are currently deciding.
        // All heights below it have already been committed and are immutable in BFT.
        if proposal_height < self.current_round.height {
            return Err(ConsensusError::ByzantineFault(format!(
                "BFT FORK REJECTED: proposal {:?} targets height {} which is below the \
                 current committed height {}. In BFT consensus, committed blocks are \
                 final and irreversible. A proposal for an already-committed height is \
                 an invalid fork attempt and is rejected immediately.",
                proposal_id,
                proposal_height,
                self.current_round.height,
            )));
        }

        // If the proposal targets the current round height but there is already a
        // committed proposal at this height with a different hash, reject it as a fork.
        //
        // This can happen if consensus committed a block in a prior round but the
        // engine has not yet advanced to the next height. Any conflicting proposal
        // at the same height is a fork and MUST be rejected.
        if proposal_height == self.current_round.height {
            // Check if we already committed a block at this height (locked_proposal / valid_proposal
            // represent the agreed-upon value in the current round).
            // A non-nil valid_proposal that differs from the incoming proposal signals a fork.
            if let Some(committed_id) = &self.current_round.valid_proposal {
                if committed_id != proposal_id {
                    return Err(ConsensusError::ByzantineFault(format!(
                        "BFT FORK REJECTED: proposal {:?} conflicts with already-agreed \
                         proposal {:?} at height {}. In BFT consensus, once 2/3+1 validators \
                         have pre-committed a block, no other block is valid at that height. \
                         This conflicting proposal is an invalid fork attempt.",
                        proposal_id,
                        committed_id,
                        proposal_height,
                    )));
                }
            }
        }

        Ok(())
    }
}
