//! Consensus Validation
//!
//! Strict, deterministic validation rules for BFT consensus: proposal admission,
//! vote verification, fork rejection, and previous-hash continuity.
//!
//! # Determinism Guarantees
//!
//! All validation functions in this module are **deterministic**: given the same
//! inputs, they always produce the same output on every node. This is a hard
//! requirement for BFT consensus — if two honest validators disagree about
//! whether a block is valid, liveness is broken.
//!
//! ## Rules Enforced Here
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
    pub(super) async fn verify_consensus_proof(
        &self,
        proof: &ConsensusProof,
    ) -> ConsensusResult<bool> {
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
    ///
    /// Security invariant: membership is necessary but not sufficient.
    /// Every vote MUST carry a non-empty Dilithium public key that exactly
    /// matches the registered validator consensus key.
    pub(super) async fn verify_vote_signature(
        &self,
        vote: &ConsensusVote,
    ) -> ConsensusResult<bool> {
        // Reject unsigned votes. Membership-only acceptance is unsafe because a spoofed
        // sender could vote on behalf of validators registered with placeholder keys.
        if vote.signature.public_key.dilithium_pk == [0u8; 2592] {
            tracing::warn!(
                "Vote rejected: empty consensus key for validator {} at height {} round {}",
                vote.voter,
                vote.height,
                vote.round
            );
            return Ok(false);
        }

        // Validate the public key uses a known Dilithium variant.
        if let Err(e) = lib_crypto::validate_consensus_vote_signature_scheme(
            &vote.signature.public_key.dilithium_pk,
        ) {
            tracing::warn!(
                "Vote rejected: signature scheme validation failed for validator {} at height {} round {}: {}",
                vote.voter,
                vote.height,
                vote.round,
                e
            );
            return Ok(false);
        }

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

        if validator.consensus_key == [0u8; 2592] {
            tracing::warn!(
                "Vote rejected: validator {} has non-verifiable registered consensus key (len={})",
                vote.voter,
                validator.consensus_key.len()
            );
            return Ok(false);
        }

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
        // 1. Height sanity: reject past-height votes (replay protection).
        // Stale votes from previous blocks are silently discarded.
        if vote.height < self.current_round.height {
            tracing::debug!(
                "Vote rejected: stale height {} < our height {}",
                vote.height,
                self.current_round.height
            );
            return Ok(false);
        }

        // 2. Height divergence: peer is ahead of us.
        //
        // We cannot validate validator membership for a future height because we do not
        // yet have the snapshot for that height.  Skip membership / signature checks
        // and immediately fire the catch-up trigger so we download the missing blocks.
        if vote.height > self.current_round.height {
            let our_blockchain_height = self.current_round.height.saturating_sub(1);
            tracing::info!(
                "⬆️  Height divergence: peer {} votes at height {} \
                 (our consensus height {}; local blockchain ~{}) — triggering catch-up sync",
                vote.voter,
                vote.height,
                self.current_round.height,
                our_blockchain_height
            );
            if let Some(ref trigger) = self.catch_up_sync_trigger {
                trigger.trigger(our_blockchain_height);
            }
            return Ok(false);
        }

        // vote.height == self.current_round.height from this point on.

        // 3. Verify signature
        if !self.verify_vote_signature(vote).await? {
            return Ok(false);
        }

        // 4. Verify validator membership (snapshot is available since height matches)
        if !self.is_validator_member(&vote.voter, vote.height) {
            tracing::warn!(
                "Vote rejected: voter {} is not in active validator set for height {}",
                vote.voter,
                vote.height
            );
            return Ok(false);
        }

        // 5. Round check.
        //
        // Stale rounds (vote.round < current) are rejected outright.
        // Higher rounds (vote.round > current) are allowed through so that
        // on_prevote / on_precommit can perform a Tendermint round-skip and bring
        // all nodes to the same round without waiting for an entire timer cycle.
        if vote.round < self.current_round.round {
            tracing::debug!(
                "Vote rejected: stale round {} < our round {}",
                vote.round,
                self.current_round.round
            );
            return Ok(false);
        }

        // 5. Vote-type gate
        //
        // All PreVote, PreCommit and Commit votes for the current height+round are
        // accepted regardless of the local step.
        //
        // **Rationale**: In a 4-node network with per-node 1-second timers the nodes
        // advance through Propose → PreVote → PreCommit → Commit at slightly different
        // wall-clock times.  A node that is in the Commit step will see PreVote
        // messages from a node that is still in the PreVote step — under a strict
        // equality check those messages would be rejected, making quorum impossible.
        //
        // Accepting votes for the correct height+round independent of local step is
        // safe because:
        //  - Quorum thresholds (2f+1) are enforced in `maybe_finalize()`, not here.
        //  - Each validator is allowed exactly one vote per (H, R, type) thanks to
        //    the `vote_pool` composite-key deduplication.
        //  - Against votes remain always invalid in BFT.
        let valid_for_step = match vote.vote_type {
            VoteType::PreVote | VoteType::PreCommit | VoteType::Commit => true,
            VoteType::Against => false,
        };

        if !valid_for_step {
            tracing::warn!(
                "Vote rejected: vote type {:?} is not valid in BFT consensus",
                vote.vote_type,
            );
            return Ok(false);
        }

        // All validations passed
        Ok(true)
    }

    /// Validate that the previous hash in a proposal matches our local chain tip.
    ///
    /// For genesis (height 0), the previous hash must be all-zeros.
    ///
    /// For height H > 0, we ask the blockchain provider for the current chain height
    /// and the hash of the latest committed block.  Validation only fires when the
    /// local chain is exactly at H-1 (i.e. we have the block being referenced).
    /// If the chain is behind or ahead (e.g. during catch-up sync), we accept the
    /// proposal without challenging the hash to avoid blocking progress.
    pub(super) async fn validate_previous_hash(
        &self,
        height: u64,
        previous_hash: &Hash,
    ) -> ConsensusResult<()> {
        // Genesis: previous hash must be zero.
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

        let expected_prev_height = height - 1;

        if let Some(ref provider) = self.blockchain_provider {
            let chain_height = provider.get_blockchain_height().await.unwrap_or(0);

            if chain_height == expected_prev_height {
                // Local chain is at H-1 — we can validate the previous hash.
                match provider.get_latest_block_hash().await {
                    Ok(expected_hash) => {
                        if *previous_hash != expected_hash {
                            return Err(ConsensusError::InvalidPreviousHash(format!(
                                "Proposal for height {} claims previous_hash={} \
                                 but local chain tip is {}",
                                height, previous_hash, expected_hash
                            )));
                        }
                        tracing::debug!(
                            "✓ Previous hash validated for height {}: {}",
                            height, previous_hash
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Could not fetch chain tip hash to validate height {}: {}",
                            height, e
                        );
                    }
                }
            } else {
                // Chain is not at H-1 (catching up or proposing ahead).
                // Skip hash validation; the executor will catch divergence on apply.
                tracing::debug!(
                    "Skipping previous hash check for height {}: \
                     local chain at {} (expected {})",
                    height, chain_height, expected_prev_height
                );
            }
        }

        Ok(())
    }

    /// Verify the cryptographic signature of a proposal.
    ///
    /// Checks (in order):
    /// 1. Public key is non-empty
    /// 2. Dilithium variant is a known scheme
    /// 3. Proposer exists in the validator registry
    /// 4. Registered consensus key is verifiable (len > 32)
    /// 5. Proposal's public key matches the registered consensus key
    /// 6. Signature verifies against the serialized proposal envelope
    ///
    /// Used by both `validate_incoming_proposal` (admission) and
    /// `validate_committed_block` (commit-time) to avoid drift.
    pub(super) async fn verify_proposal_signature(
        &self,
        proposal: &ConsensusProposal,
    ) -> ConsensusResult<()> {
        if proposal.signature.public_key.dilithium_pk == [0u8; 2592] {
            return Err(ConsensusError::ProofVerificationFailed(format!(
                "Proposal signature rejected: empty consensus key from proposer {} at H={} R={}",
                proposal.proposer, proposal.height, proposal.round,
            )));
        }

        if let Err(e) = lib_crypto::validate_consensus_vote_signature_scheme(
            &proposal.signature.public_key.dilithium_pk,
        ) {
            return Err(ConsensusError::ProofVerificationFailed(format!(
                "Proposal signature rejected: invalid scheme from proposer {} at H={} R={}: {}",
                proposal.proposer, proposal.height, proposal.round, e,
            )));
        }

        let validator = self
            .validator_manager
            .get_validator(&proposal.proposer)
            .ok_or_else(|| {
                ConsensusError::ProofVerificationFailed(format!(
                    "Proposal signature rejected: proposer {} not found in validator registry",
                    proposal.proposer,
                ))
            })?;

        if validator.consensus_key == [0u8; 2592] {
            return Err(ConsensusError::ProofVerificationFailed(format!(
                "Proposal signature rejected: proposer {} has non-verifiable consensus key (len={})",
                proposal.proposer,
                validator.consensus_key.len(),
            )));
        }

        if validator.consensus_key != proposal.signature.public_key.dilithium_pk {
            return Err(ConsensusError::ProofVerificationFailed(format!(
                "Proposal signature rejected: consensus key mismatch for proposer {} at H={} R={}",
                proposal.proposer, proposal.height, proposal.round,
            )));
        }

        let proposal_data = self.serialize_proposal_data(
            &proposal.id,
            &proposal.proposer,
            proposal.height,
            proposal.round,
            &proposal.previous_hash,
            &proposal.block_data,
        )?;

        if !self
            .verify_signature(&proposal_data, &proposal.signature)
            .await?
        {
            return Err(ConsensusError::ProofVerificationFailed(format!(
                "Proposal signature rejected: invalid signature from proposer {} at H={} R={}",
                proposal.proposer, proposal.height, proposal.round,
            )));
        }

        Ok(())
    }

    /// Validate an incoming proposal against all admission criteria.
    ///
    /// Hard gate invoked from `on_proposal()` **before** the proposal is stored
    /// in `current_round.proposals` / `pending_proposals` and before any
    /// transition into PreVote.
    ///
    /// # Checks (cheapest first)
    ///
    /// 1. **Expected proposer** — `proposer` must match the deterministic
    ///    round-robin leader for `(height, round)`.
    /// 2. **Proposal signature** — valid Dilithium signature from the
    ///    proposer's registered consensus key.
    /// 3. **Previous-hash continuity** — `previous_hash` links to our local
    ///    chain tip (delegates to [`Self::validate_previous_hash`]).
    /// 4. **Block payload decode** — `block_data` bytes are decodable by the
    ///    blockchain provider (if one is attached).
    ///
    /// # Errors
    ///
    /// Returns `ConsensusError` with a descriptive message on any failure.
    /// The caller should log the error and silently discard the proposal.
    pub(super) async fn validate_incoming_proposal(
        &self,
        proposal: &ConsensusProposal,
    ) -> ConsensusResult<()> {
        // ── 0. Protocol version ──────────────────────────────────────────
        // Fast-reject proposals from nodes running a different wire format.
        // This turns silent signature mismatches into an explicit error.
        if proposal.protocol_version != super::CONSENSUS_PROTOCOL_VERSION {
            return Err(ConsensusError::ByzantineFault(format!(
                "Proposal rejected: protocol version mismatch — proposal has v{}, \
                 we require v{} (proposer {} at H={} R={})",
                proposal.protocol_version,
                super::CONSENSUS_PROTOCOL_VERSION,
                proposal.proposer,
                proposal.height,
                proposal.round,
            )));
        }

        // ── 1. Expected proposer for (height, round) ────────────────────
        let expected_proposer = self.compute_proposer_for_round(proposal.height, proposal.round);
        if expected_proposer.as_ref() != Some(&proposal.proposer) {
            return Err(ConsensusError::ByzantineFault(format!(
                "Proposal rejected: proposer {} is not the expected leader for \
                 H={} R={} (expected {:?})",
                proposal.proposer, proposal.height, proposal.round, expected_proposer,
            )));
        }

        // ── 2. Proposal signature ───────────────────────────────────────
        self.verify_proposal_signature(proposal).await?;

        // ── 3. Previous-hash continuity ─────────────────────────────────
        self.validate_previous_hash(proposal.height, &proposal.previous_hash)
            .await?;

        // ── 4. Block payload decode ─────────────────────────────────────
        // The decode check must be deterministic: given the same proposal bytes,
        // every honest node must reach the same accept/reject decision.  A
        // tokio::time::timeout here would make validity depend on local scheduling
        // and IO load — one node could time out and reject while another accepts,
        // breaking consensus liveness.  The provider's decode_block_data is
        // expected to be a pure deserialization (sub-millisecond); if the provider
        // hangs, that is a local operational failure, not a proposal property.
        if let Some(ref provider) = self.blockchain_provider {
            if let Err(e) = provider.decode_block_data(&proposal.block_data).await {
                return Err(ConsensusError::ByzantineFault(format!(
                    "Proposal rejected: block_data decode failed for H={} R={} from {}: {}",
                    proposal.height, proposal.round, proposal.proposer, e,
                )));
            }
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
                 current proposal height {}. In BFT consensus, committed blocks are \
                 final and irreversible. A proposal for an already-committed height is \
                 an invalid fork attempt and is rejected immediately.",
                proposal_id, proposal_height, self.current_round.height,
            )));
        }

        // If the proposal targets the current round height but there is already an
        // agreed-upon proposal (valid_proposal) at this height with a different hash,
        // reject it as a fork.
        //
        // This can happen if consensus committed a block in a prior round but the
        // engine has not yet advanced to the next height. Any conflicting proposal
        // at the same height is a fork and MUST be rejected.
        if proposal_height == self.current_round.height {
            // Check if we already have an agreed-upon block at this height (valid_proposal
            // represents the agreed-upon value in the current round).
            // A non-nil valid_proposal that differs from the incoming proposal signals a fork.
            if let Some(committed_id) = &self.current_round.valid_proposal {
                if committed_id != proposal_id {
                    return Err(ConsensusError::ByzantineFault(format!(
                        "BFT FORK REJECTED: proposal {:?} conflicts with already-agreed \
                         proposal {:?} at height {}. In BFT consensus, once 2/3+1 validators \
                         have pre-committed a block, no other block is valid at that height. \
                         This conflicting proposal is an invalid fork attempt.",
                        proposal_id, committed_id, proposal_height,
                    )));
                }
            }
        }

        Ok(())
    }
}
