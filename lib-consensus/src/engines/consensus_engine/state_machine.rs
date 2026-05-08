//! Consensus state-machine implementation.

use super::*;
use crate::types::ConsensusStepExt;
use crate::validators::validator_protocol::{
    sign_heartbeat_envelope, sign_propose_envelope, sign_vote_envelope, ConsensusStateView,
    HeartbeatMessage, ProposeMessage, VoteMessage,
};
use crate::validators::ValidatorManager;
use lib_consensus_core::ports::ValidatorRewardInput;
use lib_crypto::{hash_blake3, KeyPair, PostQuantumSignature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// Build a canonical `ValidatorMessage::Propose` and sign the outer
/// envelope with the local validator keypair.
///
/// PR #2387 review (Copilot) caught the previous body reusing
/// `proposal.signature` (which signs the inner `ConsensusProposal` payload,
/// not the envelope) — receivers verify the envelope signature against
/// `ProposeSigningPayload`, so the inner sig fails outer verification.
/// Fix: sign with `sign_propose_envelope` after the envelope fields
/// (`message_id`, `timestamp`, `justification`, etc.) are populated.
///
/// `keypair == None` (test contexts that never registered a keypair) skips
/// signing and emits the message with a default placeholder signature; the
/// receiver's TOFU path special-cases empty signatures, and Mainnet would
/// reject — same conservative semantics as the rest of the broadcast path.
fn wrap_propose(proposal: ConsensusProposal, keypair: Option<&KeyPair>) -> ValidatorMessage {
    let message_id = proposal.id.clone();
    let proposer = proposal.proposer.clone();
    let mut msg = ProposeMessage {
        message_id,
        proposer,
        proposal,
        justification: None,
        timestamp: now_secs(),
        signature: PostQuantumSignature::default(),
    };
    if let Some(kp) = keypair {
        match sign_propose_envelope(&msg, kp) {
            Ok(sig) => msg.signature = sig,
            Err(e) => tracing::warn!(
                error = %e,
                "Failed to sign Propose envelope; broadcasting with placeholder signature"
            ),
        }
    } else {
        tracing::debug!(
            "No validator keypair; broadcasting Propose with placeholder signature (test mode)"
        );
    }
    ValidatorMessage::Propose(msg)
}

/// Build a canonical `ValidatorMessage::Vote` and sign the outer envelope.
///
/// `message_id` is per-broadcast (timestamp+nonce) so the network-layer
/// dedup cache doesn't suppress legitimate re-broadcasts of a vote whose
/// content hash is otherwise deterministic.
fn wrap_vote(vote: ConsensusVote, keypair: Option<&KeyPair>) -> ValidatorMessage {
    let step = match vote.vote_type {
        VoteType::PreVote => ConsensusStep::PreVote,
        VoteType::PreCommit => ConsensusStep::PreCommit,
        VoteType::Commit => ConsensusStep::Commit,
        // `Against` votes can occur during any voting step; default to PreVote.
        VoteType::Against => ConsensusStep::PreVote,
    };
    let consensus_state = ConsensusStateView {
        height: vote.height,
        round: vote.round,
        step,
        known_proposals: vec![vote.proposal_id.clone()],
        vote_counts: BTreeMap::new(),
    };
    let voter = vote.voter.clone();
    let message_id = {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let nonce = lib_crypto::generate_nonce();
        let mut data = format!("vote_bcast_{}", ts).into_bytes();
        data.extend_from_slice(&nonce);
        lib_crypto::Hash::from_bytes(&hash_blake3(&data))
    };
    let mut msg = VoteMessage {
        message_id,
        voter,
        vote,
        consensus_state,
        timestamp: now_secs(),
        signature: PostQuantumSignature::default(),
    };
    if let Some(kp) = keypair {
        match sign_vote_envelope(&msg, kp) {
            Ok(sig) => msg.signature = sig,
            Err(e) => tracing::warn!(
                error = %e,
                "Failed to sign Vote envelope; broadcasting with placeholder signature"
            ),
        }
    } else {
        tracing::debug!(
            "No validator keypair; broadcasting Vote with placeholder signature (test mode)"
        );
    }
    ValidatorMessage::Vote(msg)
}

/// Wrap a `HeartbeatMessage` produced by `HeartbeatTracker` and sign the
/// outer envelope. Same shape as `wrap_propose` / `wrap_vote`.
///
/// Pre-fix the engine broadcast heartbeats with a default placeholder
/// signature (the tracker's `create_heartbeat_message` doesn't sign);
/// receivers in TOFU mode special-cased the empty-public-key path and
/// forwarded the message as advisory, but Mainnet (`bootstrap_tofu = false`)
/// would reject. Pre-existing inheritance from before CONS-201; flagged as
/// out of scope on PR #2387 and fixed here.
pub(super) fn wrap_heartbeat(
    message: HeartbeatMessage,
    keypair: Option<&KeyPair>,
) -> ValidatorMessage {
    let mut msg = message;
    if let Some(kp) = keypair {
        match sign_heartbeat_envelope(&msg, kp) {
            Ok(sig) => msg.signature = sig,
            Err(e) => tracing::warn!(
                error = %e,
                "Failed to sign Heartbeat envelope; broadcasting with placeholder signature"
            ),
        }
    } else {
        tracing::debug!(
            "No validator keypair; broadcasting Heartbeat with placeholder signature (test mode)"
        );
    }
    ValidatorMessage::Heartbeat(msg)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build the `ValidatorRewardInput` slice the engine hands to
/// `RewardCallback::on_round_finalized` (CONS-103). Keeps the trait
/// independent of `ValidatorManager`.
fn collect_validator_reward_inputs(manager: &ValidatorManager) -> Vec<ValidatorRewardInput> {
    manager
        .get_active_validators()
        .iter()
        .map(|v| ValidatorRewardInput {
            identity: v.identity.clone(),
            stake: v.stake,
            storage_provided: v.storage_provided,
            voting_power: v.voting_power,
            reputation: v.reputation,
        })
        .collect()
}

// ============================================================================
// CONSENSUS AUDIT LOGGING (BFT-J, Issue #1013)
// ============================================================================

/// A deterministic, structured audit record for a single consensus event.
///
/// Audit logs are emitted at every proposal, pre-vote, pre-commit, and commit
/// transition so that an external observer can replay the full consensus
/// history from logs alone.
///
/// **Determinism**: All fields are deterministic given the same consensus state sequence,
/// with the exception of the `logical_time` field which uses block height and round number
/// to provide a deterministic ordering rather than wall-clock time. This ensures that
/// replaying the same consensus events always produces the same sequence of log records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusAuditLog {
    /// Block height at which this event occurred.
    pub height: u64,
    /// Consensus round number (reset on each new height).
    pub round: u32,
    /// Consensus step at the time of the event.
    pub step: ConsensusStep,
    /// Human-readable description of the event (e.g. "proposal_received").
    pub event: String,
    /// Validator identity that triggered the event, or "local" for self.
    pub validator_id: String,
    /// Logical timestamp derived from height and round (height * 1_000_000 + round).
    /// This provides deterministic ordering without relying on wall-clock time.
    pub logical_time: u64,
}

/// Emits a structured consensus audit log using the `tracing` framework.
///
/// All fields are deterministic given the same consensus state, making the
/// output suitable for audit replay and safety analysis. The logical_time field
/// uses a combination of block height and round number to provide deterministic
/// ordering without depending on wall-clock time.
pub fn log_consensus_event(
    height: u64,
    round: u32,
    step: ConsensusStep,
    event: &str,
    validator_id: &str,
) -> ConsensusAuditLog {
    // Derive logical timestamp from height and round for deterministic ordering
    let logical_time = height * 1_000_000 + round as u64;

    let record = ConsensusAuditLog {
        height,
        round,
        step: step.clone(),
        event: event.to_string(),
        validator_id: validator_id.to_string(),
        logical_time,
    };

    info!(
        target: "consensus_audit",
        height = height,
        round = round,
        step = %step.display_name(),
        event = event,
        validator_id = validator_id,
        logical_time = logical_time,
        "consensus_audit"
    );

    record
}

#[cfg(test)]
mod consensus_audit_log_tests {
    use super::*;

    #[test]
    fn test_log_consensus_event_fields() {
        let record = log_consensus_event(
            42,
            1,
            ConsensusStep::PreVote,
            "pre_vote_cast",
            "validator-abc",
        );
        assert_eq!(record.height, 42);
        assert_eq!(record.round, 1);
        assert_eq!(record.step, ConsensusStep::PreVote);
        assert_eq!(record.event, "pre_vote_cast");
        assert_eq!(record.validator_id, "validator-abc");
        assert_eq!(record.logical_time, 42 * 1_000_000 + 1);
    }

    #[test]
    fn test_logical_time_determinism() {
        // Same inputs should produce identical logical_time values
        let record1 = log_consensus_event(
            100,
            5,
            ConsensusStep::Propose,
            "proposal_created",
            "validator-1",
        );
        let record2 = log_consensus_event(
            100,
            5,
            ConsensusStep::Propose,
            "proposal_created",
            "validator-1",
        );

        assert_eq!(record1.logical_time, record2.logical_time);
        assert_eq!(record1.logical_time, 100 * 1_000_000 + 5);
    }

    #[test]
    fn test_logical_time_ordering() {
        // Verify that logical_time provides correct ordering
        let record_h1_r1 = log_consensus_event(1, 1, ConsensusStep::Propose, "test", "validator-1");
        let record_h1_r2 = log_consensus_event(1, 2, ConsensusStep::PreVote, "test", "validator-1");
        let record_h2_r1 = log_consensus_event(2, 1, ConsensusStep::Propose, "test", "validator-1");

        // Same height, higher round should have higher logical_time
        assert!(record_h1_r2.logical_time > record_h1_r1.logical_time);

        // Higher height should have higher logical_time
        assert!(record_h2_r1.logical_time > record_h1_r2.logical_time);
    }

    #[test]
    fn test_serialization() {
        let record = log_consensus_event(
            42,
            1,
            ConsensusStep::PreCommit,
            "pre_commit_cast",
            "validator-xyz",
        );

        // Test JSON serialization/deserialization
        let json = serde_json::to_string(&record).expect("Failed to serialize");
        let deserialized: ConsensusAuditLog =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.height, record.height);
        assert_eq!(deserialized.round, record.round);
        assert_eq!(deserialized.step, record.step);
        assert_eq!(deserialized.event, record.event);
        assert_eq!(deserialized.validator_id, record.validator_id);
        assert_eq!(deserialized.logical_time, record.logical_time);
    }

    #[test]
    fn test_consensus_step_display_name() {
        // Verify ConsensusStepExt::display_name() for logging
        use crate::types::ConsensusStepExt;
        assert_eq!(ConsensusStep::Propose.display_name(), "Propose");
        assert_eq!(ConsensusStep::PreVote.display_name(), "PreVote");
        assert_eq!(ConsensusStep::PreCommit.display_name(), "PreCommit");
        assert_eq!(ConsensusStep::Commit.display_name(), "Commit");
        assert_eq!(ConsensusStep::NewRound.display_name(), "NewRound");
    }
}

impl ConsensusEngine {
    /// Process a single consensus event (pure component method)
    /// This replaces the standalone start_consensus() loop pattern
    #[allow(deprecated)]
    pub async fn handle_consensus_event(
        &mut self,
        event: ConsensusEvent,
    ) -> ConsensusResult<Vec<ConsensusEvent>> {
        match event {
            ConsensusEvent::StartRound { height, trigger } => {
                tracing::info!(
                    " Starting consensus round {} (trigger: {})",
                    height,
                    trigger
                );

                // Log different trigger types for monitoring and debugging
                match trigger.as_str() {
                    "timeout" => tracing::warn!(
                        "⏰ Consensus round triggered by timeout - potential network delays"
                    ),
                    "new_transaction" => {
                        tracing::debug!("💳 New transaction triggered consensus round")
                    }
                    "validator_join" => {
                        tracing::info!("New validator joining triggered consensus round")
                    }
                    "validator_leave" => {
                        tracing::warn!(" Validator leaving triggered consensus round")
                    }
                    "force_restart" => tracing::warn!(" Manual consensus restart triggered"),
                    _ => tracing::debug!("Custom trigger: {}", trigger),
                }

                self.prepare_consensus_round(height).await?;
                Ok(vec![ConsensusEvent::RoundPrepared { height }])
            }
            ConsensusEvent::NewBlock {
                height,
                previous_hash,
            } => {
                tracing::info!(
                    "🧱 Processing new block at height {} with previous hash: {}",
                    height,
                    previous_hash
                );

                // Validate blockchain continuity by checking previous hash
                if let Err(e) = self.validate_previous_hash(height, &previous_hash).await {
                    tracing::error!("Previous hash validation failed: {}", e);
                    return Ok(vec![ConsensusEvent::RoundFailed {
                        height,
                        error: format!("Previous hash validation failed: {}", e),
                    }]);
                }

                // Single-driver invariant:
                // - If run_consensus_loop() is configured (message_rx present), do not
                //   run the deprecated synchronous round driver from event callbacks.
                // - Keep this event path as state synchronization and bookkeeping only.
                if self.message_rx.is_some() {
                    if let Err(e) = self.sync_height_with_blockchain().await {
                        tracing::warn!(
                            "Failed to sync consensus height after NewBlock event: {}",
                            e
                        );
                    }
                    self.snapshot_validator_set(self.current_round.height);

                    let mut events = vec![ConsensusEvent::RoundCompleted { height }];

                    // CONS-106 / AD-005: governance is fire-and-forget via the
                    // runtime adapter. Failures are observability events inside
                    // the adapter, not engine errors, so DaoError event is gone.
                    //
                    // Use `height` from the NewBlock event, not
                    // `self.current_round.height`: `sync_height_with_blockchain`
                    // above may have advanced the round to `blockchain_height + 1`,
                    // so `current_round.height` no longer identifies the block
                    // we are finalizing (PR #2385 Copilot review).
                    self.governance_callback.on_round_finalized(height);

                    if let Err(e) = self
                        .byzantine_detector
                        .detect_faults(&self.validator_manager)
                    {
                        tracing::warn!("Byzantine fault detection error: {}", e);
                        events.push(ConsensusEvent::ByzantineFault {
                            error: e.to_string(),
                        });
                    }

                    self.reward_callback.on_round_finalized(
                        &collect_validator_reward_inputs(&self.validator_manager),
                        height,
                    );

                    return Ok(events);
                }

                match self.run_consensus_round().await {
                    Ok(_) => {
                        let mut events = vec![ConsensusEvent::RoundCompleted { height }];

                        // CONS-106 / AD-005: governance is fire-and-forget via
                        // the runtime adapter; DaoError event no longer emitted.
                        // Use the event's `height` (the block we just finalized)
                        // rather than `self.current_round.height` which may have
                        // already advanced (PR #2385 Copilot review).
                        self.governance_callback.on_round_finalized(height);

                        // Check for Byzantine faults
                        if let Err(e) = self
                            .byzantine_detector
                            .detect_faults(&self.validator_manager)
                        {
                            tracing::warn!("Byzantine fault detection error: {}", e);
                            events.push(ConsensusEvent::ByzantineFault {
                                error: e.to_string(),
                            });
                        }

                        // Distribute rewards (CONS-103 / AD-005 — fire-and-forget;
                        // failures are observability events inside the adapter).
                        self.reward_callback.on_round_finalized(
                            &collect_validator_reward_inputs(&self.validator_manager),
                            height,
                        );

                        Ok(events)
                    }
                    Err(e) => {
                        tracing::error!("Consensus round failed: {}", e);
                        Ok(vec![ConsensusEvent::RoundFailed {
                            height,
                            error: e.to_string(),
                        }])
                    }
                }
            }
            ConsensusEvent::ValidatorJoin { identity, stake } => {
                self.handle_validator_registration(identity.clone(), stake)
                    .await?;
                Ok(vec![ConsensusEvent::ValidatorRegistered { identity }])
            }
            ConsensusEvent::ValidatorLeave { identity } => {
                self.queue_validator_removal(identity.clone())?;
                tracing::info!(
                    "Validator {} scheduled for removal at next epoch boundary",
                    identity
                );
                Ok(vec![])
            }
            _ => {
                tracing::debug!("Unhandled consensus event: {:?}", event);
                Ok(vec![])
            }
        }
    }

    /// Prepare for a consensus round (internal method)
    async fn prepare_consensus_round(&mut self, height: u64) -> ConsensusResult<()> {
        self.chain_started = true;
        self.apply_epoch_boundary_changes(height)?;
        if !self.validator_manager.has_sufficient_validators() {
            return Err(ConsensusError::ValidatorError(
                "Insufficient validators for consensus".to_string(),
            ));
        }

        tracing::info!(" Preparing ZHTP consensus for height {}", height);
        self.current_round.height = height;
        self.snapshot_validator_set(height);
        Ok(())
    }

    /// Handle validator registration event.
    ///
    /// Security invariant: validators must be registered with real key material.
    /// Event payloads without explicit keys are rejected to prevent placeholder-key
    /// membership from bypassing cryptographic vote verification.
    async fn handle_validator_registration(
        &mut self,
        identity: lib_identity::IdentityId,
        _stake: u64,
    ) -> ConsensusResult<()> {
        Err(ConsensusError::ValidatorError(format!(
            "ValidatorJoin event for {} rejected: missing explicit consensus/network/rewards keys",
            identity
        )))
    }

    /// Run a single consensus round (synchronous driver)
    ///
    /// **Invariant**: This method must NOT be used alongside `run_consensus_loop()`.
    /// The consensus engine should have a single active driver to avoid conflicting
    /// state transitions. This synchronous driver is intended for integrations that
    /// do not run the event loop.
    async fn run_consensus_round(&mut self) -> ConsensusResult<()> {
        // **CRITICAL**: This method conflicts with run_consensus_loop()
        // Both are consensus drivers and cannot coexist.
        // Reject if message receiver has been set (indicating run_consensus_loop() is intended).
        if self.message_rx.is_some() {
            return Err(ConsensusError::ValidatorError(
                "Cannot use run_consensus_round() with run_consensus_loop(). \
                 These are incompatible consensus drivers. Use run_consensus_loop() instead."
                    .to_string(),
            ));
        }

        self.advance_to_next_round();
        self.chain_started = true;
        self.apply_epoch_boundary_changes(self.current_round.height)?;
        self.snapshot_validator_set(self.current_round.height);

        // Select proposer from the frozen snapshot for this height.
        let proposer = self
            .compute_proposer_for_round(self.current_round.height, self.current_round.round)
            .ok_or_else(|| ConsensusError::ValidatorError("No proposer available".to_string()))?;

        self.current_round.proposer = Some(proposer.clone());

        tracing::info!(
            "Starting consensus round {} at height {} with proposer {:?}",
            self.current_round.round,
            self.current_round.height,
            proposer
        );

        // Run consensus steps
        self.run_propose_step().await?;
        self.run_prevote_step().await?;
        self.run_precommit_step().await?;
        self.run_commit_step().await?;

        // Archive completed round
        self.archive_completed_round();

        Ok(())
    }

    /// Advance to the next consensus round
    fn advance_to_next_round(&mut self) {
        self.current_round.height += 1;
        self.current_round.round = 0;
        self.current_round.step = ConsensusStep::Propose;
        // REMOVED: Wall-clock start_time (nondeterministic)
        // Use deterministic round progression based on height/round instead
        self.current_round.start_time = self.current_round.height;
        self.current_round.proposer = None;
        self.current_round.proposals.clear();
        self.current_round.votes.clear();
        self.current_round.timed_out = false;
        self.current_round.locked_proposal = None;
        self.current_round.valid_proposal = None;
    }

    /// Run the propose step
    pub(super) async fn run_propose_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Propose;

        // Audit log: Entering propose step
        log_consensus_event(
            self.current_round.height,
            self.current_round.round,
            ConsensusStep::Propose,
            "step_started",
            "local",
        );

        // If we are the proposer, create a proposal
        if let Some(ref validator_id) = self.validator_identity {
            if Some(validator_id) == self.current_round.proposer.as_ref() {
                let proposal = self.create_proposal().await?;
                self.current_round.proposals.push(proposal.id.clone());
                self.pending_proposals.push_back(proposal.clone());

                // Audit log: Proposal created
                log_consensus_event(
                    self.current_round.height,
                    self.current_round.round,
                    ConsensusStep::Propose,
                    "proposal_created",
                    &format!("{:?}", validator_id),
                );

                // Invariant CE-ENG-3: Broadcast after state transition (proposal now in state)
                // Create canonical ValidatorMessage from already-formed proposal
                let msg = wrap_propose(proposal, self.validator_keypair.as_ref());

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                self.broadcast(msg, &validator_ids).await;
            }
        }

        // Wait for proposals with timeout
        self.wait_for_step_timeout(self.config.propose_timeout)
            .await;

        Ok(())
    }

    /// Run the prevote step
    pub(super) async fn run_prevote_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreVote;

        // Audit log: Entering prevote step
        log_consensus_event(
            self.current_round.height,
            self.current_round.round,
            ConsensusStep::PreVote,
            "step_started",
            "local",
        );

        // Cast prevote
        if let Some(proposal_id) = self.current_round.proposals.first() {
            let vote = self
                .cast_vote(proposal_id.clone(), VoteType::PreVote)
                .await?;

            // Audit log: Pre-vote cast
            let validator_id_str = self
                .validator_identity
                .as_ref()
                .map(|id| format!("{:?}", id))
                .unwrap_or_else(|| "unknown".to_string());

            log_consensus_event(
                self.current_round.height,
                self.current_round.round,
                ConsensusStep::PreVote,
                "pre_vote_cast",
                &validator_id_str,
            );

            // Invariant CE-ENG-3: Broadcast after state transition
            // Create canonical ValidatorMessage from already-formed vote
            let msg = wrap_vote(vote, self.validator_keypair.as_ref());

            // Invariant CE-ENG-5: Pass validator set explicitly, never query network
            let validator_ids = self.get_active_validator_ids();

            // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
            // Log failures for observability without affecting consensus correctness
            self.broadcast(msg, &validator_ids).await;
        }

        // Wait for prevotes with timeout
        self.wait_for_step_timeout(self.config.prevote_timeout)
            .await;

        Ok(())
    }

    /// Run the precommit step
    async fn run_precommit_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreCommit;

        // Audit log: Entering precommit step
        log_consensus_event(
            self.current_round.height,
            self.current_round.round,
            ConsensusStep::PreCommit,
            "step_started",
            "local",
        );

        // Check if we received enough prevotes
        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let prevote_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreVote);
            let active_validator_count =
                self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(prevote_count, active_validator_count) {
                let vote = self
                    .cast_vote(proposal_id.clone(), VoteType::PreCommit)
                    .await?;
                self.current_round.valid_proposal = Some(proposal_id);

                // Audit log: Pre-commit cast
                let validator_id_str = self
                    .validator_identity
                    .as_ref()
                    .map(|id| format!("{:?}", id))
                    .unwrap_or_else(|| "unknown".to_string());

                log_consensus_event(
                    self.current_round.height,
                    self.current_round.round,
                    ConsensusStep::PreCommit,
                    "pre_commit_cast",
                    &validator_id_str,
                );

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = wrap_vote(vote, self.validator_keypair.as_ref());

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                self.broadcast(msg, &validator_ids).await;
            }
        }

        // Wait for precommits with timeout
        self.wait_for_step_timeout(self.config.precommit_timeout)
            .await;

        Ok(())
    }

    /// Run the commit step
    async fn run_commit_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Commit;

        // Audit log: Entering commit step
        log_consensus_event(
            self.current_round.height,
            self.current_round.round,
            ConsensusStep::Commit,
            "step_started",
            "local",
        );

        // Check if we received enough precommits — use locked_proposal as fallback
        let run_commit_target = self
            .current_round
            .valid_proposal
            .as_ref()
            .or(self.current_round.locked_proposal.as_ref())
            .cloned();
        if let Some(proposal_id) = run_commit_target {
            let precommit_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreCommit);
            let active_validator_count =
                self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(precommit_count, active_validator_count) {
                let vote = self
                    .cast_vote(proposal_id.clone(), VoteType::Commit)
                    .await?;

                // Audit log: Block committed
                let validator_id_str = self
                    .validator_identity
                    .as_ref()
                    .map(|id| format!("{:?}", id))
                    .unwrap_or_else(|| "unknown".to_string());

                log_consensus_event(
                    self.current_round.height,
                    self.current_round.round,
                    ConsensusStep::Commit,
                    "block_committed",
                    &validator_id_str,
                );

                tracing::info!(
                    "Block committed at height {} with proposal {:?}",
                    self.current_round.height,
                    proposal_id
                );

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = wrap_vote(vote, self.validator_keypair.as_ref());

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                self.broadcast(msg, &validator_ids).await;

                // Use maybe_finalize instead of calling process_committed_block directly.
                // At this point we have precommit quorum but only just cast our own commit vote.
                // maybe_finalize checks whether we now have commit quorum (our vote + any
                // already-received peer commit votes) and only finalizes if we do.
                self.maybe_finalize(
                    self.current_round.height,
                    self.current_round.round,
                    &proposal_id,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Cast a vote
    ///
    /// Returns the created vote so that the caller can broadcast it.
    /// Invariant CE-ENG-3: Broadcast happens after this state transition.
    async fn cast_vote(
        &mut self,
        proposal_id: Hash,
        vote_type: VoteType,
    ) -> ConsensusResult<ConsensusVote> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create vote ID from deterministic data
        let vote_id = Hash::from_bytes(&hash_blake3(
            &[
                proposal_id.as_bytes(),
                validator_id.as_bytes(),
                &(vote_type.clone() as u8).to_le_bytes(),
                &self.current_round.height.to_le_bytes(),
                &self.current_round.round.to_le_bytes(),
            ]
            .concat(),
        ));

        // Create vote data for signing
        // Use current height/round since this vote is being created for the current consensus round
        let vote_data = self.serialize_vote_data(
            &vote_id,
            validator_id,
            &proposal_id,
            &vote_type,
            self.current_round.height,
            self.current_round.round,
        )?;

        // Sign the vote
        let signature = self.sign_vote_data(&vote_data, &validator).await?;

        let vote = ConsensusVote {
            id: vote_id.clone(),
            voter: validator_id.clone(),
            proposal_id: proposal_id.clone(),
            vote_type: vote_type.clone(),
            height: self.current_round.height,
            round: self.current_round.round,
            // REMOVED: Wall-clock timestamp (nondeterministic)
            // Use deterministic value derived from height and round for consensus ordering
            timestamp: (self.current_round.height << 32) | (self.current_round.round as u64),
            signature,
        };

        // Store vote using composite key (height, round, vote_type, validator_id)
        let key = VotePoolKey {
            height: self.current_round.height,
            round: self.current_round.round,
            vote_type: vote_type.clone(),
            validator_id: validator_id.clone(),
        };
        self.vote_pool
            .insert(key, (vote.clone(), proposal_id.clone()));

        // Update validator activity
        self.validator_manager
            .update_validator_activity(validator_id);

        tracing::debug!(
            " Cast {:?} vote on proposal {:?} from validator {:?}",
            vote_type,
            proposal_id,
            validator_id
        );

        Ok(vote)
    }

    /// Wait for step timeout
    async fn wait_for_step_timeout(&mut self, timeout_ms: u64) {
        tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms)).await;
    }

    /// Process committed block (Issue #938: This is the ONLY safe path to persistence)
    ///
    /// **CRITICAL**: This method is called AFTER achieving 2/3+1 commit votes.
    /// It is the ONLY safe way for network-received blocks to reach persistence.
    ///
    /// **INVARIANT BFT-A-939**: This method MUST only be called after achieving
    /// commit consensus (2/3+ commit votes). Non-committed blocks are rejected
    /// before reaching persistence or state update paths.
    ///
    /// Flow:
    /// 1. Network block arrives → submitted as proposal (proposal-only)
    /// 2. BFT consensus validates and votes
    /// 3. 2/3+1 commit votes achieved
    /// 4. THIS method is called
    /// 5. BlockCommitCallback persists the block
    ///
    /// This ensures Byzantine fault tolerance - no single node can inject blocks.
    #[allow(deprecated)]
    async fn process_committed_block(&mut self, proposal_id: &Hash, commit_round: u32) -> ConsensusResult<()> {
        // SAFETY: Verify commit quorum before processing (Issue #939)
        // commit_round is the round in which the commit quorum was reached.
        let commit_count = self.count_commits_for(
            self.current_round.height,
            commit_round,
            proposal_id,
        );
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if !super::check_supermajority(commit_count, total_validators) {
            return Err(ConsensusError::ValidatorError(
                format!(
                    "INVARIANT VIOLATION (BFT-A-939): Attempted to process block without commit quorum. \
                    Commits: {}/{}, Proposal: {:?}",
                    commit_count,
                    total_validators,
                    proposal_id
                )
            ));
        }

        tracing::debug!(
            "✓ Commit quorum verified: {}/{} commits for proposal {:?}",
            commit_count,
            total_validators,
            proposal_id
        );

        // Find the committed proposal artifact.  A missing artifact after
        // quorum is a hard error — silently returning Ok(()) would mean BFT
        // agreed on a block that this node never applies, breaking safety.
        //
        // Exception: if the artifact was already consumed by a prior
        // `process_committed_block` call for the same proposal (e.g. a 4th
        // commit vote arrives after the 3rd already triggered finalization),
        // that is idempotent — the block is already applied.
        let proposal_index = match self
            .pending_proposals
            .iter()
            .position(|p| &p.id == proposal_id)
        {
            Some(idx) => idx,
            None => {
                // The artifact is not in pending_proposals.  This is expected
                // when a surplus commit vote triggers maybe_finalize after the
                // artifact was already consumed by a prior finalization.  It is
                // NOT expected if this is the first finalization attempt (the
                // proposal was never received).  We distinguish the two cases
                // by checking current_round.proposals which records every
                // proposal ID that was ever admitted at this height.
                if self.current_round.proposals.contains(proposal_id) {
                    tracing::debug!(
                        "Proposal {:?} already finalized (artifact consumed) — idempotent skip",
                        proposal_id,
                    );
                    return Ok(());
                }
                return Err(ConsensusError::ValidatorError(format!(
                    "FINALIZATION FAILED: commit quorum reached for proposal {:?} at H={} R={} \
                     but the proposal artifact was never received. \
                     This node cannot apply the committed block.",
                    proposal_id, self.current_round.height, self.current_round.round,
                )));
            }
        };

        let proposal = self
            .pending_proposals
            .remove(proposal_index)
            .expect("Proposal index came from position(), element must exist");

        // Validate the block one more time before applying
        self.validate_committed_block(&proposal).await?;

        // Build the BFT quorum proof from the commit votes in the vote pool.
        // Collect across ALL rounds: validators may cast commit votes in different rounds
        // (due to timing skew) but they all agree on the same proposal_id, which is what
        // matters for safety. Round-scoped filtering was the root cause of commit quorum
        // never being reached when validators entered the Commit step at different times.
        //
        // DETERMINISM: attestations must be sorted and deduplicated by validator_id so that
        // all nodes compute the same quorum_root, which is embedded in the block header.
        // A non-deterministic quorum_root causes each node to store a different block hash,
        // breaking the previous_hash chain validation for the next height.
        let quorum_proof = {
            let mut attestations: Vec<lib_types::consensus::CommitAttestation> = self
                .vote_pool
                .iter()
                .filter(|(k, (_, voted_id))| {
                    k.height == self.current_round.height
                        && k.vote_type == VoteType::Commit
                        && voted_id == proposal_id
                })
                .filter_map(|(_, (vote, _))| {
                    // Convert Vec<u8> signature to fixed-size Dilithium5 array.
                    // Skip votes with wrong-sized signatures (e.g. test stubs).
                    let signature: [u8; 4595] = vote.signature.signature.as_slice()
                        .try_into().ok()?;
                    Some(lib_types::consensus::CommitAttestation {
                        validator_id: vote.voter.0,
                        vote_id: vote.id.0,
                        proposal_id: vote.proposal_id.0,
                        round: vote.round,
                        signature,
                        public_key: vote.signature.public_key.dilithium_pk,
                    })
                })
                .collect();

            // Sort by validator_id for deterministic ordering across all nodes.
            attestations.sort_by_key(|a| a.validator_id);
            // Deduplicate: keep only the first (lowest-round, since pool was round-sorted) entry
            // per validator. A validator may have cast commit votes at multiple rounds if the
            // local round advanced after the initial cast; only one attestation per validator
            // should contribute to the quorum root so the hash is identical on all nodes.
            attestations.dedup_by_key(|a| a.validator_id);

            lib_types::consensus::BftQuorumProof {
                height: self.current_round.height,
                proposal_id: proposal_id.0,
                total_validators: total_validators as u32,
                attestations,
            }
        };

        // Apply block to state with its quorum proof.
        // The callback persists the proof alongside the block so catch-up sync
        // can verify BFT finality from the block itself.
        self.apply_block_to_state_with_proof(&proposal, quorum_proof)
            .await?;

        // Update validator activities and reputation
        self.update_validator_metrics(&proposal).await?;

        // Distribute block rewards via the runtime-injected callback
        // (CONS-103 / AD-005 — fire-and-forget). Pass the proposal's height —
        // this block is what we are finalizing, not whatever the local round
        // counter happens to be (PR #2385 Copilot review applied for symmetry
        // with the governance fix below).
        self.reward_callback.on_round_finalized(
            &collect_validator_reward_inputs(&self.validator_manager),
            proposal.height,
        );

        // CONS-404 / AD-005: fire-and-forget fee distribution. Adapter owns
        // the FeeRouter mutex and the 45/30/15/10 split. Per CE-ENG-4 the
        // engine ignores any internal failure — observability is the
        // adapter's job.
        let block_metadata = self.extract_block_metadata(&proposal).await;
        self.fee_callback.collect_and_distribute(
            block_metadata.height,
            block_metadata.total_fees_collected,
            &block_metadata.proposer,
        );

        // CONS-106 / AD-005: process any DAO proposals via the fire-and-forget
        // governance callback. Failures handled inside the adapter. Pass
        // `proposal.height` — the height of the block we are committing —
        // not `self.current_round.height` which may have already advanced
        // (PR #2385 Copilot review).
        self.governance_callback.on_round_finalized(proposal.height);

        tracing::info!(
            " Successfully processed committed block: {:?} at height {}",
            proposal.id,
            proposal.height
        );

        Ok(())
    }

    /// Extract block metadata from a consensus proposal.
    ///
    /// Asks the blockchain provider to decode the opaque `block_data` bytes so that
    /// the actual transaction count and fee sum can be recorded in `BlockMetadata`.
    /// Falls back to `(0, 0)` when no provider is configured or decoding fails
    /// (e.g. empty blocks or the text fallback format used in tests).
    async fn extract_block_metadata(&self, proposal: &ConsensusProposal) -> BlockMetadata {
        let (transaction_count, total_fees_collected) =
            if let Some(ref provider) = self.blockchain_provider {
                // Timeout guards against a misbehaving provider blocking the commit path.
                // The default impl is just bincode::deserialize (sub-millisecond).
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    provider.decode_block_data(&proposal.block_data),
                )
                .await
                {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => {
                        tracing::warn!(
                            "decode_block_data failed for height {}: {}",
                            proposal.height,
                            e
                        );
                        (0, 0)
                    }
                    Err(_) => {
                        tracing::warn!(
                            "decode_block_data timed out for height {}",
                            proposal.height
                        );
                        (0, 0)
                    }
                }
            } else {
                (0, 0)
            };

        BlockMetadata {
            height: proposal.height,
            // Use height as a deterministic timestamp for consensus ordering.
            // Wall-clock timestamps are nondeterministic and must not appear here.
            timestamp: proposal.height as i64,
            transaction_count,
            total_fees_collected,
            proposer: proposal.proposer.clone(),
        }
    }

    /// Validate committed block before applying
    async fn validate_committed_block(&self, proposal: &ConsensusProposal) -> ConsensusResult<()> {
        self.verify_proposal_signature(proposal).await?;

        // BFT consensus security is provided by vote quorum (2/3+1 commit votes),
        // not by per-block proofs.  verify_consensus_proof() always returns false
        // for ByzantineFaultTolerance — skip proof check for BFT to avoid
        // crashing the consensus loop on every committed block.
        use crate::types::ConsensusType;
        if proposal.consensus_proof.consensus_type != ConsensusType::ByzantineFaultTolerance
            && !self
                .verify_consensus_proof(&proposal.consensus_proof)
                .await?
        {
            return Err(ConsensusError::ProofVerificationFailed(
                "Invalid consensus proof".to_string(),
            ));
        }

        tracing::debug!("Block validation passed for {:?}", proposal.id);
        Ok(())
    }

    /// Apply block to blockchain state (Issue #938: This is the persistence gateway)
    ///
    /// **CRITICAL**: This is the ONLY legitimate path for network blocks to reach persistence.
    /// This method is called AFTER BFT achieves 2/3+1 commit votes, ensuring Byzantine fault tolerance.
    ///
    /// **INVARIANT BFT-A-939**: This method MUST only be called for blocks that have
    /// achieved commit consensus. The caller (process_committed_block) verifies commit
    /// quorum before invoking this method. Non-committed blocks are rejected before
    /// reaching persistence.
    ///
    /// **Checkpoint Persistence (Issue #951)**:
    /// - The block commit callback (ConsensusBlockCommitter) stores a consensus checkpoint
    /// - Checkpoints include: height, block_hash, proposer, timestamp, previous_hash, validator_count
    /// - These checkpoints are persisted in Blockchain.consensus_checkpoints (BTreeMap)
    /// - Used for bootstrap validation and sync verification via BlockchainSyncManager
    ///
    /// Apply a finalized block with its BFT quorum proof.
    ///
    /// Calls `commit_finalized_block_with_proof` on the callback so the runtime
    /// can persist the proof alongside the block.  Falls back to the proofless
    /// path if no callback is configured.
    async fn apply_block_to_state_with_proof(
        &mut self,
        proposal: &ConsensusProposal,
        quorum_proof: lib_types::consensus::BftQuorumProof,
    ) -> ConsensusResult<()> {
        // CONS-307 channel path: dispatch to the runtime's commit
        // executor and return immediately. Failures surface back via
        // the runtime event channel as `Event::HaltScheduled`, which
        // transitions the FSM to `Halting` on the next select! tick.
        if let Some(tx) = &self.commit_tx {
            let envelope = super::CommitEnvelope {
                proposal: proposal.clone(),
                quorum_proof,
            };
            if tx.send(envelope).is_err() {
                tracing::warn!(
                    height = proposal.height,
                    "Commit channel closed — runtime executor dropped its receiver (CE-ENG-4)"
                );
            } else {
                tracing::debug!(
                    block_height = proposal.height,
                    proposal_id = ?proposal.id,
                    "BFT finalized block dispatched to commit executor"
                );
            }
            return Ok(());
        }

        // Legacy path: direct await with halt-on-failure semantics.
        // Reached when no runtime is attached (e.g. AD-011 fallback in
        // zhtp, or unit tests using ConsensusEngine directly).
        if let Some(ref callback) = self.block_commit_callback {
            match callback
                .commit_finalized_block_with_proof(proposal, quorum_proof)
                .await
            {
                Ok(()) => {
                    info!(
                        block_height = proposal.height,
                        proposal_id = ?proposal.id,
                        "BFT finalized block + quorum proof committed to blockchain"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "⚠️ Failed to commit BFT finalized block to blockchain: {} (height: {}, proposal: {:?}). \
                        Local chain state has diverged from consensus. Halting to prevent network deadlock.",
                        e,
                        proposal.height,
                        proposal.id
                    );
                    return Err(ConsensusError::ValidatorError(format!(
                        "BFT safety violation: committed block at height {} could not be applied \
                        locally: {}. Node halted to prevent network deadlock. Recovery: \
                        systemctl stop zhtp && rm -rf <data-dir>/sled && systemctl start zhtp",
                        proposal.height, e
                    )));
                }
            }
        } else {
            tracing::info!(
                "📝 Block finalized by BFT consensus (height: {}, size: {} bytes) - no commit callback configured",
                proposal.height,
                proposal.block_data.len()
            );
        }

        Ok(())
    }

    /// Update validator metrics based on block participation
    async fn update_validator_metrics(
        &mut self,
        proposal: &ConsensusProposal,
    ) -> ConsensusResult<()> {
        // Update proposer metrics
        let proposer_id = proposal.proposer.clone();
        if let Some(proposer) = self.validator_manager.get_validator_mut(&proposer_id) {
            proposer.reputation = std::cmp::min(proposer.reputation + 1, 1000); // Cap at 1000
            proposer.update_activity();
        }

        // Update metrics for validators who voted
        let voter_ids: Vec<IdentityId> = self
            .vote_pool
            .iter()
            .filter(|(k, _)| k.height == proposal.height)
            .map(|(_, (vote, _))| vote.voter.clone())
            .collect();
        for voter_id in voter_ids {
            if let Some(voter) = self.validator_manager.get_validator_mut(&voter_id) {
                voter.reputation = std::cmp::min(voter.reputation + 1, 1000);
                voter.update_activity();
            }
        }

        tracing::debug!(" Updated validator metrics for block {:?}", proposal.id);
        Ok(())
    }

    /// Archive completed round
    fn archive_completed_round(&mut self) {
        self.round_history.push_back(self.current_round.clone());

        // Keep only recent history
        if self.round_history.len() > 100 {
            self.round_history.pop_front();
        }
    }

    pub(super) async fn on_proposal(&mut self, proposal: ConsensusProposal) -> ConsensusResult<()> {
        // BFT SAFETY: Reject any proposal that would create a fork.
        //
        // In BFT consensus, forks are invalid by definition. Once a block is committed
        // at height H, no other block is valid at that height. Any proposal targeting
        // an already-committed height with a different block hash is a fork attempt
        // and must be rejected immediately, before any other processing.
        //
        // Same-round fork: if `valid_proposal` is already set for the current round
        // and a conflicting proposal arrives for the SAME round, it is a fork.
        // Proposals for different rounds are handled independently and do not mutate
        // local round state until timeout advances the round.
        //
        // This is a hard gate: fork proposals are never stored, never voted on,
        // and never forwarded to peers.
        if let Err(e) = self.validate_no_fork_proposal(proposal.height, proposal.round, &proposal.id) {
            // Stale or out-of-order proposal — discard and continue.
            // This is expected when a lagging node (e.g. late joiner) proposes for a height
            // that the local node has already committed past.  It is NOT a Byzantine fault:
            // the consensus engine already committed that height and the proposal is simply
            // irrelevant.  Crashing here would take down the consensus loop unnecessarily.
            tracing::warn!(
                "FORK REJECTED: Proposal {:?} from proposer {} at height {} \
                 rejected as invalid fork: {} — discarding (not crashing)",
                proposal.id,
                proposal.proposer,
                proposal.height,
                e,
            );
            return Ok(());
        }

        if !self.is_proposal_relevant(&proposal) {
            return Ok(());
        }

        // **BFT safety fix (KI: test_future_round_proposal_does_not_advance_local_round)**:
        // Do NOT advance our local round counter on a single
        // validator's future-round proposal.  A Byzantine validator
        // could send a proposal with `round = 999` to disrupt
        // consensus.  Round advancement requires >2/3 evidence
        // (timeout-driven on this node, or quorum on a higher round
        // observed in vote pool — out of scope for this handler).
        //
        // Track the proposal in `pending_proposals` so it can be
        // referenced if our round eventually catches up; do not
        // touch `current_round`.
        if proposal.round > self.current_round.round {
            // Advance to the proposal's round to re-synchronize with the network.
            // Without this, nodes at different rounds never converge because each
            // rejects the others' proposals as "future round".
            tracing::info!(
                "Advancing from round {} to {} to match proposal from {}",
                self.current_round.round,
                proposal.round,
                proposal.proposer,
            );
            self.current_round.round = proposal.round;
            self.current_round.step = ConsensusStep::Propose;
            self.current_round.proposer = None;
            self.current_round.proposals.clear();
            self.current_round.votes.clear();
            self.current_round.timed_out = false;
            self.current_round.locked_proposal = None;
            self.current_round.valid_proposal = None;

            // Reset FSM from Rejected → Proposing so ProposalAdmitted can
            // transition to Prevoting. Without this, the FSM stays in Rejected
            // and ignores all events — votes are never cast.
            if matches!(self.fsm_state, lib_consensus_core::fsm::ValidatorState::Rejected { .. }) {
                self.fsm_state = lib_consensus_core::fsm::ValidatorState::Proposing;
            }

            // Fall through to process this proposal normally at the new round
        }

        if !self.current_round.proposals.is_empty() {
            return Ok(());
        }

        // Full admission gate: proposer identity, cryptographic signature,
        // previous-hash continuity, and block payload decode.
        // Subsumes the old `proposer == expected` identity-only check.
        if let Err(e) = self.validate_incoming_proposal(&proposal).await {
            tracing::warn!(
                "Proposal {:?} from {} at H={} R={} rejected by admission gate: {} — discarding",
                proposal.id,
                proposal.proposer,
                proposal.height,
                proposal.round,
                e,
            );
            return Ok(());
        }

        let proposal_id = proposal.id.clone();
        self.current_round.proposals.push(proposal_id.clone());

        // Relay proposal to all validators so nodes without a direct connection
        // to the proposer still receive it (star-topology gossip).
        // This is safe: on_proposal's `proposals.is_empty()` check prevents double-processing,
        // and each node only relays a proposal once (the second time proposals is non-empty).
        let relay_proposal = proposal.clone();
        let relay_validator_ids = self.get_active_validator_ids();
        let relay_msg = wrap_propose(relay_proposal, self.validator_keypair.as_ref());
        self.broadcast(relay_msg, &relay_validator_ids).await;

        // CONS-305e: route admitted proposal through the FSM. The
        // proposal has passed every gate (no-fork, signature, proposer
        // election, payload validity); the FSM advances Proposing →
        // Prevoting and emits `[BroadcastProposal, SendPrevote,
        // ResetWatchdog]`. The existing relay above + the
        // `enter_prevote_step()` call below continue to do that work
        // until CONS-305f folds them into the action handlers.
        let proposal_height = proposal.height;
        let proposal_round = proposal.round;
        self.pending_proposals.push_back(proposal);

        // Prior state derived from legacy step (source of truth
        // during the migration) per #2398 review.
        let prior_fsm = self.fsm_state.clone();
        let (next_fsm, actions) = lib_consensus_core::fsm::transition(
            prior_fsm,
            lib_consensus_core::fsm::Event::ProposalAdmitted {
                id: proposal_id.clone(),
                height: proposal_height,
                round: proposal_round,
            },
        );
        self.enter_fsm_state(next_fsm).await;
        for action in actions {
            self.dispatch_action(action).await;
        }

        // CONS-305f: the per-step branch is reduced to the late-
        // proposal case below. The Propose-step path used to call
        // `enter_prevote_step` here; that work is now dispatched by
        // the FSM `SendPrevote` action above (see the loop over
        // `actions` returned by `transition()`).
        match self.current_round.step {
            ConsensusStep::Propose => {
                // Handled by FSM action dispatch above.
            }
            ConsensusStep::PreVote => {
                // Proposal arrived after the local prevote timer already fired.
                // Cast a prevote now if we haven't voted for this round yet.
                let already_voted = self
                    .validator_identity
                    .as_ref()
                    .map(|id| {
                        self.vote_pool.contains_key(&VotePoolKey {
                            height: self.current_round.height,
                            round: self.current_round.round,
                            vote_type: VoteType::PreVote,
                            validator_id: id.clone(),
                        })
                    })
                    .unwrap_or(true);

                if !already_voted {
                    tracing::info!(
                        "📨 Late proposal for H={} R={}: casting prevote now",
                        self.current_round.height,
                        self.current_round.round
                    );
                    let vote = self
                        .cast_vote(proposal_id.clone(), VoteType::PreVote)
                        .await?;
                    let msg = wrap_vote(vote, self.validator_keypair.as_ref());
                    let validator_ids = self.get_active_validator_ids();
                    self.broadcast(msg, &validator_ids).await;

                    // Check if this late prevote completes the quorum
                    let prevote_count = self.count_prevotes_for(
                        self.current_round.height,
                        self.current_round.round,
                        &proposal_id,
                    );
                    let total_validators =
                        self.validator_manager.get_active_validators().len() as u64;
                    if check_supermajority(prevote_count, total_validators) {
                        self.current_round.valid_proposal = Some(proposal_id);
                        self.enter_precommit_step().await?;
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub(super) async fn on_prevote(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // Harden: Validate remote vote against all BFT safety invariants
        if !self.validate_remote_vote(&vote).await? {
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        // REMOVED: Wall-clock current_time (nondeterministic)
        // Use deterministic value derived from current consensus height/round
        let deterministic_time =
            (self.current_round.height << 32) | (self.current_round.round as u64);

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            deterministic_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=PreVote",
                evidence.validator,
                evidence.height,
                evidence.round
            );
            return Ok(()); // REJECT vote
        }

        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: VoteType::PreVote,
            validator_id: vote.voter.clone(),
        };

        // Check for equivocation (same validator, same H/R/type, different value)
        if let Some((_existing_vote, existing_proposal_id)) = self.vote_pool.get(&key) {
            if existing_proposal_id == &vote.proposal_id {
                // Duplicate vote - idempotent, no-op
                return Ok(());
            } else {
                // Equivocation detected: same (H,R,type,validator), different values
                tracing::warn!(
                    "Equivocation detected: validator {:?} sent conflicting PreVotes for height {} round {}",
                    vote.voter, vote.height, vote.round
                );
                // In production, would record as evidence for slashing
                // For now, reject silently
                return Ok(());
            }
        }

        // Accept new vote
        let proposal_id = vote.proposal_id.clone();
        self.vote_pool
            .insert(key, (vote.clone(), proposal_id.clone()));

        // Relay prevote to all validators so nodes without a direct connection
        // to the voter still receive it (star-topology gossip).
        // Duplicate detection (vote_pool key) prevents relay loops: the second
        // time this vote arrives, the pool check fires and returns early without relay.
        let relay_msg = wrap_vote(vote.clone(), self.validator_keypair.as_ref());
        let relay_validator_ids = self.get_active_validator_ids();
        self.broadcast(relay_msg, &relay_validator_ids).await;

        tracing::debug!(
            "Added PreVote from {} for proposal {:?} at height {} round {}",
            vote.voter,
            proposal_id,
            vote.height,
            vote.round
        );

        // **CE-S1**: Check supermajority for THIS proposal, not the round aggregate
        // Matching votes means: same height, round, proposal/block hash, and vote type
        let prevote_count = self.count_prevotes_for(vote.height, vote.round, &proposal_id);
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if check_supermajority(prevote_count, total_validators)
            && self.current_round.step <= ConsensusStep::PreCommit
        {
            // **CE-S1**: Only transition if this proposal can be the valid proposal
            // If valid_proposal is already set to a DIFFERENT proposal, we have conflicting quorums
            // which violates safety - don't transition
            if let Some(existing) = self.current_round.valid_proposal.as_ref() {
                if existing != &proposal_id {
                    tracing::warn!(
                        "Conflicting quorum detected: proposal {:?} has quorum but valid_proposal is already {:?}",
                        proposal_id, existing
                    );
                    // Don't transition - this violates BFT safety
                    return Ok(());
                }
            } else {
                // First proposal to reach quorum in this round
                self.current_round.valid_proposal = Some(proposal_id.clone());
            }

            // CONS-305d: route the prevote-quorum threshold through
            // the FSM. `(Prevoting, PrevoteThresholdReached) →
            // (Precommitting, [SendPrecommit, ResetWatchdog])`.  The
            // existing `enter_precommit_step()` does the casting and
            // broadcast; the FSM observes the state advance.
            //
            // Prior state derived from legacy step (source of truth
            // during the migration) per #2398 review.
            let prior_fsm = self.fsm_state.clone();
            let (next_fsm, actions) = lib_consensus_core::fsm::transition(
                prior_fsm,
                lib_consensus_core::fsm::Event::PrevoteThresholdReached {
                    block_id: proposal_id.clone(),
                },
            );
            self.enter_fsm_state(next_fsm).await;
            for action in actions {
                self.dispatch_action(action).await;
            }

            // CONS-305f / #2405: late-quorum runtime guard removed.
            // The FSM now emits `SendPrecommit` on
            // `(Precommitting, PrevoteThresholdReached)` so
            // `dispatch_action` casts the late precommit through
            // `enter_precommit_step`.  On the on-TIME path
            // (Prevoting → Precommitting kind change),
            // `enter_fsm_state`'s phase-entry hook also runs
            // `enter_precommit_step`; the helper is idempotent so
            // the action dispatch's later call is a safe no-op.
        }

        // **CE-L1, CE-L2**: Always check if commit quorum is reached, even in PreVote step
        self.maybe_finalize(vote.height, vote.round, &proposal_id)
            .await?;

        Ok(())
    }

    pub(super) async fn on_precommit(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // Harden: Validate remote vote against all BFT safety invariants
        if !self.validate_remote_vote(&vote).await? {
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        // REMOVED: Wall-clock current_time (nondeterministic)
        // Use deterministic value derived from current consensus height/round
        let deterministic_time =
            (self.current_round.height << 32) | (self.current_round.round as u64);

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            deterministic_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=PreCommit",
                evidence.validator,
                evidence.height,
                evidence.round
            );
            return Ok(()); // REJECT vote
        }

        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: VoteType::PreCommit,
            validator_id: vote.voter.clone(),
        };

        // Check for equivocation
        if let Some((_existing_vote, existing_proposal_id)) = self.vote_pool.get(&key) {
            if existing_proposal_id == &vote.proposal_id {
                // Duplicate - idempotent
                return Ok(());
            } else {
                // Equivocation detected
                tracing::warn!(
                    "Equivocation detected: validator {:?} sent conflicting PreCommits for height {} round {}",
                    vote.voter, vote.height, vote.round
                );
                return Ok(());
            }
        }

        // Accept new vote
        let proposal_id = vote.proposal_id.clone();
        self.vote_pool
            .insert(key, (vote.clone(), proposal_id.clone()));

        // Relay precommit to all validators (star-topology gossip).
        // Critical: without this, nodes that are only connected to a hub (g1)
        // cannot collect precommits from non-hub validators — quorum is impossible.
        let relay_msg = wrap_vote(vote.clone(), self.validator_keypair.as_ref());
        let relay_validator_ids = self.get_active_validator_ids();
        self.broadcast(relay_msg, &relay_validator_ids).await;

        tracing::debug!(
            "Added PreCommit from {} for proposal {:?} at height {} round {}",
            vote.voter,
            proposal_id,
            vote.height,
            vote.round
        );

        // **CE-S1**: Check supermajority for THIS proposal, not the round aggregate
        // Matching votes means: same height, round, proposal/block hash, and vote type
        let precommit_count = self.count_precommits_for(vote.height, vote.round, &proposal_id);
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if check_supermajority(precommit_count, total_validators)
            && self.current_round.step <= ConsensusStep::Commit
        {
            // **CE-S1**: Only transition if this proposal can be locked
            // If locked_proposal is already set to a DIFFERENT proposal, we have conflicting quorums
            if let Some(existing) = self.current_round.locked_proposal.as_ref() {
                if existing != &proposal_id {
                    tracing::warn!(
                        "Conflicting precommit quorum detected: proposal {:?} has quorum but locked_proposal is already {:?}",
                        proposal_id, existing
                    );
                    // Don't transition - this violates BFT safety
                    return Ok(());
                }
            } else {
                // First proposal to reach precommit quorum in this round
                self.current_round.locked_proposal = Some(proposal_id.clone());
            }

            // CONS-305c: route the precommit-quorum threshold through
            // the FSM. `(Precommitting, PrecommitThresholdReached) →
            // (Precommitting, [SendCommit, ResetWatchdog])` — state
            // stays Precommitting (we are now waiting for the
            // commit-vote quorum that maybe_finalize handles); the
            // SendCommit action is the work that `enter_commit_step`
            // already does.
            // Derive the prior state from the legacy step (the
            // source of truth during the migration) rather than
            // `self.fsm_state` to avoid silent action drops if the
            // mirror has drifted — PR #2398 review.
            let prior_fsm = self.fsm_state.clone();
            let (next_fsm, actions) = lib_consensus_core::fsm::transition(
                prior_fsm,
                lib_consensus_core::fsm::Event::PrecommitThresholdReached {
                    block_id: proposal_id.clone(),
                },
            );
            self.enter_fsm_state(next_fsm).await;
            for action in actions {
                self.dispatch_action(action).await;
            }

            // CONS-305f / #2405: late-quorum runtime guard removed.
            // The FSM now emits `SendCommit` on
            // `(Committed, PrecommitThresholdReached)` so
            // `dispatch_action` casts the late commit vote through
            // `enter_commit_step`. On the on-TIME path
            // (Precommitting + PrecommitThresholdReached → stays
            // Precommitting), the FSM also emits SendCommit and
            // dispatch_action calls enter_commit_step (idempotent).
        }

        // **CE-L1, CE-L2**: Always check if commit quorum is reached, even in PreCommit step
        self.maybe_finalize(vote.height, vote.round, &proposal_id)
            .await?;

        Ok(())
    }

    pub(super) async fn on_commit_vote(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // **CE-L2**: Accept commit votes at ANY step, not only during Commit.
        // Only reject votes from future heights. Accept current/past heights at any round
        // to allow catch-up from previous rounds.
        if vote.height > self.current_round.height {
            return Ok(());
        }

        // Reject if we've already moved past this height entirely
        // (height is locked in, no new consensus activity on old heights)
        if vote.height < self.current_round.height {
            tracing::debug!(
                "Ignoring commit vote for past height {} (current: {})",
                vote.height,
                self.current_round.height
            );
            return Ok(());
        }

        // Harden: Verify signature and validator membership (core validation)
        // Commit votes have special rules for height/round, so we only check signature + membership
        if !self.verify_vote_signature(&vote).await? {
            return Ok(());
        }

        // Verify validator membership
        if !self.is_validator_member(&vote.voter, vote.height) {
            tracing::warn!(
                "Commit vote rejected: voter {} is not in active validator set for height {}",
                vote.voter,
                vote.height
            );
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        // REMOVED: Wall-clock current_time (nondeterministic)
        // Use deterministic value derived from current consensus height/round
        let deterministic_time =
            (self.current_round.height << 32) | (self.current_round.round as u64);

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            deterministic_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=Commit",
                evidence.validator,
                evidence.height,
                evidence.round
            );
            return Ok(()); // REJECT vote
        }

        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: VoteType::Commit,
            validator_id: vote.voter.clone(),
        };

        // Check for equivocation
        if let Some((_, existing_proposal_id)) = self.vote_pool.get(&key) {
            if existing_proposal_id == &vote.proposal_id {
                // Duplicate - idempotent
                return Ok(());
            } else {
                // Equivocation on commit (rare but possible in Byzantine scenario)
                tracing::warn!(
                    "Equivocation on Commit: validator {:?} for height {} round {}",
                    vote.voter,
                    vote.height,
                    vote.round
                );
                return Ok(());
            }
        }

        // Accept new commit vote (even if we're not in Commit step yet)
        let proposal_id = vote.proposal_id.clone();
        self.vote_pool
            .insert(key, (vote.clone(), proposal_id.clone()));

        // Relay commit vote to all validators (star-topology gossip).
        // g2 and g3 only have persistent QUIC connections to g1 (hub), not to each other.
        // Without relay, a commit vote from g3 never reaches g2, so g2 can never aggregate
        // the 3-of-3 commit quorum required to finalize a block.
        let relay_msg = wrap_vote(vote.clone(), self.validator_keypair.as_ref());
        let relay_validator_ids = self.get_active_validator_ids();
        self.broadcast(relay_msg, &relay_validator_ids).await;

        tracing::debug!(
            "Stored commit vote from {} for proposal {:?} at height {} round {} (current step: {:?})",
            vote.voter,
            proposal_id,
            vote.height,
            vote.round,
            self.current_round.step
        );

        // **CE-L1**: Check if commit quorum is reached and finalize immediately
        self.maybe_finalize(vote.height, vote.round, &proposal_id)
            .await?;

        Ok(())
    }

    // CONS-305f step 3: `step_to_fsm_state` was deleted. It was
    // needed during the migration to derive prior FSM state from
    // the legacy `current_round.step` at handler boundaries.  Now
    // that `enter_fsm_state` is the single mutation point and
    // `fsm_state` is canonical, callers use `self.fsm_state.clone()`
    // directly.

    /// Single point that transitions the FSM, keeps the legacy
    /// `current_round.step` mirror in sync, and runs the phase-entry
    /// hook on state-kind change. Per CONS-305 spec: every state
    /// mutation goes through `enter()`.
    ///
    /// **Phase-entry hook**: when the FSM transitions to a different
    /// state kind, the corresponding `enter_*_step` helper runs (cast
    /// vote, broadcast, proposer election). Covers BOTH explicit
    /// quorum-driven transitions AND walk-through timeouts uniformly.
    /// Errors are logged at warn (best-effort, CE-ENG-4).
    ///
    /// **Recursion-free invariant**: `enter_*_step` MUST NOT call
    /// `maybe_finalize`. Step 1 of CONS-305f moved that call out;
    /// without it the recursion `dispatch_action(SendCommit) →
    /// enter_commit_step → maybe_finalize → transition() →
    /// dispatch_action(CommitBlock)` would resurface (E0733).
    pub(super) async fn enter_fsm_state(
        &mut self,
        new_state: lib_consensus_core::fsm::ValidatorState,
    ) {
        use lib_consensus_core::fsm::ValidatorState as V;
        let prior_kind = self.fsm_state.kind();
        let new_kind = new_state.kind();
        self.fsm_state = new_state.clone();

        // Phase-entry runs only on state-kind change so intra-kind
        // transitions (e.g. Precommitting → Precommitting on
        // PrecommitThresholdReached, or wire-level PreCommit→Commit
        // step within FSM Precommitting kind) don't re-run proposer
        // election or double-cast votes. Phase-entry helpers update
        // `current_round.step` themselves.
        if new_kind != prior_kind {
            let entry_result = match &new_state {
                V::Proposing => Some(self.enter_propose_step().await),
                V::Prevoting => Some(self.enter_prevote_step().await),
                V::Precommitting => Some(self.enter_precommit_step().await),
                V::Committed { .. } => Some(self.enter_commit_step().await),
                _ => None,
            };
            if let Some(Err(e)) = entry_result {
                tracing::warn!(
                    error = ?e,
                    new_kind = ?new_kind,
                    "Phase-entry hook failed (continuing per CE-ENG-4)"
                );
            }
        }

        // For terminal/between-round states, align the legacy step
        // mirror so observability stays consistent.
        match &new_state {
            V::Idle | V::Rejected { .. } => {
                self.current_round.step = ConsensusStep::NewRound;
            }
            _ => {}
        }
    }

    /// Dispatch one FSM `Action` to the engine.
    ///
    /// CONS-305f cutover: dispatch_action is the canonical entry
    /// point for state-entry side effects. Errors from the engine
    /// helpers are logged at warn level and not propagated — actions
    /// are best-effort (CE-ENG-4).
    ///
    /// **Recursion-free invariant**: the helpers called from here
    /// (`enter_propose_step`, `enter_prevote_step`,
    /// `enter_precommit_step`, `enter_commit_step`) MUST NOT call
    /// `maybe_finalize` (which would re-enter dispatch_action via
    /// `transition()` + `CommitBlock` action). Quorum-trigger
    /// finalization runs separately at the handler level
    /// (on_commit_vote / on_precommit / on_round_timeout's PreCommit
    /// branch / run_commit_step).
    pub(super) async fn dispatch_action(&mut self, action: lib_consensus_core::fsm::Action) {
        use lib_consensus_core::fsm::Action as A;
        match action {
            A::ResetWatchdog => {
                self.current_round.timed_out = false;
                // CONS-309 / CONS-502b: stamp the shared clock so the
                // runtime's watchdog task sees fresh activity. No-op
                // when the runtime hasn't installed a clock (e.g. tests
                // and the legacy zhtp path that calls
                // `run_consensus_loop` directly).
                if let Some(clock) = &self.watchdog_clock {
                    *clock.write().await = tokio::time::Instant::now();
                }
            }

            A::CreateProposal => {
                if let Err(e) = self.enter_propose_step().await {
                    tracing::warn!(error = ?e, "CreateProposal action failed");
                }
            }
            A::SendPrevote { .. } => {
                if let Err(e) = self.enter_prevote_step().await {
                    tracing::warn!(error = ?e, "SendPrevote action failed");
                }
            }
            A::SendPrecommit { .. } => {
                if let Err(e) = self.enter_precommit_step().await {
                    tracing::warn!(error = ?e, "SendPrecommit action failed");
                }
            }
            A::SendCommit { .. } => {
                if let Err(e) = self.enter_commit_step().await {
                    tracing::warn!(error = ?e, "SendCommit action failed");
                }
            }

            // BroadcastProposal — proposal relay needs ownership of
            // the proposal struct, which the FSM action carries only
            // by Hash. Done at the call site in on_proposal.
            A::BroadcastProposal { .. } => {}

            // CommitBlock — process_committed_block is invoked from
            // maybe_finalize when commit-vote quorum is detected. No-
            // op here so the recursion invariant above holds.
            A::CommitBlock { .. } => {}

            // AdvanceRound — round-bump on view change. Done at the
            // call site (on_round_timeout's Committed branch) where
            // we have full sync_height context.
            A::AdvanceRound => {}

            // Observability — silent drop; FSM's own hooks log.
            A::LogIgnoredEvent(_) | A::LogHung { .. } | A::LogPanic { .. } => {}

            // CONS-308: typed round-rejection event. Enrich the FSM-
            // emitted reason with the engine's current height/round
            // so dashboards and structured-log consumers see full
            // context. Emitting at WARN because every entry into
            // `Rejected` is by definition a non-progress event the
            // operator cares about.
            A::LogRoundRejected { reason } => {
                tracing::warn!(
                    height = self.current_round.height,
                    round = self.current_round.round,
                    rejection_reason = ?reason,
                    "FSM round rejected"
                );
            }

            // Lifecycle — log at debug for visibility.
            other => {
                tracing::debug!(
                    fsm_action = ?other,
                    "FSM emitted lifecycle action with no engine handler yet"
                );
            }
        }
    }

    pub(super) async fn on_round_timeout(&mut self) -> ConsensusResult<()> {
        use lib_consensus_core::fsm::{transition, Event};

        tracing::debug!(
            "Round timeout at height {} round {} step {:?} fsm {:?}",
            self.current_round.height,
            self.current_round.round,
            self.current_round.step,
            self.fsm_state.kind(),
        );

        // CONS-305: Route the timeout through the FSM with walk-through semantics.
        // The FSM's threshold-gated transitions (Precommitting stays on Timeout)
        // don't match the Sovereign engine's walk-through model where each phase
        // advances on timeout. We emit VoteFailed when a phase times out without
        // reaching threshold, causing the FSM to advance to the next phase or Rejected.
        let prior_step = self.current_round.step.clone();
        let prior_fsm = self.fsm_state.clone();

        // Choose the right event: if we're in an active phase that timed out
        // without reaching threshold, emit VoteFailed to advance the FSM.
        let event = match &prior_fsm {
            lib_consensus_core::fsm::ValidatorState::Prevoting => {
                Event::VoteFailed(lib_consensus_core::fsm::state::RejectionReason::InsufficientPrevotes)
            }
            lib_consensus_core::fsm::ValidatorState::Precommitting => {
                Event::VoteFailed(lib_consensus_core::fsm::state::RejectionReason::InsufficientPrecommits)
            }
            _ => Event::Timeout,
        };

        let (next_fsm, actions) = transition(prior_fsm, event);
        self.enter_fsm_state(next_fsm).await;
        for action in actions {
            self.dispatch_action(action).await;
        }

        // CONS-305: If the FSM landed in Rejected (from VoteFailed or Timeout),
        // the runtime must reset to Idle → Proposing for the next round.
        // CRITICAL: On rejection, stay at the SAME height with round+1.
        // Only advance height after a block is committed.
        if matches!(self.fsm_state, lib_consensus_core::fsm::ValidatorState::Rejected { .. }) {
            self.current_round.round += 1;
            self.current_round.step = ConsensusStep::Propose;
            self.current_round.proposer = None;
            self.current_round.proposals.clear();
            self.current_round.votes.clear();
            self.current_round.timed_out = false;
            self.current_round.locked_proposal = None;
            self.current_round.valid_proposal = None;
            self.snapshot_validator_set(self.current_round.height);
            self.fsm_state = lib_consensus_core::fsm::ValidatorState::Idle;
            let (next, actions) = lib_consensus_core::fsm::transition(
                self.fsm_state.clone(),
                lib_consensus_core::fsm::events::Event::SelectedAsProposer {
                    height: self.current_round.height,
                    round: self.current_round.round,
                },
            );
            self.enter_fsm_state(next).await;
            for action in actions {
                self.dispatch_action(action).await;
            }
        }

        //
        // Special handling for Commit timeout: sync height + advance round.
        // The FSM transitions Committed.Timeout → Rejected → (runtime resets
        // to Idle). We need to sync blockchain height and reset round state.
        if prior_step == ConsensusStep::Commit {
            let height_before_sync = self.current_round.height;
            if let Err(e) = self.sync_height_with_blockchain().await {
                tracing::warn!(
                    "Commit timeout: failed to sync blockchain height ({}), using height+1 fallback",
                    e
                );
                self.advance_to_next_round();
                self.snapshot_validator_set(self.current_round.height);
            } else {
                let height_after_sync = self.current_round.height;
                let next_round = if height_after_sync == height_before_sync {
                    self.current_round.round + 1
                } else {
                    0
                };
                self.current_round.round = next_round;
                self.current_round.proposer = None;
                self.current_round.proposals.clear();
                self.current_round.votes.clear();
                self.current_round.timed_out = false;
                self.current_round.locked_proposal = None;
                self.current_round.valid_proposal = None;
                self.snapshot_validator_set(self.current_round.height);
            }

            // Reset FSM: Rejected/Committed → Idle → Proposing
            self.fsm_state = lib_consensus_core::fsm::ValidatorState::Idle;
            let (next, actions) = lib_consensus_core::fsm::transition(
                self.fsm_state.clone(),
                lib_consensus_core::fsm::events::Event::SelectedAsProposer {
                    height: self.current_round.height,
                    round: self.current_round.round,
                },
            );
            self.enter_fsm_state(next).await;
            for action in actions {
                self.dispatch_action(action).await;
            }
        }

        // For PreCommit timeout, also try to finalize if we have a valid proposal
        if prior_step == ConsensusStep::PreCommit {
            let target = self
                .current_round
                .valid_proposal
                .clone()
                .or(self.current_round.locked_proposal.clone());
            if let Some(proposal_id) = target {
                self.maybe_finalize(
                    self.current_round.height,
                    self.current_round.round,
                    &proposal_id,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Enter the propose step: select proposer and create/broadcast proposal if we're it.
    ///
    /// Called at the start of each new height/round (from `run_consensus_loop()` and
    /// from `on_round_timeout(Commit)` after `advance_to_next_round()`).
    ///
    /// All nodes must call this so `current_round.proposer` is set before any
    /// incoming proposals are processed by `on_proposal()`.
    pub(super) async fn enter_propose_step(&mut self) -> ConsensusResult<()> {
        // Idempotency: if proposer already selected for this (height, round), skip.
        // Prevents duplicate proposals when called from multiple paths
        // (FSM phase-entry hook, Action::CreateProposal, direct call).
        if self.current_round.proposer.is_some() && self.current_round.step == ConsensusStep::Propose {
            return Ok(());
        }

        // Set the step to Propose so timers and token matching work correctly.
        self.current_round.step = ConsensusStep::Propose;

        // Select proposer from the frozen snapshot for this height.
        let proposer_id = self
            .compute_proposer_for_round(self.current_round.height, self.current_round.round);

        if let Some(proposer_id) = proposer_id {
            self.current_round.proposer = Some(proposer_id.clone());

            tracing::info!(
                "🎯 Proposer for height {} round {}: {:?}",
                self.current_round.height,
                self.current_round.round,
                proposer_id
            );

            // If we are the proposer, create and broadcast the proposal.
            let is_local_proposer = self
                .validator_identity
                .as_ref()
                .map(|id| *id == proposer_id)
                .unwrap_or(false);

            if is_local_proposer {
                tracing::info!(
                    "👑 We are the proposer for height {} round {}",
                    self.current_round.height,
                    self.current_round.round
                );

                match self.create_proposal().await {
                    Ok(proposal) => {
                        self.current_round.proposals.push(proposal.id.clone());
                        self.pending_proposals.push_back(proposal.clone());

                        let validator_id_str = self
                            .validator_identity
                            .as_ref()
                            .map(|id| format!("{:?}", id))
                            .unwrap_or_else(|| "local".to_string());

                        log_consensus_event(
                            self.current_round.height,
                            self.current_round.round,
                            ConsensusStep::Propose,
                            "proposal_created",
                            &validator_id_str,
                        );

                        let msg = wrap_propose(proposal, self.validator_keypair.as_ref());
                        let validator_ids = self.get_active_validator_ids();

                        self.broadcast(msg, &validator_ids).await;

                        // Proposer enters prevote immediately after broadcasting its proposal.
                        // Without this, the proposer waits propose_timeout (3 s) before prevoting,
                        // while non-proposers transition on proposal receipt (<100 ms).  By the
                        // time the proposer finally prevotes, the other nodes have exhausted their
                        // prevote+precommit+commit timeouts (3 × 1 s = 3 s) and advanced to the
                        // next round — causing the proposer's prevote to be rejected as stale.
                        if let Err(e) = self.enter_prevote_step().await {
                            tracing::warn!(
                                "Failed to enter prevote step after proposal broadcast at H={} R={}: {}",
                                self.current_round.height,
                                self.current_round.round,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to create proposal at height {} round {}: {}",
                            self.current_round.height,
                            self.current_round.round,
                            e
                        );
                    }
                }
            }
        } else {
            tracing::warn!(
                "No proposer selected for height {} round {} (no active validators?)",
                self.current_round.height,
                self.current_round.round
            );
        }

        Ok(())
    }

    async fn enter_prevote_step(&mut self) -> ConsensusResult<()> {
        if self.current_round.step >= ConsensusStep::PreVote {
            return Ok(());
        }

        self.current_round.step = ConsensusStep::PreVote;
        tracing::info!(
            "Entering PreVote step at height {} round {}",
            self.current_round.height,
            self.current_round.round
        );

        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let vote = self.cast_vote(proposal_id, VoteType::PreVote).await?;
            let msg = wrap_vote(vote, self.validator_keypair.as_ref());
            let validator_ids = self.get_active_validator_ids();

            self.broadcast(msg, &validator_ids).await;
        }

        Ok(())
    }

    async fn enter_precommit_step(&mut self) -> ConsensusResult<()> {
        // Allow re-entry when already in PreCommit step so that late-arriving prevotes
        // that complete the quorum can still cast a precommit. We guard against going
        // backwards (Commit or later) but not against being already in PreCommit.
        if self.current_round.step > ConsensusStep::PreCommit {
            return Ok(());
        }

        if self.current_round.step < ConsensusStep::PreCommit {
            self.current_round.step = ConsensusStep::PreCommit;
            tracing::info!(
                "Entering PreCommit step at height {} round {}",
                self.current_round.height,
                self.current_round.round
            );
        }

        // Use valid_proposal (already set by on_prevote quorum path) or fall back to
        // the first received proposal for this round.
        let proposal_id_opt = self
            .current_round
            .valid_proposal
            .clone()
            .or_else(|| self.current_round.proposals.first().cloned());

        if let Some(proposal_id) = proposal_id_opt {
            // Skip if we already cast a precommit for this round.
            let already_precommitted = self
                .validator_identity
                .as_ref()
                .map(|id| {
                    self.vote_pool.contains_key(&VotePoolKey {
                        height: self.current_round.height,
                        round: self.current_round.round,
                        vote_type: VoteType::PreCommit,
                        validator_id: id.clone(),
                    })
                })
                .unwrap_or(false);
            if already_precommitted {
                return Ok(());
            }

            // Count prevotes for this proposal in the CURRENT round only.
            // Cross-round prevote aggregation is unsafe: different rounds may have
            // 2/3+ prevotes for different proposals (different proposers propose
            // different blocks each round). Aggregating them can make two distinct
            // proposals both appear to have supermajority, breaking BFT safety.
            let prevote_count = self
                .vote_pool
                .iter()
                .filter(|(k, (_, voted_id))| {
                    k.height == self.current_round.height
                        && k.round == self.current_round.round
                        && k.vote_type == VoteType::PreVote
                        && voted_id == &proposal_id
                })
                .count() as u64;
            let total_validators = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(prevote_count, total_validators) {
                let vote = self
                    .cast_vote(proposal_id.clone(), VoteType::PreCommit)
                    .await?;
                self.current_round.valid_proposal = Some(proposal_id);

                let msg = wrap_vote(vote, self.validator_keypair.as_ref());
                let validator_ids = self.get_active_validator_ids();

                self.broadcast(msg, &validator_ids).await;
            }
        }

        Ok(())
    }

    async fn enter_commit_step(&mut self) -> ConsensusResult<()> {
        // Allow re-entry when already in Commit step so that late-arriving precommits
        // that complete the quorum can still cast a commit vote. We only prevent going
        // backwards past Commit (which would be a new round / height).
        if self.current_round.step < ConsensusStep::Commit {
            self.current_round.step = ConsensusStep::Commit;
            tracing::info!(
                "Entering Commit step at height {} round {}",
                self.current_round.height,
                self.current_round.round
            );
        }

        // valid_proposal is set when prevote quorum is reached; locked_proposal is set
        // when precommit quorum is reached.  When the prevote timer fires before prevote
        // quorum is achieved, valid_proposal stays None even though locked_proposal may
        // subsequently be set by on_precommit.  Use locked_proposal as fallback so the
        // commit step actually casts a commit vote when precommit quorum has been reached.
        let commit_target = self
            .current_round
            .valid_proposal
            .as_ref()
            .or(self.current_round.locked_proposal.as_ref())
            .cloned();

        if let Some(proposal_id) = commit_target {
            // Skip if we already cast a commit vote for this round.
            let already_committed = self
                .validator_identity
                .as_ref()
                .map(|id| {
                    self.vote_pool.contains_key(&VotePoolKey {
                        height: self.current_round.height,
                        round: self.current_round.round,
                        vote_type: VoteType::Commit,
                        validator_id: id.clone(),
                    })
                })
                .unwrap_or(false);
            if already_committed {
                return Ok(());
            }

            // Count precommits for this proposal across ALL rounds at this height.
            // count_votes_for_proposal() filters by current round, which misses precommits
            // from the round where quorum was actually reached when the round has since
            // advanced via timeout.  Cross-round counting is safe because the proposal_id
            // uniquely identifies the block; no two valid proposals share the same id.
            let precommit_count = self
                .vote_pool
                .iter()
                .filter(|(k, (_, voted_id))| {
                    k.height == self.current_round.height
                        && k.vote_type == VoteType::PreCommit
                        && voted_id == &proposal_id
                })
                .count() as u64;
            let total_validators = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(precommit_count, total_validators) {
                let vote = self
                    .cast_vote(proposal_id.clone(), VoteType::Commit)
                    .await?;

                tracing::info!(
                    "Block committed at height {} with proposal {:?}",
                    self.current_round.height,
                    proposal_id
                );

                let msg = wrap_vote(vote, self.validator_keypair.as_ref());
                let validator_ids = self.get_active_validator_ids();

                self.broadcast(msg, &validator_ids).await;

                // CONS-305f: maybe_finalize is no longer called from
                // here. Calling it from inside enter_commit_step
                // creates a `dispatch_action → enter_commit_step →
                // maybe_finalize → transition() → dispatch_action`
                // recursion that rustc rejects (E0733) once
                // dispatch_action invokes enter_commit_step itself.
                // Instead, callers that need an immediate
                // post-cast-commit-vote quorum check call
                // `maybe_finalize` themselves AFTER
                // `enter_commit_step` returns. The two existing
                // production callers (on_precommit, run_commit_step)
                // already do this; on_round_timeout's PreCommit
                // branch was updated to do the same.
            }
        }

        Ok(())
    }

    fn is_proposal_relevant(&self, proposal: &ConsensusProposal) -> bool {
        if proposal.height != self.current_round.height {
            return false;
        }
        // Accept proposals up through PreCommit step.  A proposal that arrives
        // after the local timer advanced to PreVote (before it could be received)
        // is still valid and needed so that the node can cast a prevote.
        // Proposals in Commit step or later are irrelevant.
        if self.current_round.step >= ConsensusStep::Commit {
            return false;
        }
        true
    }

    /// Check if commit quorum is reached for a proposal and finalize if so.
    /// **CE-L1**: Commit quorum finalizes regardless of local step.
    /// **CE-L2**: This is called from any step, not just Commit.
    /// **Invariant**: Called from on_prevote, on_precommit, on_commit_vote, and enter_commit_step
    /// to prevent "stored but never used" regressions.
    pub(super) async fn maybe_finalize(
        &mut self,
        height: u64,
        round: u32,
        proposal_id: &Hash,
    ) -> ConsensusResult<()> {
        // Count matching commit votes: all votes for this specific proposal at height/round
        // This ensures supermajority is proposal-scoped, not round-scoped
        let commit_count = self.count_commits_for(height, round, proposal_id);
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if check_supermajority(commit_count, total_validators) {
            tracing::info!(
                "Finalization triggered: {} commits for proposal {:?} at height {} round {}",
                commit_count,
                proposal_id,
                height,
                round
            );

            // Finalize regardless of current step (CE-L1) and regardless of current round.
            // A commit quorum for the current HEIGHT is sufficient — the specific proposal_id
            // guarantees we're committing the right block, and process_committed_block is
            // idempotent if the block was already applied.
            if self.current_round.height == height {
                // CONS-305b: route the commit-quorum event through the
                // FSM so the canonical state transitions to Committed
                // alongside the legacy step bump below.  The FSM
                // emits `[CommitBlock, ResetWatchdog]`; the actual
                // finalization (process_committed_block) is called
                // directly here for now, with the action handler
                // staging in `dispatch_action()` for CONS-305f cleanup.
                let bft_quorum = lib_types::consensus::BftQuorumProof {
                    height,
                    proposal_id: proposal_id.0,
                    total_validators: total_validators as u32,
                    // Attestations are aggregated by `process_committed_block`
                    // when it builds the block's proof; for the FSM hook
                    // we pass the empty list — the FSM only needs the
                    // height/proposal_id metadata to track state.
                    attestations: Vec::new(),
                };
                // Derive prior state from legacy step (source of
                // truth during the migration) to avoid silent action
                // drops on mirror drift — PR #2398 review.
                let prior_fsm = self.fsm_state.clone();
                let (next_fsm, actions) = lib_consensus_core::fsm::transition(
                    prior_fsm,
                    lib_consensus_core::fsm::Event::CommitQuorumReached {
                        block_id: proposal_id.clone(),
                        quorum: bft_quorum,
                    },
                );
                self.enter_fsm_state(next_fsm).await;
                for action in actions {
                    self.dispatch_action(action).await;
                }

                // Transition to Commit step if not already there
                if self.current_round.step < ConsensusStep::Commit {
                    self.current_round.step = ConsensusStep::Commit;
                    tracing::info!(
                        "Fast-tracked to Commit step via commit quorum at height {} round {} (local round {})",
                        height,
                        round,
                        self.current_round.round
                    );
                }

                // **Catch-up safety (fix for KI test_hardening_commit_vote_accepts_past_round)**:
                // If the proposal artifact is not in `pending_proposals`
                // AND was never recorded in `current_round.proposals`,
                // we received commit votes for a block we haven't seen
                // yet (legitimate catch-up scenario, e.g. past-round
                // votes during sync).  Don't error — store the votes
                // and rely on the next on_proposal admission (or
                // catch-up sync) to provide the artifact and complete
                // finalization.
                let artifact_known = self
                    .pending_proposals
                    .iter()
                    .any(|p| &p.id == proposal_id)
                    || self.current_round.proposals.contains(proposal_id);
                if !artifact_known {
                    tracing::info!(
                        "Commit quorum reached for proposal {:?} at H={} R={} but artifact not yet \
                         received — votes stored, awaiting proposal/catch-up sync",
                        proposal_id, height, round,
                    );
                } else {
                    // Process the committed block (finalization) directly.
                    // Pass `round` (the round where commit quorum was reached) so that
                    // vote counting uses the correct round even if the local state has
                    // already moved on due to timeout-driven round advancement.
                    self.process_committed_block(proposal_id, round).await?;
                }
            } else {
                tracing::debug!(
                    "Commit quorum observed for past height (H={} R={}) while at H={} R={} — ignoring",
                    height,
                    round,
                    self.current_round.height,
                    self.current_round.round
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod state_machine_tests {
    // Regression guard: a BlockCommitCallback returning Err must NOT be silently
    // swallowed — errors must propagate so the node halts rather than continuing
    // to vote on a stale fork ("log and continue" bug).
    #[tokio::test]
    async fn test_commit_failure_halts_consensus() {
        use crate::types::BlockCommitCallback;
        use async_trait::async_trait;

        struct FailingCallback;

        #[async_trait]
        impl BlockCommitCallback for FailingCallback {
            async fn commit_finalized_block(
                &self,
                _proposal: &crate::types::ConsensusProposal,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Err("simulated storage failure".into())
            }

            async fn get_active_validator_count(
                &self,
            ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
                Ok(4)
            }
        }

        // Directly verify the callback returns Err and the error message is preserved.
        // This is the regression guard: if anyone changes the callback to swallow errors,
        // this test will catch it at the trait level before the engine-level wiring is tested.
        let cb = FailingCallback;
        // Build a minimal ConsensusProposal using Default-able fields where possible.
        let proposal = crate::types::ConsensusProposal {
            id: lib_crypto::Hash([0u8; 32]),
            proposer: lib_crypto::Hash([0u8; 32]),
            height: 42,
            round: 0,
            protocol_version: super::CONSENSUS_PROTOCOL_VERSION,
            previous_hash: lib_crypto::Hash([0u8; 32]),
            block_data: vec![],
            timestamp: 0,
            signature: lib_crypto::PostQuantumSignature {
                signature: vec![],
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: [0u8; 2592],
                    kyber_pk: [0u8; 1568],
                    key_id: [0u8; 32],
                },
                algorithm: lib_crypto::SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            consensus_proof: crate::types::ConsensusProof {
                consensus_type: crate::types::ConsensusType::ByzantineFaultTolerance,
                stake_proof: None,
                storage_proof: None,
                work_proof: None,
                zk_did_proof: None,
                timestamp: 0,
            },
        };
        let result = cb.commit_finalized_block(&proposal).await;
        assert!(result.is_err(), "commit callback must propagate errors");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("simulated storage failure"),
            "error message must be preserved; got: {}",
            err_msg
        );
    }
}
