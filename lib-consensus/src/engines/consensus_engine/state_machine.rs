use super::*;
use lib_crypto::hash_blake3;
use tracing::info;

// ============================================================================
// AUDIT AND LOGGING CONSTANTS
// ============================================================================

/// Maximum number of audit records to display in logs
///
/// When logging per-transaction fee audit records during fee collection,
/// limit output to avoid log spam in blocks with many transactions.
/// Full audit trails are still maintained in the audit data structures.
///
/// **Usage**: `.take(MAX_AUDIT_RECORDS_TO_LOG)` on audit record iterators
/// when displaying in logs.
///
/// **Timeline**: Will be used in Week 13 when FeeCollector trait integration
/// adds per-transaction audit record logging to collect_and_distribute_fees().
#[allow(dead_code)] // Will be used in Week 13 audit logging
const MAX_AUDIT_RECORDS_TO_LOG: usize = 10;

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

                match self.run_consensus_round().await {
                    Ok(_) => {
                        let mut events = vec![ConsensusEvent::RoundCompleted { height }];

                        // Process DAO proposals
                        if let Err(e) = self.dao_engine.process_expired_proposals().await {
                            tracing::warn!("DAO processing error: {}", e);
                            events.push(ConsensusEvent::DaoError {
                                error: e.to_string(),
                            });
                        }

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

                        // Calculate and distribute rewards
                        if let Err(e) = self.reward_calculator.calculate_round_rewards(
                            &self.validator_manager,
                            self.current_round.height,
                        ) {
                            tracing::warn!("Reward calculation error: {}", e);
                            events.push(ConsensusEvent::RewardError {
                                error: e.to_string(),
                            });
                        }

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

    /// Handle validator registration event
    async fn handle_validator_registration(
        &mut self,
        identity: lib_identity::IdentityId,
        stake: u64,
    ) -> ConsensusResult<()> {
        self.register_validator(
            identity.clone(),
            stake,
            1024 * 1024 * 1024, // Default storage capacity
            vec![0u8; 32],      // Default consensus key
            5,                  // Default commission rate
            false,              // Not genesis
        )
        .await?;
        Ok(())
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

        // Select proposer for this round
        let proposer = self
            .validator_manager
            .select_proposer(self.current_round.height, self.current_round.round)
            .ok_or_else(|| ConsensusError::ValidatorError("No proposer available".to_string()))?;

        self.current_round.proposer = Some(proposer.identity.clone());

        tracing::info!(
            "Starting consensus round {} at height {} with proposer {:?}",
            self.current_round.round,
            self.current_round.height,
            proposer.identity
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
        self.current_round.start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
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

        // If we are the proposer, create a proposal
        if let Some(ref validator_id) = self.validator_identity {
            if Some(validator_id) == self.current_round.proposer.as_ref() {
                let proposal = self.create_proposal().await?;
                self.current_round.proposals.push(proposal.id.clone());
                self.pending_proposals.push_back(proposal.clone());

                // Invariant CE-ENG-3: Broadcast after state transition (proposal now in state)
                // Create canonical ValidatorMessage from already-formed proposal
                let msg = ValidatorMessage::Propose {
                    proposal,
                };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        "Failed to broadcast proposal to validators (continuing per CE-ENG-4)"
                    );
                }
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

        // Cast prevote
        if let Some(proposal_id) = self.current_round.proposals.first() {
            let vote = self.cast_vote(proposal_id.clone(), VoteType::PreVote)
                .await?;

            // Invariant CE-ENG-3: Broadcast after state transition
            // Create canonical ValidatorMessage from already-formed vote
            let msg = ValidatorMessage::Vote { vote };

            // Invariant CE-ENG-5: Pass validator set explicitly, never query network
            let validator_ids = self.get_active_validator_ids();

            // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
            // Log failures for observability without affecting consensus correctness
            if let Err(e) = self.broadcaster
                .broadcast_to_validators(msg, &validator_ids)
                .await
            {
                tracing::debug!(
                    error = ?e,
                    height = self.current_round.height,
                    "Failed to broadcast prevote to validators (continuing per CE-ENG-4)"
                );
            }
        }

        // Wait for prevotes with timeout
        self.wait_for_step_timeout(self.config.prevote_timeout)
            .await;

        Ok(())
    }

    /// Run the precommit step
    async fn run_precommit_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreCommit;

        // Check if we received enough prevotes
        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let prevote_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreVote);
            let active_validator_count = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(prevote_count, active_validator_count) {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::PreCommit)
                    .await?;
                self.current_round.valid_proposal = Some(proposal_id);

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = ValidatorMessage::Vote { vote };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        "Failed to broadcast precommit to validators (continuing per CE-ENG-4)"
                    );
                }
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

        // Check if we received enough precommits
        if let Some(proposal_id) = self.current_round.valid_proposal.as_ref().cloned() {
            let precommit_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreCommit);
            let active_validator_count = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(precommit_count, active_validator_count) {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::Commit)
                    .await?;

                tracing::info!(
                    "Block committed at height {} with proposal {:?}",
                    self.current_round.height,
                    proposal_id
                );

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = ValidatorMessage::Vote { vote };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        proposal_id = ?proposal_id,
                        "Failed to broadcast commit vote to validators (continuing per CE-ENG-4)"
                    );
                }

                // Process the committed block
                self.process_committed_block(&proposal_id).await?;
            }
        }

        Ok(())
    }

    /// Cast a vote
    ///
    /// Returns the created vote so that the caller can broadcast it.
    /// Invariant CE-ENG-3: Broadcast happens after this state transition.
    async fn cast_vote(&mut self, proposal_id: Hash, vote_type: VoteType) -> ConsensusResult<ConsensusVote> {
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
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            signature,
        };

        // Store vote using composite key (height, round, vote_type, validator_id)
        let key = VotePoolKey {
            height: self.current_round.height,
            round: self.current_round.round,
            vote_type: vote_type.clone(),
            validator_id: validator_id.clone(),
        };
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

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
    async fn process_committed_block(&mut self, proposal_id: &Hash) -> ConsensusResult<()> {
        // SAFETY: Verify commit quorum before processing (Issue #939)
        // This is a defense-in-depth check - callers must already verify commit votes
        let commit_count = self.count_commits_for(
            self.current_round.height,
            self.current_round.round,
            proposal_id
        );
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if !super::check_supermajority(commit_count, total_validators) {
            return Err(ConsensusError::ConsensusError(
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

        // Find and process the committed proposal
        if let Some(proposal_index) = self
            .pending_proposals
            .iter()
            .position(|p| &p.id == proposal_id)
        {
            // Safe: index came from position() which found it
            let proposal = self.pending_proposals.remove(proposal_index)
                .expect("Proposal index came from position(), element must exist");

            // Validate the block one more time before applying
            self.validate_committed_block(&proposal).await?;

            // Apply block to state (Issue #938: This triggers BlockCommitCallback → persistence)
            self.apply_block_to_state(&proposal).await?;

            // Update validator activities and reputation
            self.update_validator_metrics(&proposal).await?;

            // Calculate and distribute block rewards
            let reward_round = self
                .reward_calculator
                .calculate_round_rewards(&self.validator_manager, self.current_round.height)?;
            self.reward_calculator.distribute_rewards(&reward_round)?;

            // Collect and distribute fees from block (Week 7 integration)
            // Mirrors reward distribution pattern - happens at block finalization
            let block_metadata = self.extract_block_metadata(&proposal);
            if let Err(e) = self.collect_and_distribute_fees(&block_metadata) {
                tracing::warn!(
                    "Error collecting fees for block {}: {}",
                    proposal.height,
                    e
                );
                // Non-critical: Fee collection failure does NOT block consensus
                // See Invariant CE-ENG-4: Consensus correctness independent of fee collection
            }

            // Process any DAO proposals that may have expired
            if let Err(e) = self.dao_engine.process_expired_proposals().await {
                tracing::warn!("Error processing DAO proposals: {}", e);
            }

            tracing::info!(
                " Successfully processed committed block: {:?} at height {}",
                proposal.id,
                proposal.height
            );
        }

        Ok(())
    }

    /// Collect and distribute fees from block metadata
    ///
    /// Called after block finalization to trigger fee collection and distribution.
    /// Uses BlockMetadata to track fees without requiring transaction execution.
    /// Mirrors reward distribution pattern.
    ///
    /// **Invariant CE-ENG-4**: Consensus correctness does NOT depend on fee collection
    /// success. Fee collection is a side-effect of block finalization, not a prerequisite.
    ///
    /// **Invariant FC-1**: Fee collection is a side-effect of block finalization
    /// **Invariant FC-2**: Fee distribution follows the 45/30/15/10 split exactly
    fn collect_and_distribute_fees(&self, metadata: &BlockMetadata) -> ConsensusResult<()> {
        // Skip if no fees to collect
        if metadata.total_fees_collected == 0 {
            tracing::debug!(
                "💰 No fees to collect for block {} (genesis or empty block)",
                metadata.height
            );
            return Ok(());
        }

        // Log fee collection attempt
        tracing::info!(
            "💰 Collecting fees from block height {} (total_fees: {})",
            metadata.height,
            metadata.total_fees_collected
        );

        // If FeeCollector is set, collect and distribute fees
        if let Some(ref fee_router_arc) = self.fee_router {
            // Lock the fee router for exclusive access
            let mut fee_router = match fee_router_arc.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!(
                        "💰 FeeCollector mutex poisoned at block {}: {}",
                        metadata.height,
                        poisoned
                    );
                    // Recover from poisoned mutex
                    poisoned.into_inner()
                }
            };

            // Check if fee collector is initialized
            if !fee_router.is_initialized() {
                tracing::warn!(
                    "💰 FeeCollector not initialized - skipping fee collection for block {}",
                    metadata.height
                );
                return Ok(());
            }

            // Step 1: Collect fees
            if let Err(e) = fee_router.collect_fee(metadata.total_fees_collected) {
                tracing::warn!(
                    "💰 Failed to collect fees for block {}: {}",
                    metadata.height,
                    e
                );
                // Non-critical: Continue even if collection fails
                return Ok(());
            }

            tracing::debug!(
                "💰 Fees collected for block {} (amount: {}, pending: {})",
                metadata.height,
                metadata.total_fees_collected,
                fee_router.pending_fees()
            );

            // Step 2: Distribute fees according to 45/30/15/10 split
            match fee_router.distribute_fees(metadata.height) {
                Ok(distribution) => {
                    tracing::info!(
                        "💰 Fees distributed for block {}: UBI={} (45%), Consensus={} (30%), Governance={} (15%), Treasury={} (10%), Total={}",
                        metadata.height,
                        distribution.ubi_amount,
                        distribution.consensus_amount,
                        distribution.governance_amount,
                        distribution.treasury_amount,
                        distribution.total_distributed
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "💰 Failed to distribute fees for block {}: {}",
                        metadata.height,
                        e
                    );
                    // Non-critical: Fees remain pending for next distribution
                }
            }
        } else {
            tracing::debug!(
                "💰 No FeeCollector configured - skipping fee collection for block {}",
                metadata.height
            );
        }

        Ok(())
    }

    /// Extract block metadata from a consensus proposal
    ///
    /// Creates BlockMetadata structure for fee tracking.
    /// Week 7: Uses simulated fees (production will extract from actual transactions)
    ///
    /// **NOTE**: Temporary stub for transaction_count. Will be replaced with actual
    /// transaction count extraction in Week 10 when full transaction execution is integrated.
    fn extract_block_metadata(&self, proposal: &ConsensusProposal) -> BlockMetadata {
        let simulated_fees = self.simulate_block_fees(proposal.height);

        BlockMetadata {
            height: proposal.height,
            timestamp: chrono::Utc::now().timestamp(),
            transaction_count: 0, // Temporary stub - will be replaced in Week 10
            total_fees_collected: simulated_fees,
            proposer: proposal.proposer.clone(),
        }
    }

    /// Simulate block fees for Week 7 testing
    ///
    /// Production implementation will extract fees from actual transactions.
    /// This stub provides deterministic simulated fees for testing fee collection.
    ///
    /// **NOTE**: This is temporary simulation logic. Will be replaced with actual
    /// transaction fee extraction in Week 10 when full transaction execution is integrated.
    fn simulate_block_fees(&self, height: u64) -> u64 {
        // Genesis block (height 0) has no transaction fees
        if height == 0 {
            return 0;
        }

        // Simulate realistic fee distribution for non-genesis blocks:
        // - Every 10th block: 10,000 tokens (large block)
        // - Blocks 1-7: 1,000 tokens each (normal blocks)
        // - Blocks 8-9: 100 tokens each (small blocks)
        match height % 10 {
            0 => 10_000,  // Large block
            1..=7 => 1_000,   // Normal blocks
            _ => 100,     // Small blocks
        }
    }

    /// Validate committed block before applying
    async fn validate_committed_block(&self, proposal: &ConsensusProposal) -> ConsensusResult<()> {
        // Verify proposal signature
        let proposal_data = self.serialize_proposal_data(
            &proposal.id,
            &proposal.proposer,
            proposal.height,
            &proposal.previous_hash,
            &proposal.block_data,
        )?;

        let proposer = self.validator_manager.get_validator(&proposal.proposer).ok_or_else(|| {
            ConsensusError::ValidatorError("Proposer not found for proposal validation".to_string())
        })?;

        if proposer.consensus_key != proposal.signature.public_key.dilithium_pk {
            return Err(ConsensusError::ProofVerificationFailed(
                "Proposal signature key does not match proposer consensus key".to_string(),
            ));
        }

        if !self
            .verify_signature(&proposal_data, &proposal.signature)
            .await?
        {
            return Err(ConsensusError::ProofVerificationFailed(
                "Invalid proposal signature".to_string(),
            ));
        }

        // Verify consensus proof
        if !self
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
    /// # Safety Guarantee (Issue #938)
    /// Network-received blocks MUST flow through:
    /// 1. Network → proposal submission (proposal-only, no persistence)
    /// 2. BFT validation (2/3+1 validators agree)
    /// 3. THIS method (BlockCommitCallback → persistence)
    ///
    /// Any path that bypasses this flow violates consensus safety.
    async fn apply_block_to_state(&mut self, proposal: &ConsensusProposal) -> ConsensusResult<()> {
        // Call the block commit callback if configured
        // This is the bridge to the actual blockchain storage layer
        if let Some(ref callback) = self.block_commit_callback {
            match callback.commit_finalized_block(proposal).await {
                Ok(()) => {
                    info!(
                        block_height = proposal.height,
                        proposal_id = ?proposal.id,
                        "BFT finalized block committed to blockchain"
                    );
                    info!("Issue #938: Block persisted ONLY after 2/3+1 commit votes");
                }
                Err(e) => {
                    // Log but don't fail consensus - block commit is best-effort
                    // The block is still finalized in consensus, storage is a side effect
                    tracing::error!(
                        "⚠️ Failed to commit BFT finalized block to blockchain: {} (height: {}, proposal: {:?})",
                        e,
                        proposal.height,
                        proposal.id
                    );
                }
            }
        } else {
            // No callback configured - log the state change for debugging
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
        if !self.is_proposal_relevant(&proposal) {
            return Ok(());
        }

        if !self.current_round.proposals.is_empty() {
            return Ok(());
        }

        if Some(&proposal.proposer) != self.current_round.proposer.as_ref() {
            return Ok(());
        }

        self.current_round.proposals.push(proposal.id.clone());
        self.pending_proposals.push_back(proposal);

        if self.current_round.step == ConsensusStep::Propose {
            self.enter_prevote_step().await?;
        }

        Ok(())
    }

    pub(super) async fn on_prevote(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // Harden: Validate remote vote against all BFT safety invariants
        if !self.validate_remote_vote(&vote).await? {
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            current_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=PreVote",
                evidence.validator, evidence.height, evidence.round
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
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

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

        if check_supermajority(prevote_count, total_validators) && self.current_round.step == ConsensusStep::PreVote {
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
            self.enter_precommit_step().await?;
        }

        // **CE-L1, CE-L2**: Always check if commit quorum is reached, even in PreVote step
        self.maybe_finalize(vote.height, vote.round, &proposal_id).await?;

        Ok(())
    }

    pub(super) async fn on_precommit(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // Harden: Validate remote vote against all BFT safety invariants
        if !self.validate_remote_vote(&vote).await? {
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            current_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=PreCommit",
                evidence.validator, evidence.height, evidence.round
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
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

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

        if check_supermajority(precommit_count, total_validators) && self.current_round.step == ConsensusStep::PreCommit {
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
            self.enter_commit_step().await?;
        }

        // **CE-L1, CE-L2**: Always check if commit quorum is reached, even in PreCommit step
        self.maybe_finalize(vote.height, vote.round, &proposal_id).await?;

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
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            current_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=Commit",
                evidence.validator, evidence.height, evidence.round
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
                    vote.voter, vote.height, vote.round
                );
                return Ok(());
            }
        }

        // Accept new commit vote (even if we're not in Commit step yet)
        let proposal_id = vote.proposal_id.clone();
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

        tracing::debug!(
            "Stored commit vote from {} for proposal {:?} at height {} round {} (current step: {:?})",
            vote.voter,
            proposal_id,
            vote.height,
            vote.round,
            self.current_round.step
        );

        // **CE-L1**: Check if commit quorum is reached and finalize immediately
        self.maybe_finalize(vote.height, vote.round, &proposal_id).await?;

        Ok(())
    }

    pub(super) async fn on_round_timeout(&mut self) -> ConsensusResult<()> {
        tracing::debug!(
            "Round timeout at height {} round {} step {:?}",
            self.current_round.height,
            self.current_round.round,
            self.current_round.step
        );

        match self.current_round.step {
            ConsensusStep::Propose => {
                self.enter_prevote_step().await?;
            }
            ConsensusStep::PreVote => {
                self.enter_precommit_step().await?;
            }
            ConsensusStep::PreCommit => {
                self.enter_commit_step().await?;
            }
            ConsensusStep::Commit => {
                self.advance_to_next_round();
            }
            ConsensusStep::NewRound => {}
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
            let msg = ValidatorMessage::Vote { vote };
            let validator_ids = self.get_active_validator_ids();

            if let Err(e) = self.broadcaster
                .broadcast_to_validators(msg, &validator_ids)
                .await
            {
                tracing::debug!(
                    error = ?e,
                    "Failed to broadcast prevote (continuing per CE-ENG-4)"
                );
            }
        }

        Ok(())
    }

    async fn enter_precommit_step(&mut self) -> ConsensusResult<()> {
        if self.current_round.step >= ConsensusStep::PreCommit {
            return Ok(());
        }

        self.current_round.step = ConsensusStep::PreCommit;
        tracing::info!(
            "Entering PreCommit step at height {} round {}",
            self.current_round.height,
            self.current_round.round
        );

        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let prevote_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreVote);
            let total_validators = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(prevote_count, total_validators) {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::PreCommit).await?;
                self.current_round.valid_proposal = Some(proposal_id);

                let msg = ValidatorMessage::Vote { vote };
                let validator_ids = self.get_active_validator_ids();

                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        "Failed to broadcast precommit (continuing per CE-ENG-4)"
                    );
                }
            }
        }

        Ok(())
    }

    async fn enter_commit_step(&mut self) -> ConsensusResult<()> {
        if self.current_round.step >= ConsensusStep::Commit {
            return Ok(());
        }

        self.current_round.step = ConsensusStep::Commit;
        tracing::info!(
            "Entering Commit step at height {} round {}",
            self.current_round.height,
            self.current_round.round
        );

        if let Some(proposal_id) = self.current_round.valid_proposal.as_ref().cloned() {
            let precommit_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreCommit);
            let total_validators = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(precommit_count, total_validators) {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::Commit).await?;

                tracing::info!(
                    "Block committed at height {} with proposal {:?}",
                    self.current_round.height,
                    proposal_id
                );

                let msg = ValidatorMessage::Vote { vote };
                let validator_ids = self.get_active_validator_ids();

                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        "Failed to broadcast commit vote (continuing per CE-ENG-4)"
                    );
                }

                // Process the committed block (finalization)
                // Note: maybe_finalize will be called by on_commit_vote after our vote is stored
                self.process_committed_block(&proposal_id).await?;
            }
        }

        Ok(())
    }

    fn is_proposal_relevant(&self, proposal: &ConsensusProposal) -> bool {
        if proposal.height < self.current_round.height {
            return false;
        }
        if proposal.height > self.current_round.height {
            return false;
        }
        if self.current_round.step > ConsensusStep::Propose {
            return false;
        }
        true
    }

    /// Check if commit quorum is reached for a proposal and finalize if so.
    /// **CE-L1**: Commit quorum finalizes regardless of local step.
    /// **CE-L2**: This is called from any step, not just Commit.
    /// **Invariant**: Called from on_prevote, on_precommit, on_commit_vote, and enter_commit_step
    /// to prevent "stored but never used" regressions.
    pub(super) async fn maybe_finalize(&mut self, height: u64, round: u32, proposal_id: &Hash) -> ConsensusResult<()> {
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

            // Finalize regardless of current step (CE-L1)
            if self.current_round.height == height && self.current_round.round == round {
                // Transition to Commit step if not already there
                if self.current_round.step < ConsensusStep::Commit {
                    self.current_round.step = ConsensusStep::Commit;
                    tracing::info!(
                        "Fast-tracked to Commit step via commit quorum at height {} round {}",
                        height,
                        round
                    );
                }

                // Process the committed block (finalization) directly
                // Note: This is safe even if we've already finalized once,
                // process_committed_block is idempotent.
                self.process_committed_block(proposal_id).await?;
            } else {
                tracing::debug!(
                    "Commit quorum observed for past round (H={} R={}) while at H={} R={}",
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
