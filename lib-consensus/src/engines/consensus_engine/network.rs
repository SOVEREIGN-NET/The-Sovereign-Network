use super::*;

impl ConsensusEngine {
    /// Main consensus loop with tokio::select!
    ///
    /// Waits on:
    /// - Round timer firing (only accepted if token matches current state)
    /// - Messages from the network receiver
    /// - Receiver closure (exits gracefully)
    ///
    /// Processes PreVote/PreCommit/Proposal messages and maintains vote_pool.
    ///
    /// Invariant: This is the ONLY consensus driver. run_consensus_round() must NOT be used
    /// alongside this loop (they would conflict). The loop handles all progression:
    /// - Timer events drive phase transitions (Propose → PreVote → PreCommit → Commit)
    /// - Messages drive quorum detection and early transitions
    /// - Receiver closure causes graceful shutdown
    ///
    /// Mode Awareness:
    /// - BFT Mode (>= 3 validators): Full consensus participation
    /// - Bootstrap Mode (< 3 validators): Passive monitoring, no proposals
    pub async fn run_consensus_loop(&mut self) -> ConsensusResult<()> {
        let mut message_rx = self.message_rx.take().ok_or_else(|| {
            ConsensusError::ValidatorError("Message receiver not set".to_string())
        })?;
        let mut validator_update_rx = self.validator_update_rx.take();

        // Sync consensus height with blockchain before starting
        // This ensures we start at the correct height after bootstrap mode
        self.sync_height_with_blockchain().await?;

        // Auto-initialize heartbeat sender if not already initialized
        if self.heartbeat_interval.is_none() {
            self.initialize_heartbeat_sender();
        }

        // Auto-initialize liveness monitor if not already initialized
        if self.liveness_check_interval.is_none() {
            self.initialize_liveness_monitor();
        }

        let mut heartbeat_interval = self.heartbeat_interval.take();

        let mut timer_token = TimerToken::new(
            self.current_round.height,
            self.current_round.round,
            &self.current_round.step,
        );
        let mut timer_fut = Box::pin(self.round_timer.next_deadline(
            self.current_round.height,
            self.current_round.round,
            &self.current_round.step,
        ));

        // Track the last time our blockchain height advanced, so we can trigger
        // a catch-up sync even in bootstrap mode (< 3 validators) where the
        // HeartbeatTracker has no entries and the stall detector never fires.
        let mut last_height_seen: u64 = self.current_round.height;
        let mut last_height_advance_secs: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        /// After this many seconds at the same height without a stall event,
        /// fire catch-up anyway.  Short enough to recover quickly; long enough
        /// not to spam the sync layer.
        const BOOTSTRAP_CATCHUP_TIMEOUT_SECS: u64 = 30;

        // Ensure validator membership snapshot is initialized for the current height
        self.snapshot_validator_set(self.current_round.height);

        // Track BFT mode for transition logging
        let mut last_bft_mode = self.is_bft_mode_active();
        let validator_count = self.get_validator_count();

        if last_bft_mode {
            tracing::info!(
                "🛡️ Starting consensus loop in BFT MODE ({} validators) at height {} round {} step {:?}",
                validator_count,
                self.current_round.height,
                self.current_round.round,
                self.current_round.step
            );
            // Kick off the initial propose step: select proposer and create proposal if we're it.
            // This must happen before the select! loop so current_round.proposer is set before
            // any incoming proposals are processed by on_proposal().
            if let Err(e) = self.enter_propose_step().await {
                tracing::warn!("Failed to enter initial propose step: {}", e);
            }
            // Re-arm timer: enter_propose_step doesn't change step, so token stays valid.
            // Re-arm anyway to get a fresh deadline from the current state.
            timer_token = TimerToken::new(
                self.current_round.height,
                self.current_round.round,
                &self.current_round.step,
            );
            timer_fut.set(self.round_timer.next_deadline(
                self.current_round.height,
                self.current_round.round,
                &self.current_round.step,
            ));
        } else {
            tracing::info!(
                "⛏️ Starting consensus loop in BOOTSTRAP MODE ({} validators, need ≥{} for BFT) at height {}",
                validator_count,
                crate::types::MIN_BFT_VALIDATORS,
                self.current_round.height
            );
            tracing::info!("   Consensus loop will monitor for BFT mode activation");
        }

        loop {
            // Publish the height BFT is actively working on so catch-up sync
            // doesn't race with block commits at the same height.
            // Only publish in BFT mode (>= 3 validators). In bootstrap mode,
            // catch-up sync must be unrestricted to fill the gap.
            if let Some(ref bft_height) = self.bft_active_height {
                if self.is_bft_mode_active() {
                    bft_height.store(
                        self.current_round.height,
                        std::sync::atomic::Ordering::Release,
                    );
                } else {
                    // Clear the guard in bootstrap mode so catch-up proceeds freely.
                    bft_height.store(0, std::sync::atomic::Ordering::Release);
                }
            }

            tokio::select! {
                // Timer fired: only process if token matches current state
                _ = &mut timer_fut => {
                    // Check for mode transitions (Bootstrap <-> BFT)
                    let current_bft_mode = self.is_bft_mode_active();
                    if current_bft_mode != last_bft_mode {
                        let validator_count = self.get_validator_count();
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        if current_bft_mode {
                            // Transitioning TO BFT mode
                            tracing::info!(
                                "🔄 MODE TRANSITION: Bootstrap → BFT ({} validators now active)",
                                validator_count
                            );
                            // Re-sync height with blockchain to ensure continuity
                            if let Err(e) = self.sync_height_with_blockchain().await {
                                tracing::warn!("Failed to sync height during mode transition: {}", e);
                            }
                            // Snapshot validator set for the new height
                            self.snapshot_validator_set(self.current_round.height);
                            // Emit mode transition event
                            self.emit_liveness_event(ConsensusEvent::ModeTransitionToBft {
                                validator_count,
                                height: self.current_round.height,
                                timestamp,
                            });
                            // Kick off the propose step: select proposer and create/broadcast
                            // proposal if this node is the designated proposer.
                            if let Err(e) = self.enter_propose_step().await {
                                tracing::warn!("Failed to enter propose step on BFT transition: {}", e);
                            }
                            // Re-arm timer for the (potentially new) height/step
                            timer_token = TimerToken::new(
                                self.current_round.height,
                                self.current_round.round,
                                &self.current_round.step,
                            );
                            timer_fut.set(self.round_timer.next_deadline(
                                self.current_round.height,
                                self.current_round.round,
                                &self.current_round.step,
                            ));
                        } else {
                            // Transitioning TO Bootstrap mode (degraded)
                            tracing::warn!(
                                "🔄 MODE TRANSITION: BFT → Bootstrap ({} validators, need ≥{} for BFT)",
                                validator_count,
                                crate::types::MIN_BFT_VALIDATORS
                            );
                            tracing::warn!(
                                "   Consensus loop entering passive mode - mining loop will handle blocks"
                            );
                            // Emit mode transition event
                            self.emit_liveness_event(ConsensusEvent::ModeTransitionToBootstrap {
                                validator_count,
                                min_required: crate::types::MIN_BFT_VALIDATORS,
                                height: self.current_round.height,
                                timestamp,
                            });
                        }
                        last_bft_mode = current_bft_mode;
                    }

                    // Only process timeouts in BFT mode
                    if !current_bft_mode {
                        // In bootstrap mode, just re-arm the timer and wait
                        timer_token = TimerToken::new(
                            self.current_round.height,
                            self.current_round.round,
                            &self.current_round.step,
                        );
                        timer_fut.set(self.round_timer.next_deadline(
                            self.current_round.height,
                            self.current_round.round,
                            &self.current_round.step,
                        ));
                        continue;
                    }

                    if timer_token.matches(self.current_round.height, self.current_round.round, &self.current_round.step) {
                        tracing::debug!(
                            "Timer fired for height {} round {} step {:?}",
                            self.current_round.height,
                            self.current_round.round,
                            self.current_round.step
                        );
                        self.on_round_timeout().await?;
                    } else {
                        let stale_step = ConsensusStep::from_ordinal(timer_token.step_ordinal)
                            .map(|s| format!("{:?}", s))
                            .unwrap_or_else(|| "Unknown".to_string());
                        tracing::debug!(
                            "Ignoring stale timer for height {} round {} step {} (current: {} {} {:?})",
                            timer_token.height,
                            timer_token.round,
                            stale_step,
                            self.current_round.height,
                            self.current_round.round,
                            self.current_round.step
                        );
                    }

                    // Re-arm timer for current state
                    timer_token = TimerToken::new(
                        self.current_round.height,
                        self.current_round.round,
                        &self.current_round.step,
                    );
                    timer_fut.set(self.round_timer.next_deadline(
                        self.current_round.height,
                        self.current_round.round,
                        &self.current_round.step,
                    ));
                }

                // Message from network
                maybe_msg = message_rx.recv() => {
                    match maybe_msg {
                        Some(msg) => {
                            self.on_message(msg).await?;

                            // If height advanced, record the time so the
                            // bootstrap catch-up timer resets correctly.
                            let h_now = self.current_round.height;
                            if h_now != last_height_seen {
                                last_height_seen = h_now;
                                last_height_advance_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                            }

                            // Re-arm timer if state changed
                            let state_changed = !timer_token.matches(
                                self.current_round.height,
                                self.current_round.round,
                                &self.current_round.step,
                            );
                            if state_changed {
                                timer_token = TimerToken::new(
                                    self.current_round.height,
                                    self.current_round.round,
                                    &self.current_round.step,
                                );
                                timer_fut.set(self.round_timer.next_deadline(
                                    self.current_round.height,
                                    self.current_round.round,
                                    &self.current_round.step,
                                ));
                            }
                        }
                        None => {
                            // Receiver closed: engine cannot make further progress
                            tracing::info!("Consensus message receiver closed, shutting down loop");
                            break;
                        }
                    }
                }

                // Heartbeat interval tick (optional - only if initialized)
                _ = async {
                    match &mut heartbeat_interval {
                        Some(interval) => interval.tick().await,
                        None => loop { std::future::pending::<()>().await },
                    }
                } => {
                    // Send heartbeat (best-effort, ignore errors)
                    if let Some(validator_id) = &self.validator_identity {
                        let heartbeat_msg = self.heartbeat_tracker.create_heartbeat_message(
                            self.current_round.height,
                            self.current_round.round,
                            self.current_round.step.clone(),
                            self.validator_manager.get_active_validators().len() as u32,
                        );

                        // Keep local liveness state fresh even when self-heartbeats are not looped
                        // back through the network receiver path.
                        self.heartbeat_tracker
                            .record_heartbeat(validator_id, heartbeat_msg.timestamp);
                        self.liveness_monitor.mark_responsive(validator_id);

                        // Get all validator IDs for broadcast
                        let validator_ids: Vec<_> = self.validator_manager
                            .get_active_validators()
                            .iter()
                            .map(|v| v.identity.clone())
                            .collect();

                        // Broadcast heartbeat (best-effort, ignore failures)
                        if let Err(e) = self.broadcaster.broadcast_to_validators(
                            ValidatorMessage::Heartbeat {
                                message: heartbeat_msg,
                            },
                            &validator_ids,
                        ).await {
                            tracing::debug!("Heartbeat broadcast failed: {}", e);
                        }
                    }
                }

                // Liveness check interval tick (every 5 seconds)
                _ = async {
                    if let Some(interval) = &mut self.liveness_check_interval {
                        interval.tick().await
                    } else {
                        loop { std::future::pending::<()>().await }
                    }
                } => {
                    // Check for validator timeouts and consensus stalls
                    let state_changed = self.liveness_monitor.watch_timeouts(&self.heartbeat_tracker);

                    if state_changed {
                        // Check for stall transition
                        if let Some((is_stalled, timed_out_set)) = self.liveness_monitor.check_stall_transition() {
                            let timed_out_validators: Vec<_> = timed_out_set.into_iter().collect();
                            if is_stalled {
                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                tracing::warn!(
                                    event = "ConsensusStalled",
                                    height = self.current_round.height,
                                    round = self.current_round.round,
                                    timed_out_count = timed_out_validators.len(),
                                    total_validators = self.liveness_monitor.total_validators,
                                    threshold = self.liveness_monitor.stall_threshold,
                                    "CONSENSUS STALLED: {}/{} validators timed out, quorum impossible",
                                    timed_out_validators.len(),
                                    self.liveness_monitor.total_validators,
                                );
                                self.emit_liveness_event(ConsensusEvent::ConsensusStalled {
                                    height: self.current_round.height,
                                    round: self.current_round.round,
                                    timed_out_validators,
                                    total_validators: self.liveness_monitor.total_validators as usize,
                                    timestamp,
                                });

                                // Trigger catch-up sync unconditionally on stall — we may be
                                // behind peers and unable to receive their higher-height votes
                                // because of the height divergence itself.  This breaks the
                                // deadlock: detection → action, no in-band message required.
                                let our_blockchain_height =
                                    self.current_round.height.saturating_sub(1);
                                if let Some(ref trigger) = self.catch_up_sync_trigger {
                                    tracing::info!(
                                        "🔄 Stall detected — triggering catch-up sync from height {}",
                                        our_blockchain_height
                                    );
                                    trigger.trigger(our_blockchain_height);
                                }
                            } else {
                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                tracing::info!(
                                    event = "ConsensusRecovered",
                                    height = self.current_round.height,
                                    round = self.current_round.round,
                                    "CONSENSUS RECOVERED: Sufficient validators responsive again"
                                );
                                self.emit_liveness_event(ConsensusEvent::ConsensusRecovered {
                                    height: self.current_round.height,
                                    round: self.current_round.round,
                                    timestamp,
                                });
                            }
                        }
                    }

                    // NEW: Periodic partition detection
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    if let Some(partition_evidence) = self.byzantine_detector.detect_network_partition(
                        &self.liveness_monitor,
                        self.current_round.height,
                        self.current_round.round,
                        current_time,
                    ) {
                        tracing::error!(
                            "🔌 PARTITION SUSPECTED: {}/{} validators timed out (threshold: {})",
                            partition_evidence.timed_out_validators.len(),
                            partition_evidence.total_validators,
                            partition_evidence.stall_threshold
                        );

                    }

                    // Bootstrap-mode / height-0 catch-up: if the node has been
                    // stuck at the same blockchain height for ≥30 s and no
                    // stall event fired (because there are no tracked validators
                    // yet), nudge the sync layer unconditionally.  This covers
                    // the case where a node restarts after a wipe and has no
                    // peers' votes to trigger the normal height-divergence path.
                    let h = self.current_round.height;
                    if h != last_height_seen {
                        last_height_seen = h;
                        last_height_advance_secs = current_time;
                    } else if current_time.saturating_sub(last_height_advance_secs)
                        >= BOOTSTRAP_CATCHUP_TIMEOUT_SECS
                    {
                        let our_blockchain_height = h.saturating_sub(1);
                        if let Some(ref trigger) = self.catch_up_sync_trigger {
                            tracing::info!(
                                "🔄 Height {} stuck for {}s — triggering catch-up sync (bootstrap/partition recovery)",
                                h,
                                current_time.saturating_sub(last_height_advance_secs)
                            );
                            trigger.trigger(our_blockchain_height);
                        }
                        // Reset timer so we don't spam every 5 s
                        last_height_advance_secs = current_time;
                    }
                }

                // Validator set update from runtime
                Some(update) = recv_validator_update(&mut validator_update_rx) => {
                    let mut added = 0usize;
                    for entry in &update.entries {
                        if !self.validator_manager.is_validator(&entry.identity_id) {
                            if let Err(e) = self.validator_manager.register_validator(
                                entry.identity_id.clone(),
                                entry.stake,
                                0,
                                entry.consensus_key.clone(),
                                Vec::new(),
                                Vec::new(),
                                0,
                            ) {
                                tracing::warn!("Validator register failed for {}: {}", entry.identity_id, e);
                            } else {
                                added += 1;
                            }
                        }
                    }
                    if added > 0 {
                        tracing::info!(
                            "Validator set updated from runtime: {} new (staged for height {}+)",
                            added,
                            self.current_round.height + 1,
                        );
                    }
                    if let Some(id) = update.local_identity {
                        let _ = self.set_local_validator_identity(id);
                    }
                    if let Some(kp) = update.local_keypair {
                        let _ = self.set_validator_keypair(kp);
                    }
                    // Snapshot is write-once: if this height is already sealed the
                    // new validators will appear in the next height's snapshot.
                    // Attempt to snapshot anyway for the case where the current
                    // height hasn't been sealed yet (e.g. bootstrap startup).
                    self.snapshot_validator_set(self.current_round.height);
                }
            }
        }

        tracing::info!(
            "Consensus loop exited at height {} round {} step {:?}",
            self.current_round.height,
            self.current_round.round,
            self.current_round.step
        );
        Ok(())
    }

    async fn on_message(&mut self, msg: ValidatorMessage) -> ConsensusResult<()> {
        match msg {
            ValidatorMessage::Propose { proposal } => {
                self.on_proposal(proposal).await?;
            }
            ValidatorMessage::Vote { vote } => {
                // Compute payload hash for replay detection
                let payload_bytes =
                    bincode::serialize(&vote).expect("Vote serialization cannot fail");
                let payload_hash =
                    lib_crypto::Hash::from_bytes(&lib_crypto::hash_blake3(&payload_bytes));

                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Detect replay attack
                if let Some(replay_evidence) = self.byzantine_detector.detect_replay_attack(
                    &vote.voter,
                    payload_hash.clone(),
                    current_time,
                ) {
                    tracing::trace!(
                        "Duplicate message from {} (count={})",
                        vote.voter,
                        replay_evidence.replay_count
                    );
                    // Continue processing (replay is advisory, not blocking)
                }

                // Record forensic signature
                let message_type = match vote.vote_type {
                    VoteType::PreVote => crate::byzantine::ForensicMessageType::PreVote,
                    VoteType::PreCommit => crate::byzantine::ForensicMessageType::PreCommit,
                    VoteType::Commit => crate::byzantine::ForensicMessageType::Commit,
                    VoteType::Against => {
                        tracing::debug!("Received Against vote, ignoring");
                        return Ok(());
                    }
                };

                self.byzantine_detector.record_message_signature(
                    vote.id.clone(),
                    vote.voter.clone(),
                    vote.signature.clone(),
                    payload_hash,
                    message_type,
                    current_time,
                    None, // peer_id if available from network layer
                );

                // Route to handler
                match vote.vote_type {
                    VoteType::PreVote => self.on_prevote(vote).await?,
                    VoteType::PreCommit => self.on_precommit(vote).await?,
                    VoteType::Commit => self.on_commit_vote(vote).await?,
                    VoteType::Against => {
                        // Defensive: filtered by the early return above, but a
                        // refactor could remove that guard.  Never panic on a
                        // network-facing message — just drop it.
                        tracing::warn!("Against vote reached routing (should have been filtered)");
                    }
                }
            }
            ValidatorMessage::Heartbeat { message } => {
                // Process heartbeat (advisory only, never affects consensus)
                let is_validator = |vid: &IdentityId| {
                    self.validator_manager
                        .get_active_validators()
                        .iter()
                        .any(|v| v.identity == *vid)
                };

                let validator_id = message.validator.clone();
                let result = self.heartbeat_tracker.process_heartbeat(
                    message,
                    is_validator,
                    self.current_round.height,
                );

                match result {
                    crate::network::HeartbeatProcessingResult::Accepted => {
                        tracing::debug!("Heartbeat accepted from {}", validator_id);
                        // Mark validator as responsive in liveness monitor
                        self.liveness_monitor.mark_responsive(&validator_id);
                    }
                    crate::network::HeartbeatProcessingResult::Rejected(reason) => {
                        tracing::debug!("Heartbeat rejected: {}", reason);
                    }
                }
                // Heartbeats never affect consensus state
            }
        }
        Ok(())
    }
}

/// Helper for `tokio::select!`: receives from the validator update channel if present,
/// or pends forever if no channel is configured.
async fn recv_validator_update(
    rx: &mut Option<tokio::sync::mpsc::Receiver<super::ValidatorSetUpdate>>,
) -> Option<super::ValidatorSetUpdate> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}
