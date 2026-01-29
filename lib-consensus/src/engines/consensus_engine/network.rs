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
    /// Gap 4: Vote Aggregation from Remote Validators
    ///
    /// Invariant: This is the ONLY consensus driver. run_consensus_round() must NOT be used
    /// alongside this loop (they would conflict). The loop handles all progression:
    /// - Timer events drive phase transitions (Propose → PreVote → PreCommit → Commit)
    /// - Messages drive quorum detection and early transitions
    /// - Receiver closure causes graceful shutdown
    ///
    /// Mode Awareness (Phase 4):
    /// - BFT Mode (>= 4 validators): Full consensus participation
    /// - Bootstrap Mode (< 4 validators): Passive monitoring, no proposals
    pub async fn run_consensus_loop(&mut self) -> ConsensusResult<()> {
        let mut message_rx = self.message_rx.take()
            .ok_or_else(|| ConsensusError::ValidatorError("Message receiver not set".to_string()))?;

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
        } else {
            tracing::info!(
                "⛏️ Starting consensus loop in BOOTSTRAP MODE ({} validators, need ≥{} for BFT) at height {}",
                validator_count,
                crate::types::MIN_BFT_VALIDATORS,
                self.current_round.height
            );
            tracing::info!(
                "   Consensus loop will monitor for BFT mode activation"
            );
        }

        loop {
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
                            // Update timer token for new height
                            timer_token = TimerToken::new(
                                self.current_round.height,
                                self.current_round.round,
                                &self.current_round.step,
                            );
                            // Emit mode transition event
                            self.emit_liveness_event(ConsensusEvent::ModeTransitionToBft {
                                validator_count,
                                height: self.current_round.height,
                                timestamp,
                            });
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
                    if let Some(_validator_id) = &self.validator_identity {
                        let heartbeat_msg = self.heartbeat_tracker.create_heartbeat_message(
                            self.current_round.height,
                            self.current_round.round,
                            self.current_round.step.clone(),
                            self.validator_manager.get_active_validators().len() as u32,
                        );

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
                                // NOTE: This represents a ConsensusStalled event.
                                // Currently logged for observability; future work will emit as proper events.
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
                            } else {
                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                // NOTE: This represents a ConsensusRecovered event.
                                // Currently logged for observability; future work will emit as proper events.
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

                        // Could trigger automatic response (future work):
                        // - Round timeout acceleration
                        // - Proposer rotation
                        // - Emergency validator set update
                    }
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
                // NEW: Compute payload hash for replay detection
                let payload_bytes = bincode::serialize(&vote)
                    .expect("Vote serialization cannot fail");
                let payload_hash = lib_crypto::Hash::from_bytes(&lib_crypto::hash_blake3(&payload_bytes));

                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // NEW: Detect replay attack
                if let Some(replay_evidence) = self.byzantine_detector.detect_replay_attack(
                    &vote.voter,
                    payload_hash.clone(),
                    current_time,
                ) {
                    tracing::warn!(
                        "⚠️  REPLAY: Validator {} sent duplicate message {} times",
                        vote.voter, replay_evidence.replay_count
                    );
                    // Continue processing (replay is advisory, not blocking)
                }

                // NEW: Record forensic signature
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
                    VoteType::PreVote => {
                        self.on_prevote(vote).await?;
                    }
                    VoteType::PreCommit => {
                        self.on_precommit(vote).await?;
                    }
                    VoteType::Commit => {
                        self.on_commit_vote(vote).await?;
                    }
                    VoteType::Against => {
                        // Should not reach here (already returned above)
                    }
                }
            }
            ValidatorMessage::Heartbeat { message } => {
                // Process heartbeat (advisory only, never affects consensus)
                let is_validator = |vid: &IdentityId| {
                    self.validator_manager.get_active_validators()
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
