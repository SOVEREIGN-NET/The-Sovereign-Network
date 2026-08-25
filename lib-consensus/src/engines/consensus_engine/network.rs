use super::*;
use super::state_machine::wrap_heartbeat;

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
        // CONS-309 / CONS-502b: receiver for runtime-injected FSM events
        // (today: `WatchdogFired`). Optional — when `None`, the matching
        // select branch never resolves and the engine behaves as before.
        let mut runtime_event_rx = self.runtime_event_rx.take();

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

        // Track BFT mode for transition logging.
        // Start as false to force the transition block to run on the first tick
        // when validators are already seeded — otherwise the node stays in
        // Bootstrapping forever because current_bft_mode == last_bft_mode.
        let mut last_bft_mode = false;
        let validator_count = self.get_validator_count();

        // CONS-305: Start in Bootstrapping state — do NOT propose immediately.
        // Wait for quorum connectivity before entering active consensus.
        tracing::info!(
            "🔄 Starting consensus loop in BOOTSTRAPPING state ({} validators detected) at height {}",
            validator_count,
            self.current_round.height,
        );

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

            // If halted, don't spin the timer — sleep longer and log sparingly
            if matches!(self.fsm_state, lib_consensus_core::fsm::ValidatorState::Halting { .. }) {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                tracing::info!(
                    "🛑 HALTED — consensus stopped at height {} (waiting for manual restart)",
                    self.current_round.height,
                );
                continue;
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
                            // CONS-305: Transitioning TO BFT mode via FSM
                            tracing::info!(
                                "🔄 MODE TRANSITION: Bootstrapping → BFT ({} validators now active)",
                                validator_count
                            );
                            // CONS-512: do NOT call `sync_height_with_blockchain`
                            // here. The engine's height was initialized from
                            // storage at boot and has been authoritatively
                            // advanced by `process_committed_block` ever since.
                            // Re-reading storage at mode transition would
                            // regress the engine to whatever sled flushed last,
                            // re-introducing the pre-CONS-512 wedge bug.
                            // Snapshot validator set for the current height.
                            self.snapshot_validator_set(self.current_round.height);
                            // Emit mode transition event
                            self.emit_liveness_event(ConsensusEvent::ModeTransitionToBft {
                                validator_count,
                                height: self.current_round.height,
                                timestamp,
                            });

                            // Re-arm timer; the Bootstrapping→Idle gate runs on every
                            // tick below (not only on this transition edge), so peers'
                            // heights arriving later still cause us to advance.
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

                    // Bootstrapping→Idle gate: evaluated every tick (not only on
                    // the mode-transition edge above) so that peer heights observed
                    // AFTER we entered BFT mode still unblock us. Previously this
                    // check only ran inside the `current_bft_mode != last_bft_mode`
                    // block, which meant that if `last_height_seen` was still 0 at
                    // the moment we transitioned, we'd stay in Bootstrapping forever
                    // even after peer proposals/votes arrived (CR #2660).
                    //
                    // Require BOTH a confirmed observation of a peer's height
                    // (`last_height_seen > 1`) AND local-within-2-of-tip. The
                    // weaker `last_height_seen <= 1` short-circuit would let a
                    // freshly-restarted node — having received zero proposals yet
                    // — start proposing into a partition before any sync. Fresh
                    // networks come up via the bootstrap (mining-loop) path until
                    // enough validators exist for BFT.
                    if current_bft_mode
                        && matches!(self.fsm_state, lib_consensus_core::fsm::ValidatorState::Bootstrapping)
                    {
                        let blockchain_height = self.current_round.height.saturating_sub(1);

                        // In development mode, skip the peer-height catch-up check
                        // and immediately transition to active consensus. This allows
                        // single-validator dev/test nodes to bypass the network-height
                        // gate that expects peer observations before entering Idle.
                        let caught_up = if self.config.development_mode {
                            true
                        } else {
                            last_height_seen > 1
                                && blockchain_height + 2 >= last_height_seen
                        };

                        if !caught_up {
                            tracing::debug!(
                                "⛏️ Still catching up: local height {}, network height ~{}",
                                blockchain_height,
                                last_height_seen,
                            );
                            if let Some(ref trigger) = self.catch_up_sync_trigger {
                                trigger.trigger(last_height_seen);
                            }
                        } else {
                            tracing::info!(
                                "🛡️ Caught up at height {} — entering active consensus",
                                self.current_round.height,
                            );
                            let (next, actions) = lib_consensus_core::fsm::transition(
                                self.fsm_state.clone(),
                                lib_consensus_core::fsm::events::Event::BootstrapComplete,
                            );
                            self.enter_fsm_state(next).await;
                            for action in actions {
                                self.dispatch_action(action).await;
                            }
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
                            if let Err(e) = self.enter_propose_step().await {
                                tracing::warn!("Failed to enter propose step: {}", e);
                            }
                        }
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
                            // CONS-305: In Bootstrapping/CatchingUp states, don't process
                            // proposals through old handlers — the FSM will ignore them.
                            // This prevents the race where all nodes propose simultaneously.
                            if matches!(
                                self.fsm_state,
                                lib_consensus_core::fsm::ValidatorState::Bootstrapping
                                    | lib_consensus_core::fsm::ValidatorState::CatchingUp { .. }
                            ) {
                                tracing::debug!(
                                    "Ignoring network message in {:?} state",
                                    self.fsm_state
                                );
                                // Still need to re-arm timer and check height
                            } else {
                                self.on_message(msg).await?;
                            }

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

                        // Broadcast heartbeat (best-effort, ignore failures).
                        // wrap_heartbeat signs the outer envelope so receivers
                        // running with `bootstrap_tofu = false` (Mainnet) can
                        // verify against `HeartbeatSigningPayload` instead of
                        // dropping unsigned messages.
                        let msg = wrap_heartbeat(heartbeat_msg, self.validator_keypair.as_ref());
                        self.broadcast(msg, &validator_ids).await;
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

                // CONS-309 / CONS-502b: drain runtime-injected FSM events
                // (today: `WatchdogFired` from the runtime's watchdog
                // task). Each event flows through `transition()` exactly
                // like a network message would, so the FSM stays the
                // single source of truth and the runtime never mutates
                // engine state directly.
                Some(event) = recv_runtime_event(&mut runtime_event_rx) => {
                    let prior = self.fsm_state.clone();
                    let (next, actions) =
                        lib_consensus_core::fsm::transition(prior, event);
                    self.enter_fsm_state(next).await;
                    for action in actions {
                        self.dispatch_action(action).await;
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
            ValidatorMessage::Propose(propose_msg) => {
                self.on_proposal(propose_msg.proposal).await?;
            }
            ValidatorMessage::Vote(vote_msg) => {
                if let Err(reason) =
                    lib_consensus_core::build_id::validate_peer_build_id(&vote_msg.build_id)
                {
                    tracing::warn!(
                        "Vote rejected: {} — peer epoch {:?}, we require {:?} \
                         (voter {} H={} R={} {:?})",
                        reason.as_str(),
                        vote_msg.build_id,
                        lib_consensus_core::build_id::CONSENSUS_BUILD_ID,
                        vote_msg.voter,
                        vote_msg.vote.height,
                        vote_msg.vote.round,
                        vote_msg.vote.vote_type,
                    );
                    return Ok(());
                }

                let vote = vote_msg.vote;
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
            ValidatorMessage::Heartbeat(heartbeat_msg) => {
                // Process heartbeat (advisory only, never affects consensus)
                let is_validator = |vid: &IdentityId| {
                    self.validator_manager
                        .get_active_validators()
                        .iter()
                        .any(|v| v.identity == *vid)
                };

                let validator_id = heartbeat_msg.validator.clone();
                let result = self.heartbeat_tracker.process_heartbeat(
                    heartbeat_msg,
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
            ValidatorMessage::Halt(halt_msg) => {
                tracing::warn!(
                    "🛑 Received HALT command from network: reason={}, height={}, initiated_by={}",
                    halt_msg.reason,
                    halt_msg.height,
                    halt_msg.initiated_by,
                );
                // Inject HaltScheduled into the FSM
                let (next, actions) = lib_consensus_core::fsm::transition(
                    self.fsm_state.clone(),
                    lib_consensus_core::fsm::events::Event::HaltScheduled {
                        reason: lib_consensus_core::fsm::state::HaltReason::UpgradeScheduled,
                        triggered_at_height: self.current_round.height,
                        resume_condition: lib_consensus_core::fsm::events::ResumeConditionEvent::ManualRestart,
                    },
                );
                self.enter_fsm_state(next).await;
                for action in actions {
                    self.dispatch_action(action).await;
                }
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

/// Helper for `tokio::select!`: receives from the runtime FSM-event channel
/// if present, or pends forever if the runtime hasn't installed one.
/// Pending-forever keeps the channel branch dormant in the legacy zhtp path
/// where `run_consensus_loop` is called directly without a runtime wrapper.
async fn recv_runtime_event(
    rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<lib_consensus_core::fsm::Event>>,
) -> Option<lib_consensus_core::fsm::Event> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}
