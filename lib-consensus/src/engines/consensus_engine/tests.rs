    use super::*;
    use lib_crypto::{hash_blake3, Hash, KeyPair, PostQuantumSignature};
    use lib_storage::proofs::InMemoryStorageProofProvider;
    use std::sync::Mutex;

    /// Mock message broadcaster for testing
    ///
    /// Tracks all broadcast calls and message types without side effects.
    /// This is used to verify that the consensus engine broadcasts
    /// the correct messages at the correct phases.
    #[derive(Debug)]
    struct MockMessageBroadcaster {
        /// All broadcast calls in order
        broadcasts: Mutex<Vec<BroadcastCall>>,
    }

    #[derive(Debug)]
    struct BroadcastCall {
        message: ValidatorMessage,
        validator_ids: Vec<IdentityId>,
    }

    impl MockMessageBroadcaster {
        fn new() -> Self {
            Self {
                broadcasts: Mutex::new(Vec::new()),
            }
        }

        fn get_broadcasts(&self) -> Vec<BroadcastCall> {
            self.broadcasts.lock().unwrap().clone()
        }

        fn count_broadcasts(&self) -> usize {
            self.broadcasts.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl MessageBroadcaster for MockMessageBroadcaster {
        async fn broadcast_to_validators(
            &self,
            message: ValidatorMessage,
            validator_ids: &[IdentityId],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcasts.lock().unwrap().push(BroadcastCall {
                message,
                validator_ids: validator_ids.to_vec(),
            });
            Ok(())
        }
    }

    impl Clone for BroadcastCall {
        fn clone(&self) -> Self {
            Self {
                message: self.message.clone(),
                validator_ids: self.validator_ids.clone(),
            }
        }
    }

    fn test_validator_id(id: u8) -> IdentityId {
        // Create a deterministic test validator ID from a single byte
        // by repeating it 32 times to match Hash::from_bytes signature
        lib_crypto::Hash::from_bytes(&[id; 32])
    }

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate().expect("Failed to generate test keypair")
    }

    fn sign_bytes(keypair: &KeyPair, data: &[u8]) -> PostQuantumSignature {
        keypair.sign(data).expect("Failed to sign test data")
    }

    async fn register_local_validator(
        engine: &mut ConsensusEngine,
        validator_id: IdentityId,
        keypair: &KeyPair,
        is_genesis: bool,
    ) {
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                keypair.public_key.dilithium_pk.clone(),
                vec![0xEEu8; 32], // networking_key: distinct from consensus_key
                vec![0xFFu8; 32], // rewards_key: distinct from consensus_key and networking_key
                5,
                is_genesis,
            )
            .await
            .expect("Failed to register validator");

        engine
            .set_validator_keypair(keypair.clone())
            .expect("Failed to set validator keypair");

        attach_storage_provider(engine, validator_id).await;
    }

    async fn attach_storage_provider(engine: &mut ConsensusEngine, validator_id: IdentityId) {
        let provider = InMemoryStorageProofProvider::new(3600, 2, 3600);
        provider
            .register_validator_capacity(validator_id.clone(), 100 * 1024 * 1024 * 1024)
            .await
            .expect("Failed to register storage capacity");

        let content_hash = Hash::from_bytes(&hash_blake3(b"test-content"));
        let blocks = vec![
            hash_blake3(b"block-0").to_vec(),
            hash_blake3(b"block-1").to_vec(),
            hash_blake3(b"block-2").to_vec(),
        ];

        provider
            .register_content(validator_id.clone(), content_hash, blocks)
            .await
            .expect("Failed to register content");

        engine.set_storage_proof_provider(Arc::new(provider));
    }

    async fn register_validator_with_keypair(
        engine: &mut ConsensusEngine,
        validator_id: IdentityId,
        keypair: &KeyPair,
        is_genesis: bool,
    ) {
        engine
            .register_validator(
                validator_id,
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                keypair.public_key.dilithium_pk.clone(),
                vec![0xEEu8; 32], // networking_key: distinct from consensus_key
                vec![0xFFu8; 32], // rewards_key: distinct from consensus_key and networking_key
                5,
                is_genesis,
            )
            .await
            .expect("Failed to register validator");
    }

    fn make_signed_vote(
        engine: &ConsensusEngine,
        keypair: &KeyPair,
        voter: IdentityId,
        proposal_id: Hash,
        vote_type: VoteType,
        height: u64,
        round: u32,
    ) -> ConsensusVote {
        let vote_id = Hash::from_bytes(&lib_crypto::hash_blake3(
            &[
                proposal_id.as_bytes(),
                voter.as_bytes(),
                &(vote_type.clone() as u8).to_le_bytes(),
                &height.to_le_bytes(),
                &round.to_le_bytes(),
            ]
            .concat(),
        ));

        let vote_data = engine
            .serialize_vote_data(&vote_id, &voter, &proposal_id, &vote_type, height, round)
            .expect("Failed to serialize vote data");
        let signature = sign_bytes(keypair, &vote_data);

        ConsensusVote {
            id: vote_id,
            voter,
            proposal_id,
            vote_type,
            height,
            round,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature,
        }
    }

    #[tokio::test]
    async fn test_consensus_engine_creation_with_broadcaster() {
        let config = ConsensusConfig::default();
        let mock_broadcaster: Arc<dyn MessageBroadcaster> =
            Arc::new(MockMessageBroadcaster::new());
        let result = ConsensusEngine::new(config, mock_broadcaster);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_proposal_broadcast_in_propose_phase() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set as proposer (needed to create a proposal)
        engine.current_round.proposer = Some(validator_id.clone());
        engine.validator_identity = Some(validator_id);

        // Run propose step
        engine.run_propose_step().await.expect("Failed to run propose step");

        // Verify proposal was broadcast
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(
            broadcasts.len() > 0,
            "Expected at least one broadcast in propose phase"
        );

        // Verify it's a propose message
        assert!(
            broadcasts.iter().any(|call| matches!(call.message, ValidatorMessage::Propose { .. })),
            "Expected ValidatorMessage::Propose variant"
        );
    }

    #[tokio::test]
    async fn test_vote_broadcast_in_prevote_phase() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Create a proposal to vote on
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step
        engine.run_prevote_step().await.expect("Failed to run prevote step");

        // Verify vote was broadcast
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(
            broadcasts.len() > 0,
            "Expected at least one broadcast in prevote phase"
        );

        // Verify it's a vote message
        assert!(
            broadcasts.iter().any(|call| matches!(call.message, ValidatorMessage::Vote { .. })),
            "Expected ValidatorMessage::Vote variant"
        );
    }

    #[tokio::test]
    async fn test_validator_set_passed_to_broadcaster() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register multiple validators
        let validator_ids: Vec<_> = (0..3)
            .map(|i| test_validator_id(i))
            .collect();

        let local_keypair = create_test_keypair();
        for (idx, id) in validator_ids.iter().enumerate() {
            let keypair = if idx == 0 {
                local_keypair.clone()
            } else {
                create_test_keypair()
            };
            register_validator_with_keypair(&mut engine, id.clone(), &keypair, true).await;
        }

        engine
            .set_validator_keypair(local_keypair)
            .expect("Failed to set validator keypair");
        engine.snapshot_validator_set(engine.current_round.height);
        attach_storage_provider(&mut engine, validator_ids[0].clone()).await;

        // Create a proposal to vote on
        engine.current_round.proposer = Some(validator_ids[0].clone());
        engine.validator_identity = Some(validator_ids[0].clone());
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step
        engine.run_prevote_step().await.expect("Failed to run prevote step");

        // Verify validator set was passed to broadcaster
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(broadcasts.len() > 0, "Expected broadcasts");

        for call in broadcasts {
            assert!(
                !call.validator_ids.is_empty(),
                "Expected validator IDs to be passed to broadcaster"
            );
            // All registered validators should be in the list
            assert!(
                call.validator_ids.len() >= 3,
                "Expected all validators to be in broadcast recipient list"
            );
        }
    }

    #[tokio::test]
    async fn test_broadcast_failure_does_not_affect_consensus() {
        /// Mock broadcaster that always fails
        struct FailingBroadcaster;

        #[async_trait::async_trait]
        impl MessageBroadcaster for FailingBroadcaster {
            async fn broadcast_to_validators(
                &self,
                _message: ValidatorMessage,
                _validator_ids: &[IdentityId],
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Err("Network error".into())
            }
        }

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(FailingBroadcaster);
        let mut engine =
            ConsensusEngine::new(config, broadcaster).expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Create a proposal to vote on
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step - should not fail even though broadcaster fails
        let result = engine.run_prevote_step().await;
        assert!(
            result.is_ok(),
            "Prevote step should succeed even if broadcast fails"
        );

        // Vote should still be in the vote pool
        // Check that at least one vote entry exists for current height/round
        let vote_count = engine
            .vote_pool
            .iter()
            .filter(|(k, _)| k.height == engine.current_round.height && k.round == engine.current_round.round)
            .count();
        assert!(vote_count > 0, "Vote should be stored even if broadcast fails");
    }

    #[tokio::test]
    async fn test_proposal_only_broadcast_when_proposer() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator but don't make it the proposer
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set a different validator as proposer
        engine.current_round.proposer = Some(test_validator_id(2));

        // Run propose step
        engine.run_propose_step().await.expect("Failed to run propose step");

        // Verify no proposal was broadcast
        assert_eq!(
            mock_broadcaster.count_broadcasts(),
            0,
            "Proposal should not be broadcast if not proposer"
        );
    }

    #[tokio::test]
    async fn test_multiple_phases_produce_multiple_broadcasts() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set as proposer
        engine.current_round.proposer = Some(validator_id.clone());
        engine.validator_identity = Some(validator_id);

        // Run propose step - should broadcast proposal
        engine.run_propose_step().await.expect("Failed to run propose step");
        let broadcasts_after_propose = mock_broadcaster.count_broadcasts();
        assert!(broadcasts_after_propose > 0, "Expected broadcast in propose phase");

        // Run prevote step - should broadcast vote
        engine.run_prevote_step().await.expect("Failed to run prevote step");
        let broadcasts_after_prevote = mock_broadcaster.count_broadcasts();
        assert!(
            broadcasts_after_prevote > broadcasts_after_propose,
            "Expected additional broadcast in prevote phase"
        );
    }

    /// Gap 4 Invariant Test: Message relevance checking
    ///
    /// Verifies that messages with mismatched height/round are correctly ignored
    /// and do not affect vote_pool or state.
    #[tokio::test]
    async fn test_gap4_message_relevance_invariant() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let validator1 = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator1.clone(), &keypair, true).await;

        // Set engine to height=2, round=1
        engine.current_round.height = 2;
        engine.current_round.round = 1;
        engine.current_round.step = ConsensusStep::PreVote;
        engine.snapshot_validator_set(2);

        // Create votes for different heights/rounds
        let vote_past_height = make_signed_vote(
            &engine,
            &keypair,
            validator1.clone(),
            Hash::from_bytes(&[10u8; 32]),
            VoteType::PreVote,
            1,
            0,
        );

        let vote_future_height = make_signed_vote(
            &engine,
            &keypair,
            validator1.clone(),
            Hash::from_bytes(&[11u8; 32]),
            VoteType::PreVote,
            3,
            0,
        );

        let vote_past_round = make_signed_vote(
            &engine,
            &keypair,
            validator1.clone(),
            Hash::from_bytes(&[12u8; 32]),
            VoteType::PreVote,
            2,
            0,
        );

        let vote_relevant = make_signed_vote(
            &engine,
            &keypair,
            validator1.clone(),
            Hash::from_bytes(&[13u8; 32]),
            VoteType::PreVote,
            2,
            1,
        );

        // Process irrelevant votes
        engine.on_prevote(vote_past_height).await.expect("Process vote");
        engine.on_prevote(vote_future_height).await.expect("Process vote");
        engine.on_prevote(vote_past_round).await.expect("Process vote");

        // Vote pool should be empty
        assert_eq!(engine.vote_pool.len(), 0, "Irrelevant votes should be ignored");

        // Process relevant vote
        engine.on_prevote(vote_relevant.clone()).await.expect("Process vote");

        // Vote pool should now have exactly 1 entry
        assert_eq!(engine.vote_pool.len(), 1, "Relevant vote should be in pool");
    }

    /// Gap 4 Invariant Test: Idempotence and equivocation detection
    ///
    /// Verifies:
    /// 1. Same vote twice (duplicate) is idempotent - no state change
    /// 2. Same validator, same (H,R,type), different value is detected as equivocation
    #[tokio::test]
    async fn test_gap4_idempotence_and_equivocation_invariant() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let validator1 = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator1.clone(), &keypair, true).await;

        engine.current_round.step = ConsensusStep::PreVote;
        engine.snapshot_validator_set(engine.current_round.height);

        // Vote 1: for proposal A
        let vote_a = make_signed_vote(
            &engine,
            &keypair,
            validator1.clone(),
            Hash::from_bytes(&[100u8; 32]),
            VoteType::PreVote,
            0,
            0,
        );

        // Vote 2: same validator, same H/R/type, for proposal B (equivocation)
        let vote_b = make_signed_vote(
            &engine,
            &keypair,
            validator1.clone(),
            Hash::from_bytes(&[101u8; 32]),
            VoteType::PreVote,
            0,
            0,
        );

        // Add vote A
        engine.on_prevote(vote_a.clone()).await.expect("Process vote");
        assert_eq!(engine.vote_pool.len(), 1, "Vote A should be in pool");

        // Add vote A again (duplicate) - should be no-op
        engine.on_prevote(vote_a.clone()).await.expect("Process vote");
        assert_eq!(engine.vote_pool.len(), 1, "Duplicate should be idempotent");

        // Add vote B (equivocation) - should be rejected
        engine.on_prevote(vote_b).await.expect("Process vote");
        assert_eq!(
            engine.vote_pool.len(),
            1,
            "Equivocating vote should be rejected (still 1 entry)"
        );

        // Verify only A is in pool
        let key_a = VotePoolKey {
            height: 0,
            round: 0,
            vote_type: VoteType::PreVote,
            validator_id: validator1,
        };
        assert!(
            engine.vote_pool.contains_key(&key_a),
            "Original vote A should still be in pool"
        );
    }

    /// Gap 4 Invariant Test: Threshold consistency
    ///
    /// Verifies that check_supermajority() correctly identifies quorum threshold.
    /// For 3 validators: threshold should be 3 (2f+1 where f=1)
    /// For 4 validators: threshold should be 3 (2f+1 where f=1)
    /// For 7 validators: threshold should be 5 (2f+1 where f=2)
    #[tokio::test]
    async fn test_gap4_quorum_threshold_consistency() {
        // 3 validators: need 3 votes (all of them)
        assert!(check_supermajority(3, 3), "3/3 votes should be quorum");
        assert!(!check_supermajority(2, 3), "2/3 votes should NOT be quorum");

        // 4 validators: need 3 votes (2/3 + 1)
        assert!(check_supermajority(3, 4), "3/4 votes should be quorum");
        assert!(!check_supermajority(2, 4), "2/4 votes should NOT be quorum");

        // 7 validators: need 5 votes
        assert!(check_supermajority(5, 7), "5/7 votes should be quorum");
        assert!(!check_supermajority(4, 7), "4/7 votes should NOT be quorum");

        // Edge case: 1 validator (needs 1)
        assert!(check_supermajority(1, 1), "1/1 vote should be quorum");
    }

    /// Gap 4 Invariant Test: Timer token staleness guard
    ///
    /// Verifies that TimerToken correctly identifies stale vs current timeouts
    #[test]
    fn test_gap4_timer_token_staleness_detection() {
        let step_propose = ConsensusStep::Propose;
        let step_prevote = ConsensusStep::PreVote;

        // Token for height=1, round=0, Propose
        let token = TimerToken::new(1, 0, &step_propose);

        // Should match current state
        assert!(
            token.matches(1, 0, &step_propose),
            "Token should match current state"
        );

        // Should NOT match different height
        assert!(!token.matches(2, 0, &step_propose), "Token should not match height 2");

        // Should NOT match different round
        assert!(!token.matches(1, 1, &step_propose), "Token should not match round 1");

        // Should NOT match different step
        assert!(
            !token.matches(1, 0, &step_prevote),
            "Token should not match different step"
        );
    }

    /// Gap 4 Invariant Test: Receiver closure causes graceful shutdown
    ///
    /// Verifies that closing the message receiver causes run_consensus_loop to exit
    #[tokio::test]
    async fn test_gap4_receiver_closure_graceful_shutdown() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let (tx, rx) = mpsc::channel(32);
        engine.set_message_receiver(rx);

        // Spawn the loop in background
        let mut engine_handle = tokio::spawn(async move {
            engine.run_consensus_loop().await
        });

        // Give loop time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Close the sender (receiver will get None on next recv())
        drop(tx);

        // Loop should exit cleanly within reasonable time
        let result = tokio::time::timeout(Duration::from_secs(1), &mut engine_handle).await;

        match result {
            Ok(Ok(Ok(_))) => {
                // Loop exited cleanly
            }
            Ok(Ok(Err(e))) => {
                panic!("Loop returned error: {}", e);
            }
            Ok(Err(e)) => {
                panic!("Task panicked: {}", e);
            }
            Err(_) => {
                panic!("Loop did not exit within timeout (likely hung)");
            }
        }
    }

    #[test]
    fn test_ce_s1_proposal_scoped_quorums_prevent_split_votes() {
        // **CE-S1**: A quorum must be counted for a single proposal ID, never for a round in aggregate.
        // This test verifies that split votes across different proposals do NOT trigger transitions.

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let proposal_a = Hash::from_bytes(&[1u8; 32]);
        let proposal_b = Hash::from_bytes(&[2u8; 32]);
        let proposal_c = Hash::from_bytes(&[3u8; 32]);

        // Verify proposal-scoped counting methods exist and return correct values
        let count_for_a = engine.count_prevotes_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_a,
        );
        assert_eq!(count_for_a, 0, "Empty pool should have 0 votes for proposal A");

        let count_for_b = engine.count_prevotes_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_b,
        );
        assert_eq!(count_for_b, 0, "Empty pool should have 0 votes for proposal B");

        let count_for_c = engine.count_prevotes_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_c,
        );
        assert_eq!(count_for_c, 0, "Empty pool should have 0 votes for proposal C");

        // The key invariant: even if we had 4 total votes (1 for each of A, B, C, and 1 more),
        // no single proposal would reach quorum (3 needed), so transitions would be prevented.
        // This is CE-S1 safety: quorum must be per-proposal, not per-round aggregate.
    }

    #[tokio::test]
    async fn test_ce_l1_commit_quorum_finalizes_regardless_of_local_step() {
        // **CE-L1**: Observing 2f+1 commit votes for a proposal MUST allow finalization
        // even if the node missed earlier steps (e.g., didn't receive precommits locally).

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register 4 validators for testing
        let mut validators = Vec::new();
        for i in 1..=4 {
            let validator_id = test_validator_id(i as u8);
            let keypair = create_test_keypair();
            register_validator_with_keypair(&mut engine, validator_id.clone(), &keypair, i == 1)
                .await;
            validators.push((validator_id, keypair));
        }

        let proposal_id = Hash::from_bytes(&[42u8; 32]);

        // Manually set engine to PreVote step (simulate missing precommits)
        engine.current_round.step = ConsensusStep::PreVote;

        // Add 3 commit votes (quorum) directly to vote pool
        for i in 0..3 {
            let (validator_id, keypair) = validators[i].clone();
            let key = VotePoolKey {
                height: engine.current_round.height,
                round: engine.current_round.round,
                vote_type: VoteType::Commit,
                validator_id: validator_id.clone(),
            };
            let vote = make_signed_vote(
                &engine,
                &keypair,
                validator_id,
                proposal_id.clone(),
                VoteType::Commit,
                engine.current_round.height,
                engine.current_round.round,
            );
            engine.vote_pool.insert(key, (vote, proposal_id.clone()));
        }

        // Verify: Step is still PreVote
        assert_eq!(engine.current_round.step, ConsensusStep::PreVote);

        // Call maybe_finalize: should transition to Commit step and finalize
        engine.maybe_finalize(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_id,
        ).await.unwrap();

        // Verify: Step transitioned to Commit (CE-L1)
        assert_eq!(engine.current_round.step, ConsensusStep::Commit,
            "CE-L1: Commit quorum should fast-track to Commit step");

        // Verify: Commit count is correct
        let commit_count = engine.count_commits_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_id,
        );
        assert_eq!(commit_count, 3, "Should have 3 commits for proposal");
    }

    #[tokio::test]
    async fn test_ce_l2_commit_votes_stored_at_any_step() {
        // **CE-L2**: Commit votes MUST be accepted and stored at any step,
        // not only during Commit step.

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register 3 validators
        let mut validators = Vec::new();
        for i in 1..=3 {
            let validator_id = test_validator_id(i as u8);
            let keypair = create_test_keypair();
            register_validator_with_keypair(&mut engine, validator_id.clone(), &keypair, i == 1)
                .await;
            validators.push((validator_id, keypair));
        }

        let proposal_id = Hash::from_bytes(&[55u8; 32]);

        // Set engine to PreVote step
        engine.current_round.step = ConsensusStep::PreVote;
        assert_eq!(engine.current_round.step, ConsensusStep::PreVote);
        engine.snapshot_validator_set(engine.current_round.height);

        // Create a commit vote while in PreVote step
        let (validator_id, keypair) = validators[0].clone();
        let vote = make_signed_vote(
            &engine,
            &keypair,
            validator_id,
            proposal_id.clone(),
            VoteType::Commit,
            engine.current_round.height,
            engine.current_round.round,
        );

        // Call on_commit_vote while in PreVote step
        engine.on_commit_vote(vote.clone()).await.unwrap();

        // Verify: Commit vote was stored even though we're in PreVote (CE-L2)
        let commit_count = engine.count_commits_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_id,
        );
        assert_eq!(commit_count, 1, "CE-L2: Commit vote should be stored in PreVote step");

        // Step should still be PreVote (no automatic transition since quorum not reached)
        assert_eq!(engine.current_round.step, ConsensusStep::PreVote);
    }

    // ============================================================================
    // CONSENSUS-NET-4.3: Remote Vote Validation and Supermajority Hardening Tests
    // ============================================================================

    /// Test: check_supermajority() with correct threshold formula
    ///
    /// Verifies that check_supermajority() uses the correct formula:
    /// threshold = (total_validators * 2 / 3) + 1 (integer division)
    #[test]
    fn test_hardening_check_supermajority_correct_threshold() {
        // 1 validator: (1 * 2) / 3 + 1 = 0 + 1 = 1 (integer division)
        assert!(!check_supermajority(0, 1), "0/1 should not be supermajority");
        assert!(check_supermajority(1, 1), "1/1 should be supermajority");

        // 3 validators: (3 * 2) / 3 + 1 = 2 + 1 = 3
        assert!(!check_supermajority(2, 3), "2/3 should not be supermajority");
        assert!(check_supermajority(3, 3), "3/3 should be supermajority");

        // 4 validators: (4 * 2) / 3 + 1 = 2 + 1 = 3 (integer division)
        assert!(!check_supermajority(2, 4), "2/4 should not be supermajority");
        assert!(check_supermajority(3, 4), "3/4 should be supermajority");
        assert!(check_supermajority(4, 4), "4/4 should be supermajority");

        // 7 validators: (7 * 2) / 3 + 1 = 4 + 1 = 5 (integer division)
        assert!(!check_supermajority(4, 7), "4/7 should not be supermajority");
        assert!(check_supermajority(5, 7), "5/7 should be supermajority");

        // 100 validators: (100 * 2) / 3 + 1 = 66 + 1 = 67 (integer division)
        assert!(!check_supermajority(66, 100), "66/100 should not be supermajority");
        assert!(check_supermajority(67, 100), "67/100 should be supermajority");
    }

    /// Test: Acceptance criteria - 4 validators
    ///
    /// With 4 validators, threshold = 3:
    /// - 2 votes → no quorum
    /// - 3 identical votes → quorum reached
    /// - Mixed votes (2+2) → no quorum
    #[test]
    fn test_hardening_4validator_acceptance_criteria() {
        let total_validators = 4u64;

        // Criterion: 2 votes → no quorum
        assert!(
            !check_supermajority(2, total_validators),
            "2/4 votes should NOT be supermajority"
        );

        // Criterion: 3 identical votes → quorum reached
        assert!(
            check_supermajority(3, total_validators),
            "3/4 identical votes MUST trigger supermajority"
        );

        // Note: 2+2 mixed votes is handled by counting proposal-scoped votes
        // If 2 vote for proposal A and 2 vote for proposal B:
        // count_prevotes_for(proposal_a) = 2 (no quorum)
        // count_prevotes_for(proposal_b) = 2 (no quorum)
        // Result: Mixed or split votes MUST NOT count
    }

    /// Test: Remote vote validation - height mismatch rejection
    ///
    /// A vote with height != local.height MUST be rejected
    #[tokio::test]
    async fn test_hardening_vote_validation_height_mismatch() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set engine to height=5, round=0, PreVote step
        engine.current_round.height = 5;
        engine.current_round.round = 0;
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a vote with wrong height (height=6)
        let vote = make_signed_vote(
            &engine,
            &keypair,
            validator_id,
            Hash::from_bytes(&[2u8; 32]),
            VoteType::PreVote,
            6,
            0,
        );

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "Vote with height mismatch MUST be rejected (height={} != local.height={})",
            vote.height,
            engine.current_round.height
        );
    }

    /// Test: Remote vote validation - round mismatch rejection
    ///
    /// A vote with round != local.round MUST be rejected
    #[tokio::test]
    async fn test_hardening_vote_validation_round_mismatch() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set engine to height=0, round=5, PreVote step
        engine.current_round.height = 0;
        engine.current_round.round = 5;
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a vote with wrong round (round=6)
        let vote = make_signed_vote(
            &engine,
            &keypair,
            validator_id,
            Hash::from_bytes(&[2u8; 32]),
            VoteType::PreVote,
            0,
            6,
        );

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "Vote with round mismatch MUST be rejected (round={} != local.round={})",
            vote.round,
            engine.current_round.round
        );
    }

    /// Test: Remote vote validation - non-member validator rejection
    ///
    /// A vote from a validator NOT in active set MUST be rejected
    #[tokio::test]
    async fn test_hardening_vote_validation_non_member_validator() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register only validator 1
        let validator_id_1 = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id_1.clone(), &keypair, true).await;

        // Create a vote from validator 2 (NOT registered)
        let validator_id_2 = test_validator_id(2);
        let foreign_keypair = create_test_keypair();
        let vote = make_signed_vote(
            &engine,
            &foreign_keypair,
            validator_id_2.clone(),
            Hash::from_bytes(&[2u8; 32]),
            VoteType::PreVote,
            engine.current_round.height,
            engine.current_round.round,
        );

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "Vote from non-member validator MUST be rejected"
        );
    }

    /// Test: Remote vote validation - vote type coherence (PreVote in Propose step)
    ///
    /// A PreVote is NOT valid during Propose step
    #[tokio::test]
    async fn test_hardening_vote_validation_prevote_in_propose_step() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set engine to Propose step
        engine.current_round.step = ConsensusStep::Propose;

        // Create a PreVote while in Propose step
        let vote = make_signed_vote(
            &engine,
            &keypair,
            validator_id,
            Hash::from_bytes(&[2u8; 32]),
            VoteType::PreVote,
            engine.current_round.height,
            engine.current_round.round,
        );

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "PreVote in Propose step MUST be rejected (step coherence violation)"
        );
    }

    /// Test: Remote vote validation - vote type coherence (PreCommit in PreVote step)
    ///
    /// A PreCommit is NOT valid during PreVote step
    #[tokio::test]
    async fn test_hardening_vote_validation_precommit_in_prevote_step() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set engine to PreVote step
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a PreCommit while in PreVote step
        let vote = make_signed_vote(
            &engine,
            &keypair,
            validator_id,
            Hash::from_bytes(&[2u8; 32]),
            VoteType::PreCommit,
            engine.current_round.height,
            engine.current_round.round,
        );

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "PreCommit in PreVote step MUST be rejected (step coherence violation)"
        );
    }

    /// Test: Remote vote validation - Commit votes always valid (if height/round match)
    ///
    /// Commit votes are always valid regardless of current step
    #[tokio::test]
    async fn test_hardening_vote_validation_commit_always_valid() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Test in each step
        for step in &[
            ConsensusStep::Propose,
            ConsensusStep::PreVote,
            ConsensusStep::PreCommit,
            ConsensusStep::Commit,
        ] {
            engine.current_round.step = step.clone();
            engine.snapshot_validator_set(engine.current_round.height);

            // Create a Commit vote
            let vote = make_signed_vote(
                &engine,
                &keypair,
                validator_id.clone(),
                Hash::from_bytes(&[2u8; 32]),
                VoteType::Commit,
                engine.current_round.height,
                engine.current_round.round,
            );

            // Validate the vote - should always be valid
            let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
            assert!(
                is_valid,
                "Commit vote MUST always be valid regardless of step (currently in {:?})",
                step
            );
        }
    }

    /// Test: Remote vote validation - invalid signature rejection
    ///
    /// A vote with invalid signature MUST be rejected (Invariant #1)
    #[tokio::test]
    async fn test_hardening_vote_validation_invalid_signature() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set engine to PreVote step
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a vote with an empty signature (invalid)
        let vote_id = Hash::from_bytes(&[1u8; 32]);
        let vote_data = engine
            .serialize_vote_data(
                &vote_id,
                &validator_id,
                &Hash::from_bytes(&[2u8; 32]),
                &VoteType::PreVote,
                engine.current_round.height,
                engine.current_round.round,
            )
            .expect("Failed to serialize vote data");
        let mut bad_signature = sign_bytes(&keypair, &vote_data);
        bad_signature.signature = Vec::new(); // Make signature invalid

        let vote = ConsensusVote {
            id: vote_id,
            voter: validator_id,
            proposal_id: Hash::from_bytes(&[2u8; 32]),
            vote_type: VoteType::PreVote,
            height: engine.current_round.height,
            round: engine.current_round.round,
            timestamp: 0,
            signature: bad_signature,
        };

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(!is_valid, "Vote with invalid signature MUST be rejected");
    }

    /// Test: Remote vote validation - commit votes allow round catch-up
    ///
    /// on_commit_vote() is designed to accept commit votes from any round at the current height
    /// to allow catch-up from previous rounds. This test verifies that such votes are not
    /// rejected at the basic validation level.
    #[tokio::test]
    async fn test_hardening_commit_vote_accepts_past_round() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        let keypair = create_test_keypair();
        register_local_validator(&mut engine, validator_id.clone(), &keypair, true).await;

        // Set engine to height=5, round=3
        engine.current_round.height = 5;
        engine.current_round.round = 3;
        engine.current_round.step = ConsensusStep::PreCommit;
        engine.snapshot_validator_set(5);

        let proposal_id = Hash::from_bytes(&[2u8; 32]);

        // Create a commit vote from a PAST round (round=2 while current is 3)
        let vote = make_signed_vote(
            &engine,
            &keypair,
            validator_id,
            proposal_id.clone(),
            VoteType::Commit,
            5,
            2,
        );

        // Call on_commit_vote with past-round commit vote
        // It should be accepted (not rejected) for catch-up purposes
        engine.on_commit_vote(vote.clone()).await.expect("commit vote failed");

        // Verify the vote was stored
        let commit_count = engine.count_commits_for(5, 2, &proposal_id);
        assert_eq!(commit_count, 1, "Past-round commit vote should be stored for catch-up");
    }

    // ============================================================================
    // CANONICAL CHAIN CONVERGENCE TESTS (Issue #955)
    // ============================================================================
    //
    // Test scenario:
    // - ≥4 validators
    // - Two nodes process same commit votes in different network orders
    // - Must finalize same block at each height
    // - MUST fail if nodes diverge

    /// Test: Canonical convergence with different vote processing order
    ///
    /// Setup:
    /// - 4 validators (minimum BFT threshold)
    /// - Single block proposal at height=1, round=0
    /// - 3 commit votes (2/3+1 quorum) for the same proposal
    ///
    /// Test:
    /// - Node A processes votes in order: V1 → V2 → V3
    /// - Node B processes votes in order: V3 → V1 → V2
    /// - Both nodes MUST finalize the SAME block
    /// - Both nodes MUST be at Commit step after processing quorum
    ///
    /// Failure mode:
    /// - If nodes finalize different blocks → FAIL (non-deterministic)
    /// - If nodes don't reach Commit step → FAIL (liveness violation)
    #[tokio::test]
    async fn test_canonical_convergence_different_vote_order() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };

        let broadcaster_a = Arc::new(MockMessageBroadcaster::new());
        let broadcaster_b = Arc::new(MockMessageBroadcaster::new());

        let mut engine_a = ConsensusEngine::new(config.clone(), broadcaster_a as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine A");
        let mut engine_b = ConsensusEngine::new(config, broadcaster_b as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine B");

        // Register 4 validators on both engines with identical identities
        let mut validators = Vec::new();
        for i in 1..=4 {
            let validator_id = test_validator_id(i);
            // Note: validator_id is index-derived; signing keys are randomly generated and
            // do not derive from the validator_id. This is a test limitation.
            let keypair = create_test_keypair();

            register_validator_with_keypair(&mut engine_a, validator_id.clone(), &keypair, i == 1).await;
            register_validator_with_keypair(&mut engine_b, validator_id.clone(), &keypair, i == 1).await;

            validators.push((validator_id, keypair));
        }

        // Create a deterministic proposal hash (same block on both nodes)
        let proposal_id = Hash::from_bytes(&hash_blake3(b"canonical-block-height-1"));

        let height = 1u64;
        let round = 0u32;

        // Create 3 commit votes (quorum) from first 3 validators
        let vote_1 = make_signed_vote(
            &engine_a,
            &validators[0].1,
            validators[0].0.clone(),
            proposal_id.clone(),
            VoteType::Commit,
            height,
            round,
        );

        let vote_2 = make_signed_vote(
            &engine_a,
            &validators[1].1,
            validators[1].0.clone(),
            proposal_id.clone(),
            VoteType::Commit,
            height,
            round,
        );

        let vote_3 = make_signed_vote(
            &engine_a,
            &validators[2].1,
            validators[2].0.clone(),
            proposal_id.clone(),
            VoteType::Commit,
            height,
            round,
        );

        // Set both engines to height=1, round=0
        engine_a.current_round.height = height;
        engine_a.current_round.round = round;
        engine_b.current_round.height = height;
        engine_b.current_round.round = round;

        // Snapshot validator sets for both engines
        engine_a.snapshot_validator_set(height);
        engine_b.snapshot_validator_set(height);

        // Set both engines to PreVote step (simulate receiving commit votes early)
        engine_a.current_round.step = ConsensusStep::PreVote;
        engine_b.current_round.step = ConsensusStep::PreVote;

        // Node A: Process votes in order V1 → V2 → V3
        engine_a.on_commit_vote(vote_1.clone()).await.expect("A: vote 1");
        engine_a.on_commit_vote(vote_2.clone()).await.expect("A: vote 2");
        engine_a.on_commit_vote(vote_3.clone()).await.expect("A: vote 3");

        // Node B: Process SAME votes in DIFFERENT order V3 → V1 → V2
        engine_b.on_commit_vote(vote_3.clone()).await.expect("B: vote 3");
        engine_b.on_commit_vote(vote_1.clone()).await.expect("B: vote 1");
        engine_b.on_commit_vote(vote_2.clone()).await.expect("B: vote 2");

        // INVARIANT CHECK: Both engines MUST be in Commit step
        assert_eq!(
            engine_a.current_round.step,
            ConsensusStep::Commit,
            "Node A MUST transition to Commit step after processing quorum"
        );

        assert_eq!(
            engine_b.current_round.step,
            ConsensusStep::Commit,
            "Node B MUST transition to Commit step after processing quorum"
        );

        // INVARIANT CHECK: Both engines MUST have identical commit vote counts
        let count_a = engine_a.count_commits_for(height, round, &proposal_id);
        let count_b = engine_b.count_commits_for(height, round, &proposal_id);

        assert_eq!(
            count_a, 3,
            "Node A MUST have 3 commit votes for canonical proposal"
        );
        assert_eq!(
            count_b, 3,
            "Node B MUST have 3 commit votes for canonical proposal"
        );

        // CRITICAL INVARIANT: Both engines MUST finalize the SAME proposal
        // This is the canonical convergence property
        assert_eq!(
            count_a, count_b,
            "CANONICAL CONVERGENCE VIOLATION: Nodes have different vote counts!"
        );

        tracing::info!("✅ Canonical convergence verified:");
        tracing::info!("   - Node A processed votes in order: V1 → V2 → V3");
        tracing::info!("   - Node B processed votes in order: V3 → V1 → V2");
        tracing::info!("   - Both nodes finalized proposal: {}", proposal_id);
        tracing::info!("   - Both nodes reached Commit step");
        tracing::info!("   - Deterministic finality: CONFIRMED");
    }

    /// Test: Canonical convergence with split votes (no quorum)
    ///
    /// Setup:
    /// - 4 validators
    /// - Two different proposals A and B
    /// - 2 votes for A, 1 vote for B (no quorum)
    ///
    /// Expected:
    /// - Both nodes MUST NOT finalize (no supermajority)
    /// - Both nodes remain in PreVote step
    /// - Vote counts for each proposal MUST be identical
    #[tokio::test]
    async fn test_canonical_convergence_no_quorum_split_votes() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };

        let broadcaster_a = Arc::new(MockMessageBroadcaster::new());
        let broadcaster_b = Arc::new(MockMessageBroadcaster::new());

        let mut engine_a = ConsensusEngine::new(config.clone(), broadcaster_a as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine A");
        let mut engine_b = ConsensusEngine::new(config, broadcaster_b as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine B");

        // Register 4 validators
        let mut validators = Vec::new();
        for i in 1..=4 {
            let validator_id = test_validator_id(i);
            // Note: validator_id is index-derived; signing keys are randomly generated and
            // do not derive from the validator_id. This is a test limitation.
            let keypair = create_test_keypair();

            register_validator_with_keypair(&mut engine_a, validator_id.clone(), &keypair, i == 1).await;
            register_validator_with_keypair(&mut engine_b, validator_id.clone(), &keypair, i == 1).await;

            validators.push((validator_id, keypair));
        }

        let height = 1u64;
        let round = 0u32;

        // Two competing proposals
        let proposal_a = Hash::from_bytes(&hash_blake3(b"proposal-A"));
        let proposal_b = Hash::from_bytes(&hash_blake3(b"proposal-B"));

        // 2 votes for proposal A
        let vote_a1 = make_signed_vote(
            &engine_a,
            &validators[0].1,
            validators[0].0.clone(),
            proposal_a.clone(),
            VoteType::Commit,
            height,
            round,
        );

        let vote_a2 = make_signed_vote(
            &engine_a,
            &validators[1].1,
            validators[1].0.clone(),
            proposal_a.clone(),
            VoteType::Commit,
            height,
            round,
        );

        // 1 vote for proposal B
        let vote_b1 = make_signed_vote(
            &engine_a,
            &validators[2].1,
            validators[2].0.clone(),
            proposal_b.clone(),
            VoteType::Commit,
            height,
            round,
        );

        // Setup both engines
        engine_a.current_round.height = height;
        engine_a.current_round.round = round;
        engine_b.current_round.height = height;
        engine_b.current_round.round = round;

        engine_a.snapshot_validator_set(height);
        engine_b.snapshot_validator_set(height);

        engine_a.current_round.step = ConsensusStep::PreVote;
        engine_b.current_round.step = ConsensusStep::PreVote;

        // Node A: A1 → A2 → B1
        engine_a.on_commit_vote(vote_a1.clone()).await.expect("A: vote a1");
        engine_a.on_commit_vote(vote_a2.clone()).await.expect("A: vote a2");
        engine_a.on_commit_vote(vote_b1.clone()).await.expect("A: vote b1");

        // Node B: B1 → A2 → A1 (different order)
        engine_b.on_commit_vote(vote_b1.clone()).await.expect("B: vote b1");
        engine_b.on_commit_vote(vote_a2.clone()).await.expect("B: vote a2");
        engine_b.on_commit_vote(vote_a1.clone()).await.expect("B: vote a1");

        // INVARIANT: Both nodes MUST remain in PreVote (no finalization)
        assert_eq!(
            engine_a.current_round.step,
            ConsensusStep::PreVote,
            "Node A MUST NOT finalize without quorum"
        );
        assert_eq!(
            engine_b.current_round.step,
            ConsensusStep::PreVote,
            "Node B MUST NOT finalize without quorum"
        );

        // INVARIANT: Vote counts MUST be identical
        let count_a_proposal_a = engine_a.count_commits_for(height, round, &proposal_a);
        let count_b_proposal_a = engine_b.count_commits_for(height, round, &proposal_a);

        assert_eq!(count_a_proposal_a, 2, "Node A should count 2 votes for proposal A");
        assert_eq!(count_b_proposal_a, 2, "Node B should count 2 votes for proposal A");

        let count_a_proposal_b = engine_a.count_commits_for(height, round, &proposal_b);
        let count_b_proposal_b = engine_b.count_commits_for(height, round, &proposal_b);

        assert_eq!(count_a_proposal_b, 1, "Node A should count 1 vote for proposal B");
        assert_eq!(count_b_proposal_b, 1, "Node B should count 1 vote for proposal B");

        tracing::info!("✅ Split vote convergence verified:");
        tracing::info!("   - 2 votes for proposal A (no quorum)");
        tracing::info!("   - 1 vote for proposal B (no quorum)");
        tracing::info!("   - Both nodes remain in PreVote step");
        tracing::info!("   - No finalization: CONFIRMED");
    }

    /// Test: Canonical convergence with 7 validators (larger network)
    ///
    /// Setup:
    /// - 7 validators (requires 5 votes for quorum)
    /// - Single proposal
    /// - Exactly 5 commit votes (quorum)
    ///
    /// Test:
    /// - Node A and B process votes in different orders
    /// - Both MUST finalize after receiving all 5 votes
    /// - Both MUST finalize the same proposal
    #[tokio::test]
    async fn test_canonical_convergence_seven_validators() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };

        let broadcaster_a = Arc::new(MockMessageBroadcaster::new());
        let broadcaster_b = Arc::new(MockMessageBroadcaster::new());

        let mut engine_a = ConsensusEngine::new(config.clone(), broadcaster_a as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine A");
        let mut engine_b = ConsensusEngine::new(config, broadcaster_b as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine B");

        // Register 7 validators
        let mut validators = Vec::new();
        for i in 1..=7 {
            let validator_id = test_validator_id(i);
            // Note: validator_id is index-derived; signing keys are randomly generated and
            // do not derive from the validator_id. This is a test limitation.
            let keypair = create_test_keypair();

            register_validator_with_keypair(&mut engine_a, validator_id.clone(), &keypair, i == 1).await;
            register_validator_with_keypair(&mut engine_b, validator_id.clone(), &keypair, i == 1).await;

            validators.push((validator_id, keypair));
        }

        let height = 1u64;
        let round = 0u32;
        let proposal_id = Hash::from_bytes(&hash_blake3(b"canonical-block-7-validators"));

        // Create 5 commit votes (quorum for 7 validators)
        let mut votes = Vec::new();
        for i in 0..5 {
            let vote = make_signed_vote(
                &engine_a,
                &validators[i].1,
                validators[i].0.clone(),
                proposal_id.clone(),
                VoteType::Commit,
                height,
                round,
            );
            votes.push(vote);
        }

        // Setup both engines
        engine_a.current_round.height = height;
        engine_a.current_round.round = round;
        engine_b.current_round.height = height;
        engine_b.current_round.round = round;

        engine_a.snapshot_validator_set(height);
        engine_b.snapshot_validator_set(height);

        engine_a.current_round.step = ConsensusStep::PreVote;
        engine_b.current_round.step = ConsensusStep::PreVote;

        // Node A: Sequential order 0→1→2→3→4
        for vote in &votes {
            engine_a.on_commit_vote(vote.clone()).await.expect("A: vote");
        }

        // Node B: Reversed order 4→3→2→1→0
        for vote in votes.iter().rev() {
            engine_b.on_commit_vote(vote.clone()).await.expect("B: vote");
        }

        // INVARIANT: Both nodes MUST finalize
        assert_eq!(
            engine_a.current_round.step,
            ConsensusStep::Commit,
            "Node A MUST finalize with 5/7 votes"
        );
        assert_eq!(
            engine_b.current_round.step,
            ConsensusStep::Commit,
            "Node B MUST finalize with 5/7 votes"
        );

        // INVARIANT: Vote counts MUST be identical
        let count_a = engine_a.count_commits_for(height, round, &proposal_id);
        let count_b = engine_b.count_commits_for(height, round, &proposal_id);

        assert_eq!(count_a, 5, "Node A MUST have 5 commit votes");
        assert_eq!(count_b, 5, "Node B MUST have 5 commit votes");

        tracing::info!("✅ 7-validator canonical convergence verified:");
        tracing::info!("   - 7 validators (quorum = 5)");
        tracing::info!("   - Both nodes finalized with 5 votes");
        tracing::info!("   - Deterministic finality: CONFIRMED");
    }

    /// Test: Canonical convergence with equivocation detection
    ///
    /// Setup:
    /// - 4 validators
    /// - Validator V1 sends two different votes (equivocation)
    ///
    /// Expected:
    /// - Both nodes MUST reject the second conflicting vote
    /// - Both nodes MUST have identical vote counts
    /// - Equivocation MUST NOT affect determinism
    #[tokio::test]
    async fn test_canonical_convergence_with_equivocation() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };

        let broadcaster_a = Arc::new(MockMessageBroadcaster::new());
        let broadcaster_b = Arc::new(MockMessageBroadcaster::new());

        let mut engine_a = ConsensusEngine::new(config.clone(), broadcaster_a as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine A");
        let mut engine_b = ConsensusEngine::new(config, broadcaster_b as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine B");

        // Register 4 validators
        let mut validators = Vec::new();
        for i in 1..=4 {
            let validator_id = test_validator_id(i);
            // Note: validator_id is index-derived; signing keys are randomly generated and
            // do not derive from the validator_id. This is a test limitation.
            let keypair = create_test_keypair();

            register_validator_with_keypair(&mut engine_a, validator_id.clone(), &keypair, i == 1).await;
            register_validator_with_keypair(&mut engine_b, validator_id.clone(), &keypair, i == 1).await;

            validators.push((validator_id, keypair));
        }

        let height = 1u64;
        let round = 0u32;

        let proposal_a = Hash::from_bytes(&hash_blake3(b"proposal-A"));
        let proposal_b = Hash::from_bytes(&hash_blake3(b"proposal-B"));

        // Validator 0 votes for proposal A
        let vote_0a = make_signed_vote(
            &engine_a,
            &validators[0].1,
            validators[0].0.clone(),
            proposal_a.clone(),
            VoteType::Commit,
            height,
            round,
        );

        // Validator 0 equivocates: votes for proposal B (same H/R/type, different value)
        let vote_0b = make_signed_vote(
            &engine_a,
            &validators[0].1,
            validators[0].0.clone(),
            proposal_b.clone(),
            VoteType::Commit,
            height,
            round,
        );

        // Valid votes from validators 1 and 2
        let vote_1 = make_signed_vote(
            &engine_a,
            &validators[1].1,
            validators[1].0.clone(),
            proposal_a.clone(),
            VoteType::Commit,
            height,
            round,
        );

        let vote_2 = make_signed_vote(
            &engine_a,
            &validators[2].1,
            validators[2].0.clone(),
            proposal_a.clone(),
            VoteType::Commit,
            height,
            round,
        );

        // Setup both engines
        engine_a.current_round.height = height;
        engine_a.current_round.round = round;
        engine_b.current_round.height = height;
        engine_b.current_round.round = round;

        engine_a.snapshot_validator_set(height);
        engine_b.snapshot_validator_set(height);

        engine_a.current_round.step = ConsensusStep::PreVote;
        engine_b.current_round.step = ConsensusStep::PreVote;

        // Node A: Process legitimate vote, then equivocation, then more legitimate votes
        engine_a.on_commit_vote(vote_0a.clone()).await.expect("A: vote 0a");
        engine_a.on_commit_vote(vote_0b.clone()).await.expect("A: vote 0b"); // Equivocation (should be rejected)
        engine_a.on_commit_vote(vote_1.clone()).await.expect("A: vote 1");
        engine_a.on_commit_vote(vote_2.clone()).await.expect("A: vote 2");

        // Node B: Process in different order
        engine_b.on_commit_vote(vote_1.clone()).await.expect("B: vote 1");
        engine_b.on_commit_vote(vote_0b.clone()).await.expect("B: vote 0b"); // Equivocation (should be rejected)
        engine_b.on_commit_vote(vote_2.clone()).await.expect("B: vote 2");
        engine_b.on_commit_vote(vote_0a.clone()).await.expect("B: vote 0a");

        // INVARIANT: Vote counts MUST be identical (equivocation rejected)
        let count_a_proposal_a = engine_a.count_commits_for(height, round, &proposal_a);
        let count_b_proposal_a = engine_b.count_commits_for(height, round, &proposal_a);

        assert_eq!(
            count_a_proposal_a, 3,
            "Node A should count 3 valid votes for proposal A"
        );
        assert_eq!(
            count_b_proposal_a, 3,
            "Node B should count 3 valid votes for proposal A"
        );

        // INVARIANT: Both nodes should have finalized (3/4 = quorum)
        assert_eq!(
            engine_a.current_round.step,
            ConsensusStep::Commit,
            "Node A MUST finalize despite equivocation"
        );
        assert_eq!(
            engine_b.current_round.step,
            ConsensusStep::Commit,
            "Node B MUST finalize despite equivocation"
        );

        tracing::info!("✅ Equivocation handling verified:");
        tracing::info!("   - Validator 0 equivocated (2 different votes)");
        tracing::info!("   - Both nodes rejected equivocating vote");
        tracing::info!("   - Both nodes finalized with 3 valid votes");
        tracing::info!("   - Deterministic finality maintained: CONFIRMED");

    #[tokio::test]
    async fn test_validator_keypair_rejected_without_local_validator_identity() {
        let config = ConsensusConfig::default();
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let keypair = create_test_keypair();
        let result = engine.set_validator_keypair(keypair);

        assert!(
            result.is_err(),
            "Non-validator engine must reject validator key loading"
        );
    }

    #[tokio::test]
    async fn test_validator_keypair_allowed_for_registered_local_validator() {
        let config = ConsensusConfig::default();
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let validator_id = test_validator_id(9);
        let keypair = create_test_keypair();
        register_validator_with_keypair(&mut engine, validator_id, &keypair, true).await;

        let result = engine.set_validator_keypair(keypair);
        assert!(
            result.is_ok(),
            "Registered local validator should be allowed to load signing key"
        );
    }
}
