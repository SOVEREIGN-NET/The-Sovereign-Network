//! Integration tests for heartbeat and liveness tracking
//!
//! These tests verify the full heartbeat flow including sending, reception,
//! validation, and liveness detection across the consensus engine.

use lib_consensus::network::{HeartbeatTracker, HeartbeatProcessingResult};
use lib_consensus::types::ConsensusStep;
use lib_consensus::validators::validator_protocol::NetworkSummary;
use lib_crypto::{hash_blake3, Hash, PostQuantumSignature, PublicKey, SignatureAlgorithm};
use lib_identity::IdentityId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Counter for generating unique test IDs
static TEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Helper to create a test IdentityId
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

/// Helper to create a unique test IdentityId
fn create_unique_identity() -> IdentityId {
    let id = TEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    Hash::from_bytes(&hash_blake3(format!("test-validator-{}", id).as_bytes()))
}

/// Helper to get current unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Helper to create a valid test signature for testing
fn create_test_signature(timestamp: u64) -> PostQuantumSignature {
    // Create a valid test signature: >= 32 bytes, non-trivial pattern
    let mut sig_bytes = vec![timestamp as u8; 64];
    for i in 0..32 {
        sig_bytes[i] = sig_bytes[i].wrapping_add(i as u8);
    }

    PostQuantumSignature {
        signature: sig_bytes,
        public_key: PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: [0u8; 32],
        },
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp,
    }
}

/// Helper to create a placeholder network summary for testing
fn create_test_network_summary(active_count: u32) -> NetworkSummary {
    NetworkSummary {
        active_validators: active_count,
        health_score: 0.95,
        block_rate: 0.1,
    }
}

/// Helper to create a HeartbeatMessage for testing
fn create_test_heartbeat(
    validator: IdentityId,
    height: u64,
    round: u32,
    step: ConsensusStep,
    timestamp: u64,
) -> lib_consensus::validators::validator_protocol::HeartbeatMessage {
    lib_consensus::validators::validator_protocol::HeartbeatMessage {
        message_id: Hash::from_bytes(&[0u8; 32]),
        validator,
        height,
        round,
        step,
        network_summary: create_test_network_summary(4),
        timestamp,
        signature: create_test_signature(timestamp),
    }
}

/// Test that heartbeat tracker accepts valid heartbeats
#[test]
fn test_heartbeat_reception_marks_validator_alive() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator_id = create_unique_identity();

    // Initially, validator should not be alive (no heartbeat received)
    assert!(!tracker.is_validator_alive(&validator_id));

    // Create and process a heartbeat
    let heartbeat = create_test_heartbeat(
        validator_id.clone(),
        100,
        0,
        ConsensusStep::PreVote,
        current_timestamp(),
    );

    // Process heartbeat (mock validator check)
    let is_validator = |vid: &IdentityId| vid == &validator_id;
    let result = tracker.process_heartbeat(heartbeat, is_validator, 100);

    // Should accept the heartbeat
    assert!(matches!(result, HeartbeatProcessingResult::Accepted));

    // Now validator should be alive
    assert!(tracker.is_validator_alive(&validator_id));
}

/// Test that validators become not alive after timeout
#[test]
fn test_liveness_timeout_detection() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator_id = create_unique_identity();

    // Record a recent heartbeat
    tracker.record_heartbeat(&validator_id, current_timestamp());
    assert!(tracker.is_validator_alive(&validator_id));

    // Test with an old timestamp (older than 10 second timeout)
    let old_timestamp = current_timestamp() - 15; // 15 seconds in the past
    tracker.record_heartbeat(&validator_id, old_timestamp);

    // Should not be alive due to timeout
    assert!(!tracker.is_validator_alive(&validator_id));

    // Test that a recent heartbeat restores liveness
    tracker.record_heartbeat(&validator_id, current_timestamp());
    assert!(tracker.is_validator_alive(&validator_id));
}

/// Test last_heartbeat_age calculation
#[test]
fn test_last_heartbeat_age_calculation() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator_id = create_unique_identity();

    // No heartbeat yet
    assert_eq!(tracker.last_heartbeat_age(&validator_id), None);

    // Record a heartbeat with a recent timestamp
    let recent_timestamp = current_timestamp() - 2; // 2 seconds ago
    tracker.record_heartbeat(&validator_id, recent_timestamp);

    // Age should be approximately 2 seconds
    if let Some(age) = tracker.last_heartbeat_age(&validator_id) {
        // Allow 1 second variance for test execution time
        assert!(age.as_secs() >= 1 && age.as_secs() <= 3);
    } else {
        panic!("Expected Some(duration), got None");
    }
}

/// Test invalid heartbeat rejection (not a validator)
#[test]
fn test_invalid_heartbeat_not_validator() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator_id = create_unique_identity();
    let other_id = create_unique_identity();

    let heartbeat = create_test_heartbeat(other_id.clone(), 100, 0, ConsensusStep::PreVote, current_timestamp());

    // Process with validator check that fails
    let is_validator = |vid: &IdentityId| vid == &validator_id; // other_id won't match
    let result = tracker.process_heartbeat(heartbeat, is_validator, 100);

    // Should reject
    assert!(matches!(result, HeartbeatProcessingResult::Rejected(_)));

    // Sender should not be marked as alive
    assert!(!tracker.is_validator_alive(&other_id));
}

/// Test invalid heartbeat rejection (height skew too large)
#[test]
fn test_invalid_heartbeat_height_skew() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator_id = create_unique_identity();

    let heartbeat = create_test_heartbeat(
        validator_id.clone(),
        100,
        0,
        ConsensusStep::PreVote,
        current_timestamp(),
    );

    // Process with local height 200 (21 blocks ahead - exceeds ±10 limit)
    let is_validator = |vid: &IdentityId| vid == &validator_id;
    let result = tracker.process_heartbeat(heartbeat, is_validator, 200);

    // Should reject due to height skew
    assert!(matches!(result, HeartbeatProcessingResult::Rejected(_)));
}

/// Test invalid heartbeat rejection (timestamp skew too large)
#[test]
fn test_invalid_heartbeat_timestamp_skew() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator_id = create_unique_identity();

    // Heartbeat with timestamp 60 seconds in the future
    let future_timestamp = current_timestamp() + 60;
    let heartbeat = create_test_heartbeat(
        validator_id.clone(),
        100,
        0,
        ConsensusStep::PreVote,
        future_timestamp,
    );

    let is_validator = |vid: &IdentityId| vid == &validator_id;
    let result = tracker.process_heartbeat(heartbeat, is_validator, 100);

    // Should reject due to timestamp skew
    assert!(matches!(result, HeartbeatProcessingResult::Rejected(_)));
}

/// Test multiple validators tracked independently
#[test]
fn test_multiple_validators_independent() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator1 = create_unique_identity();
    let validator2 = create_unique_identity();
    let validator3 = create_unique_identity();

    // Record heartbeat for validator1
    tracker.record_heartbeat(&validator1, current_timestamp());
    assert!(tracker.is_validator_alive(&validator1));
    assert!(!tracker.is_validator_alive(&validator2));
    assert!(!tracker.is_validator_alive(&validator3));

    // Record heartbeat for validator3
    tracker.record_heartbeat(&validator3, current_timestamp());
    assert!(tracker.is_validator_alive(&validator1));
    assert!(!tracker.is_validator_alive(&validator2));
    assert!(tracker.is_validator_alive(&validator3));

    // Test with old timestamp for validator2 - should still not be alive
    tracker.record_heartbeat(&validator2, current_timestamp() - 100);
    assert!(!tracker.is_validator_alive(&validator2));
}

/// Test configurable liveness timeout
#[test]
fn test_configurable_liveness_timeout() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(5));
    let validator_id = create_unique_identity();

    let timestamp = current_timestamp() - 4; // 4 seconds old
    tracker.record_heartbeat(&validator_id, timestamp);

    // With 5s timeout, should be alive
    assert!(tracker.is_validator_alive(&validator_id));

    // Change timeout to 3 seconds
    tracker.set_liveness_timeout(Duration::from_secs(3));

    // Now 4 seconds old exceeds 3 second timeout, should not be alive
    assert!(!tracker.is_validator_alive(&validator_id));

    // Change timeout to 10 seconds
    tracker.set_liveness_timeout(Duration::from_secs(10));

    // 4 seconds old is within 10 second timeout, should be alive again
    assert!(tracker.is_validator_alive(&validator_id));
}

/// Test heartbeat message creation
#[test]
fn test_heartbeat_message_creation() {
    let tracker = HeartbeatTracker::new(Duration::from_secs(10));

    let msg = tracker.create_heartbeat_message(
        100,
        5,
        ConsensusStep::PreCommit,
        10,
    );

    assert_eq!(msg.height, 100);
    assert_eq!(msg.round, 5);
    assert_eq!(msg.step, ConsensusStep::PreCommit);
    assert_eq!(msg.network_summary.active_validators, 10);
    // Timestamp should be recent
    let age = current_timestamp().saturating_sub(msg.timestamp);
    assert!(age <= 5); // Should be created within last 5 seconds
}

/// Test heartbeat restoration after timeout
#[test]
fn test_heartbeat_restoration_after_timeout() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(2));
    let validator_id = create_unique_identity();

    // Record old heartbeat
    tracker.record_heartbeat(&validator_id, current_timestamp() - 100);
    assert!(!tracker.is_validator_alive(&validator_id));

    // Record new heartbeat
    tracker.record_heartbeat(&validator_id, current_timestamp());
    assert!(tracker.is_validator_alive(&validator_id));

    // Age should be recent
    if let Some(age) = tracker.last_heartbeat_age(&validator_id) {
        assert!(age.as_secs() < 5);
    } else {
        panic!("Expected Some(duration), got None");
    }
}

/// Test with validator set simulation
#[test]
fn test_alive_validators_filtering() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));

    let validators: Vec<IdentityId> = (0..5).map(|_| create_unique_identity()).collect();

    // Record heartbeats for first 3 validators
    for i in 0..3 {
        tracker.record_heartbeat(&validators[i], current_timestamp());
    }

    // Record old heartbeats for last 2 validators (should timeout)
    for i in 3..5 {
        tracker.record_heartbeat(&validators[i], current_timestamp() - 100);
    }

    // Check alive validators
    for i in 0..3 {
        assert!(tracker.is_validator_alive(&validators[i]));
    }
    for i in 3..5 {
        assert!(!tracker.is_validator_alive(&validators[i]));
    }
}

/// Test that invalid heartbeats don't panic
#[test]
fn test_invalid_heartbeats_no_panic() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));

    let invalid_cases: Vec<(
        lib_consensus::validators::validator_protocol::HeartbeatMessage,
        Vec<IdentityId>,
    )> = vec![
        // Non-existent validator
        {
            let validator_id = create_unique_identity();
            let hb = create_test_heartbeat(
                validator_id.clone(),
                100,
                0,
                ConsensusStep::PreVote,
                current_timestamp(),
            );
            (hb, vec![create_unique_identity()]) // Different validator set
        },
        // Old timestamp
        {
            let validator_id = create_unique_identity();
            let hb = create_test_heartbeat(
                validator_id.clone(),
                100,
                0,
                ConsensusStep::PreVote,
                current_timestamp() - 100,
            );
            (hb, vec![validator_id])
        },
        // Future timestamp
        {
            let validator_id = create_unique_identity();
            let hb = create_test_heartbeat(
                validator_id.clone(),
                100,
                0,
                ConsensusStep::PreVote,
                current_timestamp() + 100,
            );
            (hb, vec![validator_id])
        },
    ];

    for (heartbeat, valid_set) in invalid_cases {
        let is_validator = |vid: &IdentityId| valid_set.contains(vid);
        // This should not panic, even with invalid input
        let result = tracker.process_heartbeat(heartbeat, is_validator, 100);
        // Result will be rejected, but importantly, no panic
        assert!(matches!(result, HeartbeatProcessingResult::Rejected(_)));
    }
}

/// Test heartbeat with network jitter resilience
#[test]
fn test_heartbeat_jitter_resilience() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let validator_id = create_unique_identity();

    // Simulate heartbeats arriving with varying delays
    // All within acceptable skew tolerance
    let current = current_timestamp();
    let delays = vec![
        0,  // immediate
        2,  // 2 seconds
        5,  // 5 seconds
        8,  // 8 seconds
        10, // 10 seconds
        1,  // out of order arrival
        3,  // out of order arrival
    ];

    let is_validator = |vid: &IdentityId| vid == &validator_id;

    for delay in delays {
        let heartbeat = create_test_heartbeat(
            validator_id.clone(),
            100,
            0,
            ConsensusStep::PreVote,
            current + delay,
        );

        let result = tracker.process_heartbeat(heartbeat, is_validator, 100);
        // All should be accepted (within ±30s skew tolerance)
        assert!(
            matches!(result, HeartbeatProcessingResult::Accepted),
            "Heartbeat with delay {} was rejected",
            delay
        );
    }

    // Validator should be alive after receiving heartbeats
    assert!(tracker.is_validator_alive(&validator_id));
}
