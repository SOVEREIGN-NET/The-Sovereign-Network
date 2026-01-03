//! Integration tests for liveness monitor and consensus stall detection
//!
//! These tests verify the full liveness monitoring workflow including:
//! - Watching validator timeouts via HeartbeatTracker
//! - Detecting stall transitions
//! - Handling flapping validators
//! - Recovery from consensus stalls

use lib_consensus::network::{HeartbeatTracker, LivenessMonitor};
use lib_consensus::types::ConsensusStep;
use lib_consensus::validators::validator_protocol::NetworkSummary;
use lib_crypto::{hash_blake3, Hash, PostQuantumSignature, PublicKey, SignatureAlgorithm};
use lib_identity::IdentityId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Counter for generating unique test IDs
static TEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

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

/// Test watch_timeouts integration with HeartbeatTracker
#[test]
fn test_watch_timeouts_with_heartbeat_tracker() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let mut monitor = LivenessMonitor::new();

    let validators: Vec<IdentityId> = (0..5).map(|_| create_unique_identity()).collect();
    monitor.update_validator_set(&validators);

    // Record fresh heartbeats for all validators
    for validator in &validators {
        tracker.record_heartbeat(validator, current_timestamp());
    }

    // All should be responsive (no state change)
    assert!(!monitor.watch_timeouts(&tracker));
    assert!(!monitor.is_stalled());

    // Now simulate timeout for validators 0-2 (3 validators = exactly 1/3 + 1)
    let old_timestamp = current_timestamp() - 15; // Older than 10s timeout
    for i in 0..3 {
        tracker.record_heartbeat(&validators[i], old_timestamp);
    }

    // State should change (timeouts detected)
    let state_changed = monitor.watch_timeouts(&tracker);
    assert!(state_changed);

    // Should be stalled now
    assert!(monitor.is_stalled());
    assert_eq!(monitor.timed_out_validators().len(), 3);
}

/// Test flapping validator detection (alternating responsive/timed out)
#[test]
fn test_flapping_validator_detection() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let mut monitor = LivenessMonitor::new();

    let validators: Vec<IdentityId> = (0..5).map(|_| create_unique_identity()).collect();
    monitor.update_validator_set(&validators);

    // Initialize all validators as responsive
    for validator in &validators {
        tracker.record_heartbeat(validator, current_timestamp());
    }
    let _ = monitor.watch_timeouts(&tracker);

    let validator_to_flap = &validators[0];

    // Timeout validator
    let old_timestamp = current_timestamp() - 15;
    tracker.record_heartbeat(validator_to_flap, old_timestamp);
    let state_changed = monitor.watch_timeouts(&tracker);
    assert!(state_changed); // State changed to timeout
    assert!(monitor.timed_out_validators().contains(validator_to_flap));

    // Recover
    tracker.record_heartbeat(validator_to_flap, current_timestamp());
    let state_changed = monitor.watch_timeouts(&tracker);
    assert!(state_changed); // State changed back to responsive
    assert!(!monitor.timed_out_validators().contains(validator_to_flap));
}

/// Test full stall recovery cycle
#[test]
fn test_stall_recovery_cycle() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let mut monitor = LivenessMonitor::new();

    let validators: Vec<IdentityId> = (0..7).map(|_| create_unique_identity()).collect();
    monitor.update_validator_set(&validators);

    // All responsive initially
    for validator in &validators {
        tracker.record_heartbeat(validator, current_timestamp());
    }
    assert!(!monitor.watch_timeouts(&tracker));
    assert!(!monitor.is_stalled());

    // Trigger stall: timeout 3 validators (3/7 > 1/3)
    let old_timestamp = current_timestamp() - 15;
    for i in 0..3 {
        tracker.record_heartbeat(&validators[i], old_timestamp);
    }
    monitor.watch_timeouts(&tracker);
    assert!(monitor.is_stalled());

    // Check stall transition detected
    if let Some((is_stalled, timed_out_set)) = monitor.check_stall_transition() {
        assert!(is_stalled);
        assert_eq!(timed_out_set.len(), 3);
    } else {
        panic!("Expected stall transition");
    }

    // Recover: heartbeats from timed-out validators
    for i in 0..3 {
        tracker.record_heartbeat(&validators[i], current_timestamp());
    }
    monitor.watch_timeouts(&tracker);
    assert!(!monitor.is_stalled());

    // Check recovery transition
    if let Some((is_stalled, timed_out_set)) = monitor.check_stall_transition() {
        assert!(!is_stalled);
        assert_eq!(timed_out_set.len(), 0);
    } else {
        panic!("Expected recovery transition");
    }
}

/// Test gradual timeout accumulation
#[test]
fn test_multiple_validators_timeout() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let mut monitor = LivenessMonitor::new();

    let validators: Vec<IdentityId> = (0..10).map(|_| create_unique_identity()).collect();
    monitor.update_validator_set(&validators);

    // All responsive
    for validator in &validators {
        tracker.record_heartbeat(validator, current_timestamp());
    }
    assert!(!monitor.is_stalled());

    // Gradually timeout validators
    let old_timestamp = current_timestamp() - 15;
    for i in 0..4 {
        // After 4 timeouts (4/10 > 1/3), should stall
        tracker.record_heartbeat(&validators[i], old_timestamp);
        monitor.watch_timeouts(&tracker);

        if i < 3 {
            // 0-2 timeouts: not stalled (need floor(10/3) + 1 = 4)
            assert!(!monitor.is_stalled());
        } else {
            // 3+ timeouts: stalled
            assert!(monitor.is_stalled());
        }
    }

    assert_eq!(monitor.timed_out_validators().len(), 4);
}

/// Test no false stall under normal network jitter
#[test]
fn test_no_false_stall_under_jitter() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let mut monitor = LivenessMonitor::new();

    let validators: Vec<IdentityId> = (0..10).map(|_| create_unique_identity()).collect();
    monitor.update_validator_set(&validators);

    let current = current_timestamp();

    // Simulate heartbeats with varying arrival times (all within tolerance)
    // 10-second timeout with 8-second max delay = no false stalls
    for validator in &validators {
        let delay = (validator.as_bytes()[0] as u64) % 8; // 0-7 second delays
        tracker.record_heartbeat(validator, current.saturating_sub(delay));
    }

    // Check liveness - all should still be responsive
    monitor.watch_timeouts(&tracker);
    assert!(!monitor.is_stalled());

    // All validators reported as alive
    assert_eq!(monitor.timed_out_validators().len(), 0);
}

/// Test validator set change updates threshold
#[test]
fn test_validator_set_changes_update_threshold() {
    let monitor = LivenessMonitor::new();

    // Initially empty
    assert_eq!(monitor.total_validators, 0);

    let validators: Vec<IdentityId> = (0..5).map(|_| create_unique_identity()).collect();
    let mut monitor = monitor;
    monitor.update_validator_set(&validators);

    // Verify threshold: floor(5/3) + 1 = floor(1.67) + 1 = 2
    assert_eq!(monitor.total_validators, 5);
    assert_eq!(monitor.stall_threshold, 2);

    // Add more validators
    let mut more_validators = validators.clone();
    more_validators.extend((0..5).map(|_| create_unique_identity()));
    monitor.update_validator_set(&more_validators);

    // Verify new threshold: floor(10/3) + 1 = 4
    assert_eq!(monitor.total_validators, 10);
    assert_eq!(monitor.stall_threshold, 4);
}

/// Test idempotent transition detection (no repeated events)
#[test]
fn test_idempotent_transition_detection() {
    let mut monitor = LivenessMonitor::new();

    // Use 7 validators: threshold = floor(7/3) + 1 = 3
    let validators: Vec<IdentityId> = (0..7).map(|_| create_unique_identity()).collect();
    monitor.update_validator_set(&validators);

    // Manually trigger stall by timing out 4 validators (4 >= 3)
    for validator in &validators[0..4] {
        monitor.report_timeout(validator);
    }

    // First transition should be detected
    if let Some((is_stalled, _)) = monitor.check_stall_transition() {
        assert!(is_stalled);
    } else {
        panic!("Expected stall transition");
    }

    // Second call should return None (no transition)
    let result = monitor.check_stall_transition();
    assert!(result.is_none());

    // Only when state changes should transition be detected again
    monitor.mark_responsive(&validators[0]);
    if let Some((is_stalled, _)) = monitor.check_stall_transition() {
        assert!(is_stalled); // Still stalled with 3 timeouts (3 >= 3)
    } else {
        panic!("Expected stall transition after mark_responsive");
    }
}

/// Test interaction between heartbeat tracker and liveness monitor
#[test]
fn test_heartbeat_tracker_integration() {
    let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
    let mut monitor = LivenessMonitor::new();

    let validator = create_unique_identity();
    monitor.update_validator_set(&[validator.clone()]);

    // Initially not alive
    assert!(!tracker.is_validator_alive(&validator));
    assert!(!monitor.is_stalled());

    // Send heartbeat
    tracker.record_heartbeat(&validator, current_timestamp());
    assert!(tracker.is_validator_alive(&validator));

    // Liveness monitor should reflect this
    monitor.watch_timeouts(&tracker);
    assert!(!monitor.is_stalled());

    // Expire the heartbeat
    tracker.record_heartbeat(&validator, current_timestamp() - 15);
    assert!(!tracker.is_validator_alive(&validator));

    // Monitor should detect timeout
    monitor.watch_timeouts(&tracker);
    assert!(monitor.is_stalled()); // Single validator stalled = true
}
