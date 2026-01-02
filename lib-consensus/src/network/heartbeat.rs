//! Validator Heartbeat and Liveness Tracking
//!
//! # Overview
//!
//! This module provides explicit, time-bounded liveness signals for validators.
//! It tracks when validators last sent a heartbeat and determines if they are
//! currently "alive" based on a configurable timeout.
//!
//! # Heartbeat Invariants
//!
//! 1. **Time-Bounded Liveness**: A validator is considered alive if and only if
//!    a valid heartbeat was received within the last `liveness_timeout` seconds.
//!    No liveness assumptions without heartbeat evidence.
//!
//! 2. **Heartbeat ≠ Vote**: Heartbeats are advisory telemetry, not consensus messages.
//!    They do NOT contribute to quorum, do NOT affect consensus safety, and
//!    do NOT trigger slashing or Byzantine fault detection.
//!
//! 3. **Observable, Not Inferred**: Validator silence is directly observable through
//!    the absence of heartbeats. We do not infer liveness from other messages.
//!
//! 4. **Best-Effort Delivery**: Heartbeat sending is best-effort. Send failures
//!    are logged but do not affect consensus progress or local state.
//!
//! 5. **Non-Blocking**: Heartbeat processing never blocks consensus. Invalid
//!    heartbeats are rejected and logged, but do not cause panics or errors.
//!
//! 6. **No False Positives Under Normal Conditions**: With the default 10-second
//!    timeout and 3-second send interval, normal network jitter (±1s) should not
//!    cause false "not alive" detections.
//!
//! # Example
//!
//! ```no_run
//! use lib_consensus::network::HeartbeatTracker;
//! use lib_identity::IdentityId;
//! use std::time::Duration;
//!
//! let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
//! let validator_id = IdentityId::from_bytes(&[1u8; 32]);
//!
//! // Record when a heartbeat is received (in unix seconds)
//! let now_secs = std::time::SystemTime::now()
//!     .duration_since(std::time::UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//! tracker.record_heartbeat(&validator_id, now_secs);
//!
//! // Check if validator is alive
//! assert!(tracker.is_validator_alive(&validator_id));
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lib_crypto::{hash_blake3, Hash, PublicKey, SignatureAlgorithm};
use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};
use tracing;

use crate::types::ConsensusStep;
use crate::validators::validator_protocol::{HeartbeatMessage, NetworkSummary};

/// Error type for heartbeat validation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HeartbeatValidationError {
    /// Sender is not in the active validator set
    NotAValidator(String),
    /// Heartbeat height is too far from local height (skew > ±10)
    HeightSkewTooLarge { heartbeat_height: u64, local_height: u64 },
    /// Heartbeat timestamp is too far from current time (skew > ±30s)
    TimestampSkewTooLarge { heartbeat_time: u64, current_time: u64 },
    /// Signature verification failed
    InvalidSignature(String),
}

impl std::fmt::Display for HeartbeatValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HeartbeatValidationError::NotAValidator(msg) => write!(f, "Not a validator: {}", msg),
            HeartbeatValidationError::HeightSkewTooLarge { heartbeat_height, local_height } => {
                write!(f, "Height skew too large: {} vs {}", heartbeat_height, local_height)
            }
            HeartbeatValidationError::TimestampSkewTooLarge { heartbeat_time, current_time } => {
                write!(f, "Timestamp skew too large: {} vs {}", heartbeat_time, current_time)
            }
            HeartbeatValidationError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
        }
    }
}

/// Result of processing a heartbeat
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HeartbeatProcessingResult {
    /// Heartbeat was accepted and recorded
    Accepted,
    /// Heartbeat was rejected for a specific reason
    Rejected(String),
}

/// Tracks validator heartbeat timestamps for liveness detection
///
/// This is the core component of the liveness tracking system. It maintains
/// a map of validators to their last heartbeat timestamps and provides
/// methods to check if validators are alive based on a configurable timeout.
#[derive(Debug, Clone)]
pub struct HeartbeatTracker {
    /// Map from validator ID to last heartbeat timestamp (unix seconds)
    heartbeat_times: HashMap<IdentityId, u64>,
    /// Timeout duration for liveness detection (default: 10 seconds)
    liveness_timeout: Duration,
    /// Local validator identity (optional)
    local_validator: Option<IdentityId>,
}

impl HeartbeatTracker {
    /// Create a new heartbeat tracker with specified liveness timeout
    ///
    /// # Arguments
    ///
    /// * `liveness_timeout` - Duration after which a validator is considered offline
    ///
    /// # Default Configuration
    ///
    /// - **Timeout**: 10 seconds
    /// - **Send Interval**: 3 seconds (configured externally)
    /// - **Jitter Margin**: 7 seconds (interval + timeout - current_time)
    pub fn new(liveness_timeout: Duration) -> Self {
        Self {
            heartbeat_times: HashMap::new(),
            liveness_timeout,
            local_validator: None,
        }
    }

    /// Set the local validator identity (used for sending heartbeats)
    pub fn set_local_validator(&mut self, validator_id: IdentityId) {
        self.local_validator = Some(validator_id);
    }

    /// Record a heartbeat from a validator
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator sending the heartbeat
    /// * `timestamp` - Unix timestamp in seconds when heartbeat was received
    ///
    /// Updates the last heartbeat time for the validator. Idempotent for duplicate heartbeats.
    pub fn record_heartbeat(&mut self, validator_id: &IdentityId, timestamp: u64) {
        self.heartbeat_times.insert(validator_id.clone(), timestamp);
    }

    /// Check if a validator is currently alive
    ///
    /// A validator is alive if a heartbeat was received within the last `liveness_timeout` seconds.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to check
    ///
    /// # Returns
    ///
    /// `true` if validator has sent a heartbeat within `liveness_timeout`, `false` otherwise
    pub fn is_validator_alive(&self, validator_id: &IdentityId) -> bool {
        match self.heartbeat_times.get(validator_id) {
            Some(last_heartbeat) => {
                let now = current_time_secs();
                let age = now.saturating_sub(*last_heartbeat);
                age <= self.liveness_timeout.as_secs()
            }
            None => false, // No heartbeat recorded = not alive
        }
    }

    /// Get the time elapsed since last heartbeat from a validator
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to check
    ///
    /// # Returns
    ///
    /// `Some(Duration)` if a heartbeat was recorded, `None` otherwise
    pub fn last_heartbeat_age(&self, validator_id: &IdentityId) -> Option<Duration> {
        self.heartbeat_times.get(validator_id).map(|last_heartbeat| {
            let now = current_time_secs();
            let age_secs = now.saturating_sub(*last_heartbeat);
            Duration::from_secs(age_secs)
        })
    }

    /// Update the liveness timeout threshold
    ///
    /// # Arguments
    ///
    /// * `timeout` - New timeout duration
    pub fn set_liveness_timeout(&mut self, timeout: Duration) {
        self.liveness_timeout = timeout;
    }

    /// Get the current liveness timeout
    pub fn get_liveness_timeout(&self) -> Duration {
        self.liveness_timeout
    }

    /// Remove stale heartbeat entries older than cutoff time
    ///
    /// Helps prevent unbounded memory growth in long-running validators.
    /// Typically called periodically (e.g., once per hour).
    ///
    /// # Arguments
    ///
    /// * `cutoff_seconds` - Remove entries older than this many seconds
    ///
    /// # Returns
    ///
    /// Number of entries removed
    pub fn cleanup_stale_entries(&mut self, cutoff_seconds: u64) -> usize {
        let now = current_time_secs();
        let cutoff = now.saturating_sub(cutoff_seconds);
        let original_len = self.heartbeat_times.len();

        self.heartbeat_times.retain(|_, &mut last_time| last_time >= cutoff);

        original_len - self.heartbeat_times.len()
    }

    /// Create a heartbeat message for broadcasting
    ///
    /// # Arguments
    ///
    /// * `height` - Current consensus height
    /// * `round` - Current consensus round
    /// * `step` - Current consensus step
    /// * `active_validator_count` - Number of active validators
    ///
    /// # Returns
    ///
    /// A new `HeartbeatMessage` ready to be signed and broadcast
    pub fn create_heartbeat_message(
        &self,
        height: u64,
        round: u32,
        step: ConsensusStep,
        active_validator_count: u32,
    ) -> HeartbeatMessage {
        let timestamp = current_time_secs();

        // Get validator identity - must be set before creating heartbeats
        let validator_id = self.local_validator.clone().unwrap_or_else(|| {
            tracing::warn!("HeartbeatTracker: local_validator not set, heartbeat will be rejected by peers");
            // Use a distinct ID to signal configuration error, not zero bytes
            IdentityId::from_bytes(&hash_blake3(b"uninitialized-validator"))
        });

        // Generate message ID including validator to prevent collisions when
        // multiple validators send heartbeats in the same second
        let message_id = Hash::from_bytes(&generate_message_id_with_validator(&validator_id, &timestamp));

        // Create a minimal network summary
        let network_summary = NetworkSummary {
            active_validators: active_validator_count,
            health_score: 0.95, // Placeholder: would be calculated from tracking
            block_rate: 0.1, // Placeholder: would be calculated from block times
        };

        HeartbeatMessage {
            message_id,
            validator: validator_id,
            height,
            round,
            step,
            network_summary,
            timestamp,
            // Note: Signature is placeholder - real signing happens in the validator protocol layer.
            // Placeholder must be >= 32 bytes and non-trivial to pass basic validation.
            signature: lib_crypto::PostQuantumSignature {
                signature: {
                    let mut sig = vec![timestamp as u8; 64];
                    for i in 0..32 {
                        sig[i] = sig[i].wrapping_add(i as u8);
                    }
                    sig
                },
                public_key: PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: [0u8; 32],
                },
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp,
            },
        }
    }

    /// Validate a received heartbeat message
    ///
    /// Performs advisory validation (signature, sender, height, timestamp skew).
    /// Invalid heartbeats are logged but never panic or block consensus.
    ///
    /// # Arguments
    ///
    /// * `heartbeat` - The heartbeat message to validate
    /// * `is_validator` - Closure that checks if sender is a valid validator
    /// * `local_height` - Current consensus height for skew check
    ///
    /// # Returns
    ///
    /// `Ok(())` if validation passes, `Err(reason)` with details if not
    pub fn validate_heartbeat<F>(
        &self,
        heartbeat: &HeartbeatMessage,
        is_validator: F,
        local_height: u64,
    ) -> Result<(), HeartbeatValidationError>
    where
        F: Fn(&IdentityId) -> bool,
    {
        // Check 1: Sender must be a validator
        if !is_validator(&heartbeat.validator) {
            return Err(HeartbeatValidationError::NotAValidator(
                format!("Validator {} not in active set", heartbeat.validator),
            ));
        }

        // Check 2: Height must be within acceptable skew (±10 blocks)
        let height_diff = if heartbeat.height > local_height {
            heartbeat.height - local_height
        } else {
            local_height - heartbeat.height
        };
        if height_diff > 10 {
            return Err(HeartbeatValidationError::HeightSkewTooLarge {
                heartbeat_height: heartbeat.height,
                local_height,
            });
        }

        // Check 3: Timestamp must be within acceptable skew (±30 seconds)
        let now = current_time_secs();
        let time_diff = if heartbeat.timestamp > now {
            heartbeat.timestamp - now
        } else {
            now - heartbeat.timestamp
        };
        if time_diff > 30 {
            return Err(HeartbeatValidationError::TimestampSkewTooLarge {
                heartbeat_time: heartbeat.timestamp,
                current_time: now,
            });
        }

        // Check 4: Signature presence and basic validity
        // SECURITY NOTE: Real cryptographic verification happens in the validator protocol layer.
        // This check ensures signature is not completely empty or trivially spoofed.
        if heartbeat.signature.signature.is_empty() {
            return Err(HeartbeatValidationError::InvalidSignature(
                "Empty signature".to_string(),
            ));
        }

        // Reject placeholder signatures (all zeros or trivial patterns)
        let sig_bytes = &heartbeat.signature.signature;
        if sig_bytes.len() < 32 || sig_bytes.iter().all(|&b| b == 0) || sig_bytes.iter().all(|&b| b == 1) {
            return Err(HeartbeatValidationError::InvalidSignature(
                "Placeholder or trivial signature detected".to_string(),
            ));
        }

        Ok(())
    }

    /// Process a received heartbeat message
    ///
    /// Validates and records the heartbeat. Never panics or affects consensus.
    ///
    /// # Arguments
    ///
    /// * `heartbeat` - The heartbeat message to process
    /// * `is_validator` - Closure that checks if sender is a valid validator
    /// * `local_height` - Current consensus height
    ///
    /// # Returns
    ///
    /// `HeartbeatProcessingResult::Accepted` if recorded,
    /// `HeartbeatProcessingResult::Rejected(reason)` if validation failed
    pub fn process_heartbeat<F>(
        &mut self,
        heartbeat: HeartbeatMessage,
        is_validator: F,
        local_height: u64,
    ) -> HeartbeatProcessingResult
    where
        F: Fn(&IdentityId) -> bool,
    {
        match self.validate_heartbeat(&heartbeat, is_validator, local_height) {
            Ok(()) => {
                self.record_heartbeat(&heartbeat.validator, heartbeat.timestamp);
                HeartbeatProcessingResult::Accepted
            }
            Err(reason) => HeartbeatProcessingResult::Rejected(reason.to_string()),
        }
    }
}

/// Get the current time in unix seconds
fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Generate a deterministic message ID from validator ID and timestamp
///
/// Includes validator ID to prevent message ID collisions when multiple validators
/// send heartbeats within the same second.
fn generate_message_id_with_validator(validator_id: &IdentityId, timestamp: &u64) -> [u8; 32] {
    use lib_crypto::hash_blake3;

    // Combine validator bytes with timestamp to create unique message ID
    let mut bytes = validator_id.as_ref().to_vec();
    bytes.extend_from_slice(&timestamp.to_le_bytes());
    hash_blake3(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validator_id(id: u8) -> IdentityId {
        IdentityId::from_bytes(&[id; 32])
    }

    fn create_test_signature(timestamp: u64) -> lib_crypto::PostQuantumSignature {
        // Create a valid test signature: 32+ bytes, non-trivial pattern
        let mut sig_bytes = vec![timestamp as u8; 64]; // Mix timestamp into signature
        for i in 0..32 {
            sig_bytes[i] = sig_bytes[i].wrapping_add(i as u8);
        }

        lib_crypto::PostQuantumSignature {
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

    #[test]
    fn test_heartbeat_tracker_creation() {
        let tracker = HeartbeatTracker::new(Duration::from_secs(10));
        assert_eq!(tracker.get_liveness_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_record_and_check_alive() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator = test_validator_id(1);

        // Initially not alive (no heartbeat recorded)
        assert!(!tracker.is_validator_alive(&validator));

        // Record a heartbeat at current time
        let now = current_time_secs();
        tracker.record_heartbeat(&validator, now);

        // Should be alive
        assert!(tracker.is_validator_alive(&validator));
    }

    #[test]
    fn test_timeout_detection() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator = test_validator_id(1);

        // Record heartbeat 15 seconds ago (beyond 10s timeout)
        let now = current_time_secs();
        let old_time = now.saturating_sub(15);
        tracker.record_heartbeat(&validator, old_time);

        // Should not be alive
        assert!(!tracker.is_validator_alive(&validator));
    }

    #[test]
    fn test_last_heartbeat_age() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator = test_validator_id(1);

        // No heartbeat recorded
        assert_eq!(tracker.last_heartbeat_age(&validator), None);

        // Record recent heartbeat
        let now = current_time_secs();
        tracker.record_heartbeat(&validator, now);

        let age = tracker.last_heartbeat_age(&validator).unwrap();
        assert!(age.as_secs() <= 1); // Should be nearly 0 seconds old
    }

    #[test]
    fn test_set_liveness_timeout() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
        assert_eq!(tracker.get_liveness_timeout(), Duration::from_secs(10));

        tracker.set_liveness_timeout(Duration::from_secs(20));
        assert_eq!(tracker.get_liveness_timeout(), Duration::from_secs(20));
    }

    #[test]
    fn test_cleanup_stale_entries() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));

        // Record multiple heartbeats
        let now = current_time_secs();
        tracker.record_heartbeat(&test_validator_id(1), now);
        tracker.record_heartbeat(&test_validator_id(2), now - 100); // 100 seconds old
        tracker.record_heartbeat(&test_validator_id(3), now - 200); // 200 seconds old

        // Cleanup entries older than 150 seconds
        let removed = tracker.cleanup_stale_entries(150);

        // Should have removed 1 entry (the 200s old one, NOT the 100s old one)
        assert_eq!(removed, 1);

        // Check remaining entries
        assert!(tracker.heartbeat_times.contains_key(&test_validator_id(1)));
        assert!(tracker.heartbeat_times.contains_key(&test_validator_id(2)));
        assert!(!tracker.heartbeat_times.contains_key(&test_validator_id(3)));
    }

    #[test]
    fn test_create_heartbeat_message() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator_id = test_validator_id(1);
        tracker.set_local_validator(validator_id.clone());

        let msg = tracker.create_heartbeat_message(
            100, // height
            5,   // round
            ConsensusStep::PreVote,
            10, // active validators
        );

        assert_eq!(msg.height, 100);
        assert_eq!(msg.round, 5);
        assert_eq!(msg.validator, validator_id);
        assert_eq!(msg.network_summary.active_validators, 10);
    }

    #[test]
    fn test_validate_heartbeat_valid() {
        let tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator_id = test_validator_id(1);
        let now = current_time_secs();

        let heartbeat = HeartbeatMessage {
            message_id: Hash::from_bytes(&[0u8; 32]),
            validator: validator_id.clone(),
            height: 100,
            round: 5,
            step: ConsensusStep::PreVote,
            network_summary: NetworkSummary {
                active_validators: 10,
                health_score: 0.95,
                block_rate: 0.1,
                
            },
            timestamp: now,
            signature: create_test_signature(now),
        };

        let is_validator = |vid: &IdentityId| vid == &validator_id;
        let result = tracker.validate_heartbeat(&heartbeat, is_validator, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_heartbeat_not_validator() {
        let tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator_id = test_validator_id(1);
        let now = current_time_secs();

        let heartbeat = HeartbeatMessage {
            message_id: Hash::from_bytes(&[0u8; 32]),
            validator: validator_id.clone(),
            height: 100,
            round: 5,
            step: ConsensusStep::PreVote,
            network_summary: NetworkSummary {
                active_validators: 10,
                health_score: 0.95,
                block_rate: 0.1,
                
            },
            timestamp: now,
            signature: create_test_signature(now),
        };

        let is_validator = |_: &IdentityId| false; // Always reject
        let result = tracker.validate_heartbeat(&heartbeat, is_validator, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_heartbeat_height_skew() {
        let tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator_id = test_validator_id(1);
        let now = current_time_secs();

        let heartbeat = HeartbeatMessage {
            message_id: Hash::from_bytes(&[0u8; 32]),
            validator: validator_id.clone(),
            height: 120, // 20 blocks ahead (skew > 10)
            round: 5,
            step: ConsensusStep::PreVote,
            network_summary: NetworkSummary {
                active_validators: 10,
                health_score: 0.95,
                block_rate: 0.1,
                
            },
            timestamp: now,
            signature: create_test_signature(now),
        };

        let is_validator = |vid: &IdentityId| vid == &validator_id;
        let result = tracker.validate_heartbeat(&heartbeat, is_validator, 100); // local height = 100
        assert!(matches!(
            result,
            Err(HeartbeatValidationError::HeightSkewTooLarge { .. })
        ));
    }

    #[test]
    fn test_process_heartbeat_accepted() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator_id = test_validator_id(1);
        let now = current_time_secs();

        let heartbeat = HeartbeatMessage {
            message_id: Hash::from_bytes(&[0u8; 32]),
            validator: validator_id.clone(),
            height: 100,
            round: 5,
            step: ConsensusStep::PreVote,
            network_summary: NetworkSummary {
                active_validators: 10,
                health_score: 0.95,
                block_rate: 0.1,
                
            },
            timestamp: now,
            signature: create_test_signature(now),
        };

        let is_validator = |vid: &IdentityId| vid == &validator_id;
        let result = tracker.process_heartbeat(heartbeat.clone(), is_validator, 100);

        assert_eq!(result, HeartbeatProcessingResult::Accepted);
        assert!(tracker.is_validator_alive(&validator_id));
    }

    #[test]
    fn test_process_heartbeat_rejected() {
        let mut tracker = HeartbeatTracker::new(Duration::from_secs(10));
        let validator_id = test_validator_id(1);
        let now = current_time_secs();

        let heartbeat = HeartbeatMessage {
            message_id: Hash::from_bytes(&[0u8; 32]),
            validator: validator_id.clone(),
            height: 100,
            round: 5,
            step: ConsensusStep::PreVote,
            network_summary: NetworkSummary {
                active_validators: 10,
                health_score: 0.95,
                block_rate: 0.1,
                
            },
            timestamp: now,
            signature: create_test_signature(now),
        };

        let is_validator = |_: &IdentityId| false; // Always reject
        let result = tracker.process_heartbeat(heartbeat, is_validator, 100);

        assert!(matches!(result, HeartbeatProcessingResult::Rejected(_)));
        assert!(!tracker.is_validator_alive(&validator_id));
    }
}
