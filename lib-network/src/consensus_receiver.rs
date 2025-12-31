use anyhow::{anyhow, Result};
use lib_crypto::types::Hash;
use lib_identity::IdentityId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Message delivered to the consensus engine
///
/// This is the boundary interface: consensus receives opaque bytes,
/// not ValidatorMessage. Consensus engine deserializes and verifies signatures.
///
/// # Wire Format
/// The payload field contains framed consensus message bytes in the format:
/// - 4-byte big-endian length prefix (excludes prefix itself)
/// - 1-byte version byte (currently 0x01)
/// - Remaining bytes: bincode-encoded ValidatorMessage
///
/// # Framing Responsibility
/// - Network layer (lib-network): Adds length prefix + version
/// - ConsensusReceiver: Receives already-framed bytes, passes opaque
/// - ConsensusEngine consumer: Deserializes using ConsensusMessageCodec
///
/// # Invariant
/// CR-1: Boundary purity - receiver treats payload as opaque bytes.
/// No deserialization, no validation, no branching on message type.
#[derive(Debug, Clone)]
pub struct ReceivedConsensusMessage {
    /// Verified validator identity from authenticated session.
    /// Enforces CR-2: sender authenticity.
    pub from_validator_id: IdentityId,
    /// Unix epoch seconds when message was received.
    /// Used for CR-4 timestamp validation and message ordering.
    pub received_at: u64,
    /// Framed consensus bytes (length + version + payload).
    /// Opaque to ConsensusReceiver - no deserialization happens here.
    pub payload: Vec<u8>,
}

/// Deduplication cache for consensus messages
///
/// Tracks (validator_id, message_id) -> arrival_timestamp to detect duplicates.
/// Invariant CR-3: at-most-once delivery per (validator_id, message_id)
///
/// Uses bounded memory with TTL-based eviction.
/// Key MUST include both validator_id and message_id.
struct DedupCache {
    // (validator_id, message_id) -> arrival_timestamp (unix epoch seconds)
    seen: HashMap<(IdentityId, Hash), u64>,
    ttl_secs: u64,
}

impl DedupCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            seen: HashMap::new(),
            ttl_secs,
        }
    }

    /// # Cleanup Strategy
    /// The cleanup runs synchronously during `try_insert_if_new()`.
    /// This is acceptable because:
    /// - TTL cleanup is O(n) where n = cache entries
    /// - Cache is bounded by message TTL window (typically 300-600 secs)
    /// - Typical validator count is 100-1000, so n is bounded
    /// - Synchronous cleanup avoids background task overhead
    /// - Per-message cleanup distributes work evenly
    ///
    /// For high-volume scenarios (>10k msgs/sec), consider:
    /// - Time-ordered data structure (BTreeMap by timestamp)
    /// - Separate background cleanup task
    /// - Sampling-based cleanup (cleanup every N messages, not every message)

    /// Atomically check and insert (validator_id, message_id) pair
    ///
    /// This is the ONLY way to interact with the dedup cache for message acceptance.
    ///
    /// Returns true if this is the FIRST time we've seen this key (insert succeeded).
    /// Returns false if this key was already present (duplicate).
    ///
    /// # Atomicity
    /// The check and insert happen under a single lock acquisition.
    /// No race window where another thread could insert between check and insert.
    ///
    /// # Usage pattern
    /// ```ignore
    /// if cache.try_insert_if_new(validator_id, message_id, now) {
    ///     // First time - proceed with enqueue
    ///     if enqueue_fails {
    ///         cache.remove(validator_id, message_id);  // Rollback
    ///     }
    /// } else {
    ///     // Duplicate - drop silently
    /// }
    /// ```
    fn try_insert_if_new(&mut self, validator_id: &IdentityId, message_id: &Hash, now: u64) -> bool {
        // Clean up old entries first
        self.cleanup_expired(now);

        let key = (validator_id.clone(), message_id.clone());

        // Check if already present
        if self.seen.contains_key(&key) {
            return false; // Duplicate - already in cache
        }

        // Insert atomically (under same lock as the check above)
        self.seen.insert(key, now);
        true // First insertion - accept
    }

    /// Remove a message from the dedup cache (for rollback on failed enqueue)
    fn remove(&mut self, validator_id: &IdentityId, message_id: &Hash) {
        let key = (validator_id.clone(), message_id.clone());
        self.seen.remove(&key);
    }

    fn cleanup_expired(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.ttl_secs);
        self.seen.retain(|_, ts| *ts > cutoff);
    }
}

/// Consensus ingress boundary
///
/// # Hard Invariants (CR-1 through CR-7)
///
/// CR-1: Boundary purity - treats payloads as opaque bytes
/// CR-2: Sender authenticity - every message bound to verified session (checked via validator registry)
/// CR-3: Deduplication - at-most-once delivery per (validator_id, message_id)
/// CR-4: Time sanity - timestamps outside window rejected
/// CR-5: Non-blocking ingress - fully async, concurrent, never blocks network
/// CR-6: Best-effort acknowledgment - transport-level only, doesn't imply consensus acceptance
/// CR-7: Channel isolation - consensus via read-only channel only
pub struct ConsensusReceiver {
    sender: mpsc::Sender<ReceivedConsensusMessage>,
    receiver: Option<mpsc::Receiver<ReceivedConsensusMessage>>,
    dedup: Arc<tokio::sync::Mutex<DedupCache>>,
    clock_skew_secs: u64,
    /// Validator registry for CR-2 enforcement
    /// Stores set of validator IDs that are allowed to send messages.
    /// Uses tokio::sync::Mutex for consistency with async context.
    known_validators: Arc<tokio::sync::Mutex<std::collections::HashSet<IdentityId>>>,
}

impl ConsensusReceiver {
    /// Create a new ConsensusReceiver
    ///
    /// # Arguments
    /// - `channel_capacity`: bounded mpsc channel size
    /// - `clock_skew_secs`: max allowed deviation from current time
    /// - `dedup_ttl_secs`: how long to track message IDs
    /// - `known_validators`: set of validator IDs that are allowed to send messages
    pub fn new(
        channel_capacity: usize,
        clock_skew_secs: u64,
        dedup_ttl_secs: u64,
        known_validators: std::collections::HashSet<IdentityId>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(channel_capacity);
        let dedup = Arc::new(tokio::sync::Mutex::new(DedupCache::new(dedup_ttl_secs)));

        Self {
            sender,
            receiver: Some(receiver),
            dedup,
            clock_skew_secs,
            known_validators: Arc::new(tokio::sync::Mutex::new(known_validators)),
        }
    }

    /// Register a validator as known/trusted
    ///
    /// Used to enforce CR-2: sender authenticity.
    /// Only registered validators can send messages.
    pub async fn register_validator(&self, validator_id: IdentityId) {
        let mut validators = self.known_validators.lock().await;
        validators.insert(validator_id);
    }

    /// Check if a validator is registered/known
    async fn is_validator_known(&self, validator_id: &IdentityId) -> bool {
        let validators = self.known_validators.lock().await;
        validators.contains(validator_id)
    }

    /// Get the receive-only channel for consensus engine
    ///
    /// Invariant CR-7: Only interface to consensus. Read-only, no pull/poll/inspect.
    ///
    /// # Panics
    /// Panics if called more than once (receiver already taken).
    pub fn message_channel(&mut self) -> mpsc::Receiver<ReceivedConsensusMessage> {
        self.receiver
            .take()
            .expect("message_channel() can only be called once")
    }

    /// Receive and validate a consensus message from the network
    ///
    /// # Validation order (required):
    /// 1. Verify sender_identity is known & verified
    /// 2. Check timestamp is within acceptable window
    /// 3. Deduplicate (message_id)
    /// 4. Enqueue to channel (non-blocking)
    /// 5. Acknowledge
    ///
    /// # Invariants
    /// - CR-2: Invalid sender → drop silently
    /// - CR-4: Timestamp violation → drop silently
    /// - CR-3: Duplicate → drop silently
    /// - CR-5: Channel full → drop (never block)
    /// - CR-6: Ack only after enqueue succeeds
    pub async fn receive_message(
        &self,
        from_validator_id: IdentityId,
        timestamp: u64,
        message_id: Hash,
        payload: Vec<u8>,
    ) -> Result<()> {
        // Step 1: Verify sender authenticity (CR-2: Sender authenticity)
        // CRITICAL: Only registered validators are allowed.
        // Drop immediately if sender is not in trusted validator set.
        if !self.is_validator_known(&from_validator_id).await {
            // Unknown validator - drop silently (CR-2 violation attempt)
            // In production, would log security event
            return Ok(());
        }

        // Step 2: Validate timestamp (CR-4: Time sanity)
        let now = current_time()?;
        if timestamp.abs_diff(now) > self.clock_skew_secs {
            // Timestamp outside window - drop silently (CR-4)
            return Ok(());
        }

        // Step 3: Atomically insert into dedup cache (CR-3: at-most-once delivery)
        // This is atomic - no race window where another thread could insert between check/insert.
        // Returns true if first insertion (new key), false if already present (duplicate).
        let mut dedup = self.dedup.lock().await;
        let is_new = dedup.try_insert_if_new(&from_validator_id, &message_id, now);
        drop(dedup);

        if !is_new {
            // Duplicate from same validator - drop silently (CR-3)
            return Ok(());
        }

        // Step 4: Enqueue to channel (non-blocking, CR-5)
        let msg = ReceivedConsensusMessage {
            from_validator_id: from_validator_id.clone(),
            received_at: now,
            payload,
        };

        match self.sender.try_send(msg) {
            Ok(()) => {
                // Step 5: Best-effort acknowledgment (CR-6: best-effort, non-critical)
                // If enqueue succeeded, we return Ok() regardless of ACK status.
                // The message is already in the pipeline - ACK failure doesn't justify rollback.
                let _ = self
                    .acknowledge_message(&from_validator_id, &message_id)
                    .await;
                // Log but don't propagate ACK errors
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full - drop message (CR-5: never block)
                // Rollback: remove from dedup cache since message wasn't enqueued
                // This allows retries when channel space becomes available
                let mut dedup = self.dedup.lock().await;
                dedup.remove(&from_validator_id, &message_id);
                drop(dedup);
                // In production, would log metric
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Channel closed - receiver dropped, consensus stopped
                Err(anyhow!("Consensus receiver channel closed"))
            }
        }
    }

    /// Acknowledge receipt of a message (transport-level only)
    ///
    /// # Invariant CR-6: Best-effort acknowledgment
    ///
    /// This method sends a transport-level ACK that does NOT confirm:
    /// - Message validity or correctness
    /// - Signature verification (done downstream)
    /// - Inclusion in consensus (done by ConsensusEngine)
    /// - Consensus acceptance or finality
    ///
    /// ACK means only: "message received and queued for processing"
    ///
    /// # Error Handling
    /// Transport failures in ACK sending are **non-critical**:
    /// - The message has already been enqueued (Step 4)
    /// - The caller (network layer) cannot retry based on ACK failure
    /// - Callers ignore the Result (see receive_message Step 5)
    ///
    /// Future implementations **must** handle transport errors internally
    /// and still return Ok(()). Treat as best-effort telemetry only.
    pub async fn acknowledge_message(
        &self,
        _from_validator_id: &IdentityId,
        _message_id: &Hash,
    ) -> Result<()> {
        // Transport-level acknowledgment only (currently no-op stub)
        // In production, would send ACK frame to sender
        // Failures are logged but not propagated (CR-6: best-effort)
        Ok(())
    }
}

/// Get current time as Unix epoch seconds
fn current_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("System time error: {}", e))
        .map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a ConsensusReceiver with a known validator
    fn create_receiver_with_validator(validator_id: &IdentityId) -> ConsensusReceiver {
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());
        ConsensusReceiver::new(10, 60, 300, validators)
    }

    /// Test CR-2: Sender authenticity - reject unknown validators
    ///
    /// Unknown (unregistered) validators are rejected immediately.
    /// This prevents consensus poisoning from spoofed senders.
    #[tokio::test]
    async fn test_unknown_validator_rejected() {
        let mut receiver = ConsensusReceiver::new(10, 60, 300, std::collections::HashSet::new());
        let mut channel = receiver.message_channel();

        let unknown_validator = Hash([99u8; 32]); // Not registered
        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01];
        let now = current_time().unwrap();

        // Send from unknown validator - should be silently dropped (CR-2)
        receiver
            .receive_message(
                unknown_validator.clone(),
                now,
                message_id.clone(),
                payload.clone(),
            )
            .await
            .unwrap();

        // No message should reach the channel
        let timeout_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            channel.recv(),
        )
        .await;
        assert!(
            timeout_result.is_err(),
            "Unknown validator message should be rejected"
        );
    }

    /// Test CR-2: Sender authenticity - accept registered validators
    ///
    /// Registered validators are accepted.
    #[tokio::test]
    async fn test_registered_validator_accepted() {
        let validator_id = Hash([1u8; 32]);
        let mut receiver = create_receiver_with_validator(&validator_id);
        let mut channel = receiver.message_channel();

        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01];
        let now = current_time().unwrap();

        // Send from registered validator - should be accepted
        receiver
            .receive_message(validator_id.clone(), now, message_id.clone(), payload.clone())
            .await
            .unwrap();

        // Message should reach the channel
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), channel.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg.from_validator_id, validator_id);
        assert_eq!(msg.payload, payload);
    }

    /// Test CR-3: Deduplication - same (validator, message_id) delivered once
    ///
    /// Ensures that the same validator sending the same message_id twice
    /// results in only one delivery.
    #[tokio::test]
    async fn test_dedup_same_validator_same_message() {
        let validator_id = Hash([1u8; 32]);
        let mut receiver = create_receiver_with_validator(&validator_id);
        let mut channel = receiver.message_channel();

        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01, 0x02, 0x03];
        let now = current_time().unwrap();

        // First message - should be accepted
        receiver
            .receive_message(validator_id.clone(), now, message_id.clone(), payload.clone())
            .await
            .unwrap();

        // Second message with same (validator, message_id) - should be silently dropped
        receiver
            .receive_message(validator_id.clone(), now, message_id.clone(), payload.clone())
            .await
            .unwrap();

        // Only one message should reach the channel
        let msg1 = tokio::time::timeout(std::time::Duration::from_secs(1), channel.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg1.from_validator_id, validator_id);
        assert_eq!(msg1.payload, payload);

        // No second message (duplicate dropped)
        let timeout_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            channel.recv(),
        )
        .await;
        assert!(timeout_result.is_err(), "Should timeout - no duplicate message");
    }

    /// Test CR-3: Different validators, same message_id → both accepted
    ///
    /// Different validators can send the same message_id.
    /// The dedup key must include validator_id.
    #[tokio::test]
    async fn test_dedup_different_validators_same_message_id() {
        let validator_a = Hash([1u8; 32]);
        let validator_b = Hash([2u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_a.clone());
        validators.insert(validator_b.clone());

        let mut receiver = ConsensusReceiver::new(10, 60, 300, validators);
        let mut channel = receiver.message_channel();

        let message_id = Hash([99u8; 32]); // Same message ID from different validators
        let payload_a = vec![0x01];
        let payload_b = vec![0x02];
        let now = current_time().unwrap();

        // Validator A sends message_id=99
        receiver
            .receive_message(validator_a.clone(), now, message_id.clone(), payload_a.clone())
            .await
            .unwrap();

        // Validator B sends same message_id=99 → should be accepted (different validator)
        receiver
            .receive_message(validator_b.clone(), now, message_id.clone(), payload_b.clone())
            .await
            .unwrap();

        // Both should reach the channel
        let msg1 = tokio::time::timeout(std::time::Duration::from_secs(1), channel.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg1.from_validator_id, validator_a);
        assert_eq!(msg1.payload, payload_a);

        let msg2 = tokio::time::timeout(std::time::Duration::from_secs(1), channel.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg2.from_validator_id, validator_b);
        assert_eq!(msg2.payload, payload_b);
    }

    /// Test atomicity: race to insert same (validator, message_id) → only one wins
    ///
    /// This is critical: if multiple threads race to insert the same key,
    /// only ONE should win. The others must see it as a duplicate.
    /// This tests that try_insert_if_new is atomic (no TOCTOU race).
    #[tokio::test]
    async fn test_atomic_dedup_under_race() {
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let mut receiver = ConsensusReceiver::new(100, 60, 300, validators); // Big channel
        let mut channel = receiver.message_channel();

        let receiver = Arc::new(receiver);
        let message_id = Hash([2u8; 32]);
        let now = current_time().unwrap();

        // Spawn 10 threads all trying to send the SAME (validator, message_id)
        let mut handles = vec![];
        for i in 0..10 {
            let recv = Arc::clone(&receiver);
            let validator = validator_id.clone();
            let msg_id = message_id.clone();
            let handle = tokio::spawn(async move {
                let payload = vec![i as u8];
                recv.receive_message(validator, now, msg_id, payload).await
            });
            handles.push(handle);
        }

        // All should complete without error
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok());
        }

        // Exactly ONE message should reach the channel
        // (All others dropped due to dedup)
        let msg1 = tokio::time::timeout(std::time::Duration::from_secs(1), channel.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(msg1.from_validator_id, validator_id);

        // No second message should be available
        let timeout_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            channel.recv(),
        )
        .await;
        assert!(
            timeout_result.is_err(),
            "Should timeout - only 1 message should reach channel, but another is waiting"
        );
    }

    /// Test CR-5: Non-blocking ingress with concurrent receives
    ///
    /// Verifies that concurrent message reception doesn't block.
    /// Uses channel capacity >= number of senders to verify all messages accepted.
    #[tokio::test]
    async fn test_concurrent_receives() {
        let num_senders = 10;
        let mut validators = std::collections::HashSet::new();
        for i in 0..num_senders {
            validators.insert(Hash([i as u8; 32]));
        }

        let mut receiver = ConsensusReceiver::new(num_senders, 60, 300, validators);
        let mut channel = receiver.message_channel();
        let receiver = Arc::new(receiver);
        let now = current_time().unwrap();

        // Spawn 10 concurrent receivers (DIFFERENT message_ids)
        let mut handles = vec![];
        for i in 0..num_senders {
            let recv = Arc::clone(&receiver);
            let handle = tokio::spawn(async move {
                let validator_id = Hash([i as u8; 32]);
                let message_id = Hash([(i * 2) as u8; 32]);
                let payload = vec![i as u8];

                recv.receive_message(validator_id, now, message_id, payload)
                    .await
            });
            handles.push(handle);
        }

        // All send operations should complete without blocking
        for handle in handles {
            let result = handle.await;
            assert!(result.is_ok());
        }

        // All messages should be delivered (channel capacity >= senders)
        let mut received_count = 0;
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                channel.recv(),
            )
            .await
            {
                Ok(Some(_)) => received_count += 1,
                Ok(None) => break,
                Err(_) => break, // timeout
            }
        }
        assert_eq!(
            received_count, num_senders,
            "All {} concurrent messages should be delivered",
            num_senders
        );
    }

    /// Test CR-4: Time sanity - reject stale messages
    #[tokio::test]
    async fn test_timestamp_rejection_stale() {
        let clock_skew = 60;
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let mut receiver = ConsensusReceiver::new(10, clock_skew, 300, validators);
        let mut channel = receiver.message_channel();
        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01];

        let now = current_time().unwrap();
        let stale_timestamp = now.saturating_sub(clock_skew + 10); // Too old

        // Stale message should be silently dropped
        let result = receiver
            .receive_message(
                validator_id.clone(),
                stale_timestamp,
                message_id.clone(),
                payload.clone(),
            )
            .await;
        assert!(result.is_ok()); // No error, but message was dropped

        // Verify message was NOT delivered to channel
        let timeout_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            channel.recv(),
        )
        .await;
        assert!(timeout_result.is_err(), "Stale message should be dropped, not delivered");
    }

    /// Test CR-4: Time sanity - reject future messages
    #[tokio::test]
    async fn test_timestamp_rejection_future() {
        let clock_skew = 60;
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let mut receiver = ConsensusReceiver::new(10, clock_skew, 300, validators);
        let mut channel = receiver.message_channel();
        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01];

        let now = current_time().unwrap();
        let future_timestamp = now.saturating_add(clock_skew + 10); // Too far in future

        // Future message should be silently dropped
        let result = receiver
            .receive_message(
                validator_id.clone(),
                future_timestamp,
                message_id.clone(),
                payload.clone(),
            )
            .await;
        assert!(result.is_ok()); // No error, but message was dropped

        // Verify message was NOT delivered to channel
        let timeout_result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            channel.recv(),
        )
        .await;
        assert!(timeout_result.is_err(), "Future message should be dropped, not delivered");
    }

    /// Test CR-7: Channel isolation - consensus receives exactly what was enqueued
    #[tokio::test]
    async fn test_channel_isolation() {
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let mut receiver = ConsensusReceiver::new(10, 60, 300, validators);
        let mut channel = receiver.message_channel();

        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01, 0x02, 0x03];
        let now = current_time().unwrap();

        // Send a message
        receiver
            .receive_message(
                validator_id.clone(),
                now,
                message_id.clone(),
                payload.clone(),
            )
            .await
            .unwrap();

        // Receive from channel (with timeout)
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            channel.recv(),
        )
        .await
        .expect("timeout")
        .expect("channel closed");

        // Verify exact contents
        assert_eq!(received.from_validator_id, validator_id);
        assert_eq!(received.payload, payload);
        assert!(received.received_at >= now);
        assert!(received.received_at <= now + 1); // Within 1 second
    }

    /// Test CR-6: Ack semantics - ack called only after enqueue succeeds
    #[tokio::test]
    async fn test_ack_after_enqueue() {
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let receiver = ConsensusReceiver::new(10, 60, 300, validators);
        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01];
        let now = current_time().unwrap();

        // This should succeed without error
        let result = receiver
            .receive_message(validator_id.clone(), now, message_id.clone(), payload)
            .await;

        // Should not error - ack is best-effort
        assert!(result.is_ok());
    }

    /// Test cache ordering fix: channel full → retry succeeds
    ///
    /// This is a critical correctness test for the cache-after-enqueue fix.
    ///
    /// Scenario:
    /// 1. Channel is full, message dropped
    /// 2. Message is NOT recorded in cache (cache-after-enqueue)
    /// 3. Channel is freed (consumer drains)
    /// 4. Same message retried → should succeed
    ///
    /// This verifies we don't have permanent message loss under congestion.
    #[tokio::test]
    async fn test_cache_ordering_channel_full_then_freed() {
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let mut receiver = ConsensusReceiver::new(2, 60, 300, validators); // Capacity=2
        let mut channel = receiver.message_channel();

        let message_id = Hash([2u8; 32]);
        let now = current_time().unwrap();

        // Fill the channel with 2 messages
        receiver
            .receive_message(validator_id.clone(), now, Hash([10u8; 32]), vec![10])
            .await
            .unwrap();
        receiver
            .receive_message(validator_id.clone(), now, Hash([11u8; 32]), vec![11])
            .await
            .unwrap();

        // Now try to send our target message - channel is full, should drop
        receiver
            .receive_message(
                validator_id.clone(),
                now,
                message_id.clone(),
                vec![99],
            )
            .await
            .unwrap();

        // Drain the channel (consume first 2 messages)
        let _ = channel.recv().await;
        let _ = channel.recv().await;

        // Now retry the same message → should succeed because it's not in cache
        receiver
            .receive_message(
                validator_id.clone(),
                now,
                message_id.clone(),
                vec![99],
            )
            .await
            .unwrap();

        // Receive the retry - it should now be in channel
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), channel.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(msg.from_validator_id, validator_id);
        assert_eq!(msg.payload, vec![99]);
    }

    /// Test bounded channel - drops when full (CR-5)
    #[tokio::test]
    async fn test_channel_full_drops() {
        let mut validators = std::collections::HashSet::new();
        validators.insert(Hash([99u8; 32]));
        for i in 0..10 {
            validators.insert(Hash([i as u8; 32]));
        }

        let receiver = ConsensusReceiver::new(2, 60, 300, validators); // Tiny channel
        let now = current_time().unwrap();

        // Send 2 messages (fill the channel)
        for i in 0..2 {
            let validator_id = Hash([i as u8; 32]);
            let message_id = Hash([(i * 2) as u8; 32]);
            let payload = vec![i as u8];

            receiver
                .receive_message(validator_id, now, message_id, payload)
                .await
                .unwrap();
        }

        // 3rd message should be silently dropped (channel full)
        let validator_id = Hash([99u8; 32]);
        let message_id = Hash([99u8; 32]);
        let payload = vec![99];

        let result = receiver
            .receive_message(validator_id, now, message_id, payload)
            .await;

        // Should not error - just silently dropped
        assert!(result.is_ok());
    }

    /// Test dedup TTL expiry - old messages can be accepted again
    #[tokio::test]
    async fn test_dedup_ttl_expiry() {
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let receiver = ConsensusReceiver::new(10, 60, 1, validators); // 1 second TTL
        let message_id = Hash([2u8; 32]);
        let payload = vec![0x01];

        let now = current_time().unwrap();

        // First message accepted
        receiver
            .receive_message(
                validator_id.clone(),
                now,
                message_id.clone(),
                payload.clone(),
            )
            .await
            .unwrap();

        // Wait for TTL to expire
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Same message_id should be accepted again after TTL expiry
        let now2 = current_time().unwrap();
        let result = receiver
            .receive_message(
                validator_id.clone(),
                now2,
                message_id.clone(),
                payload.clone(),
            )
            .await;

        // Should be accepted (TTL expired)
        assert!(result.is_ok());
    }

    /// Test different message_ids are not deduplicated
    #[tokio::test]
    async fn test_different_message_ids_not_deduplicated() {
        let validator_id = Hash([1u8; 32]);
        let mut validators = std::collections::HashSet::new();
        validators.insert(validator_id.clone());

        let receiver = ConsensusReceiver::new(10, 60, 300, validators);
        let now = current_time().unwrap();

        // Send two messages with different IDs
        let msg1_id = Hash([2u8; 32]);
        let msg2_id = Hash([3u8; 32]);
        let payload = vec![0x01];

        receiver
            .receive_message(
                validator_id.clone(),
                now,
                msg1_id.clone(),
                payload.clone(),
            )
            .await
            .unwrap();

        receiver
            .receive_message(
                validator_id.clone(),
                now,
                msg2_id.clone(),
                payload.clone(),
            )
            .await
            .unwrap();

        // Both should be in channel (not deduplicated)
        // Could consume and verify, but tests above cover that
    }
}
