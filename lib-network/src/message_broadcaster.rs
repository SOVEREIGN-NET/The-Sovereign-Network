//! MessageBroadcaster trait for consensus validator communication
//!
//! Provides a network abstraction for broadcasting consensus messages (proposals, votes)
//! to validators across the network. Implements clean separation between consensus
//! authority (consensus layer) and network delivery (networking layer).
//!
//! # Architecture
//!
//! - **Authority Boundary**: Only ValidatorMessage (consensus-signed) can be broadcast
//! - **Consensus Independence**: Consensus correctness must NOT depend on broadcast success
//! - **Best-Effort Delivery**: Broadcasting is gossip-based, partial failure is expected
//! - **Validator Identity**: Validators identified by consensus layer, not network tier
//!
//! # Usage
//!
//! ```ignore
//! use lib_network::message_broadcaster::{MessageBroadcaster, MeshMessageBroadcaster};
//! use lib_consensus::validators::ValidatorMessage;
//! use lib_crypto::PublicKey;
//!
//! let broadcaster = MeshMessageBroadcaster::new(
//!     local_peer_id,
//!     peer_registry,
//!     mesh_router,
//! );
//!
//! let target_validators = vec![validator1_pubkey, validator2_pubkey];
//! let result = broadcaster
//!     .broadcast_to_validators(message, &target_validators)
//!     .await?;
//!
//! println!("Delivered to {}/{} validators", result.delivered, result.attempted);
//! ```

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{info, warn};

use lib_crypto::PublicKey;
use lib_identity::IdentityId;

use crate::identity::unified_peer::UnifiedPeerId;
use crate::peer_registry::SharedPeerRegistry;
use crate::routing::message_routing::MeshMessageRouter;
use crate::types::mesh_message::ZhtpMeshMessage;

// Re-export from lib-consensus for convenience
pub use lib_consensus::validators::ValidatorMessage;

/// Telemetry result of broadcast operation
///
/// This is informational, not transactional. Consensus must not
/// use this for control flow - it's for metrics/monitoring only.
#[derive(Debug, Clone)]
pub struct BroadcastResult {
    /// Number of validators targeted for broadcast
    pub attempted: usize,

    /// Number of validators successfully sent to
    pub delivered: usize,

    /// Number of validators that failed to receive message
    pub failed: usize,

    /// Number of validators skipped (not found, not authenticated, etc.)
    pub skipped: usize,

    /// IdentityIds of validators that failed (for retry/monitoring)
    ///
    /// **INFORMATIONAL ONLY**
    ///
    /// This field is telemetry and MUST NOT be used for:
    /// - Consensus decisions or voting logic
    /// - Slashing or punishment calculations
    /// - Quorum determination
    /// - Authority or validator liveness inference
    ///
    /// It reflects transient network failures, not validator authority.
    /// All network delivery information is best-effort and probabilistic.
    pub failed_validators: Vec<IdentityId>,
}

/// MessageBroadcaster trait for consensus validator communication
///
/// Provides best-effort, gossip-based broadcasting of consensus messages to validators.
/// All messages must be pre-signed ValidatorMessage instances (signed by consensus layer).
///
/// # Best-Effort Semantics
///
/// Broadcasting is non-blocking and best-effort:
/// - Partial delivery is normal and expected
/// - Transient peer failures do not cause retries
/// - Consensus correctness must NOT depend on broadcast success
/// - Broadcast results are telemetry, not control flow
#[async_trait]
pub trait MessageBroadcaster: Send + Sync {
    /// Broadcast consensus message to specified validators
    ///
    /// # Arguments
    /// * `message` - ValidatorMessage to broadcast (already signed by consensus)
    /// * `target_validators` - PublicKeys of validators to target
    ///
    /// # Returns
    /// BroadcastResult with delivery telemetry (not control flow)
    ///
    /// # Semantics
    /// - Non-blocking, best-effort operation
    /// - Individual validator failures do not stop broadcast to others
    /// - Returns immediately; does not wait for delivery confirmation
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        target_validators: &[PublicKey],
    ) -> Result<BroadcastResult>;

    /// Send consensus message to specific validator (point-to-point)
    ///
    /// # Arguments
    /// * `validator_pubkey` - PublicKey of target validator
    /// * `message` - ValidatorMessage to send (must be fully signed by consensus)
    ///
    /// # Returns
    /// Ok(()) if message was queued for delivery, Err if validator not found or invalid
    async fn send_to_validator(
        &self,
        validator_pubkey: &PublicKey,
        message: ValidatorMessage,
    ) -> Result<()>;

    /// Query number of reachable validators from target list
    ///
    /// # Arguments
    /// * `target_validators` - PublicKeys to check
    ///
    /// # Returns
    /// Count of validators currently reachable and verified in PeerRegistry
    async fn reachable_validator_count(
        &self,
        target_validators: &[PublicKey],
    ) -> Result<usize>;

    /// Check if specific validator is currently reachable
    ///
    /// # Arguments
    /// * `validator_pubkey` - PublicKey to check
    ///
    /// # Returns
    /// Ok(true) if validator is reachable and verified, Ok(false) otherwise
    async fn is_validator_reachable(
        &self,
        validator_pubkey: &PublicKey,
    ) -> Result<bool>;
}

/// Production implementation using MeshMessageRouter for delivery
pub struct MeshMessageBroadcaster {
    /// Local peer identity
    local_peer_id: UnifiedPeerId,

    /// Peer registry for validator lookup
    peer_registry: SharedPeerRegistry,

    /// Message router for delivery
    mesh_router: Arc<MeshMessageRouter>,
}

impl MeshMessageBroadcaster {
    /// Create a new MeshMessageBroadcaster
    pub fn new(
        local_peer_id: UnifiedPeerId,
        peer_registry: SharedPeerRegistry,
        mesh_router: Arc<MeshMessageRouter>,
    ) -> Self {
        Self {
            local_peer_id,
            peer_registry,
            mesh_router,
        }
    }

    /// Find validators in PeerRegistry by their PublicKeys
    ///
    /// GUARD MB-5: Only returns verified peers (is_verified() == true).
    /// Bootstrap-mode peers are excluded to prevent unverified peers from
    /// participating in consensus message delivery.
    async fn find_validators(
        &self,
        target_validators: &[PublicKey],
    ) -> Vec<UnifiedPeerId> {
        let registry = self.peer_registry.read().await;

        target_validators
            .iter()
            .filter_map(|pubkey| {
                registry.find_by_public_key(pubkey)
                    .map(|entry| entry.peer_id.clone())
            })
            .filter(|peer| peer.is_verified()) // GUARD MB-5: Only verified peers
            .collect()
    }

    /// Get current timestamp in seconds
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[async_trait]
impl MessageBroadcaster for MeshMessageBroadcaster {
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        target_validators: &[PublicKey],
    ) -> Result<BroadcastResult> {
        let attempted = target_validators.len();
        let validators = self.find_validators(target_validators).await;

        let mut delivered = 0;
        let mut failed = 0;
        let mut skipped = attempted - validators.len();
        let mut failed_validators = Vec::new();

        let sender_pubkey = self.local_peer_id.public_key();

        // Best-effort broadcast - continue on individual failures
        for validator in validators {
            // Skip self
            if validator == self.local_peer_id {
                skipped += 1;
                continue;
            }

            // Wrap in ZhtpMeshMessage for routing
            let mesh_message = ZhtpMeshMessage::ValidatorMessage(message.clone());

            // Route message via mesh router
            match self.mesh_router.route_message(
                mesh_message,
                validator.public_key().clone(),
                sender_pubkey.clone(),
            ).await {
                Ok(_) => delivered += 1,
                Err(e) => {
                    failed += 1;
                    warn!(
                        "Failed to broadcast to validator {}: {}",
                        validator.did(),
                        e
                    );
                    // Use validator's node_id as IdentityId
                    failed_validators.push(lib_crypto::Hash::from_bytes(validator.node_id().as_bytes()));
                }
            }
        }

        info!(
            "Broadcast complete: {}/{} delivered ({} failed, {} skipped)",
            delivered, attempted, failed, skipped
        );

        Ok(BroadcastResult {
            attempted,
            delivered,
            failed,
            skipped,
            failed_validators,
        })
    }

    async fn send_to_validator(
        &self,
        validator_pubkey: &PublicKey,
        message: ValidatorMessage,
    ) -> Result<()> {
        let registry = self.peer_registry.read().await;
        let validator = registry
            .find_by_public_key(validator_pubkey)
            .ok_or_else(|| anyhow!("Validator not found"))?;

        // GUARD MB-6: Prevent self-send to avoid loops and re-entrancy
        if validator.peer_id == self.local_peer_id {
            return Err(anyhow!(
                "Cannot send to self: {}",
                validator.peer_id.did()
            ));
        }

        // GUARD MB-5: Strengthen peer verification - only verified peers can receive
        if !validator.peer_id.is_verified() {
            return Err(anyhow!(
                "Cannot send to unverified validator: {}",
                validator.peer_id.did()
            ));
        }

        let mesh_message = ZhtpMeshMessage::ValidatorMessage(message);

        self.mesh_router.route_message(
            mesh_message,
            validator.peer_id.public_key().clone(),
            self.local_peer_id.public_key().clone(),
        ).await?;

        Ok(())
    }

    async fn reachable_validator_count(
        &self,
        target_validators: &[PublicKey],
    ) -> Result<usize> {
        let validators = self.find_validators(target_validators).await;
        Ok(validators.len())
    }

    async fn is_validator_reachable(
        &self,
        validator_pubkey: &PublicKey,
    ) -> Result<bool> {
        let registry = self.peer_registry.read().await;

        match registry.find_by_public_key(validator_pubkey) {
            Some(entry) => Ok(entry.peer_id.is_verified()),
            None => Ok(false),
        }
    }
}

/// Mock implementation for testing
///
/// Records all broadcast and send operations without actually routing messages.
/// Supports partition testing and failure simulation for comprehensive testing.
pub struct MockMessageBroadcaster {
    /// Recorded broadcasts: (message, target_validators)
    pub broadcasts: Arc<tokio::sync::Mutex<Vec<(ValidatorMessage, Vec<PublicKey>)>>>,

    /// Recorded sends: (validator_pubkey, message)
    pub sends: Arc<tokio::sync::Mutex<Vec<(PublicKey, ValidatorMessage)>>>,

    /// Reachable validators - used to simulate network partitions
    /// If Some, only these validators are reachable; if None, all are reachable
    pub reachable: Arc<tokio::sync::RwLock<Option<std::collections::HashSet<PublicKey>>>>,

    /// Validators that should fail - used to simulate delivery failures
    /// Any validator in this set will cause delivery to fail
    pub fail_on: Arc<tokio::sync::RwLock<std::collections::HashSet<PublicKey>>>,

    /// Simulated validator count
    pub validator_count: usize,
}

impl MockMessageBroadcaster {
    /// Create a new mock broadcaster with all validators reachable
    pub fn new(validator_count: usize) -> Self {
        Self {
            broadcasts: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            sends: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            reachable: Arc::new(tokio::sync::RwLock::new(None)),
            fail_on: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
            validator_count,
        }
    }

    /// Set which validators are reachable (simulates network partition)
    ///
    /// If called with Some(set), only validators in the set are reachable.
    /// If called with None, all validators are reachable.
    pub async fn set_reachable(&self, validators: Option<std::collections::HashSet<PublicKey>>) {
        *self.reachable.write().await = validators;
    }

    /// Mark validators that should fail delivery
    pub async fn set_fail_on(&self, validators: std::collections::HashSet<PublicKey>) {
        *self.fail_on.write().await = validators;
    }

    /// Clear all failure markers
    pub async fn clear_failures(&self) {
        self.fail_on.write().await.clear();
    }

    /// Get number of broadcast calls recorded
    pub async fn broadcast_count(&self) -> usize {
        self.broadcasts.lock().await.len()
    }

    /// Get number of send calls recorded
    pub async fn send_count(&self) -> usize {
        self.sends.lock().await.len()
    }

    /// Check if a validator is reachable (respects partition simulation)
    async fn is_reachable(&self, pubkey: &PublicKey) -> bool {
        let reachable_guard = self.reachable.read().await;
        match reachable_guard.as_ref() {
            Some(set) => set.contains(pubkey),
            None => true, // No partition, all reachable
        }
    }

    /// Check if a validator should fail (respects failure simulation)
    async fn should_fail(&self, pubkey: &PublicKey) -> bool {
        self.fail_on.read().await.contains(pubkey)
    }
}

#[async_trait]
impl MessageBroadcaster for MockMessageBroadcaster {
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        target_validators: &[PublicKey],
    ) -> Result<BroadcastResult> {
        // Record the broadcast
        self.broadcasts
            .lock()
            .await
            .push((message, target_validators.to_vec()));

        let mut delivered = 0;
        let mut failed = 0;
        let mut skipped = 0;
        let mut failed_validators = Vec::new();

        // Simulate delivery based on reachability and failure configuration
        for validator_pubkey in target_validators {
            // Check if validator is reachable (partition simulation)
            if !self.is_reachable(validator_pubkey).await {
                skipped += 1;
                continue;
            }

            // Check if validator should fail (failure simulation)
            if self.should_fail(validator_pubkey).await {
                failed += 1;
                // Convert PublicKey to Hash for failed_validators list
                let pubkey_bytes = bincode::serialize(validator_pubkey)
                    .unwrap_or_else(|_| vec![0u8; 32]);
                failed_validators.push(lib_crypto::Hash::from_bytes(&pubkey_bytes[..]));
            } else {
                delivered += 1;
            }
        }

        Ok(BroadcastResult {
            attempted: target_validators.len(),
            delivered,
            failed,
            skipped,
            failed_validators,
        })
    }

    async fn send_to_validator(
        &self,
        validator_pubkey: &PublicKey,
        message: ValidatorMessage,
    ) -> Result<()> {
        // Record the send
        self.sends.lock().await.push((validator_pubkey.clone(), message));

        // Check if validator is reachable
        if !self.is_reachable(validator_pubkey).await {
            return Err(anyhow!("Validator not reachable (partition simulated)"));
        }

        // Check if validator should fail
        if self.should_fail(validator_pubkey).await {
            return Err(anyhow!("Send to validator failed (simulated)"));
        }

        Ok(())
    }

    async fn reachable_validator_count(
        &self,
        target_validators: &[PublicKey],
    ) -> Result<usize> {
        let mut count = 0;
        for validator_pubkey in target_validators {
            if self.is_reachable(validator_pubkey).await {
                count += 1;
            }
        }
        Ok(count)
    }

    async fn is_validator_reachable(
        &self,
        validator_pubkey: &PublicKey,
    ) -> Result<bool> {
        Ok(self.is_reachable(validator_pubkey).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_result_creation() {
        let result = BroadcastResult {
            attempted: 10,
            delivered: 8,
            failed: 2,
            skipped: 0,
            failed_validators: vec![],
        };

        assert_eq!(result.attempted, 10);
        assert_eq!(result.delivered, 8);
        assert_eq!(result.failed, 2);
    }

    #[tokio::test]
    async fn test_mock_broadcaster_records_broadcasts() {
        let mock = MockMessageBroadcaster::new(5);

        assert_eq!(mock.broadcast_count().await, 0);
        assert_eq!(mock.send_count().await, 0);
    }

    #[tokio::test]
    async fn test_mock_broadcaster_reachable_count() {
        let mock = MockMessageBroadcaster::new(5);
        let target = vec![];

        let count = mock.reachable_validator_count(&target).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_mock_broadcaster_is_reachable() {
        let mock = MockMessageBroadcaster::new(5);
        let validator_pubkey = PublicKey::new(vec![0u8; 32]);

        let reachable = mock.is_validator_reachable(&validator_pubkey).await.unwrap();
        assert!(reachable);
    }
}
