//! Store-and-forward queue for identity envelopes (Phase 3 baseline)

use lib_protocols::types::{IdentityEnvelope, MessageTtl, DeliveryReceipt};
use lib_protocols::identity_messaging::verify_pouw_stamp_with_sender_did;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct QueuedEnvelope {
    envelope: IdentityEnvelope,
    expires_at: u64,
}

pub struct IdentityStoreForward {
    per_recipient: HashMap<String, VecDeque<QueuedEnvelope>>,
    max_queue_per_recipient: usize,
    pouw_verifier: Option<PoUwVerifier>,
    stats: IdentityQueueStats,
}

pub type PoUwVerifier = Arc<dyn Fn(&IdentityEnvelope) -> Result<bool, String> + Send + Sync>;

#[derive(Debug, Clone, Default)]
pub struct IdentityQueueStats {
    pub enqueued: u64,
    pub expired: u64,
    pub acknowledged: u64,
    pub retained_after_ack: u64,
}

impl IdentityStoreForward {
    pub fn new(max_queue_per_recipient: usize) -> Self {
        Self {
            per_recipient: HashMap::new(),
            max_queue_per_recipient,
            pouw_verifier: None,
            stats: IdentityQueueStats::default(),
        }
    }

    /// Set PoUW verifier used to validate incoming envelopes
    pub fn set_pouw_verifier(&mut self, verifier: PoUwVerifier) {
        self.pouw_verifier = Some(verifier);
    }

    /// Default PoUW verifier using sender DID resolution
    pub fn default_pouw_verifier() -> PoUwVerifier {
        Arc::new(|env: &IdentityEnvelope| {
            if let Some(stamp) = &env.pouw_stamp {
                verify_pouw_stamp_with_sender_did(stamp, &env.sender_did)
            } else {
                Ok(true)
            }
        })
    }

    /// Enqueue an envelope for recipient DID (TTL enforced)
    pub fn enqueue(&mut self, envelope: IdentityEnvelope) -> Result<(), String> {
        let now = current_unix_timestamp()?;
        self.enqueue_at(envelope, now)
    }

    /// Get pending envelopes for recipient (non-expired)
    pub fn get_pending(&mut self, recipient_did: &str) -> Result<Vec<IdentityEnvelope>, String> {
        self.expire()?;
        let queue = match self.per_recipient.get(recipient_did) {
            Some(queue) => queue,
            None => return Ok(Vec::new()),
        };
        Ok(queue.iter().map(|q| q.envelope.clone()).collect())
    }

    /// Get pending envelopes that include a payload for the given device_id
    pub fn get_pending_for_device(
        &mut self,
        recipient_did: &str,
        device_id: &str,
    ) -> Result<Vec<IdentityEnvelope>, String> {
        self.expire()?;
        let queue = match self.per_recipient.get(recipient_did) {
            Some(queue) => queue,
            None => return Ok(Vec::new()),
        };
        let mut filtered = Vec::new();
        for queued in queue.iter() {
            if queued.envelope.payloads.iter().any(|p| p.device_id == device_id) {
                filtered.push(queued.envelope.clone());
            }
        }
        Ok(filtered)
    }

    /// Take and clear pending envelopes for recipient (non-expired)
    pub fn take_pending(&mut self, recipient_did: &str) -> Result<Vec<IdentityEnvelope>, String> {
        self.expire()?;
        let queue = self.per_recipient.remove(recipient_did);
        Ok(queue
            .unwrap_or_default()
            .into_iter()
            .map(|q| q.envelope)
            .collect())
    }

    /// Acknowledge delivery (remove envelope by message_id)
    pub fn acknowledge_delivery(&mut self, recipient_did: &str, message_id: u64) -> Result<bool, String> {
        let queue = match self.per_recipient.get_mut(recipient_did) {
            Some(queue) => queue,
            None => return Ok(false),
        };
        let original_len = queue.len();
        queue.retain(|q| {
            if q.envelope.message_id != message_id {
                return true;
            }
            if q.envelope.retain_until_ttl {
                self.stats.retained_after_ack += 1;
                true
            } else {
                self.stats.acknowledged += 1;
                false
            }
        });
        Ok(queue.len() != original_len)
    }

    /// Acknowledge delivery using a receipt
    pub fn acknowledge_delivery_receipt(
        &mut self,
        recipient_did: &str,
        receipt: &DeliveryReceipt,
    ) -> Result<bool, String> {
        self.acknowledge_delivery(recipient_did, receipt.message_id)
    }

    /// Expire old envelopes based on TTL
    pub fn expire(&mut self) -> Result<(), String> {
        let now = current_unix_timestamp()?;
        self.expire_at(now)
    }

    pub fn stats(&self) -> IdentityQueueStats {
        self.stats.clone()
    }

    fn enqueue_at(&mut self, envelope: IdentityEnvelope, now: u64) -> Result<(), String> {
        if let Some(verifier) = &self.pouw_verifier {
            if envelope.pouw_stamp.is_some() {
                let is_valid = verifier(&envelope)?;
                if !is_valid {
                    return Err("Invalid PoUW stamp".to_string());
                }
            }
        }
        let ttl_secs = envelope.ttl.as_seconds();
        if ttl_secs == 0 {
            return Err("TTL=0 not storable".to_string());
        }
        let expires_at = now.saturating_add(ttl_secs);

        let queue = self
            .per_recipient
            .entry(envelope.recipient_did.clone())
            .or_insert_with(VecDeque::new);

        if queue.len() >= self.max_queue_per_recipient {
            // Evict oldest
            queue.pop_front();
        }

        queue.push_back(QueuedEnvelope { envelope, expires_at });
        self.stats.enqueued += 1;
        Ok(())
    }

    fn expire_at(&mut self, now: u64) -> Result<(), String> {
        self.per_recipient.retain(|_, queue| {
            let before = queue.len() as u64;
            queue.retain(|q| q.expires_at > now);
            let after = queue.len() as u64;
            if before > after {
                self.stats.expired += before - after;
            }
            !queue.is_empty()
        });
        Ok(())
    }
}

fn current_unix_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "System time before Unix epoch".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_protocols::types::{DevicePayload, MessageTtl};

    fn sample_envelope(recipient: &str, ttl: MessageTtl, message_id: u64) -> IdentityEnvelope {
        IdentityEnvelope {
            message_id,
            sender_did: "did:zhtp:sender".to_string(),
            recipient_did: recipient.to_string(),
            created_at: 1,
            ttl,
            retain_until_ttl: false,
            pouw_stamp: None,
            payloads: vec![DevicePayload {
                device_id: "device-1".to_string(),
                ciphertext: vec![1, 2, 3],
            }],
        }
    }

    #[test]
    fn test_enqueue_and_ack() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 42);
        queue.enqueue(env)?;

        let pending = queue.get_pending("did:zhtp:alice")?;
        assert_eq!(pending.len(), 1);

        let removed = queue.acknowledge_delivery("did:zhtp:alice", 42)?;
        assert!(removed);
        let pending = queue.get_pending("did:zhtp:alice")?;
        assert!(pending.is_empty());
        Ok(())
    }

    #[test]
    fn test_take_pending_clears_queue() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 9);
        queue.enqueue(env)?;
        let taken = queue.take_pending("did:zhtp:alice")?;
        assert_eq!(taken.len(), 1);
        let pending = queue.get_pending("did:zhtp:alice")?;
        assert!(pending.is_empty());
        Ok(())
    }

    #[test]
    fn test_stats_tracking() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 1);
        queue.enqueue(env)?;
        let stats = queue.stats();
        assert_eq!(stats.enqueued, 1);
        Ok(())
    }

    #[test]
    fn test_get_pending_for_device_filters() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 2);
        queue.enqueue(env)?;

        let hits = queue.get_pending_for_device("did:zhtp:alice", "device-1")?;
        assert_eq!(hits.len(), 1);

        let misses = queue.get_pending_for_device("did:zhtp:alice", "device-2")?;
        assert!(misses.is_empty());

        Ok(())
    }

    #[test]
    fn test_offline_to_online_ack_flow() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 3);
        queue.enqueue(env)?;

        let pending = queue.get_pending_for_device("did:zhtp:alice", "device-1")?;
        assert_eq!(pending.len(), 1);

        let removed = queue.acknowledge_delivery("did:zhtp:alice", 3)?;
        assert!(removed);

        let pending_after = queue.get_pending_for_device("did:zhtp:alice", "device-1")?;
        assert!(pending_after.is_empty());

        Ok(())
    }

    #[test]
    fn test_ttl_expiry() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let env = sample_envelope("did:zhtp:alice", MessageTtl::Hours24, 100);
        queue.enqueue_at(env, 10)?;
        queue.expire_at(10 + MessageTtl::Hours24.as_seconds() + 1)?;
        let pending = queue.get_pending("did:zhtp:alice")?;
        assert!(pending.is_empty());
        Ok(())
    }

    #[test]
    fn test_no_store_rejected() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let env = sample_envelope("did:zhtp:alice", MessageTtl::NoStore, 7);
        let result = queue.enqueue(env);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_retain_until_ttl_on_ack() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        let mut env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 77);
        env.retain_until_ttl = true;
        queue.enqueue(env)?;
        let removed = queue.acknowledge_delivery("did:zhtp:alice", 77)?;
        assert!(!removed, "Should retain until TTL even after ack");
        Ok(())
    }

    #[test]
    fn test_pouw_verifier_rejects() -> Result<(), String> {
        let mut queue = IdentityStoreForward::new(10);
        queue.set_pouw_verifier(Arc::new(|_env| Ok(false)));
        let mut env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 88);
        env.pouw_stamp = Some(lib_protocols::types::PoUwStamp {
            sender_device_key_id: [0u8; 32],
            challenge: vec![1],
            message_hash: [0u8; 32],
            stamp_hash: [0u8; 32],
            signature: vec![1],
            signature_algorithm: lib_crypto::types::SignatureAlgorithm::Dilithium5,
        });
        let result = queue.enqueue(env);
        assert!(result.is_err());
        Ok(())
    }
}
