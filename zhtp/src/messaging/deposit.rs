//! Deposit store — durable (in-process) store-and-forward for undelivered messages.
//!
//! ## Delivery model (MSG-R1 / MSG-R5)
//!
//! Envelopes stay in the store until the client **acks** them. Polling and inbound
//! streaming **peek** only; they never delete. That way a disconnect mid-response
//! cannot lose mail.
//!
//! Each envelope gets a stable `message_id` = hex(blake3(envelope_bytes)).
//! Duplicate deposits of the same bytes are ignored (idempotent).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// How long undelivered deposits are kept before GC purges them.
const DEPOSIT_TTL: Duration = Duration::from_secs(48 * 3600); // 48 hours

/// Maximum pending envelopes per (sender, recipient) pair.
const MAX_PENDING_PER_PAIR: usize = 100;

/// A single pending delivery (one envelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDelivery {
    /// Stable id: hex(blake3(envelope_bytes)).
    pub message_id: String,
    /// Opaque PQ-encrypted envelope (bincode of client SecureMessage / MessageEnvelope).
    pub envelope: Vec<u8>,
    /// Unix seconds when deposited (API / clients).
    pub deposited_at: u64,
    /// Monotonic clock for TTL GC (not serialized).
    #[serde(skip, default = "Instant::now")]
    pub deposited_instant: Instant,
    /// Sender DID (for cancellation / auth).
    pub sender_did: String,
    /// Recipient DID.
    pub recipient_did: String,
}

/// Compute stable message id from envelope bytes.
pub fn message_id_for_envelope(envelope: &[u8]) -> String {
    hex::encode(lib_crypto::hash_blake3(envelope))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// In-memory deposit store (process-local; Phase 3 will add sled).
#[derive(Debug, Default)]
pub struct DepositStore {
    /// Keyed by (sender_did, recipient_did).
    pending: RwLock<HashMap<(String, String), Vec<PendingDelivery>>>,
    /// Index message_id → (sender, recipient) for O(1) ack.
    by_id: RwLock<HashMap<String, (String, String)>>,
}

impl DepositStore {
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            by_id: RwLock::new(HashMap::new()),
        }
    }

    /// Deposit a single envelope. Returns `(message_id, is_new)`.
    /// If the same envelope bytes were already deposited, returns existing id and `false`.
    pub fn deposit_one(
        &self,
        sender_did: &str,
        recipient_did: &str,
        envelope: Vec<u8>,
    ) -> Result<(String, bool), String> {
        let message_id = message_id_for_envelope(&envelope);
        let key = (sender_did.to_string(), recipient_did.to_string());

        {
            let by_id = self.by_id.read();
            if by_id.contains_key(&message_id) {
                debug!(
                    message_id = %message_id,
                    "deposit: duplicate envelope, already stored"
                );
                return Ok((message_id, false));
            }
        }

        let mut store = self.pending.write();
        let mut by_id = self.by_id.write();

        // Re-check under write lock
        if by_id.contains_key(&message_id) {
            return Ok((message_id, false));
        }

        let queue = store.entry(key.clone()).or_default();

        if queue.len() >= MAX_PENDING_PER_PAIR {
            warn!(
                sender = %sender_did,
                recipient = %recipient_did,
                max = MAX_PENDING_PER_PAIR,
                "deposit store full for pair — rejecting"
            );
            return Err(format!(
                "deposit store full: max {MAX_PENDING_PER_PAIR} pending for this pair"
            ));
        }

        queue.push(PendingDelivery {
            message_id: message_id.clone(),
            envelope,
            deposited_at: now_unix(),
            deposited_instant: Instant::now(),
            sender_did: sender_did.to_string(),
            recipient_did: recipient_did.to_string(),
        });
        by_id.insert(message_id.clone(), key);

        info!(
            sender = %sender_did,
            recipient = %recipient_did,
            message_id = %message_id,
            pending = queue.len(),
            "message deposited"
        );
        Ok((message_id, true))
    }

    /// Deposit many envelopes. Returns `(accepted_count, message_ids)`.
    /// Stops on first capacity error after accepting earlier envelopes.
    pub fn deposit(
        &self,
        sender_did: &str,
        recipient_did: &str,
        envelopes: Vec<Vec<u8>>,
    ) -> Result<(usize, Vec<String>), String> {
        if envelopes.is_empty() {
            return Err("no envelopes".to_string());
        }
        let mut ids = Vec::with_capacity(envelopes.len());
        let mut accepted = 0usize;
        for env in envelopes {
            match self.deposit_one(sender_did, recipient_did, env) {
                Ok((id, is_new)) => {
                    ids.push(id);
                    if is_new {
                        accepted += 1;
                    }
                }
                Err(e) => {
                    if accepted == 0 && ids.is_empty() {
                        return Err(e);
                    }
                    // Partial success: return what we took
                    break;
                }
            }
        }
        Ok((accepted, ids))
    }

    /// Peek all pending envelopes for a recipient (does **not** remove).
    pub fn peek_for_recipient(&self, recipient_did: &str) -> Vec<PendingDelivery> {
        let store = self.pending.read();
        let mut out = Vec::new();
        for ((_, recip), queue) in store.iter() {
            if recip == recipient_did {
                out.extend(queue.iter().cloned());
            }
        }
        if !out.is_empty() {
            debug!(
                recipient = %recipient_did,
                count = out.len(),
                "peeked pending deposits (retained until ack)"
            );
        }
        out
    }

    /// Remove specific messages by id (client ACK). Returns count removed.
    pub fn ack(&self, message_ids: &[String]) -> usize {
        if message_ids.is_empty() {
            return 0;
        }
        let mut store = self.pending.write();
        let mut by_id = self.by_id.write();
        let mut removed = 0;

        for mid in message_ids {
            let Some((sender, recipient)) = by_id.remove(mid) else {
                continue;
            };
            if let Some(queue) = store.get_mut(&(sender.clone(), recipient.clone())) {
                let before = queue.len();
                queue.retain(|d| d.message_id != *mid);
                removed += before - queue.len();
                if queue.is_empty() {
                    store.remove(&(sender, recipient));
                }
            }
        }

        if removed > 0 {
            info!(count = removed, "acked and removed deposits");
        }
        removed
    }

    /// Cancel undelivered messages from a sender to a recipient.
    /// Returns number of envelopes cancelled.
    pub fn cancel(&self, sender_did: &str, recipient_did: &str) -> usize {
        let key = (sender_did.to_string(), recipient_did.to_string());
        let mut store = self.pending.write();
        let mut by_id = self.by_id.write();

        let Some(queue) = store.remove(&key) else {
            return 0;
        };
        let count = queue.len();
        for d in &queue {
            by_id.remove(&d.message_id);
        }
        if count > 0 {
            info!(
                sender = %sender_did,
                recipient = %recipient_did,
                count,
                "cancelled undelivered deposits"
            );
        }
        count
    }

    /// Purge expired deposits. Returns number of envelopes purged.
    pub fn gc_expired(&self) -> usize {
        let mut store = self.pending.write();
        let mut by_id = self.by_id.write();
        let mut purged = 0;
        let now = Instant::now();

        store.retain(|_, queue| {
            let before = queue.len();
            for d in queue.iter() {
                if now.duration_since(d.deposited_instant) >= DEPOSIT_TTL {
                    by_id.remove(&d.message_id);
                }
            }
            queue.retain(|d| now.duration_since(d.deposited_instant) < DEPOSIT_TTL);
            purged += before - queue.len();
            !queue.is_empty()
        });

        if purged > 0 {
            info!(purged, "GC purged expired deposits");
        }
        purged
    }

    /// Alias used by cleanup task (historical name).
    pub fn cleanup_expired(&self) -> usize {
        self.gc_expired()
    }

    /// Total pending envelopes across all pairs.
    pub fn total_pending(&self) -> usize {
        self.pending.read().values().map(|q| q.len()).sum()
    }

    pub fn has_pending(&self, recipient_did: &str) -> bool {
        self.pending
            .read()
            .iter()
            .any(|((_, r), q)| r == recipient_did && !q.is_empty())
    }
}

/// Shared deposit store handle.
pub type SharedDepositStore = Arc<DepositStore>;

/// Create a new shared deposit store.
pub fn new_shared_deposit_store() -> SharedDepositStore {
    Arc::new(DepositStore::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_peek_does_not_remove() {
        let store = DepositStore::new();
        let (id, is_new) = store
            .deposit_one("did:sov:alice", "did:sov:bob", vec![1, 2, 3])
            .unwrap();
        assert!(is_new);
        assert!(!id.is_empty());

        let peeked = store.peek_for_recipient("did:sov:bob");
        assert_eq!(peeked.len(), 1);
        assert_eq!(peeked[0].message_id, id);

        // Still there
        assert_eq!(store.peek_for_recipient("did:sov:bob").len(), 1);
        assert_eq!(store.total_pending(), 1);
    }

    #[test]
    fn ack_removes() {
        let store = DepositStore::new();
        let (id, _) = store
            .deposit_one("did:sov:alice", "did:sov:bob", vec![9, 9, 9])
            .unwrap();
        assert_eq!(store.ack(&[id]), 1);
        assert_eq!(store.total_pending(), 0);
        assert!(store.peek_for_recipient("did:sov:bob").is_empty());
    }

    #[test]
    fn duplicate_deposit_idempotent() {
        let store = DepositStore::new();
        let env = vec![7, 7, 7];
        let (id1, new1) = store
            .deposit_one("did:sov:a", "did:sov:b", env.clone())
            .unwrap();
        let (id2, new2) = store.deposit_one("did:sov:a", "did:sov:b", env).unwrap();
        assert_eq!(id1, id2);
        assert!(new1);
        assert!(!new2);
        assert_eq!(store.total_pending(), 1);
    }

    #[test]
    fn cancel_clears_pair() {
        let store = DepositStore::new();
        store
            .deposit_one("did:sov:alice", "did:sov:bob", vec![1])
            .unwrap();
        store
            .deposit_one("did:sov:alice", "did:sov:bob", vec![2])
            .unwrap();
        assert_eq!(store.cancel("did:sov:alice", "did:sov:bob"), 2);
        assert_eq!(store.total_pending(), 0);
    }

    #[test]
    fn max_pending_enforced() {
        let store = DepositStore::new();
        for i in 0..MAX_PENDING_PER_PAIR {
            store
                .deposit_one("did:sov:a", "did:sov:b", vec![i as u8])
                .unwrap();
        }
        let err = store
            .deposit_one("did:sov:a", "did:sov:b", vec![255])
            .unwrap_err();
        assert!(err.contains("full"));
    }

    #[test]
    fn batch_deposit() {
        let store = DepositStore::new();
        let (n, ids) = store
            .deposit(
                "did:sov:a",
                "did:sov:b",
                vec![vec![1], vec![2], vec![1]], // third is dup of first
            )
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(ids.len(), 3);
        assert_eq!(store.total_pending(), 2);
    }
}
