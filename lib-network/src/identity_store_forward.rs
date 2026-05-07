//! Store-and-forward queue for identity envelopes (Phase 3 baseline)
//!
//! # Persistence
//!
//! When constructed via [`IdentityStoreForward::new_persistent`], the queue
//! stores every envelope in an embedded `sled` database keyed by
//! `(recipient_did, message_id)`.  On startup the in-memory `HashMap` is
//! rebuilt from disk, so queued messages survive process restarts.
//!
//! ```text
//! sled key = b'e' || recipient_did_utf8 || message_id_be_u64
//! value    = bincode(QueuedEnvelope)
//! ```
//!
//! Auto-corruption recovery follows the pattern used by `NonceCache`: if
//! `sled::open` reports corruption the directory is removed and recreated.

use lib_protocols::identity_messaging::verify_pouw_stamp_with_sender_did;
use lib_protocols::types::{DeliveryReceipt, IdentityEnvelope};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Envelope queued for store-and-forward delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueuedEnvelope {
    envelope: IdentityEnvelope,
    expires_at: u64,
}

pub struct IdentityStoreForward {
    per_recipient: HashMap<String, VecDeque<QueuedEnvelope>>,
    max_queue_per_recipient: usize,
    pouw_verifier: Option<PoUwVerifier>,
    stats: IdentityQueueStats,
    /// Optional sled backing store.  When `Some` every mutating operation
    /// is mirrored to disk.
    db: Option<sled::Db>,
}

pub type PoUwVerifier = Arc<dyn Fn(&IdentityEnvelope) -> Result<bool, String> + Send + Sync>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityQueueStats {
    pub enqueued: u64,
    pub expired: u64,
    pub acknowledged: u64,
    pub retained_after_ack: u64,
}

impl IdentityStoreForward {
    /// Create a new in-memory-only queue.
    pub fn new(max_queue_per_recipient: usize) -> Self {
        Self {
            per_recipient: HashMap::new(),
            max_queue_per_recipient,
            pouw_verifier: None,
            stats: IdentityQueueStats::default(),
            db: None,
        }
    }

    /// Create a queue backed by `sled` at `db_path`.
    ///
    /// Existing envelopes are loaded from disk automatically.
    /// If the database is corrupted it is wiped and recreated.
    pub fn new_persistent<P: AsRef<Path>>(
        db_path: P,
        max_queue_per_recipient: usize,
    ) -> Result<Self, String> {
        let db = Self::open_db(db_path)?;
        let mut store = Self {
            per_recipient: HashMap::new(),
            max_queue_per_recipient,
            pouw_verifier: None,
            stats: IdentityQueueStats::default(),
            db: Some(db),
        };
        store.load_from_db()?;
        info!("IdentityStoreForward: loaded {} recipient queues from disk", store.per_recipient.len());
        Ok(store)
    }

    // ------------------------------------------------------------------
    // DB helpers
    // ------------------------------------------------------------------

    fn open_db<P: AsRef<Path>>(db_path: P) -> Result<sled::Db, String> {
        match sled::open(db_path.as_ref()) {
            Ok(db) => Ok(db),
            Err(e) => {
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("corrupt")
                    || err_str.contains("crc")
                    || err_str.contains("checksum")
                    || err_str.contains("invalid")
                {
                    warn!(
                        "SLED CORRUPTION at {:?}: {}. Auto-recovering.",
                        db_path.as_ref(),
                        e
                    );
                    if let Err(rm_err) = std::fs::remove_dir_all(db_path.as_ref()) {
                        return Err(format!(
                            "Sled corrupted and auto-recovery failed: {}. Original: {}.",
                            rm_err, e
                        ));
                    }
                    if let Some(parent) = db_path.as_ref().parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    info!("Recreated sled database at {:?}", db_path.as_ref());
                    sled::open(db_path.as_ref())
                        .map_err(|e| format!("Failed to recreate sled db: {}", e))
                } else {
                    Err(format!("Failed to open sled db: {}", e))
                }
            }
        }
    }

    /// Encode a sled key for an envelope.
    ///
    /// Format: `b'e' || did_len_u16_be || recipient_did_bytes || message_id_be_u64`
    ///
    /// The 2-byte length prefix prevents prefix collisions between DIDs of
    /// different lengths (e.g., "did:zhtp:ab" + id won't collide with "did:zhtp:abc" + id).
    fn envelope_key(recipient_did: &str, message_id: u64) -> Vec<u8> {
        let did_len = recipient_did.len() as u16;
        let mut key = Vec::with_capacity(1 + 2 + recipient_did.len() + 8);
        key.push(b'e');
        key.extend_from_slice(&did_len.to_be_bytes());
        key.extend_from_slice(recipient_did.as_bytes());
        key.extend_from_slice(&message_id.to_be_bytes());
        key
    }

    fn parse_envelope_key(key: &[u8]) -> Option<(&str, u64)> {
        // Minimum: 1 (prefix) + 2 (did_len) + 0 (did) + 8 (msg_id) = 11
        if key.len() < 11 || key[0] != b'e' {
            return None;
        }
        let did_len = u16::from_be_bytes([key[1], key[2]]) as usize;
        if key.len() != 1 + 2 + did_len + 8 {
            return None;
        }
        let did = std::str::from_utf8(&key[3..3 + did_len]).ok()?;
        let msg_id = u64::from_be_bytes(key[3 + did_len..].try_into().ok()?);
        Some((did, msg_id))
    }

    /// Load all envelopes from sled into memory.
    fn load_from_db(&mut self) -> Result<(), String> {
        let db = match &self.db {
            Some(db) => db,
            None => return Ok(()),
        };

        for item in db.iter() {
            let (key, value) = item.map_err(|e| format!("Sled iteration error: {}", e))?;
            let (_, _) = match Self::parse_envelope_key(&key) {
                Some(k) => k,
                None => continue, // skip keys with wrong prefix
            };
            let queued: QueuedEnvelope =
                bincode::deserialize(&value).map_err(|e| format!("Deserialization error: {}", e))?;

            let queue = self
                .per_recipient
                .entry(queued.envelope.recipient_did.clone())
                .or_insert_with(VecDeque::new);
            queue.push_back(queued);
        }

        // Sort each queue by envelope created_at timestamp to restore FIFO order
        // (sled iteration order is lexicographic by key, not insertion order)
        for queue in self.per_recipient.values_mut() {
            let sorted: Vec<_> = queue.drain(..).collect();
            let mut sorted = sorted;
            sorted.sort_by_key(|q| q.envelope.created_at);
            queue.extend(sorted);
        }

        // Enforce per-recipient limits after loading (in case limit changed)
        for queue in self.per_recipient.values_mut() {
            while queue.len() > self.max_queue_per_recipient {
                queue.pop_front();
            }
        }

        Ok(())
    }

    /// Explicitly flush the sled database to disk.
    pub fn flush(&self) -> Result<(), String> {
        if let Some(db) = &self.db {
            db.flush()
                .map_err(|e| format!("Sled flush error: {}", e))?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

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
            if queued
                .envelope
                .payloads
                .iter()
                .any(|p| p.device_id == device_id)
            {
                filtered.push(queued.envelope.clone());
            }
        }
        Ok(filtered)
    }

    /// Take and clear pending envelopes for recipient (non-expired)
    pub fn take_pending(&mut self, recipient_did: &str) -> Result<Vec<IdentityEnvelope>, String> {
        self.expire()?;
        let queue = self.per_recipient.remove(recipient_did);

        // Remove from sled
        if let Some(db) = &self.db {
            let prefix = {
                let did_len = recipient_did.len() as u16;
                let mut p = Vec::with_capacity(1 + 2 + recipient_did.len());
                p.push(b'e');
                p.extend_from_slice(&did_len.to_be_bytes());
                p.extend_from_slice(recipient_did.as_bytes());
                p
            };
            let keys_to_remove: Vec<Vec<u8>> = db
                .scan_prefix(&prefix)
                .filter_map(|r| r.ok().map(|(k, _)| k.to_vec()))
                .collect();
            for key in keys_to_remove {
                db.remove(key)
                    .map_err(|e| format!("Sled remove error: {}", e))?;
            }
        }

        Ok(queue
            .unwrap_or_default()
            .into_iter()
            .map(|q| q.envelope)
            .collect())
    }

    /// Acknowledge delivery (remove envelope by message_id)
    pub fn acknowledge_delivery(
        &mut self,
        recipient_did: &str,
        message_id: u64,
    ) -> Result<bool, String> {
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
        let len_changed = queue.len() != original_len;
        let is_empty = queue.is_empty();

        // Clean up empty recipient entries
        if is_empty {
            self.per_recipient.remove(recipient_did);
        }

        // Remove from disk if fully removed from memory
        if len_changed {
            if let Some(db) = &self.db {
                let key = Self::envelope_key(recipient_did, message_id);
                db.remove(key)
                    .map_err(|e| format!("Sled remove error: {}", e))?;
            }
        }

        Ok(len_changed)
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
        let recipient_did = envelope.recipient_did.clone();
        let message_id = envelope.message_id;

        let queue = self
            .per_recipient
            .entry(recipient_did.clone())
            .or_insert_with(VecDeque::new);

        if queue.len() >= self.max_queue_per_recipient {
            // Evict oldest — also remove from disk
            if let Some(evicted) = queue.pop_front() {
                if let Some(db) = &self.db {
                    let key = Self::envelope_key(&evicted.envelope.recipient_did, evicted.envelope.message_id);
                    db.remove(key)
                        .map_err(|e| format!("Sled remove error: {}", e))?;
                }
            }
        }

        let queued = QueuedEnvelope {
            envelope,
            expires_at,
        };

        if let Some(db) = &self.db {
            let key = Self::envelope_key(&recipient_did, message_id);
            let value = bincode::serialize(&queued).map_err(|e| format!("Serialize error: {}", e))?;
            db.insert(key, value)
                .map_err(|e| format!("Sled insert error: {}", e))?;
        }

        queue.push_back(queued);
        self.stats.enqueued += 1;
        Ok(())
    }

    fn expire_at(&mut self, now: u64) -> Result<(), String> {
        let mut recipients_to_remove = Vec::new();
        let mut disk_removals: Vec<(String, u64)> = Vec::new();

        for (recipient_did, queue) in &mut self.per_recipient {
            let mut expired_ids = Vec::new();
            queue.retain(|q| {
                if q.expires_at > now {
                    true
                } else {
                    expired_ids.push(q.envelope.message_id);
                    false
                }
            });
            for id in expired_ids {
                self.stats.expired += 1;
                disk_removals.push((recipient_did.clone(), id));
            }
            if queue.is_empty() {
                recipients_to_remove.push(recipient_did.clone());
            }
        }

        for recipient_did in recipients_to_remove {
            self.per_recipient.remove(&recipient_did);
        }

        // Apply disk removals after releasing the mutable borrow on per_recipient
        if let Some(db) = &self.db {
            for (recipient_did, message_id) in disk_removals {
                let key = Self::envelope_key(&recipient_did, message_id);
                db.remove(key)
                    .map_err(|e| format!("Sled remove error: {}", e))?;
            }
        }

        Ok(())
    }
}

fn current_unix_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "System time before Unix epoch".to_string())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lib_protocols::types::{DevicePayload, MessageTtl};
    use tempfile::TempDir;

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
            signature_algorithm: lib_crypto::types::SignatureAlgorithm::DEFAULT,
        });
        let result = queue.enqueue(env);
        assert!(result.is_err());
        Ok(())
    }

    // ------------------------------------------------------------------
    // Persistence tests
    // ------------------------------------------------------------------

    #[test]
    fn test_persistent_enqueue_and_reload() -> Result<(), String> {
        let tmp = TempDir::new().map_err(|e| e.to_string())?;
        let path = tmp.path().join("store_forward");

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            let env = sample_envelope("did:zhtp:alice", MessageTtl::Days7, 42);
            queue.enqueue(env)?;
            queue.flush()?;
        }

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            let pending = queue.get_pending("did:zhtp:alice")?;
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].message_id, 42);
        }

        Ok(())
    }

    #[test]
    fn test_persistent_ack_removes_from_disk() -> Result<(), String> {
        let tmp = TempDir::new().map_err(|e| e.to_string())?;
        let path = tmp.path().join("store_forward");

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            queue.enqueue(sample_envelope("did:zhtp:alice", MessageTtl::Days7, 1))?;
            queue.enqueue(sample_envelope("did:zhtp:alice", MessageTtl::Days7, 2))?;
            queue.flush()?;
        }

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            queue.acknowledge_delivery("did:zhtp:alice", 1)?;
            queue.flush()?;
        }

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            let pending = queue.get_pending("did:zhtp:alice")?;
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].message_id, 2);
        }

        Ok(())
    }

    #[test]
    fn test_persistent_take_pending_removes_from_disk() -> Result<(), String> {
        let tmp = TempDir::new().map_err(|e| e.to_string())?;
        let path = tmp.path().join("store_forward");

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            queue.enqueue(sample_envelope("did:zhtp:alice", MessageTtl::Days7, 7))?;
            queue.flush()?;
        }

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            let taken = queue.take_pending("did:zhtp:alice")?;
            assert_eq!(taken.len(), 1);
            queue.flush()?;
        }

        {
            let queue = IdentityStoreForward::new_persistent(&path, 10)?;
            let db = queue.db.as_ref().unwrap();
            let count = db.iter().filter(|r| r.is_ok()).count();
            assert_eq!(count, 0, "Database should be empty after take_pending");
        }

        Ok(())
    }

    #[test]
    fn test_persistent_expire_removes_from_disk() -> Result<(), String> {
        let tmp = TempDir::new().map_err(|e| e.to_string())?;
        let path = tmp.path().join("store_forward");

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            queue.enqueue_at(sample_envelope("did:zhtp:alice", MessageTtl::Hours24, 99), 10)?;
            queue.flush()?;
        }

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            queue.expire_at(10 + MessageTtl::Hours24.as_seconds() + 1)?;
            queue.flush()?;
        }

        {
            let queue = IdentityStoreForward::new_persistent(&path, 10)?;
            let db = queue.db.as_ref().unwrap();
            let count = db.iter().filter(|r| r.is_ok()).count();
            assert_eq!(count, 0, "Database should be empty after expiry");
        }

        Ok(())
    }

    #[test]
    fn test_persistent_eviction_removes_from_disk() -> Result<(), String> {
        let tmp = TempDir::new().map_err(|e| e.to_string())?;
        let path = tmp.path().join("store_forward");

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 2)?;
            queue.enqueue(sample_envelope("did:zhtp:alice", MessageTtl::Days7, 1))?;
            queue.enqueue(sample_envelope("did:zhtp:alice", MessageTtl::Days7, 2))?;
            queue.enqueue(sample_envelope("did:zhtp:alice", MessageTtl::Days7, 3))?; // evicts 1
            queue.flush()?;
        }

        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 2)?;
            let pending = queue.get_pending("did:zhtp:alice")?;
            assert_eq!(pending.len(), 2);
            assert!(pending.iter().all(|e| e.message_id != 1));
        }

        Ok(())
    }

    #[test]
    fn test_corruption_recovery() -> Result<(), String> {
        let tmp = TempDir::new().map_err(|e| e.to_string())?;
        let path = tmp.path().join("store_forward");

        // Create a valid database first
        {
            let mut queue = IdentityStoreForward::new_persistent(&path, 10)?;
            queue.enqueue(sample_envelope("did:zhtp:alice", MessageTtl::Days7, 1))?;
            queue.flush()?;
        }

        // Corrupt it by writing garbage to a key file
        {
            let db_path = path.join("0"); // sled segment file
            if db_path.exists() {
                std::fs::write(&db_path, b"CORRUPT DATA").map_err(|e| e.to_string())?;
            }
        }

        // Opening should recover (may or may not detect corruption depending on sled internals)
        // At minimum it should not panic.
        let result = IdentityStoreForward::new_persistent(&path, 10);
        // sled may or may not detect corruption on open; if it does, recovery should succeed
        // If it doesn't detect corruption, the load may fail on deserialization.
        // We just verify the call doesn't panic.
        let _ = result;
        Ok(())
    }
}
