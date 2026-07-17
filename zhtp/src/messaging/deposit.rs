//! Deposit store — durable store-and-forward for undelivered messages.
//!
//! ## Delivery model (MSG-R1 / MSG-R5–R7)
//!
//! Envelopes stay in the store until the client **acks** them (or TTL GC).
//! Polling and inbound streaming **peek** only; they never delete.
//!
//! ## Durability (MSG-R5)
//!
//! Primary storage is a `sled` tree under the node data directory
//! (`messaging_deposits.sled`). On open, indexes are rebuilt from disk so
//! undelivered mail survives process restart.
//!
//! ## Message id (MSG-R6)
//!
//! Stable `message_id` = hex(blake3(envelope_bytes)); duplicate deposits of
//! the same bytes are ignored (idempotent). Mesh re-relays hit the same id.
//!
//! ## Tombstones (MSG-R10)
//!
//! After ack (or cancel of a specific id), a short-lived tombstone prevents
//! mesh peers from re-depositing the same envelope.
//!
//! ## At-rest encryption (MSG-R13)
//!
//! Optional: set `ZHTP_MSG_AT_REST_KEY` to 64 hex chars (32-byte key). Envelope
//! blobs are ChaCha20-Poly1305 encrypted on disk; metadata (DIDs, ids) remains
//! plaintext for indexing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::metrics::{metrics, redact_did};

/// How long undelivered deposits are kept before GC purges them.
const DEPOSIT_TTL: Duration = Duration::from_secs(48 * 3600); // 48 hours

/// Tombstone retention after ack (mesh re-relay window).
const TOMBSTONE_TTL: Duration = Duration::from_secs(24 * 3600);

/// Maximum pending envelopes per (sender, recipient) pair.
const MAX_PENDING_PER_PAIR: usize = 100;

const TREE_DEPOSITS: &str = "deposits";
const TREE_TOMBSTONES: &str = "tombstones";

/// A single pending delivery (one envelope) — API / peek surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDelivery {
    /// Stable id: hex(blake3(envelope_bytes)).
    pub message_id: String,
    /// Opaque PQ-encrypted envelope (bincode of client SecureMessage / MessageEnvelope).
    pub envelope: Vec<u8>,
    /// Unix seconds when deposited (API / clients / TTL).
    pub deposited_at: u64,
    /// Sender DID (for cancellation / auth).
    pub sender_did: String,
    /// Recipient DID.
    pub recipient_did: String,
}

/// On-disk record (envelope may be at-rest encrypted).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDeposit {
    message_id: String,
    /// Plain or at-rest-encrypted envelope bytes.
    envelope_blob: Vec<u8>,
    deposited_at: u64,
    sender_did: String,
    recipient_did: String,
    /// True when `envelope_blob` is ChaCha20-Poly1305 sealed.
    at_rest: bool,
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

fn load_at_rest_key() -> Option<[u8; 32]> {
    let raw = std::env::var("ZHTP_MSG_AT_REST_KEY").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let bytes = hex::decode(raw).ok()?;
    if bytes.len() != 32 {
        warn!(
            len = bytes.len(),
            "ZHTP_MSG_AT_REST_KEY must be 32 bytes (64 hex chars) — at-rest disabled"
        );
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn seal_blob(plain: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    lib_crypto::symmetric::chacha20::encrypt_data(plain, key)
        .map_err(|e| format!("at-rest encrypt failed: {e}"))
}

fn open_blob(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    lib_crypto::symmetric::chacha20::decrypt_data(blob, key)
        .map_err(|e| format!("at-rest decrypt failed: {e}"))
}

/// Durable deposit store (sled + in-memory indexes).
pub struct DepositStore {
    db: sled::Db,
    deposits: sled::Tree,
    tombstones: sled::Tree,
    /// Keyed by (sender_did, recipient_did).
    pending: RwLock<HashMap<(String, String), Vec<PendingDelivery>>>,
    /// Index message_id → (sender, recipient) for O(1) ack.
    by_id: RwLock<HashMap<String, (String, String)>>,
    at_rest_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for DepositStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DepositStore")
            .field("pending", &self.total_pending())
            .field("at_rest", &self.at_rest_key.is_some())
            .finish()
    }
}

impl DepositStore {
    /// In-memory sled (tests / fallback when disk open fails).
    pub fn new() -> Self {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .expect("temporary sled for deposit store");
        Self::from_db(db, load_at_rest_key())
    }

    /// Open (or create) a persistent store at `path`.
    ///
    /// Uses `ZHTP_MSG_AT_REST_KEY` when set (see `open_with_at_rest_key` for tests).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        Self::open_with_at_rest_key(path, load_at_rest_key())
    }

    /// Open persistent store with an explicit at-rest key (tests / controlled config).
    pub fn open_with_at_rest_key(
        path: impl AsRef<Path>,
        at_rest_key: Option<[u8; 32]>,
    ) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        }
        let db = sled::open(path).map_err(|e| format!("open deposit sled {path:?}: {e}"))?;
        if at_rest_key.is_some() {
            info!(
                path = %path.display(),
                "messaging deposit store opened with at-rest encryption"
            );
        } else {
            info!(path = %path.display(), "messaging deposit store opened");
        }
        Ok(Self::from_db(db, at_rest_key))
    }

    /// Default path under node data dir.
    pub fn open_default() -> Result<Self, String> {
        let path: PathBuf = crate::node_data_dir().join("messaging_deposits.sled");
        Self::open(path)
    }

    fn from_db(db: sled::Db, at_rest_key: Option<[u8; 32]>) -> Self {
        let deposits = db
            .open_tree(TREE_DEPOSITS)
            .expect("open deposits tree");
        let tombstones = db
            .open_tree(TREE_TOMBSTONES)
            .expect("open tombstones tree");
        let store = Self {
            db,
            deposits,
            tombstones,
            pending: RwLock::new(HashMap::new()),
            by_id: RwLock::new(HashMap::new()),
            at_rest_key,
        };
        store.rebuild_indexes();
        store
    }

    fn rebuild_indexes(&self) {
        let mut pending = HashMap::new();
        let mut by_id = HashMap::new();
        let mut loaded = 0usize;
        let mut skipped = 0usize;

        for item in self.deposits.iter() {
            let Ok((_k, v)) = item else {
                skipped += 1;
                continue;
            };
            let Ok(stored) = bincode::deserialize::<StoredDeposit>(&v) else {
                skipped += 1;
                continue;
            };
            let envelope = match self.decode_envelope(&stored) {
                Ok(e) => e,
                Err(e) => {
                    warn!(message_id = %stored.message_id, error = %e, "skip corrupt deposit on load");
                    skipped += 1;
                    continue;
                }
            };
            let key = (stored.sender_did.clone(), stored.recipient_did.clone());
            let delivery = PendingDelivery {
                message_id: stored.message_id.clone(),
                envelope,
                deposited_at: stored.deposited_at,
                sender_did: stored.sender_did,
                recipient_did: stored.recipient_did,
            };
            by_id.insert(
                stored.message_id,
                (delivery.sender_did.clone(), delivery.recipient_did.clone()),
            );
            pending.entry(key).or_insert_with(Vec::new).push(delivery);
            loaded += 1;
        }

        *self.pending.write() = pending;
        *self.by_id.write() = by_id;
        if loaded > 0 || skipped > 0 {
            info!(loaded, skipped, "messaging deposits reloaded from sled");
        }
    }

    fn decode_envelope(&self, stored: &StoredDeposit) -> Result<Vec<u8>, String> {
        if !stored.at_rest {
            return Ok(stored.envelope_blob.clone());
        }
        let key = self
            .at_rest_key
            .as_ref()
            .ok_or_else(|| "deposit is at-rest encrypted but ZHTP_MSG_AT_REST_KEY is unset".to_string())?;
        open_blob(&stored.envelope_blob, key)
    }

    fn encode_envelope(&self, plain: &[u8]) -> Result<(Vec<u8>, bool), String> {
        if let Some(key) = &self.at_rest_key {
            Ok((seal_blob(plain, key)?, true))
        } else {
            Ok((plain.to_vec(), false))
        }
    }

    fn is_tombstoned(&self, message_id: &str) -> bool {
        let Ok(Some(raw)) = self.tombstones.get(message_id.as_bytes()) else {
            return false;
        };
        if raw.len() != 8 {
            return true;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&raw);
        let expires = u64::from_le_bytes(buf);
        if now_unix() >= expires {
            let _ = self.tombstones.remove(message_id.as_bytes());
            return false;
        }
        true
    }

    fn write_tombstone(&self, message_id: &str) {
        let expires = now_unix().saturating_add(TOMBSTONE_TTL.as_secs());
        let _ = self
            .tombstones
            .insert(message_id.as_bytes(), &expires.to_le_bytes());
    }

    fn persist_deposit(&self, delivery: &PendingDelivery) -> Result<(), String> {
        let (blob, at_rest) = self.encode_envelope(&delivery.envelope)?;
        let stored = StoredDeposit {
            message_id: delivery.message_id.clone(),
            envelope_blob: blob,
            deposited_at: delivery.deposited_at,
            sender_did: delivery.sender_did.clone(),
            recipient_did: delivery.recipient_did.clone(),
            at_rest,
        };
        let bytes = bincode::serialize(&stored).map_err(|e| format!("serialize deposit: {e}"))?;
        self.deposits
            .insert(delivery.message_id.as_bytes(), bytes)
            .map_err(|e| format!("sled insert: {e}"))?;
        Ok(())
    }

    fn remove_persisted(&self, message_id: &str) {
        let _ = self.deposits.remove(message_id.as_bytes());
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

        if self.is_tombstoned(&message_id) {
            metrics()
                .tombstone_hits
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                message_id = %message_id,
                "deposit: tombstoned (already acked) — ignoring mesh re-relay"
            );
            return Ok((message_id, false));
        }

        let key = (sender_did.to_string(), recipient_did.to_string());

        {
            let by_id = self.by_id.read();
            if by_id.contains_key(&message_id) {
                metrics()
                    .deposits_duplicate
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    message_id = %message_id,
                    "deposit: duplicate envelope, already stored"
                );
                return Ok((message_id, false));
            }
        }

        let mut store = self.pending.write();
        let mut by_id = self.by_id.write();

        if by_id.contains_key(&message_id) {
            metrics()
                .deposits_duplicate
                .fetch_add(1, Ordering::Relaxed);
            return Ok((message_id, false));
        }

        let queue = store.entry(key.clone()).or_default();

        if queue.len() >= MAX_PENDING_PER_PAIR {
            metrics()
                .deposits_rejected
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                sender = %redact_did(sender_did),
                recipient = %redact_did(recipient_did),
                max = MAX_PENDING_PER_PAIR,
                "deposit store full for pair — rejecting"
            );
            return Err(format!(
                "deposit store full: max {MAX_PENDING_PER_PAIR} pending for this pair"
            ));
        }

        let delivery = PendingDelivery {
            message_id: message_id.clone(),
            envelope,
            deposited_at: now_unix(),
            sender_did: sender_did.to_string(),
            recipient_did: recipient_did.to_string(),
        };

        if let Err(e) = self.persist_deposit(&delivery) {
            metrics()
                .deposits_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        queue.push(delivery);
        by_id.insert(message_id.clone(), key);
        metrics()
            .deposits_accepted
            .fetch_add(1, Ordering::Relaxed);

        info!(
            sender = %redact_did(sender_did),
            recipient = %redact_did(recipient_did),
            message_id = %message_id,
            pending = queue.len(),
            "message deposited"
        );
        Ok((message_id, true))
    }

    /// Deposit many envelopes. Returns `(accepted_count, message_ids)`.
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
                recipient = %redact_did(recipient_did),
                count = out.len(),
                "peeked pending deposits (retained until ack)"
            );
        }
        out
    }

    /// Remove specific messages by id **only if** they are addressed to
    /// `recipient_did` (client ACK). Returns count removed.
    pub fn ack(&self, recipient_did: &str, message_ids: &[String]) -> usize {
        if message_ids.is_empty() {
            return 0;
        }
        let mut store = self.pending.write();
        let mut by_id = self.by_id.write();
        let mut removed = 0;

        for mid in message_ids {
            let Some((sender, recipient)) = by_id.get(mid).cloned() else {
                // Still tombstone so mesh re-relays are dropped after local miss.
                self.write_tombstone(mid);
                continue;
            };
            if recipient != recipient_did {
                debug!(
                    message_id = %mid,
                    caller = %redact_did(recipient_did),
                    owner = %redact_did(&recipient),
                    "ack ignored: message not addressed to caller"
                );
                continue;
            }
            by_id.remove(mid);
            self.remove_persisted(mid);
            self.write_tombstone(mid);
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
            metrics()
                .acks_removed
                .fetch_add(removed as u64, Ordering::Relaxed);
            info!(
                count = removed,
                recipient = %redact_did(recipient_did),
                "acked and removed deposits"
            );
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
            self.remove_persisted(&d.message_id);
            self.write_tombstone(&d.message_id);
        }
        if count > 0 {
            metrics()
                .cancels
                .fetch_add(count as u64, Ordering::Relaxed);
            info!(
                sender = %redact_did(sender_did),
                recipient = %redact_did(recipient_did),
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
        let now = now_unix();
        let ttl = DEPOSIT_TTL.as_secs();

        store.retain(|_, queue| {
            let before = queue.len();
            for d in queue.iter() {
                if now.saturating_sub(d.deposited_at) >= ttl {
                    by_id.remove(&d.message_id);
                    self.remove_persisted(&d.message_id);
                    // No tombstone on TTL — allow re-send of same content later.
                }
            }
            queue.retain(|d| now.saturating_sub(d.deposited_at) < ttl);
            purged += before - queue.len();
            !queue.is_empty()
        });

        // GC expired tombstones
        let mut dead_tombs = Vec::new();
        for item in self.tombstones.iter() {
            let Ok((k, v)) = item else { continue };
            if v.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&v);
                if now >= u64::from_le_bytes(buf) {
                    dead_tombs.push(k);
                }
            }
        }
        for k in dead_tombs {
            let _ = self.tombstones.remove(k);
        }

        if purged > 0 {
            metrics()
                .gc_expired
                .fetch_add(purged as u64, Ordering::Relaxed);
            info!(purged, "GC purged expired deposits");
        }
        purged
    }

    /// Alias used by cleanup task (historical name).
    pub fn cleanup_expired(&self) -> usize {
        self.gc_expired()
    }

    /// Flush sled to disk (tests / graceful shutdown).
    pub fn flush(&self) -> Result<(), String> {
        self.db
            .flush()
            .map_err(|e| format!("sled flush: {e}"))
            .map(|_| ())
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

impl Default for DepositStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared deposit store handle.
pub type SharedDepositStore = Arc<DepositStore>;

/// Create a new shared in-memory deposit store.
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

        assert_eq!(store.peek_for_recipient("did:sov:bob").len(), 1);
        assert_eq!(store.total_pending(), 1);
    }

    #[test]
    fn ack_removes() {
        let store = DepositStore::new();
        let (id, _) = store
            .deposit_one("did:sov:alice", "did:sov:bob", vec![9, 9, 9])
            .unwrap();
        assert_eq!(store.ack("did:sov:bob", &[id]), 1);
        assert_eq!(store.total_pending(), 0);
        assert!(store.peek_for_recipient("did:sov:bob").is_empty());
    }

    #[test]
    fn ack_ignores_wrong_recipient() {
        let store = DepositStore::new();
        let (id, _) = store
            .deposit_one("did:sov:alice", "did:sov:bob", vec![1, 2, 3])
            .unwrap();
        assert_eq!(store.ack("did:sov:eve", &[id.clone()]), 0);
        assert_eq!(store.total_pending(), 1);
        assert_eq!(store.ack("did:sov:bob", &[id]), 1);
        assert_eq!(store.total_pending(), 0);
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
                vec![vec![1], vec![2], vec![1]],
            )
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(ids.len(), 3);
        assert_eq!(store.total_pending(), 2);
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deposits.sled");
        let id = {
            let store = DepositStore::open_with_at_rest_key(&path, None).unwrap();
            let (id, _) = store
                .deposit_one("did:sov:alice", "did:sov:bob", vec![42, 43, 44])
                .unwrap();
            store.flush().unwrap();
            drop(store);
            id
        };
        let store2 = DepositStore::open_with_at_rest_key(&path, None).unwrap();
        let peeked = store2.peek_for_recipient("did:sov:bob");
        assert_eq!(peeked.len(), 1);
        assert_eq!(peeked[0].message_id, id);
        assert_eq!(peeked[0].envelope, vec![42, 43, 44]);
    }

    #[test]
    fn tombstone_blocks_redeposit_after_ack() {
        let store = DepositStore::new();
        let env = vec![1, 2, 3, 4];
        let (id, _) = store
            .deposit_one("did:sov:a", "did:sov:b", env.clone())
            .unwrap();
        assert_eq!(store.ack("did:sov:b", &[id.clone()]), 1);
        let (id2, is_new) = store.deposit_one("did:sov:a", "did:sov:b", env).unwrap();
        assert_eq!(id, id2);
        assert!(!is_new);
        assert_eq!(store.total_pending(), 0);
    }

    #[test]
    fn at_rest_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enc.sled");
        let key = [0xABu8; 32];
        let id = {
            let store = DepositStore::open_with_at_rest_key(&path, Some(key)).unwrap();
            assert!(store.at_rest_key.is_some());
            let (id, _) = store
                .deposit_one("did:sov:a", "did:sov:b", b"secret-envelope".to_vec())
                .unwrap();
            store.flush().unwrap();
            drop(store);
            id
        };
        let store2 = DepositStore::open_with_at_rest_key(&path, Some(key)).unwrap();
        let peeked = store2.peek_for_recipient("did:sov:b");
        assert_eq!(peeked[0].message_id, id);
        assert_eq!(peeked[0].envelope, b"secret-envelope");
    }
}
