//! QUIC Session Log for Proof-of-Presence Verification
//!
//! Maintains a short-lived ring buffer of authenticated QUIC sessions.
//! The POUW validator cross-references this log when validating Web4 receipts
//! to confirm that the submitting DID had an authenticated QUIC session.
//!
//! Reference: PoUW-BETA #1352

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::debug;

/// TTL for session log entries (10 minutes)
pub const SESSION_LOG_TTL_SECS: u64 = 600;

/// Maximum number of entries in the session log ring buffer
pub const SESSION_LOG_MAX_ENTRIES: usize = 10_000;

/// A single authenticated QUIC session record
#[derive(Debug, Clone)]
pub struct SessionLogEntry {
    /// First 8 bytes of the 32-byte UHP v2 session_id
    pub session_id: [u8; 8],
    /// DID of the authenticated peer
    pub peer_did: String,
    /// Unix timestamp when the session was established
    pub established_at: u64,
    /// URI path prefix for this session (e.g. "/api/v1/pouw")
    pub path_prefix: String,
}

/// In-memory ring buffer of recently authenticated QUIC sessions.
///
/// Shared via `Arc<RwLock<SessionLog>>` between `QuicHandler` (writer)
/// and `ReceiptValidator` (reader).
pub struct SessionLog {
    entries: VecDeque<SessionLogEntry>,
    max_entries: usize,
    ttl_secs: u64,
}

impl SessionLog {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: SESSION_LOG_MAX_ENTRIES,
            ttl_secs: SESSION_LOG_TTL_SECS,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Record a new authenticated session
    pub fn record(
        &mut self,
        session_id: [u8; 8],
        peer_did: String,
        path_prefix: String,
    ) {
        let now = Self::now();

        // Evict expired entries from the front
        while let Some(front) = self.entries.front() {
            if now.saturating_sub(front.established_at) > self.ttl_secs {
                self.entries.pop_front();
            } else {
                break;
            }
        }

        // Evict oldest if at capacity
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }

        debug!(
            session_id = ?hex::encode(session_id),
            peer_did = %peer_did,
            "Session log: recording authenticated QUIC session"
        );

        self.entries.push_back(SessionLogEntry {
            session_id,
            peer_did,
            established_at: now,
            path_prefix,
        });
    }

    /// Verify that a session ID was established by the given DID within the TTL window
    pub fn verify(&self, session_id: [u8; 8], peer_did: &str) -> bool {
        let now = Self::now();
        self.entries.iter().any(|e| {
            e.session_id == session_id
                && e.peer_did == peer_did
                && now.saturating_sub(e.established_at) <= self.ttl_secs
        })
    }

    /// Number of active (non-expired) entries
    pub fn active_count(&self) -> usize {
        let now = Self::now();
        self.entries
            .iter()
            .filter(|e| now.saturating_sub(e.established_at) <= self.ttl_secs)
            .count()
    }
}

impl Default for SessionLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared session log type alias for convenience
pub type SharedSessionLog = Arc<RwLock<SessionLog>>;

/// Create a new shared session log
pub fn new_shared_session_log() -> SharedSessionLog {
    Arc::new(RwLock::new(SessionLog::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_verify() {
        let mut log = SessionLog::new();
        let session_id = [1u8; 8];
        let did = "did:zhtp:alice";

        log.record(session_id, did.to_string(), "/api/v1/pouw".to_string());

        assert!(log.verify(session_id, did));
        assert!(!log.verify(session_id, "did:zhtp:bob")); // wrong DID
        assert!(!log.verify([2u8; 8], did)); // wrong session_id
    }

    #[test]
    fn test_max_entries_eviction() {
        let mut log = SessionLog { entries: VecDeque::new(), max_entries: 3, ttl_secs: 600 };

        for i in 0..5u8 {
            log.record([i; 8], format!("did:zhtp:{}", i), "/".to_string());
        }

        // Should have evicted oldest, keeping 3
        assert_eq!(log.entries.len(), 3);
        // Should have kept the last 3 (2, 3, 4)
        assert!(log.verify([4u8; 8], "did:zhtp:4"));
        assert!(!log.verify([0u8; 8], "did:zhtp:0"));
    }
}
