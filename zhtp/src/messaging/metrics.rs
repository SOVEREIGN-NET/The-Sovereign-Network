//! Messaging operator metrics (MSG-R12).
//!
//! Process-local counters for deposit / ack / mesh health. No PII.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Redact a DID for logs: keep scheme prefix + first 8 identity chars.
///
/// Example: `did:zhtp:abcdef012345…` → `did:zhtp:abcdef01…`
pub fn redact_did(did: &str) -> String {
    const ID_KEEP: usize = 8;
    if let Some(last_colon) = did.rfind(':') {
        let scheme = &did[..=last_colon];
        let identity = &did[last_colon + 1..];
        if identity.chars().count() <= ID_KEEP {
            return did.to_string();
        }
        let kept: String = identity.chars().take(ID_KEEP).collect();
        return format!("{scheme}{kept}…");
    }
    if did.chars().count() <= ID_KEEP {
        return did.to_string();
    }
    let kept: String = did.chars().take(ID_KEEP).collect();
    format!("{kept}…")
}

#[derive(Debug, Default)]
pub struct MessagingMetrics {
    pub deposits_accepted: AtomicU64,
    pub deposits_duplicate: AtomicU64,
    pub deposits_rejected: AtomicU64,
    pub acks_removed: AtomicU64,
    pub cancels: AtomicU64,
    pub gc_expired: AtomicU64,
    pub mesh_relays_in: AtomicU64,
    pub mesh_relays_out: AtomicU64,
    pub live_pushes: AtomicU64,
    pub verify_rejects: AtomicU64,
    pub auth_rejects: AtomicU64,
    pub tombstone_hits: AtomicU64,
}

impl MessagingMetrics {
    pub fn snapshot(&self) -> MessagingMetricsSnapshot {
        MessagingMetricsSnapshot {
            deposits_accepted: self.deposits_accepted.load(Ordering::Relaxed),
            deposits_duplicate: self.deposits_duplicate.load(Ordering::Relaxed),
            deposits_rejected: self.deposits_rejected.load(Ordering::Relaxed),
            acks_removed: self.acks_removed.load(Ordering::Relaxed),
            cancels: self.cancels.load(Ordering::Relaxed),
            gc_expired: self.gc_expired.load(Ordering::Relaxed),
            mesh_relays_in: self.mesh_relays_in.load(Ordering::Relaxed),
            mesh_relays_out: self.mesh_relays_out.load(Ordering::Relaxed),
            live_pushes: self.live_pushes.load(Ordering::Relaxed),
            verify_rejects: self.verify_rejects.load(Ordering::Relaxed),
            auth_rejects: self.auth_rejects.load(Ordering::Relaxed),
            tombstone_hits: self.tombstone_hits.load(Ordering::Relaxed),
            pending: 0, // filled by caller with store depth
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MessagingMetricsSnapshot {
    pub deposits_accepted: u64,
    pub deposits_duplicate: u64,
    pub deposits_rejected: u64,
    pub acks_removed: u64,
    pub cancels: u64,
    pub gc_expired: u64,
    pub mesh_relays_in: u64,
    pub mesh_relays_out: u64,
    pub live_pushes: u64,
    pub verify_rejects: u64,
    pub auth_rejects: u64,
    pub tombstone_hits: u64,
    pub pending: u64,
}

static METRICS: OnceLock<MessagingMetrics> = OnceLock::new();

pub fn metrics() -> &'static MessagingMetrics {
    METRICS.get_or_init(MessagingMetrics::default)
}

#[cfg(test)]
mod tests {
    use super::redact_did;

    #[test]
    fn redact_keeps_scheme_and_eight_id_chars() {
        let full = "did:zhtp:abcdef0123456789deadbeef";
        assert_eq!(redact_did(full), "did:zhtp:abcdef01…");
    }

    #[test]
    fn redact_short_did_unchanged() {
        assert_eq!(redact_did("did:zhtp:abc"), "did:zhtp:abc");
    }
}
