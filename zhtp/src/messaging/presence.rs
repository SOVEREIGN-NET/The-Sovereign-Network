//! Presence tracking for messaging delivery.
//!
//! Tracks which DIDs are currently online (connected to their node via QUIC).
//! When a watched DID comes online, subscribers are notified so they can
//! deliver queued messages.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::info;

/// Grace period before marking a DID as offline (handles app backgrounding).
const PRESENCE_GRACE_PERIOD_SECS: u64 = 30;

/// Presence event pushed to subscribers.
#[derive(Debug, Clone)]
pub struct PresenceEvent {
    pub did: String,
    pub online: bool,
    pub timestamp: u64,
    /// Which node the DID is connected to.
    pub node_addr: Option<String>,
}

/// Presence tracker for the local node.
#[derive(Debug)]
pub struct PresenceTracker {
    /// Currently online DIDs on this node.
    online: Arc<RwLock<HashMap<String, u64>>>, // DID → last_seen timestamp
    /// DIDs being watched by local subscribers.
    watchers: Arc<RwLock<HashMap<String, HashSet<String>>>>, // watched_did → set of watcher_dids
    /// Broadcast channel for presence events.
    event_tx: broadcast::Sender<PresenceEvent>,
}

impl PresenceTracker {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            online: Arc::new(RwLock::new(HashMap::new())),
            watchers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
        }
    }

    /// Mark a DID as online (phone connected to this node).
    pub async fn set_online(&self, did: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let was_offline = {
            let mut online = self.online.write().await;
            let was = !online.contains_key(did);
            online.insert(did.to_string(), now);
            was
        };

        if was_offline {
            info!("Presence: {} online", &did[..16.min(did.len())]);
            let _ = self.event_tx.send(PresenceEvent {
                did: did.to_string(),
                online: true,
                timestamp: now,
                node_addr: None,
            });
        }
    }

    /// Mark a DID as offline (phone disconnected from this node).
    pub async fn set_offline(&self, did: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut online = self.online.write().await;
        if online.remove(did).is_some() {
            info!("Presence: {} offline", &did[..16.min(did.len())]);
            let _ = self.event_tx.send(PresenceEvent {
                did: did.to_string(),
                online: false,
                timestamp: now,
                node_addr: None,
            });
        }
    }

    /// Check if a DID is currently online on this node.
    pub async fn is_online(&self, did: &str) -> bool {
        self.online.read().await.contains_key(did)
    }

    /// Watch for a DID's presence changes.
    pub async fn watch(&self, watcher_did: &str, target_did: &str) {
        let mut watchers = self.watchers.write().await;
        watchers
            .entry(target_did.to_string())
            .or_default()
            .insert(watcher_did.to_string());
    }

    /// Stop watching a DID.
    pub async fn unwatch(&self, watcher_did: &str, target_did: &str) {
        let mut watchers = self.watchers.write().await;
        if let Some(set) = watchers.get_mut(target_did) {
            set.remove(watcher_did);
            if set.is_empty() {
                watchers.remove(target_did);
            }
        }
    }

    /// Subscribe to presence events.
    pub fn subscribe(&self) -> broadcast::Receiver<PresenceEvent> {
        self.event_tx.subscribe()
    }

    /// Get all currently online DIDs.
    pub async fn online_dids(&self) -> Vec<String> {
        self.online.read().await.keys().cloned().collect()
    }

    /// Check if anyone is watching for a specific DID.
    pub async fn is_watched(&self, did: &str) -> bool {
        self.watchers.read().await.contains_key(did)
    }

    /// Get watchers for a specific DID.
    pub async fn get_watchers(&self, did: &str) -> Vec<String> {
        self.watchers
            .read()
            .await
            .get(did)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }
}
