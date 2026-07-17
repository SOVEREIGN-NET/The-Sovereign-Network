//! Global messaging state for inbound push streams.
//!
//! Exposes:
//! - The shared `DepositStore` (so the inbound-stream handler can drain on open)
//! - The inbound-subscriber registry (DID -> mpsc::Sender for live frames)
//!
//! Used by the QUIC handler's special-case for `GET /api/v1/msg/inbound`,
//! and by `handle_send` / mesh relay to push frames live when a subscriber
//! is registered for the recipient.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::{mpsc, RwLock};

use crate::messaging::deposit::DepositStore;

/// Maximum buffered frames per subscriber. Senders use `try_send`; if the
/// subscriber falls behind the frame falls back to the deposit store.
pub const SUBSCRIBER_QUEUE_DEPTH: usize = 32;

/// Opaque token returned at registration. Required to call
/// `unregister_subscriber`. Prevents the stale-stream-removes-live-stream
/// race: when a new register replaces the prior tx, the stale stream's
/// `rx.recv()` returns `None` and it tries to clean up — but a bare
/// `remove(did)` would nuke the *new* entry by key. Tokens keyed by
/// monotonic id let `unregister` no-op when the entry has been
/// superseded.
pub type SubscriberId = u64;

struct SubscriberEntry {
    id: SubscriberId,
    tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Clone)]
pub struct MessagingProvider {
    deposits: Arc<RwLock<Option<Arc<DepositStore>>>>,
    /// recipient_did -> (id, sender). One subscriber per DID at a time
    /// (latest wins); the id lets stale stream cleanups be idempotent.
    subscribers: Arc<RwLock<HashMap<String, SubscriberEntry>>>,
    next_id: Arc<AtomicU64>,
}

impl MessagingProvider {
    pub fn new() -> Self {
        Self {
            deposits: Arc::new(RwLock::new(None)),
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub async fn set_deposits(&self, deposits: Arc<DepositStore>) {
        *self.deposits.write().await = Some(deposits);
    }

    pub async fn get_deposits(&self) -> Result<Arc<DepositStore>> {
        self.deposits
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Deposit store not yet attached"))
    }

    /// Register a subscriber for a recipient DID. Replaces any prior
    /// subscriber (the previous channel will close when its sender is
    /// dropped). Returns the new subscriber's id so the caller can pass
    /// it back to `unregister_subscriber` for a safe, idempotent cleanup.
    pub async fn register_subscriber(
        &self,
        recipient_did: String,
    ) -> (SubscriberId, mpsc::Receiver<Vec<u8>>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel::<Vec<u8>>(SUBSCRIBER_QUEUE_DEPTH);
        self.subscribers
            .write()
            .await
            .insert(recipient_did, SubscriberEntry { id, tx });
        (id, rx)
    }

    /// Remove a subscriber if and only if the entry currently in the
    /// map matches the id returned at registration. Called on stream
    /// exit. The id check is what prevents a stale stream's cleanup
    /// from removing a freshly-registered live stream.
    pub async fn unregister_subscriber(
        &self,
        recipient_did: &str,
        id: SubscriberId,
    ) {
        let mut subs = self.subscribers.write().await;
        if let Some(entry) = subs.get(recipient_did) {
            if entry.id == id {
                subs.remove(recipient_did);
            }
        }
    }

    /// Attempt to push an envelope to the registered subscriber for this DID.
    /// Returns `true` if the push succeeded. `false` means no subscriber or
    /// the subscriber's queue is full.
    ///
    /// Callers must **deposit first** (MSG-R2). A successful push is not
    /// delivery confirmation — the deposit remains until client ack.
    pub async fn try_push(&self, recipient_did: &str, envelope: Vec<u8>) -> bool {
        let subscribers = self.subscribers.read().await;
        if let Some(entry) = subscribers.get(recipient_did) {
            entry.tx.try_send(envelope).is_ok()
        } else {
            false
        }
    }
}

static GLOBAL_MESSAGING_PROVIDER: OnceLock<MessagingProvider> = OnceLock::new();

pub fn get_global_messaging_provider() -> &'static MessagingProvider {
    GLOBAL_MESSAGING_PROVIDER.get_or_init(MessagingProvider::new)
}
