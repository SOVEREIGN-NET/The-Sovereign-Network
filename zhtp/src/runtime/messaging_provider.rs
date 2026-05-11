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
use std::sync::{Arc, OnceLock};
use tokio::sync::{mpsc, RwLock};

use crate::messaging::deposit::DepositStore;

/// Maximum buffered frames per subscriber. Senders use `try_send`; if the
/// subscriber falls behind the frame falls back to the deposit store.
pub const SUBSCRIBER_QUEUE_DEPTH: usize = 32;

#[derive(Clone)]
pub struct MessagingProvider {
    deposits: Arc<RwLock<Option<Arc<DepositStore>>>>,
    /// recipient_did -> sender. One subscriber per DID at a time (latest wins).
    subscribers: Arc<RwLock<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
}

impl MessagingProvider {
    pub fn new() -> Self {
        Self {
            deposits: Arc::new(RwLock::new(None)),
            subscribers: Arc::new(RwLock::new(HashMap::new())),
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

    /// Register a subscriber for a recipient DID. Replaces any prior subscriber
    /// (the previous channel will close when its sender is dropped).
    pub async fn register_subscriber(
        &self,
        recipient_did: String,
    ) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(SUBSCRIBER_QUEUE_DEPTH);
        self.subscribers.write().await.insert(recipient_did, tx);
        rx
    }

    /// Remove a subscriber (called on disconnect).
    pub async fn unregister_subscriber(&self, recipient_did: &str) {
        self.subscribers.write().await.remove(recipient_did);
    }

    /// Attempt to push an envelope to the registered subscriber for this DID.
    /// Returns `true` if the push succeeded. `false` means no subscriber or
    /// the subscriber's queue is full — caller should fall back to deposit.
    pub async fn try_push(&self, recipient_did: &str, envelope: Vec<u8>) -> bool {
        let subscribers = self.subscribers.read().await;
        if let Some(tx) = subscribers.get(recipient_did) {
            tx.try_send(envelope).is_ok()
        } else {
            false
        }
    }
}

static GLOBAL_MESSAGING_PROVIDER: OnceLock<MessagingProvider> = OnceLock::new();

pub fn get_global_messaging_provider() -> &'static MessagingProvider {
    GLOBAL_MESSAGING_PROVIDER.get_or_init(MessagingProvider::new)
}
