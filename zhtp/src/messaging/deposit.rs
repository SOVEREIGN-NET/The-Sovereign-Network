//! Deposit-on-disconnect: temporary encrypted dead drop on sender's node.
//!
//! When the sender's phone goes offline, it deposits encrypted envelopes
//! on its node. The node holds them until the recipient comes online,
//! then relays via QUIC mesh. Deposits auto-expire after TTL.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Default deposit TTL: 48 hours.
const DEFAULT_DEPOSIT_TTL_SECS: u64 = 48 * 3600;
/// Max envelopes per sender-recipient pair.
const MAX_ENVELOPES_PER_PAIR: usize = 100;

/// A pending delivery stored on the sender's node.
#[derive(Debug, Clone)]
pub struct PendingDelivery {
    pub sender_did: String,
    pub recipient_did: String,
    /// Opaque encrypted envelopes — node cannot read these.
    pub envelopes: Vec<Vec<u8>>,
    pub deposited_at: u64,
    pub expires_at: u64,
}

/// Deposit store: keyed by (sender_did, recipient_did).
#[derive(Debug)]
pub struct DepositStore {
    deposits: Arc<RwLock<HashMap<(String, String), PendingDelivery>>>,
}

impl DepositStore {
    pub fn new() -> Self {
        Self {
            deposits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Deposit encrypted envelopes for a recipient.
    pub async fn deposit(
        &self,
        sender_did: &str,
        recipient_did: &str,
        envelopes: Vec<Vec<u8>>,
    ) -> Result<usize, String> {
        if envelopes.len() > MAX_ENVELOPES_PER_PAIR {
            return Err(format!(
                "Too many envelopes ({}, max {})",
                envelopes.len(),
                MAX_ENVELOPES_PER_PAIR
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let count = envelopes.len();
        let delivery = PendingDelivery {
            sender_did: sender_did.to_string(),
            recipient_did: recipient_did.to_string(),
            envelopes,
            deposited_at: now,
            expires_at: now + DEFAULT_DEPOSIT_TTL_SECS,
        };

        let key = (sender_did.to_string(), recipient_did.to_string());
        let mut deposits = self.deposits.write().await;
        // Append envelopes to existing deposit instead of overwriting
        if let Some(existing) = deposits.get_mut(&key) {
            if existing.envelopes.len() + count <= MAX_ENVELOPES_PER_PAIR {
                existing.envelopes.extend(delivery.envelopes);
                existing.expires_at = delivery.expires_at; // refresh TTL
            } else {
                return Err(format!(
                    "Too many envelopes ({}, max {})",
                    existing.envelopes.len() + count,
                    MAX_ENVELOPES_PER_PAIR
                ));
            }
        } else {
            deposits.insert(key, delivery);
        }

        info!(
            "Deposited {} envelopes from {} for {} (expires in {}h)",
            count,
            &sender_did[..16.min(sender_did.len())],
            &recipient_did[..16.min(recipient_did.len())],
            DEFAULT_DEPOSIT_TTL_SECS / 3600,
        );

        Ok(count)
    }

    /// Retrieve and remove all pending envelopes for a recipient.
    pub async fn collect_for_recipient(&self, recipient_did: &str) -> Vec<PendingDelivery> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut deposits = self.deposits.write().await;
        let mut collected = Vec::new();

        deposits.retain(|(_sender, _recipient), delivery| {
            if delivery.recipient_did == recipient_did && delivery.expires_at > now {
                collected.push(delivery.clone());
                false // remove from store
            } else if delivery.expires_at <= now {
                false // expired, remove
            } else {
                true // keep
            }
        });

        collected
    }

    /// Cancel a deposit (sender came back online).
    pub async fn cancel(&self, sender_did: &str, recipient_did: &str) -> bool {
        let key = (sender_did.to_string(), recipient_did.to_string());
        let mut deposits = self.deposits.write().await;
        deposits.remove(&key).is_some()
    }

    /// Clean up expired deposits.
    pub async fn cleanup_expired(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut deposits = self.deposits.write().await;
        let before = deposits.len();
        deposits.retain(|_, d| d.expires_at > now);
        before - deposits.len()
    }

    /// Check if there are any pending deposits for a recipient.
    pub async fn has_pending(&self, recipient_did: &str) -> bool {
        let deposits = self.deposits.read().await;
        deposits.values().any(|d| d.recipient_did == recipient_did)
    }

    pub async fn pending_count(&self) -> usize {
        self.deposits.read().await.len()
    }
}
