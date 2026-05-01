//! Blockchain Event Emission Infrastructure
//!
//! This module provides a complete event emission system for blockchain state changes.
//! Events are published through a broadcast channel, allowing subscribers to process
//! them asynchronously without blocking the blockchain write path.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Capacity of the broadcast channel. Slow receivers that fall behind by this
/// many events will start receiving `RecvError::Lagged`.
const EVENT_CHANNEL_CAPACITY: usize = 256;

// ============================================================================
// EVENT TYPES
// ============================================================================

/// Blockchain-level events that clients can subscribe to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockchainEvent {
    /// New block added to chain
    BlockAdded {
        height: u64,
        block_hash: [u8; 32],
        timestamp: u64,
        transaction_count: u64,
    },

    /// Block finalized (immutable)
    BlockFinalized { height: u64, block_hash: [u8; 32] },

    /// Transaction processed
    TransactionProcessed {
        tx_hash: [u8; 32],
        block_height: u64,
        success: bool,
    },

    /// Identity registration committed to a block
    IdentityRegistered {
        tx_hash: [u8; 32],
        block_height: u64,
        identity_data: crate::transaction::IdentityTransactionData,
    },

    /// Wallet registration committed to a block
    WalletRegistered {
        tx_hash: [u8; 32],
        block_height: u64,
        wallet_data: crate::transaction::WalletTransactionData,
    },

    /// Contract event emitted
    ContractEventEmitted {
        contract_name: String,
        event_type: String,
        block_height: u64,
    },

    /// Chain reorganization occurred
    ChainReorganized {
        old_height: u64,
        new_height: u64,
        reorg_depth: u64,
    },

    /// Validator registered
    ValidatorRegistered { validator_key: [u8; 32], stake: u64 },

    /// Validator unregistered
    ValidatorUnregistered { validator_key: [u8; 32] },
}

impl std::fmt::Display for BlockchainEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockchainEvent::BlockAdded { height, .. } => {
                write!(f, "BlockAdded(height={})", height)
            }
            BlockchainEvent::BlockFinalized { height, .. } => {
                write!(f, "BlockFinalized(height={})", height)
            }
            BlockchainEvent::TransactionProcessed { tx_hash, .. } => {
                write!(f, "TransactionProcessed(tx={})", hex::encode(&tx_hash[..8]))
            }
            BlockchainEvent::IdentityRegistered { tx_hash, .. } => {
                write!(f, "IdentityRegistered(tx={})", hex::encode(&tx_hash[..8]))
            }
            BlockchainEvent::WalletRegistered { tx_hash, .. } => {
                write!(f, "WalletRegistered(tx={})", hex::encode(&tx_hash[..8]))
            }
            BlockchainEvent::ContractEventEmitted { block_height, .. } => {
                write!(f, "ContractEventEmitted(block={})", block_height)
            }
            BlockchainEvent::ChainReorganized {
                old_height,
                new_height,
                ..
            } => {
                write!(f, "ChainReorganized({}->{})", old_height, new_height)
            }
            BlockchainEvent::ValidatorRegistered { .. } => write!(f, "ValidatorRegistered"),
            BlockchainEvent::ValidatorUnregistered { .. } => write!(f, "ValidatorUnregistered"),
        }
    }
}

// ============================================================================
// EVENT PUBLISHER
// ============================================================================

/// Non-blocking event publisher backed by a broadcast channel.
///
/// `publish()` never awaits listener I/O — it sends to the channel and returns
/// immediately. Subscribers receive a `broadcast::Receiver` and process events
/// in their own tokio task, fully decoupled from the blockchain write lock.
#[derive(Clone)]
pub struct BlockchainEventPublisher {
    sender: Arc<broadcast::Sender<BlockchainEvent>>,
}

impl std::fmt::Debug for BlockchainEventPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockchainEventPublisher")
            .field("subscriber_count", &self.sender.receiver_count())
            .finish()
    }
}

impl BlockchainEventPublisher {
    /// Create a new event publisher with a broadcast channel.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Subscribe to blockchain events. Returns a receiver that the caller
    /// should consume in a spawned task.
    pub fn subscribe(&self) -> broadcast::Receiver<BlockchainEvent> {
        self.sender.subscribe()
    }

    /// Publish an event to all subscribers. This is non-blocking — if no
    /// subscribers exist, the event is silently dropped.
    pub fn publish(&self, event: BlockchainEvent) {
        // send() returns Err only when there are zero receivers, which is fine
        let _ = self.sender.send(event);
    }

    /// Get number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for BlockchainEventPublisher {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_publisher_creation() {
        let publisher = BlockchainEventPublisher::new();
        assert_eq!(publisher.subscriber_count(), 0);
    }

    #[test]
    fn test_subscribe() {
        let publisher = BlockchainEventPublisher::new();
        let _rx = publisher.subscribe();
        assert_eq!(publisher.subscriber_count(), 1);
    }

    #[tokio::test]
    async fn test_publish_event_to_subscriber() {
        let publisher = BlockchainEventPublisher::new();
        let mut rx = publisher.subscribe();

        let event = BlockchainEvent::BlockAdded {
            height: 1,
            block_hash: [1u8; 32],
            timestamp: 1000,
            transaction_count: 5,
        };

        publisher.publish(event.clone());

        let received = rx.recv().await.unwrap();
        assert_eq!(received, event);
    }

    #[tokio::test]
    async fn test_multiple_subscribers_receive_events() {
        let publisher = BlockchainEventPublisher::new();
        let mut rx1 = publisher.subscribe();
        let mut rx2 = publisher.subscribe();

        assert_eq!(publisher.subscriber_count(), 2);

        let event = BlockchainEvent::BlockFinalized {
            height: 10,
            block_hash: [2u8; 32],
        };

        publisher.publish(event.clone());

        let ev1 = rx1.recv().await.unwrap();
        let ev2 = rx2.recv().await.unwrap();

        assert_eq!(ev1, event);
        assert_eq!(ev2, event);
    }
}
