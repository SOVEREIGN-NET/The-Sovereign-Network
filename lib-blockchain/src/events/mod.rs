//! Blockchain Event Emission Infrastructure
//!
//! This module provides a complete event emission system for blockchain state changes.
//! Clients can subscribe to events and receive notifications when blocks are added,
//! transactions are processed, contracts are executed, etc.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;
use async_trait::async_trait;

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
    BlockFinalized {
        height: u64,
        block_hash: [u8; 32],
    },

    /// Transaction processed
    TransactionProcessed {
        tx_hash: [u8; 32],
        block_height: u64,
        success: bool,
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
    ValidatorRegistered {
        validator_key: [u8; 32],
        stake: u64,
    },

    /// Validator unregistered
    ValidatorUnregistered {
        validator_key: [u8; 32],
    },
}

impl std::fmt::Display for BlockchainEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockchainEvent::BlockAdded { height, .. } => write!(f, "BlockAdded(height={})", height),
            BlockchainEvent::BlockFinalized { height, .. } => write!(f, "BlockFinalized(height={})", height),
            BlockchainEvent::TransactionProcessed { tx_hash, .. } => {
                write!(f, "TransactionProcessed(tx={})", hex::encode(&tx_hash[..8]))
            }
            BlockchainEvent::ContractEventEmitted { block_height, .. } => {
                write!(f, "ContractEventEmitted(block={})", block_height)
            }
            BlockchainEvent::ChainReorganized { old_height, new_height, .. } => {
                write!(f, "ChainReorganized({}->{})", old_height, new_height)
            }
            BlockchainEvent::ValidatorRegistered { .. } => write!(f, "ValidatorRegistered"),
            BlockchainEvent::ValidatorUnregistered { .. } => write!(f, "ValidatorUnregistered"),
        }
    }
}

// ============================================================================
// EVENT LISTENER TRAIT
// ============================================================================

/// Trait for entities that listen to blockchain events
#[async_trait]
pub trait BlockchainEventListener: Send {
    /// Called when a blockchain event occurs
    /// 
    /// This method is async to allow listeners to perform async operations
    /// without blocking other listeners or the blockchain thread.
    async fn on_event(&mut self, event: BlockchainEvent) -> Result<()>;
}

// ============================================================================
// EVENT PUBLISHER
// ============================================================================

/// Thread-safe event publisher for blockchain events
#[derive(Clone)]
pub struct BlockchainEventPublisher {
    /// Listeners subscribed to events
    listeners: Arc<Mutex<Vec<Box<dyn BlockchainEventListener>>>>,
}

impl std::fmt::Debug for BlockchainEventPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockchainEventPublisher")
            .finish()
    }
}

impl BlockchainEventPublisher {
    /// Create a new event publisher
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Subscribe to blockchain events
    pub async fn subscribe(&self, listener: Box<dyn BlockchainEventListener>) -> Result<()> {
        let mut listeners = self.listeners.lock().await;
        listeners.push(listener);
        Ok(())
    }

    /// Publish an event to all subscribers
    pub async fn publish(&self, event: BlockchainEvent) -> Result<()> {
        let mut listeners = self.listeners.lock().await;

        // Notify all listeners
        for listener in listeners.iter_mut() {
            if let Err(e) = listener.on_event(event.clone()).await {
                tracing::warn!("Event listener error: {}", e);
                // Continue notifying other listeners even if one fails
            }
        }

        Ok(())
    }

    /// Get number of subscribed listeners
    pub async fn listener_count(&self) -> Result<usize> {
        let listeners = self.listeners.lock().await;
        Ok(listeners.len())
    }

    /// Clear all listeners (for testing)
    pub async fn clear_listeners(&self) -> Result<()> {
        let mut listeners = self.listeners.lock().await;
        listeners.clear();
        Ok(())
    }
}

impl Default for BlockchainEventPublisher {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SIMPLE TEST LISTENER
// ============================================================================

/// Simple listener that captures events for testing
#[derive(Debug, Clone)]
pub struct TestEventListener {
    /// Events captured
    pub events: Arc<Mutex<Vec<BlockchainEvent>>>,
}

impl TestEventListener {
    /// Create a new test listener
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get captured events
    pub async fn get_events(&self) -> Result<Vec<BlockchainEvent>> {
        let events = self.events.lock().await;
        Ok(events.clone())
    }

    /// Clear captured events
    pub async fn clear(&self) -> Result<()> {
        let mut events = self.events.lock().await;
        events.clear();
        Ok(())
    }
}

impl Default for TestEventListener {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockchainEventListener for TestEventListener {
    async fn on_event(&mut self, event: BlockchainEvent) -> Result<()> {
        let mut events = self.events.lock().await;
        events.push(event);
        Ok(())
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_publisher_creation() {
        let publisher = BlockchainEventPublisher::new();
        assert_eq!(publisher.listener_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_subscribe_listener() {
        let publisher = BlockchainEventPublisher::new();
        let listener = Box::new(TestEventListener::new());
        publisher.subscribe(listener).await.unwrap();
        assert_eq!(publisher.listener_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_publish_event_to_listeners() {
        let publisher = BlockchainEventPublisher::new();
        let listener = Box::new(TestEventListener::new());
        let listener_ref = listener.clone();
        publisher.subscribe(listener).await.unwrap();

        // Publish an event
        let event = BlockchainEvent::BlockAdded {
            height: 1,
            block_hash: [1u8; 32],
            timestamp: 1000,
            transaction_count: 5,
        };

        publisher.publish(event.clone()).await.unwrap();

        // Verify listener captured the event
        let events = listener_ref.get_events().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], event);
    }

    #[tokio::test]
    async fn test_multiple_listeners_receive_events() {
        let publisher = BlockchainEventPublisher::new();

        let listener1 = Box::new(TestEventListener::new());
        let listener1_ref = listener1.clone();

        let listener2 = Box::new(TestEventListener::new());
        let listener2_ref = listener2.clone();

        publisher.subscribe(listener1).await.unwrap();
        publisher.subscribe(listener2).await.unwrap();

        assert_eq!(publisher.listener_count().await.unwrap(), 2);

        // Publish an event
        let event = BlockchainEvent::BlockFinalized {
            height: 10,
            block_hash: [2u8; 32],
        };

        publisher.publish(event.clone()).await.unwrap();

        // Both listeners should receive the event
        let events1 = listener1_ref.get_events().await.unwrap();
        let events2 = listener2_ref.get_events().await.unwrap();

        assert_eq!(events1.len(), 1);
        assert_eq!(events2.len(), 1);
        assert_eq!(events1[0], event);
        assert_eq!(events2[0], event);
    }
}
