//! Bonding Curve Events
//!
//! All state changes in the bonding curve system emit events for indexing.
//! These events are the source of truth for API responses.

use serde::{Deserialize, Serialize};

/// Bonding curve token events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BondingCurveEvent {
    /// Token purchased from curve
    TokenPurchased {
        /// Token identifier
        token_id: [u8; 32],
        /// Buyer address
        buyer: [u8; 32],
        /// Amount of stablecoin paid
        stable_amount: u64,
        /// Amount of tokens received
        token_amount: u64,
        /// Price per token at time of purchase
        price: u64,
        /// Block height
        block_height: u64,
        /// Timestamp
        timestamp: u64,
    },

    /// Token sold back to curve (if enabled)
    TokenSold {
        /// Token identifier
        token_id: [u8; 32],
        /// Seller address
        seller: [u8; 32],
        /// Amount of tokens sold
        token_amount: u64,
        /// Amount of stablecoin received
        stable_amount: u64,
        /// Price per token at time of sale
        price: u64,
        /// Block height
        block_height: u64,
        /// Timestamp
        timestamp: u64,
    },

    /// Token graduated from curve to AMM
    Graduated {
        /// Token identifier
        token_id: [u8; 32],
        /// Final reserve amount
        final_reserve: u64,
        /// Final token supply
        final_supply: u64,
        /// Graduation threshold that was met
        threshold_met: String,
        /// Block height
        block_height: u64,
        /// Timestamp
        timestamp: u64,
    },

    /// Reserve balance updated
    ReserveUpdated {
        /// Token identifier
        token_id: [u8; 32],
        /// New reserve balance
        new_reserve: u64,
        /// Change amount (positive for buy, negative for sell)
        delta: i64,
        /// Reason for update
        reason: ReserveUpdateReason,
        /// Block height
        block_height: u64,
        /// Timestamp
        timestamp: u64,
    },

    /// AMM pool seeded after graduation
    AMMSeeded {
        /// Token identifier
        token_id: [u8; 32],
        /// AMM pool identifier
        pool_id: [u8; 32],
        /// SOV amount seeded
        sov_amount: u64,
        /// Token amount seeded
        token_amount: u64,
        /// Stable amount remaining (sent to treasury)
        stable_to_treasury: u64,
        /// Block height
        block_height: u64,
        /// Timestamp
        timestamp: u64,
    },

    /// Curve parameters updated (only before graduation)
    ParametersUpdated {
        /// Token identifier
        token_id: [u8; 32],
        /// Which parameter changed
        parameter: String,
        /// Old value
        old_value: String,
        /// New value
        new_value: String,
        /// Block height
        block_height: u64,
        /// Timestamp
        timestamp: u64,
    },
}

/// Reason for reserve update
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReserveUpdateReason {
    /// User purchased tokens
    Purchase,
    /// User sold tokens
    Sale,
    /// Fees collected
    FeeCollection,
    /// Migration to AMM
    Migration,
}

impl std::fmt::Display for ReserveUpdateReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReserveUpdateReason::Purchase => write!(f, "purchase"),
            ReserveUpdateReason::Sale => write!(f, "sale"),
            ReserveUpdateReason::FeeCollection => write!(f, "fee_collection"),
            ReserveUpdateReason::Migration => write!(f, "migration"),
        }
    }
}

impl BondingCurveEvent {
    /// Get the token ID associated with this event
    pub fn token_id(&self) -> &[u8; 32] {
        match self {
            BondingCurveEvent::TokenPurchased { token_id, .. } => token_id,
            BondingCurveEvent::TokenSold { token_id, .. } => token_id,
            BondingCurveEvent::Graduated { token_id, .. } => token_id,
            BondingCurveEvent::ReserveUpdated { token_id, .. } => token_id,
            BondingCurveEvent::AMMSeeded { token_id, .. } => token_id,
            BondingCurveEvent::ParametersUpdated { token_id, .. } => token_id,
        }
    }

    /// Get the block height for this event
    pub fn block_height(&self) -> u64 {
        match self {
            BondingCurveEvent::TokenPurchased { block_height, .. } => *block_height,
            BondingCurveEvent::TokenSold { block_height, .. } => *block_height,
            BondingCurveEvent::Graduated { block_height, .. } => *block_height,
            BondingCurveEvent::ReserveUpdated { block_height, .. } => *block_height,
            BondingCurveEvent::AMMSeeded { block_height, .. } => *block_height,
            BondingCurveEvent::ParametersUpdated { block_height, .. } => *block_height,
        }
    }

    /// Get event type name
    pub fn event_type(&self) -> &'static str {
        match self {
            BondingCurveEvent::TokenPurchased { .. } => "token_purchased",
            BondingCurveEvent::TokenSold { .. } => "token_sold",
            BondingCurveEvent::Graduated { .. } => "graduated",
            BondingCurveEvent::ReserveUpdated { .. } => "reserve_updated",
            BondingCurveEvent::AMMSeeded { .. } => "amm_seeded",
            BondingCurveEvent::ParametersUpdated { .. } => "parameters_updated",
        }
    }
}

/// Event indexer interface
///
/// Implement this to index bonding curve events for API queries.
pub trait EventIndexer {
    /// Index a new event
    fn index_event(&mut self, event: BondingCurveEvent);

    /// Get all events for a token
    fn get_token_events(&self, token_id: [u8; 32]) -> Vec<&BondingCurveEvent>;

    /// Get purchase events for a token
    fn get_purchase_events(&self, token_id: [u8; 32]) -> Vec<&BondingCurveEvent>;

    /// Get events in a block range
    fn get_events_in_range(&self, start_block: u64, end_block: u64) -> Vec<&BondingCurveEvent>;

    /// Get latest event for a token
    fn get_latest_event(&self, token_id: [u8; 32]) -> Option<&BondingCurveEvent>;
}

/// In-memory event indexer for testing
#[derive(Debug, Clone, Default)]
pub struct InMemoryEventIndexer {
    events: Vec<BondingCurveEvent>,
}

impl InMemoryEventIndexer {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl EventIndexer for InMemoryEventIndexer {
    fn index_event(&mut self, event: BondingCurveEvent) {
        self.events.push(event);
    }

    fn get_token_events(&self, token_id: [u8; 32]) -> Vec<&BondingCurveEvent> {
        self.events
            .iter()
            .filter(|e| e.token_id() == &token_id)
            .collect()
    }

    fn get_purchase_events(&self, token_id: [u8; 32]) -> Vec<&BondingCurveEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.token_id() == &token_id
                    && matches!(e, BondingCurveEvent::TokenPurchased { .. })
            })
            .collect()
    }

    fn get_events_in_range(&self, start_block: u64, end_block: u64) -> Vec<&BondingCurveEvent> {
        self.events
            .iter()
            .filter(|e| {
                let height = e.block_height();
                height >= start_block && height <= end_block
            })
            .collect()
    }

    fn get_latest_event(&self, token_id: [u8; 32]) -> Option<&BondingCurveEvent> {
        self.events
            .iter()
            .filter(|e| e.token_id() == &token_id)
            .max_by_key(|e| e.block_height())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = BondingCurveEvent::TokenPurchased {
            token_id: [1u8; 32],
            buyer: [2u8; 32],
            stable_amount: 100_000_000,
            token_amount: 1000 * 100_000_000,
            price: 100_000,
            block_height: 100,
            timestamp: 1_600_000_000,
        };

        assert_eq!(event.token_id(), &[1u8; 32]);
        assert_eq!(event.block_height(), 100);
        assert_eq!(event.event_type(), "token_purchased");
    }

    #[test]
    fn test_event_indexer() {
        let mut indexer = InMemoryEventIndexer::new();

        let token1 = [1u8; 32];
        let token2 = [2u8; 32];

        indexer.index_event(BondingCurveEvent::TokenPurchased {
            token_id: token1,
            buyer: [3u8; 32],
            stable_amount: 100,
            token_amount: 1000,
            price: 100_000,
            block_height: 100,
            timestamp: 1,
        });

        indexer.index_event(BondingCurveEvent::TokenPurchased {
            token_id: token1,
            buyer: [4u8; 32],
            stable_amount: 200,
            token_amount: 2000,
            price: 100_000,
            block_height: 101,
            timestamp: 2,
        });

        indexer.index_event(BondingCurveEvent::Graduated {
            token_id: token2,
            final_reserve: 1000,
            final_supply: 10000,
            threshold_met: "reserve".to_string(),
            block_height: 150,
            timestamp: 3,
        });

        assert_eq!(indexer.event_count(), 3);

        let token1_events = indexer.get_token_events(token1);
        assert_eq!(token1_events.len(), 2);

        let token2_events = indexer.get_token_events(token2);
        assert_eq!(token2_events.len(), 1);

        let purchases = indexer.get_purchase_events(token1);
        assert_eq!(purchases.len(), 2);

        let range_events = indexer.get_events_in_range(100, 101);
        assert_eq!(range_events.len(), 2);

        let latest = indexer.get_latest_event(token1);
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().block_height(), 101);
    }
}
