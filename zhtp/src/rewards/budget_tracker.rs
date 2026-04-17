//! Unified budget tracker across all reward sources (PoUW, routing, storage).

use serde::{Deserialize, Serialize};

/// Reward source identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RewardSource {
    PoUW,
    Routing,
    Storage,
}

/// Unified budget tracker.
///
/// Tracks total paid and enforces per-source and combined caps.
/// All amounts are in SOV atomic units (18 decimals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetTracker {
    pub pouw_paid: u128,
    pub routing_paid: u128,
    pub storage_paid: u128,
    pub pouw_cap: u128,
    pub routing_cap: u128,
    pub storage_cap: u128,
}

impl BudgetTracker {
    pub fn new(pouw_cap: u128, routing_cap: u128, storage_cap: u128) -> Self {
        Self {
            pouw_paid: 0,
            routing_paid: 0,
            storage_paid: 0,
            pouw_cap,
            routing_cap,
            storage_cap,
        }
    }

    /// Check if a payment can be made from the given source without exceeding its cap.
    pub fn can_pay(&self, source: RewardSource, amount: u128) -> bool {
        let (paid, cap) = self.source_state(source);
        paid + amount <= cap
    }

    /// Record a successful payment.
    pub fn record_paid(&mut self, source: RewardSource, amount: u128) {
        match source {
            RewardSource::PoUW => self.pouw_paid = self.pouw_paid.saturating_add(amount),
            RewardSource::Routing => self.routing_paid = self.routing_paid.saturating_add(amount),
            RewardSource::Storage => self.storage_paid = self.storage_paid.saturating_add(amount),
        }
    }

    /// Total paid across all sources.
    pub fn total_paid(&self) -> u128 {
        self.pouw_paid + self.routing_paid + self.storage_paid
    }

    /// Remaining budget for a source.
    pub fn remaining(&self, source: RewardSource) -> u128 {
        let (paid, cap) = self.source_state(source);
        cap.saturating_sub(paid)
    }

    fn source_state(&self, source: RewardSource) -> (u128, u128) {
        match source {
            RewardSource::PoUW => (self.pouw_paid, self.pouw_cap),
            RewardSource::Routing => (self.routing_paid, self.routing_cap),
            RewardSource::Storage => (self.storage_paid, self.storage_cap),
        }
    }
}

impl Default for BudgetTracker {
    fn default() -> Self {
        use crate::pouw::rewards::POUW_TOTAL_BUDGET;
        // Routing and storage caps are placeholder — to be defined by governance.
        // For now, use the same cap as PoUW.
        Self::new(POUW_TOTAL_BUDGET, POUW_TOTAL_BUDGET, POUW_TOTAL_BUDGET)
    }
}
