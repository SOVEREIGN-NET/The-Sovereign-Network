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
///
/// After the PoUW sub-budget (2.1M SOV) exhausts, rewards can continue
/// from the broader DEV_GRANT_POOL (100B SOV) as long as NAI justifies them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetTracker {
    pub pouw_paid: u128,
    pub routing_paid: u128,
    pub storage_paid: u128,
    pub pouw_cap: u128,
    pub routing_cap: u128,
    pub storage_cap: u128,
    /// DEV_GRANT_POOL lifetime ceiling (100B SOV in atoms).
    /// The absolute cap across all reward sources after sub-budgets exhaust.
    pub dev_grant_pool_ceiling: u128,
    /// Total paid from DEV_GRANT_POOL (across all sources, lifetime).
    pub dev_grant_pool_paid: u128,
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
            dev_grant_pool_ceiling: super::nai::DEV_GRANT_POOL_CEILING,
            dev_grant_pool_paid: 0,
        }
    }

    /// Check if a payment can be made.
    ///
    /// First checks the per-source sub-budget. If that's exhausted, checks the
    /// broader DEV_GRANT_POOL ceiling. The DEV_GRANT_POOL is the absolute
    /// lifetime cap — never exceeded.
    pub fn can_pay(&self, source: RewardSource, amount: u128) -> bool {
        let (paid, cap) = self.source_state(source);
        if paid + amount <= cap {
            return true;
        }
        // Sub-budget exhausted — check DEV_GRANT_POOL fallback
        self.dev_grant_pool_paid + amount <= self.dev_grant_pool_ceiling
    }

    /// Record a successful payment.
    pub fn record_paid(&mut self, source: RewardSource, amount: u128) {
        match source {
            RewardSource::PoUW => self.pouw_paid = self.pouw_paid.saturating_add(amount),
            RewardSource::Routing => self.routing_paid = self.routing_paid.saturating_add(amount),
            RewardSource::Storage => self.storage_paid = self.storage_paid.saturating_add(amount),
        }
        self.dev_grant_pool_paid = self.dev_grant_pool_paid.saturating_add(amount);
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
