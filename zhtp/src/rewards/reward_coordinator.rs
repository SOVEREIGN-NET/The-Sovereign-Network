//! Unified RewardCoordinator — owns all three reward streams.
//!
//! Single struct that coordinates PoUW, routing, and storage reward processing
//! through a unified BudgetTracker and RewardMinter.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::budget_tracker::{BudgetTracker, RewardSource};
use super::reward_minter::RewardMinter;

/// Unified reward coordinator.
///
/// Owns the budget tracker and minter. All reward processors delegate
/// minting through this coordinator to enforce unified budget caps.
pub struct RewardCoordinator {
    pub budget: Arc<RwLock<BudgetTracker>>,
    pub minter: Arc<RewardMinter>,
}

impl RewardCoordinator {
    pub fn new(
        blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
        budget: BudgetTracker,
    ) -> Self {
        Self {
            budget: Arc::new(RwLock::new(budget)),
            minter: Arc::new(RewardMinter::new(blockchain)),
        }
    }

    /// Check budget, mint, and record payment — single path for all reward types.
    ///
    /// Returns the tx_hash on success, or an error if budget is exhausted or minting fails.
    pub async fn pay_reward(
        &self,
        recipient_key_id: [u8; 32],
        amount: u128,
        source: RewardSource,
        epoch: u64,
    ) -> Result<lib_blockchain::Hash> {
        // Budget check
        {
            let budget = self.budget.read().await;
            if !budget.can_pay(source, amount) {
                return Err(anyhow::anyhow!(
                    "Budget exhausted for {:?}: paid={}, cap={}, requested={}",
                    source,
                    budget.remaining(source),
                    match source {
                        RewardSource::PoUW => budget.pouw_cap,
                        RewardSource::Routing => budget.routing_cap,
                        RewardSource::Storage => budget.storage_cap,
                    },
                    amount,
                ));
            }
        }

        // Mint
        let tx_hash = self.minter.mint(recipient_key_id, amount, source, epoch).await?;

        // Record payment in budget
        self.budget.write().await.record_paid(source, amount);

        Ok(tx_hash)
    }

    /// Save budget state to disk.
    pub async fn save_budget(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        let budget = self.budget.read().await.clone();
        let encoded = bincode::serialize(&budget)
            .map_err(|e| anyhow::anyhow!("Failed to serialize budget: {}", e))?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(&encoded)?;
        debug!("Reward budget saved to {}", path.display());
        Ok(())
    }

    /// Load budget state from disk.
    pub async fn load_budget(&self, path: &std::path::Path) -> Result<()> {
        if !path.exists() {
            info!("No budget file at {} — starting fresh", path.display());
            return Ok(());
        }
        let bytes = std::fs::read(path)?;
        let loaded: BudgetTracker = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize budget: {}", e))?;
        info!(
            pouw_paid = loaded.pouw_paid,
            routing_paid = loaded.routing_paid,
            storage_paid = loaded.storage_paid,
            "Reward budget loaded from disk"
        );
        *self.budget.write().await = loaded;
        Ok(())
    }

    /// Get current budget state.
    pub async fn get_budget(&self) -> BudgetTracker {
        self.budget.read().await.clone()
    }
}
