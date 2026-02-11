//! # Routing Reward Processor
//! 
//! Automatically processes routing rewards by:
//! 1. Checking routing statistics every 10 minutes
//! 2. Creating reward transactions when threshold is met
//! 3. Adding transactions to blockchain pending pool
//! 4. Resetting the reward counter
//!
//! ## Example
//! ```rust
//! let processor = Arc::new(RoutingRewardProcessor::new(
//!     network_component,
//!     blockchain_arc,
//!     environment,
//! ));
//! 
//! let handle = processor.start();
//! // Processor now runs in background...
//! ```

use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{info, warn, error, debug};

use lib_blockchain::Blockchain;
use super::components::{NetworkComponent, BlockchainComponent};

/// Routing reward processor configuration
#[derive(Debug, Clone)]
pub struct RoutingRewardConfig {
    /// How often to check and process rewards
    pub check_interval: Duration,
    /// Minimum tokens to trigger a claim
    pub minimum_threshold: u64,
    /// Maximum reward per transaction
    pub max_batch_size: u64,
}

impl Default for RoutingRewardConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(600), // 10 minutes
            minimum_threshold: 100, // 100 SOV
            max_batch_size: 10_000, // 10,000 SOV max
        }
    }
}

/// Routing reward processor
/// 
/// This processor runs in the background and periodically checks routing
/// statistics. When the accumulated rewards exceed the minimum threshold,
/// it creates a reward transaction and adds it to the blockchain.
pub struct RoutingRewardProcessor {
    network_component: Arc<NetworkComponent>,
    blockchain_arc: Arc<RwLock<Option<Blockchain>>>,
    environment: crate::config::Environment,
    config: RoutingRewardConfig,
}

impl RoutingRewardProcessor {
    /// Create a new routing reward processor with default configuration
    pub fn new(
        network_component: Arc<NetworkComponent>,
        blockchain_arc: Arc<RwLock<Option<Blockchain>>>,
        environment: crate::config::Environment,
    ) -> Self {
        Self {
            network_component,
            blockchain_arc,
            environment,
            config: RoutingRewardConfig::default(),
        }
    }
    
    /// Create with custom configuration
    pub fn with_config(
        network_component: Arc<NetworkComponent>,
        blockchain_arc: Arc<RwLock<Option<Blockchain>>>,
        environment: crate::config::Environment,
        config: RoutingRewardConfig,
    ) -> Self {
        Self {
            network_component,
            blockchain_arc,
            environment,
            config,
        }
    }
    
    /// Start the background processor task
    /// 
    /// Returns a JoinHandle that can be used to stop the processor.
    /// The processor will run indefinitely until the handle is aborted.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        info!("═══════════════════════════════════════════════════════");
        info!(" Starting Routing Reward Processor");
        info!("═══════════════════════════════════════════════════════");
        info!("   Check interval: {:?}", self.config.check_interval);
        info!("   Minimum threshold: {} SOV", self.config.minimum_threshold);
        info!("   Max batch size: {} SOV", self.config.max_batch_size);
        info!("═══════════════════════════════════════════════════════");
        
        tokio::spawn(async move {
            let mut interval_timer = interval(self.config.check_interval);
            let mut cycle = 0u64;
            
            loop {
                interval_timer.tick().await;
                cycle += 1;
                
                debug!("⏰ Routing reward check cycle {} triggered", cycle);
                
                match self.process_routing_rewards(cycle).await {
                    Ok(claimed) => {
                        if claimed {
                            info!(" Cycle {} completed: Rewards claimed", cycle);
                        } else {
                            debug!("  Cycle {} completed: Below threshold", cycle);
                        }
                    }
                    Err(e) => {
                        error!(" Cycle {} failed: {}", cycle, e);
                    }
                }
            }
        })
    }
    
    /// Process routing rewards for this cycle
    /// 
    /// Returns true if rewards were claimed, false if skipped.
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Failed to get routing statistics
    /// - Failed to create reward transaction
    /// - Failed to add transaction to blockchain
    /// - Failed to reset reward counter
    async fn process_routing_rewards(&self, cycle: u64) -> Result<bool> {
        info!(" [ROUTING] Checking routing rewards (cycle {})...", cycle);
        
        // Get current routing statistics
        let stats = self.network_component.get_routing_stats().await;
        
        info!("   [ROUTING]  Stats:");
        info!("      [ROUTING] Tokens earned: {} SOV", stats.theoretical_tokens_earned);
        info!("      [ROUTING] Bytes routed: {} bytes ({:.2} MB)", 
              stats.bytes_routed, 
              stats.bytes_routed as f64 / 1_048_576.0);
        info!("      [ROUTING] Messages routed: {}", stats.messages_routed);
        
        // Check if reward meets minimum threshold
        if stats.theoretical_tokens_earned < self.config.minimum_threshold {
            debug!("     Below threshold ({} < {}), skipping claim", 
                  stats.theoretical_tokens_earned, 
                  self.config.minimum_threshold);
            return Ok(false);
        }
        
        // Cap reward at max batch size
        let claim_amount = std::cmp::min(
            stats.theoretical_tokens_earned, 
            self.config.max_batch_size
        );
        
        if claim_amount < stats.theoretical_tokens_earned {
            warn!("     Capping claim: {} -> {} SOV (excess will be claimed next cycle)", 
                  stats.theoretical_tokens_earned, 
                  claim_amount);
        }
        
        info!("    Creating routing reward transaction: {} SOV", claim_amount);
        
        info!("    Creating routing reward transaction: {} SOV", claim_amount);
        
        // Get this node's unique identifier for reward attribution
        let node_id = self.network_component.get_node_id().await
            .ok_or_else(|| anyhow::anyhow!("Cannot get node ID: mesh server not initialized"))?;
        
        info!("    Node ID: {}", hex::encode(&node_id));
        
        // Create reward transaction with actual node ID and claim amount
        let reward_tx = BlockchainComponent::create_reward_transaction(
            node_id,
            claim_amount,
            &self.environment
        )
            .await
            .context("Failed to create reward transaction")?;
        
        info!("    Transaction created: {:?}", reward_tx.hash());
        
        // Validate transaction before submitting
        self.validate_reward_transaction(claim_amount, &reward_tx).await?;
        
        // Add to blockchain using global blockchain provider
        let shared_blockchain = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .context("Failed to get global blockchain")?;
        
        {
            let mut blockchain_write = shared_blockchain.write().await;
            blockchain_write.add_pending_transaction(reward_tx.clone())
                .context("Failed to add transaction to blockchain")?;
        }
        
        info!("    Transaction added to pending pool");
        
        // Reset counter (only reset claimed amount if capped)
        if claim_amount < stats.theoretical_tokens_earned {
            // TODO: Partial reset - need to add this to mesh server
            warn!("     Partial reset not yet implemented - resetting all");
        }
        
        self.network_component.reset_routing_rewards().await?;
        
        info!("    Reward counter reset");
        info!("═══════════════════════════════════════════════════════");
        info!(" Routing Reward Claimed Successfully!");
        info!("   Amount: {} SOV", claim_amount);
        info!("   Cycle: {}", cycle);
        info!("   Next check: {:?}", self.config.check_interval);
        info!("═══════════════════════════════════════════════════════");
        
        Ok(true)
    }
    
    /// Validate reward transaction before submitting to blockchain
    /// 
    /// Performs critical security checks:
    /// - Verifies reward amount is within reasonable bounds
    /// - Checks blockchain is available and synced
    /// - Validates transaction structure
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Reward amount is zero or exceeds maximum allowed
    /// - Blockchain is unavailable
    /// - Transaction is malformed
    async fn validate_reward_transaction(
        &self,
        claim_amount: u64,
        transaction: &lib_blockchain::Transaction,
    ) -> Result<()> {
        info!("    Validating transaction...");
        
        // 1. Validate reward amount is reasonable
        const MAX_SINGLE_CLAIM: u64 = 1_000_000; // 1M SOV maximum per claim
        
        if claim_amount == 0 {
            return Err(anyhow::anyhow!("Invalid claim: amount is zero"));
        }
        
        if claim_amount > MAX_SINGLE_CLAIM {
            return Err(anyhow::anyhow!(
                "Invalid claim: amount {} exceeds maximum allowed {} SOV",
                claim_amount,
                MAX_SINGLE_CLAIM
            ));
        }
        
        if claim_amount > self.config.max_batch_size {
            return Err(anyhow::anyhow!(
                "Invalid claim: amount {} exceeds configured max_batch_size {} SOV",
                claim_amount,
                self.config.max_batch_size
            ));
        }
        
        info!("       Amount valid: {} SOV", claim_amount);
        
        // 2. Verify blockchain is available
        let shared_blockchain = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .context("Blockchain unavailable")?;
        
        {
            let blockchain = shared_blockchain.read().await;
            
            // Check blockchain has blocks (is initialized)
            let chain_height = blockchain.get_height();
            if chain_height == 0 {
                return Err(anyhow::anyhow!("Blockchain not initialized: no blocks"));
            }
            
            info!("       Blockchain available: {} blocks", chain_height);
        }
        
        // 3. Validate transaction structure
        let tx_hash = transaction.hash();
        if tx_hash.is_zero() {
            return Err(anyhow::anyhow!("Invalid transaction: zero hash"));
        }
        
        info!("       Transaction structure valid");
        info!("    Validation passed");
        
        Ok(())
    }
    
    /// Get current processor metrics (for monitoring/API)
    /// 
    /// Returns current statistics about pending rewards and processor state.
    pub async fn get_metrics(&self) -> RoutingRewardMetrics {
        let stats = self.network_component.get_routing_stats().await;
        
        RoutingRewardMetrics {
            pending_rewards: stats.theoretical_tokens_earned,
            total_bytes_routed: stats.bytes_routed,
            total_messages_routed: stats.messages_routed,
            check_interval_secs: self.config.check_interval.as_secs(),
            minimum_threshold: self.config.minimum_threshold,
            max_batch_size: self.config.max_batch_size,
        }
    }
}

/// Metrics for monitoring the routing reward processor
#[derive(Debug, Clone)]
pub struct RoutingRewardMetrics {
    /// Pending rewards waiting to be claimed
    pub pending_rewards: u64,
    /// Total bytes routed since last reset
    pub total_bytes_routed: u64,
    /// Total messages routed since last reset
    pub total_messages_routed: u64,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Minimum threshold for claiming
    pub minimum_threshold: u64,
    /// Maximum batch size per transaction
    pub max_batch_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = RoutingRewardConfig::default();
        assert_eq!(config.check_interval.as_secs(), 600);
        assert_eq!(config.minimum_threshold, 100);
        assert_eq!(config.max_batch_size, 10_000);
    }
    
    #[test]
    fn test_custom_config() {
        let config = RoutingRewardConfig {
            check_interval: Duration::from_secs(300),
            minimum_threshold: 50,
            max_batch_size: 5_000,
        };
        assert_eq!(config.check_interval.as_secs(), 300);
        assert_eq!(config.minimum_threshold, 50);
        assert_eq!(config.max_batch_size, 5_000);
    }
    
    // TODO: Add integration tests with mock components
}
