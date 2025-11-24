//! # Unified Reward Orchestrator
//! 
//! Manages both routing and storage reward processors with unified configuration.
//! Provides a single interface for:
//! - Starting/stopping both processors
//! - Unified configuration management
//! - Aggregated metrics
//! - Simplified lifecycle management
//!
//! ## Example
//! ```rust
//! let orchestrator = RewardOrchestrator::new(
//!     network_component,
//!     blockchain_arc,
//!     environment,
//!     config,
//! );
//! 
//! orchestrator.start_all().await?;
//! // Both processors now running...
//! let metrics = orchestrator.get_combined_metrics().await;
//! orchestrator.stop_all().await?;
//! ```

use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, error};

use lib_blockchain::Blockchain;
use super::components::NetworkComponent;
use super::routing_rewards::{RoutingRewardProcessor, RoutingRewardConfig, RoutingRewardMetrics};
use super::storage_rewards::{StorageRewardProcessor, StorageRewardConfig, StorageRewardMetrics};
use crate::config::aggregation::RewardsConfig;

/// Rate limiter for reward claims
/// 
/// Prevents abuse by tracking claim history and enforcing:
/// - Cooldown periods between claims
/// - Maximum claims per hour
#[derive(Debug, Clone)]
struct RateLimiter {
    /// Last claim timestamp for each processor
    last_claim_time: HashMap<String, Instant>,
    /// Claim count per hour for each processor
    claims_per_hour: HashMap<String, Vec<Instant>>,
    /// Cooldown period between claims (seconds)
    cooldown_period: Duration,
    /// Maximum claims allowed per hour
    max_claims_per_hour: u32,
}

impl RateLimiter {
    fn new(cooldown_secs: u64, max_claims_per_hour: u32) -> Self {
        Self {
            last_claim_time: HashMap::new(),
            claims_per_hour: HashMap::new(),
            cooldown_period: Duration::from_secs(cooldown_secs),
            max_claims_per_hour,
        }
    }
    
    /// Check if a claim is allowed for this processor
    fn can_claim(&mut self, processor_id: &str) -> Result<()> {
        let now = Instant::now();
        
        // 1. Check cooldown period
        if let Some(last_claim) = self.last_claim_time.get(processor_id) {
            let elapsed = now.duration_since(*last_claim);
            if elapsed < self.cooldown_period {
                let remaining = self.cooldown_period - elapsed;
                return Err(anyhow::anyhow!(
                    "Cooldown active: {} seconds remaining",
                    remaining.as_secs()
                ));
            }
        }
        
        // 2. Check hourly rate limit
        let one_hour_ago = now - Duration::from_secs(3600);
        
        // Get claims for this processor
        let claims = self.claims_per_hour
            .entry(processor_id.to_string())
            .or_insert_with(Vec::new);
        
        // Remove claims older than 1 hour
        claims.retain(|&timestamp| timestamp > one_hour_ago);
        
        // Check if under limit
        if claims.len() >= self.max_claims_per_hour as usize {
            return Err(anyhow::anyhow!(
                "Rate limit exceeded: {} claims in last hour (max: {})",
                claims.len(),
                self.max_claims_per_hour
            ));
        }
        
        Ok(())
    }
    
    /// Record a successful claim
    fn record_claim(&mut self, processor_id: &str) {
        let now = Instant::now();
        self.last_claim_time.insert(processor_id.to_string(), now);
        
        let claims = self.claims_per_hour
            .entry(processor_id.to_string())
            .or_insert_with(Vec::new);
        claims.push(now);
    }
    
    /// Get statistics for a processor
    fn get_stats(&self, processor_id: &str) -> RateLimitStats {
        let now = Instant::now();
        let one_hour_ago = now - Duration::from_secs(3600);
        
        let claims_in_last_hour = self.claims_per_hour
            .get(processor_id)
            .map(|claims| claims.iter().filter(|&&t| t > one_hour_ago).count())
            .unwrap_or(0) as u32;
        
        let cooldown_remaining = self.last_claim_time
            .get(processor_id)
            .and_then(|last_claim| {
                let elapsed = now.duration_since(*last_claim);
                if elapsed < self.cooldown_period {
                    Some(self.cooldown_period - elapsed)
                } else {
                    None
                }
            });
        
        RateLimitStats {
            claims_in_last_hour,
            cooldown_remaining,
            max_claims_per_hour: self.max_claims_per_hour,
        }
    }
}

/// Rate limit statistics for a processor
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub claims_in_last_hour: u32,
    pub cooldown_remaining: Option<Duration>,
    pub max_claims_per_hour: u32,
}

/// Unified reward orchestrator configuration
#[derive(Debug, Clone)]
pub struct RewardOrchestratorConfig {
    /// Routing reward configuration
    pub routing_config: RoutingRewardConfig,
    /// Storage reward configuration
    pub storage_config: StorageRewardConfig,
    /// Whether to enable routing rewards
    pub enable_routing_rewards: bool,
    /// Whether to enable storage rewards
    pub enable_storage_rewards: bool,
    /// Cooldown period between claims (seconds)
    pub cooldown_period_secs: u64,
    /// Maximum claims allowed per hour
    pub max_claims_per_hour: u32,
}

impl Default for RewardOrchestratorConfig {
    fn default() -> Self {
        Self {
            routing_config: RoutingRewardConfig::default(),
            storage_config: StorageRewardConfig::default(),
            enable_routing_rewards: true,
            enable_storage_rewards: true,
            cooldown_period_secs: 600,  // 10 minutes
            max_claims_per_hour: 6,
        }
    }
}

impl From<&RewardsConfig> for RewardOrchestratorConfig {
    fn from(config: &RewardsConfig) -> Self {
        use tokio::time::Duration;
        
        Self {
            routing_config: RoutingRewardConfig {
                check_interval: Duration::from_secs(config.routing_check_interval_secs),
                minimum_threshold: config.routing_minimum_threshold,
                max_batch_size: config.routing_max_batch_size,
            },
            storage_config: StorageRewardConfig {
                check_interval: Duration::from_secs(config.storage_check_interval_secs),
                minimum_threshold: config.storage_minimum_threshold,
                max_batch_size: config.storage_max_batch_size,
            },
            enable_routing_rewards: config.enabled && config.routing_rewards_enabled,
            enable_storage_rewards: config.enabled && config.storage_rewards_enabled,
            cooldown_period_secs: config.cooldown_period_secs,
            max_claims_per_hour: config.max_claims_per_hour,
        }
    }
}

/// Unified reward orchestrator
/// 
/// Manages both routing and storage reward processors with a single interface.
/// Simplifies lifecycle management and provides aggregated metrics.
pub struct RewardOrchestrator {
    network_component: Arc<NetworkComponent>,
    blockchain_arc: Arc<RwLock<Option<Blockchain>>>,
    environment: crate::config::Environment,
    config: RewardOrchestratorConfig,
    
    // Processor instances
    routing_processor: Arc<RoutingRewardProcessor>,
    storage_processor: Arc<StorageRewardProcessor>,
    
    // Rate limiter
    rate_limiter: Arc<RwLock<RateLimiter>>,
    
    // Task handles
    routing_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    storage_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl RewardOrchestrator {
    /// Create a new unified reward orchestrator with default configuration
    pub fn new(
        network_component: Arc<NetworkComponent>,
        blockchain_arc: Arc<RwLock<Option<Blockchain>>>,
        environment: crate::config::Environment,
    ) -> Self {
        Self::with_config(
            network_component,
            blockchain_arc,
            environment,
            RewardOrchestratorConfig::default(),
        )
    }
    
    /// Create with custom configuration
    pub fn with_config(
        network_component: Arc<NetworkComponent>,
        blockchain_arc: Arc<RwLock<Option<Blockchain>>>,
        environment: crate::config::Environment,
        config: RewardOrchestratorConfig,
    ) -> Self {
        // Create processor instances
        let routing_processor = Arc::new(RoutingRewardProcessor::with_config(
            network_component.clone(),
            blockchain_arc.clone(),
            environment.clone(),
            config.routing_config.clone(),
        ));
        
        let storage_processor = Arc::new(StorageRewardProcessor::with_config(
            network_component.clone(),
            blockchain_arc.clone(),
            environment.clone(),
            config.storage_config.clone(),
        ));
        
        // Create rate limiter
        let rate_limiter = Arc::new(RwLock::new(RateLimiter::new(
            config.cooldown_period_secs,
            config.max_claims_per_hour,
        )));
        
        Self {
            network_component,
            blockchain_arc,
            environment,
            config,
            routing_processor,
            storage_processor,
            rate_limiter,
            routing_handle: Arc::new(RwLock::new(None)),
            storage_handle: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Start all enabled reward processors
    /// 
    /// Starts routing and/or storage processors based on configuration.
    /// Returns immediately if processors are already running.
    pub async fn start_all(&self) -> Result<()> {
        info!("═══════════════════════════════════════════════════════");
        info!(" Starting Unified Reward Orchestrator");
        info!("═══════════════════════════════════════════════════════");
        info!("   Routing rewards: {}", if self.config.enable_routing_rewards { "ENABLED" } else { "DISABLED" });
        info!("   Storage rewards: {}", if self.config.enable_storage_rewards { "ENABLED" } else { "DISABLED" });
        info!("═══════════════════════════════════════════════════════");
        
        let mut started_count = 0;
        
        // Start routing processor if enabled
        if self.config.enable_routing_rewards {
            if self.routing_handle.read().await.is_some() {
                warn!("Routing reward processor already running");
            } else {
                let handle = self.routing_processor.clone().start();
                *self.routing_handle.write().await = Some(handle);
                info!(" Routing reward processor started");
                started_count += 1;
            }
        } else {
            info!("  Routing rewards disabled");
        }
        
        // Start storage processor if enabled
        if self.config.enable_storage_rewards {
            if self.storage_handle.read().await.is_some() {
                warn!("Storage reward processor already running");
            } else {
                let handle = self.storage_processor.clone().start();
                *self.storage_handle.write().await = Some(handle);
                info!(" Storage reward processor started");
                started_count += 1;
            }
        } else {
            info!("  Storage rewards disabled");
        }
        
        info!("═══════════════════════════════════════════════════════");
        info!(" Reward Orchestrator Started: {} processor(s) active", started_count);
        info!("═══════════════════════════════════════════════════════");
        
        Ok(())
    }
    
    /// Stop all reward processors
    /// 
    /// Gracefully stops all running processors.
    pub async fn stop_all(&self) -> Result<()> {
        info!("Stopping unified reward orchestrator...");
        
        let mut stopped_count = 0;
        
        // Stop routing processor
        if let Some(handle) = self.routing_handle.write().await.take() {
            info!("Stopping routing reward processor...");
            handle.abort();
            stopped_count += 1;
        }
        
        // Stop storage processor
        if let Some(handle) = self.storage_handle.write().await.take() {
            info!("Stopping storage reward processor...");
            handle.abort();
            stopped_count += 1;
        }
        
        info!(" Reward orchestrator stopped: {} processor(s) terminated", stopped_count);
        Ok(())
    }
    
    /// Get combined metrics from both processors
    /// 
    /// Returns aggregated metrics showing total pending rewards and activity
    /// across both routing and storage.
    pub async fn get_combined_metrics(&self) -> CombinedRewardMetrics {
        let routing_metrics = self.routing_processor.get_metrics().await;
        let storage_metrics = self.storage_processor.get_metrics().await;
        
        let total = routing_metrics.pending_rewards + storage_metrics.pending_rewards;
        
        CombinedRewardMetrics {
            routing: routing_metrics,
            storage: storage_metrics,
            total_pending_rewards: total,
        }
    }
    
    /// Get current configuration
    pub fn get_config(&self) -> &RewardOrchestratorConfig {
        &self.config
    }
    
    /// Check if routing processor is running
    pub async fn is_routing_running(&self) -> bool {
        self.routing_handle.read().await.is_some()
    }
    
    /// Check if storage processor is running
    pub async fn is_storage_running(&self) -> bool {
        self.storage_handle.read().await.is_some()
    }
    
    /// Get status summary
    pub async fn get_status(&self) -> RewardOrchestratorStatus {
        RewardOrchestratorStatus {
            routing_enabled: self.config.enable_routing_rewards,
            storage_enabled: self.config.enable_storage_rewards,
            routing_running: self.is_routing_running().await,
            storage_running: self.is_storage_running().await,
        }
    }
}

/// Combined metrics from both processors
#[derive(Debug, Clone)]
pub struct CombinedRewardMetrics {
    /// Routing reward metrics
    pub routing: RoutingRewardMetrics,
    /// Storage reward metrics
    pub storage: StorageRewardMetrics,
    /// Total pending rewards across both
    pub total_pending_rewards: u64,
}

impl RewardOrchestrator {
    /// Check if a reward claim is allowed (for rate limiting)
    /// 
    /// This method should be called by processors before claiming rewards.
    /// Returns Ok(()) if claim is allowed, Err with reason if not.
    pub async fn check_rate_limit(&self, processor_id: &str) -> Result<()> {
        let mut rate_limiter = self.rate_limiter.write().await;
        rate_limiter.can_claim(processor_id)
    }
    
    /// Record a successful reward claim (for rate limiting)
    /// 
    /// This method should be called by processors after successfully claiming rewards.
    pub async fn record_claim(&self, processor_id: &str) {
        let mut rate_limiter = self.rate_limiter.write().await;
        rate_limiter.record_claim(processor_id);
        info!(" Rate limit: Claim recorded for {}", processor_id);
    }
    
    /// Get rate limit statistics for a processor
    pub async fn get_rate_limit_stats(&self, processor_id: &str) -> RateLimitStats {
        let rate_limiter = self.rate_limiter.read().await;
        rate_limiter.get_stats(processor_id)
    }
    
    /// Get rate limit statistics for all processors
    pub async fn get_all_rate_limit_stats(&self) -> AllRateLimitStats {
        AllRateLimitStats {
            routing: self.get_rate_limit_stats("routing").await,
            storage: self.get_rate_limit_stats("storage").await,
        }
    }
}

/// Combined rate limit statistics
#[derive(Debug, Clone)]
pub struct AllRateLimitStats {
    pub routing: RateLimitStats,
    pub storage: RateLimitStats,
}

/// Status of the reward orchestrator
#[derive(Debug, Clone)]
pub struct RewardOrchestratorStatus {
    /// Whether routing rewards are enabled
    pub routing_enabled: bool,
    /// Whether storage rewards are enabled
    pub storage_enabled: bool,
    /// Whether routing processor is currently running
    pub routing_running: bool,
    /// Whether storage processor is currently running
    pub storage_running: bool,
}

impl RewardOrchestratorStatus {
    /// Check if orchestrator is fully operational
    pub fn is_fully_operational(&self) -> bool {
        (self.routing_enabled == self.routing_running) &&
        (self.storage_enabled == self.storage_running)
    }
    
    /// Get human-readable status description
    pub fn description(&self) -> String {
        let routing_status = match (self.routing_enabled, self.routing_running) {
            (true, true) => "Running",
            (true, false) => "Enabled but not running",
            (false, _) => "Disabled",
        };
        
        let storage_status = match (self.storage_enabled, self.storage_running) {
            (true, true) => "Running",
            (true, false) => "Enabled but not running",
            (false, _) => "Disabled",
        };
        
        format!("Routing: {}, Storage: {}", routing_status, storage_status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = RewardOrchestratorConfig::default();
        assert!(config.enable_routing_rewards);
        assert!(config.enable_storage_rewards);
        assert_eq!(config.routing_config.check_interval.as_secs(), 600);
        assert_eq!(config.storage_config.check_interval.as_secs(), 600);
    }
    
    #[test]
    fn test_status_description() {
        let status = RewardOrchestratorStatus {
            routing_enabled: true,
            storage_enabled: true,
            routing_running: true,
            storage_running: true,
        };
        assert!(status.is_fully_operational());
        assert_eq!(status.description(), "Routing: Running, Storage: Running");
        
        let partial_status = RewardOrchestratorStatus {
            routing_enabled: true,
            storage_enabled: false,
            routing_running: true,
            storage_running: false,
        };
        assert!(partial_status.is_fully_operational());
        assert_eq!(partial_status.description(), "Routing: Running, Storage: Disabled");
    }
    
    // TODO: Add integration tests with mock components
}
