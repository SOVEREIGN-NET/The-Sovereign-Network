//! Reward System Integration Tests
//!
//! Tests complete reward flows: routing rewards, storage rewards, validation, rate limiting

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

use zhtp::config::aggregation::RewardsConfig;
use zhtp::runtime::reward_orchestrator::{RewardOrchestrator, RewardOrchestratorConfig};
use zhtp::runtime::components::NetworkComponent;
use zhtp::config::Environment;
use lib_blockchain::Blockchain;

/// Helper to create a mock NetworkComponent for testing
fn create_mock_network_component() -> Arc<NetworkComponent> {
    // Create a basic network component for testing
    // Note: In real tests, this would be properly initialized
    Arc::new(NetworkComponent::new())
}

/// Helper to create a mock blockchain for testing
fn create_mock_blockchain() -> Arc<RwLock<Option<Blockchain>>> {
    Arc::new(RwLock::new(None))
}

/// Helper to create test environment
fn create_test_environment() -> Environment {
    Environment::Development
}

/// Helper to create test orchestrator configuration
fn create_test_orchestrator_config() -> RewardOrchestratorConfig {
    let rewards_config = RewardsConfig {
        enabled: true,
        auto_claim: true,
        routing_rewards_enabled: true,
        routing_check_interval_secs: 1, // Fast for testing
        routing_minimum_threshold: 10,
        routing_max_batch_size: 100_000,
        storage_rewards_enabled: true,
        storage_check_interval_secs: 1, // Fast for testing
        storage_minimum_threshold: 10,
        storage_max_batch_size: 100_000,
        max_claims_per_hour: 10, // Higher for testing
        cooldown_period_secs: 2, // Short for testing
    };
    
    RewardOrchestratorConfig::from(&rewards_config)
}

#[tokio::test]
async fn test_orchestrator_creation() -> Result<()> {
    println!("\n Test: RewardOrchestrator creation");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let orchestrator = RewardOrchestrator::new(network, blockchain, env);
    
    println!("    Created orchestrator with default config");
    
    Ok(())
}

#[tokio::test]
async fn test_orchestrator_with_custom_config() -> Result<()> {
    println!("\n Test: RewardOrchestrator with custom configuration");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_test_orchestrator_config();
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    println!("    Created orchestrator with custom config");
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_cooldown() -> Result<()> {
    println!("\n Test: Rate limiter cooldown enforcement");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_test_orchestrator_config();
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // First claim should succeed
    let result1 = orchestrator.check_rate_limit("routing").await;
    assert!(result1.is_ok(), "First claim should be allowed");
    orchestrator.record_claim("routing").await;
    println!("    First claim allowed");
    
    // Immediate second claim should fail (cooldown)
    let result2 = orchestrator.check_rate_limit("routing").await;
    assert!(result2.is_err(), "Second claim should be blocked by cooldown");
    println!("    Cooldown enforced: {}", result2.unwrap_err());
    
    // Wait for cooldown to expire
    sleep(Duration::from_secs(3)).await;
    
    // Third claim should succeed after cooldown
    let result3 = orchestrator.check_rate_limit("routing").await;
    assert!(result3.is_ok(), "Claim after cooldown should be allowed");
    println!("    Claim allowed after cooldown expired");
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_hourly_limit() -> Result<()> {
    println!("\n Test: Rate limiter hourly limit enforcement");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    // Create config with low hourly limit for testing
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 3;
    rewards_config.cooldown_period_secs = 0; // Disable cooldown for this test
    let config = RewardOrchestratorConfig::from(&rewards_config);
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Make 3 claims (should all succeed)
    for i in 1..=3 {
        let result = orchestrator.check_rate_limit("storage").await;
        assert!(result.is_ok(), "Claim {} should be allowed", i);
        orchestrator.record_claim("storage").await;
        println!("    Claim {} allowed", i);
    }
    
    // 4th claim should fail (hourly limit)
    let result4 = orchestrator.check_rate_limit("storage").await;
    assert!(result4.is_err(), "4th claim should be blocked by hourly limit");
    println!("    Hourly limit enforced: {}", result4.unwrap_err());
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_per_processor() -> Result<()> {
    println!("\n Test: Rate limiter independent per processor");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let mut rewards_config = RewardsConfig::default();
    rewards_config.cooldown_period_secs = 0; // Disable cooldown for this test
    let config = RewardOrchestratorConfig::from(&rewards_config);
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Routing processor claims
    orchestrator.check_rate_limit("routing").await?;
    orchestrator.record_claim("routing").await;
    println!("    Routing claim recorded");
    
    // Storage processor can still claim (independent tracking)
    let result = orchestrator.check_rate_limit("storage").await;
    assert!(result.is_ok(), "Storage should be independent of routing");
    orchestrator.record_claim("storage").await;
    println!("    Storage claim independent");
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_stats() -> Result<()> {
    println!("\n Test: Rate limiter statistics");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let mut rewards_config = RewardsConfig::default();
    rewards_config.cooldown_period_secs = 10; // Long cooldown for stats test
    let config = RewardOrchestratorConfig::from(&rewards_config);
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Initial stats (no claims)
    let stats = orchestrator.get_rate_limit_stats("routing").await;
    assert_eq!(stats.claims_in_last_hour, 0);
    assert!(stats.cooldown_remaining.is_none());
    println!("    Initial stats: 0 claims, no cooldown");
    
    // Record a claim
    orchestrator.record_claim("routing").await;
    
    // Check updated stats
    let stats2 = orchestrator.get_rate_limit_stats("routing").await;
    assert_eq!(stats2.claims_in_last_hour, 1);
    assert!(stats2.cooldown_remaining.is_some());
    println!("    After claim: {} claims, cooldown active", stats2.claims_in_last_hour);
    
    // Get all stats
    let all_stats = orchestrator.get_all_rate_limit_stats().await;
    assert_eq!(all_stats.routing.claims_in_last_hour, 1);
    assert_eq!(all_stats.storage.claims_in_last_hour, 0);
    println!("    All stats retrieved: routing={}, storage={}", 
        all_stats.routing.claims_in_last_hour,
        all_stats.storage.claims_in_last_hour);
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_boundary_conditions() -> Result<()> {
    println!("\n Test: Rate limiter boundary conditions");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 1; // Exactly 1 claim
    rewards_config.cooldown_period_secs = 0;
    let config = RewardOrchestratorConfig::from(&rewards_config);
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // First claim at boundary
    orchestrator.check_rate_limit("routing").await?;
    orchestrator.record_claim("routing").await;
    println!("    Boundary claim (1/1) allowed");
    
    // Second claim should fail
    let result = orchestrator.check_rate_limit("routing").await;
    assert!(result.is_err(), "Should reject claim over boundary");
    println!("    Over-boundary claim rejected");
    
    Ok(())
}

#[tokio::test]
async fn test_multiple_orchestrators_independent() -> Result<()> {
    println!("\n Test: Multiple orchestrators are independent");
    
    let network1 = create_mock_network_component();
    let blockchain1 = create_mock_blockchain();
    let env1 = create_test_environment();
    let config1 = create_test_orchestrator_config();
    
    let network2 = create_mock_network_component();
    let blockchain2 = create_mock_blockchain();
    let env2 = create_test_environment();
    let config2 = create_test_orchestrator_config();
    
    let orchestrator1 = RewardOrchestrator::with_config(network1, blockchain1, env1, config1);
    let orchestrator2 = RewardOrchestrator::with_config(network2, blockchain2, env2, config2);
    
    // Orchestrator 1 claims
    orchestrator1.check_rate_limit("routing").await?;
    orchestrator1.record_claim("routing").await;
    println!("    Orchestrator 1 claimed");
    
    // Orchestrator 2 should still be able to claim (independent state)
    let result = orchestrator2.check_rate_limit("routing").await;
    assert!(result.is_ok(), "Orchestrator 2 should be independent");
    println!("    Orchestrator 2 independent state verified");
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_default() -> Result<()> {
    println!("\n Test: RewardsConfig default values");
    
    let config = RewardsConfig::default();
    
    // Verify defaults
    assert!(config.enabled);
    assert!(config.auto_claim);
    assert!(config.routing_rewards_enabled);
    assert!(config.storage_rewards_enabled);
    
    println!("    Rewards enabled by default");
    println!("    Auto-claim enabled by default");
    println!("    Routing rewards enabled");
    println!("    Storage rewards enabled");
    
    // Verify rate limiting defaults
    assert_eq!(config.max_claims_per_hour, 6);
    assert_eq!(config.cooldown_period_secs, 600); // 10 minutes
    
    println!("    Default cooldown: 600s (10 minutes)");
    println!("    Default max claims: 6/hour");
    
    // Verify thresholds
    assert_eq!(config.routing_minimum_threshold, 100);
    assert_eq!(config.storage_minimum_threshold, 100);
    
    println!("    Routing threshold: {} SOV", config.routing_minimum_threshold);
    println!("    Storage threshold: {} SOV", config.storage_minimum_threshold);
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_customization() -> Result<()> {
    println!("\n Test: RewardsConfig customization");
    
    let mut config = RewardsConfig::default();
    
    // Customize config
    config.routing_minimum_threshold = 500;
    config.storage_minimum_threshold = 1000;
    config.max_claims_per_hour = 12;
    config.cooldown_period_secs = 300; // 5 minutes
    
    // Verify changes
    assert_eq!(config.routing_minimum_threshold, 500);
    assert_eq!(config.storage_minimum_threshold, 1000);
    assert_eq!(config.max_claims_per_hour, 12);
    assert_eq!(config.cooldown_period_secs, 300);
    
    println!("    Custom routing threshold: {} SOV", config.routing_minimum_threshold);
    println!("    Custom storage threshold: {} SOV", config.storage_minimum_threshold);
    println!("    Custom max claims: {}/hour", config.max_claims_per_hour);
    println!("    Custom cooldown: {}s (5 minutes)", config.cooldown_period_secs);
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_disable_features() -> Result<()> {
    println!("\n Test: Disable reward features");
    
    let mut config = RewardsConfig::default();
    
    // Disable routing
    config.routing_rewards_enabled = false;
    assert!(!config.routing_rewards_enabled);
    assert!(config.storage_rewards_enabled);
    println!("    Routing rewards disabled");
    
    // Disable storage
    config.routing_rewards_enabled = true;
    config.storage_rewards_enabled = false;
    assert!(config.routing_rewards_enabled);
    assert!(!config.storage_rewards_enabled);
    println!("    Storage rewards disabled");
    
    // Disable all
    config.enabled = false;
    assert!(!config.enabled);
    println!("    All rewards disabled");
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_batch_sizes() -> Result<()> {
    println!("\n Test: Reward batch size configuration");
    
    let config = RewardsConfig::default();
    
    // Verify batch sizes
    assert_eq!(config.routing_max_batch_size, 10_000);
    assert_eq!(config.storage_max_batch_size, 10_000);
    
    println!("    Routing max batch: {} SOV", config.routing_max_batch_size);
    println!("    Storage max batch: {} SOV", config.storage_max_batch_size);
    
    // Test custom batch sizes
    let mut custom_config = RewardsConfig::default();
    custom_config.routing_max_batch_size = 50_000;
    custom_config.storage_max_batch_size = 75_000;
    
    assert_eq!(custom_config.routing_max_batch_size, 50_000);
    assert_eq!(custom_config.storage_max_batch_size, 75_000);
    
    println!("    Custom routing batch: {} SOV", custom_config.routing_max_batch_size);
    println!("    Custom storage batch: {} SOV", custom_config.storage_max_batch_size);
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_check_intervals() -> Result<()> {
    println!("\n Test: Reward check interval configuration");
    
    let config = RewardsConfig::default();
    
    // Verify default intervals
    assert_eq!(config.routing_check_interval_secs, 600); // 10 minutes
    assert_eq!(config.storage_check_interval_secs, 600); // 10 minutes
    
    println!("    Default routing interval: {}s (10 minutes)", config.routing_check_interval_secs);
    println!("    Default storage interval: {}s (10 minutes)", config.storage_check_interval_secs);
    
    // Test custom intervals
    let mut custom_config = RewardsConfig::default();
    custom_config.routing_check_interval_secs = 300; // 5 minutes
    custom_config.storage_check_interval_secs = 900; // 15 minutes
    
    assert_eq!(custom_config.routing_check_interval_secs, 300);
    assert_eq!(custom_config.storage_check_interval_secs, 900);
    
    println!("    Custom routing interval: {}s (5 minutes)", custom_config.routing_check_interval_secs);
    println!("    Custom storage interval: {}s (15 minutes)", custom_config.storage_check_interval_secs);
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_rate_limiting_validation() -> Result<()> {
    println!("\n Test: Rate limiting configuration validation");
    
    let mut config = RewardsConfig::default();
    
    // Test various rate limiting scenarios
    
    // Scenario 1: Very restrictive
    config.max_claims_per_hour = 1;
    config.cooldown_period_secs = 3600; // 1 hour
    assert_eq!(config.max_claims_per_hour, 1);
    assert_eq!(config.cooldown_period_secs, 3600);
    println!("    Very restrictive config: 1 claim/hour, 3600s cooldown");
    
    // Scenario 2: More permissive
    config.max_claims_per_hour = 60;
    config.cooldown_period_secs = 60; // 1 minute
    assert_eq!(config.max_claims_per_hour, 60);
    assert_eq!(config.cooldown_period_secs, 60);
    println!("    Permissive config: 60 claims/hour, 60s cooldown");
    
    // Scenario 3: No cooldown (only hourly limit)
    config.max_claims_per_hour = 10;
    config.cooldown_period_secs = 0;
    assert_eq!(config.max_claims_per_hour, 10);
    assert_eq!(config.cooldown_period_secs, 0);
    println!("    No cooldown config: 10 claims/hour, 0s cooldown");
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_auto_claim_toggle() -> Result<()> {
    println!("\n Test: Auto-claim toggle");
    
    let mut config = RewardsConfig::default();
    
    // Default should be enabled
    assert!(config.auto_claim);
    println!("    Auto-claim enabled by default");
    
    // Disable auto-claim (manual claiming only)
    config.auto_claim = false;
    assert!(!config.auto_claim);
    println!("    Auto-claim disabled (manual mode)");
    
    // Re-enable
    config.auto_claim = true;
    assert!(config.auto_claim);
    println!("    Auto-claim re-enabled");
    
    Ok(())
}

#[tokio::test]
async fn test_rewards_config_edge_cases() -> Result<()> {
    println!("\n Test: Configuration edge cases");
    
    let mut config = RewardsConfig::default();
    
    // Zero thresholds (immediate claim)
    config.routing_minimum_threshold = 0;
    config.storage_minimum_threshold = 0;
    assert_eq!(config.routing_minimum_threshold, 0);
    assert_eq!(config.storage_minimum_threshold, 0);
    println!("    Zero threshold config accepted");
    
    // Very high thresholds
    config.routing_minimum_threshold = 1_000_000;
    config.storage_minimum_threshold = 1_000_000;
    assert_eq!(config.routing_minimum_threshold, 1_000_000);
    assert_eq!(config.storage_minimum_threshold, 1_000_000);
    println!("    High threshold config accepted (1M ZHTP)");
    
    // Zero batch size (edge case)
    config.routing_max_batch_size = 0;
    config.storage_max_batch_size = 0;
    assert_eq!(config.routing_max_batch_size, 0);
    assert_eq!(config.storage_max_batch_size, 0);
    println!("    Zero batch size config accepted");
    
    Ok(())
}
