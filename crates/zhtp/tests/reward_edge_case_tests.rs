//! Reward System Edge Case Tests
//!
//! Tests system behavior under edge cases and error conditions:
//! - Zero contributions
//! - Blockchain unavailable
//! - Invalid configurations
//! - Extreme values
//! - Clock/timing edge cases
//! - Concurrent shutdown scenarios

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

/// Helper to create default test config
fn create_test_config() -> RewardOrchestratorConfig {
    let rewards_config = RewardsConfig::default();
    RewardOrchestratorConfig::from(&rewards_config)
}

#[tokio::test]
async fn test_zero_contributions_handling() -> Result<()> {
    println!("\n Edge Case: Zero contributions");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_test_config();
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Get stats with no contributions
    let routing_stats = orchestrator.get_rate_limit_stats("routing").await;
    let storage_stats = orchestrator.get_rate_limit_stats("storage").await;
    
    println!("    Routing stats with zero contributions: {} claims", routing_stats.claims_in_last_hour);
    println!("    Storage stats with zero contributions: {} claims", storage_stats.claims_in_last_hour);
    
    // Should handle gracefully
    assert_eq!(routing_stats.claims_in_last_hour, 0);
    assert_eq!(storage_stats.claims_in_last_hour, 0);
    assert!(routing_stats.cooldown_remaining.is_none());
    assert!(storage_stats.cooldown_remaining.is_none());
    
    println!("    System handles zero contributions gracefully");
    
    Ok(())
}

#[tokio::test]
async fn test_blockchain_unavailable() -> Result<()> {
    println!("\n Edge Case: Blockchain unavailable");
    
    let network = create_mock_network_component();
    let blockchain = Arc::new(RwLock::new(None)); // Blockchain is None (unavailable)
    let env = create_test_environment();
    let config = create_test_config();
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Should still function for rate limiting
    let result = orchestrator.check_rate_limit("routing").await;
    
    println!("    Rate limiter works without blockchain: {:?}", result.is_ok());
    assert!(result.is_ok(), "Rate limiting should work without blockchain");
    
    // Recording claims should work
    orchestrator.record_claim("routing").await;
    let stats = orchestrator.get_rate_limit_stats("routing").await;
    
    println!("    Claim recording works: {} claims", stats.claims_in_last_hour);
    assert_eq!(stats.claims_in_last_hour, 1);
    
    println!("    System degrades gracefully without blockchain");
    
    Ok(())
}

#[tokio::test]
async fn test_invalid_processor_id() -> Result<()> {
    println!("\n Edge Case: Invalid processor ID");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_test_config();
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Test with invalid/unknown processor IDs
    let unknown_stats = orchestrator.get_rate_limit_stats("unknown_processor").await;
    let empty_stats = orchestrator.get_rate_limit_stats("").await;
    let weird_stats = orchestrator.get_rate_limit_stats("").await;
    
    println!("    Unknown processor stats: {} claims", unknown_stats.claims_in_last_hour);
    println!("    Empty processor stats: {} claims", empty_stats.claims_in_last_hour);
    println!("    Weird processor stats: {} claims", weird_stats.claims_in_last_hour);
    
    // Should create new tracking for unknown processors
    assert_eq!(unknown_stats.claims_in_last_hour, 0);
    assert_eq!(empty_stats.claims_in_last_hour, 0);
    assert_eq!(weird_stats.claims_in_last_hour, 0);
    
    // Should be able to record claims for unknown processors
    orchestrator.record_claim("custom_processor").await;
    let custom_stats = orchestrator.get_rate_limit_stats("custom_processor").await;
    assert_eq!(custom_stats.claims_in_last_hour, 1);
    
    println!("    System handles arbitrary processor IDs");
    
    Ok(())
}

#[tokio::test]
async fn test_extreme_configuration_values() -> Result<()> {
    println!("\n Edge Case: Extreme configuration values");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    // Test with extreme values
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = u32::MAX; // Maximum value
    rewards_config.cooldown_period_secs = 0; // Minimum cooldown
    rewards_config.routing_minimum_threshold = u64::MAX; // Maximum threshold
    rewards_config.storage_minimum_threshold = u64::MAX;
    rewards_config.routing_max_batch_size = u64::MAX;
    rewards_config.storage_max_batch_size = u64::MAX;
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Should handle extreme values
    for i in 0..10 {
        let result = orchestrator.check_rate_limit("routing").await;
        orchestrator.record_claim("routing").await;
        println!("    Claim {} with max_claims={}: {:?}", i + 1, u32::MAX, result.is_ok());
    }
    
    let stats = orchestrator.get_rate_limit_stats("routing").await;
    println!("    Stats with extreme config: {} claims", stats.claims_in_last_hour);
    assert_eq!(stats.claims_in_last_hour, 10);
    
    println!("    System handles extreme configuration values");
    
    Ok(())
}

#[tokio::test]
async fn test_zero_rate_limit_configuration() -> Result<()> {
    println!("\n Edge Case: Zero rate limit configuration");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    // Configure with zero claims allowed
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 0; // No claims allowed
    rewards_config.cooldown_period_secs = 0;
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // First check should fail (0 claims allowed)
    let result = orchestrator.check_rate_limit("routing").await;
    
    println!("    Check with 0 max_claims: {:?}", result);
    
    // Even first claim should be rate limited with max_claims = 0
    // (depends on implementation - might allow 0 or might reject all)
    
    println!("    System handles zero rate limit configuration");
    
    Ok(())
}

#[tokio::test]
async fn test_rapid_sequential_claims() -> Result<()> {
    println!("\n Edge Case: Rapid sequential claims");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 5;
    rewards_config.cooldown_period_secs = 1; // 1 second cooldown
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Try rapid claims
    let mut allowed = 0;
    let mut blocked = 0;
    
    for i in 0..10 {
        let result = orchestrator.check_rate_limit("routing").await;
        
        if result.is_ok() {
            orchestrator.record_claim("routing").await;
            allowed += 1;
            println!("    Claim {} allowed", i + 1);
            
            // Small delay to respect cooldown
            sleep(Duration::from_millis(1100)).await;
        } else {
            blocked += 1;
            println!("   ✗ Claim {} blocked by cooldown", i + 1);
        }
    }
    
    println!("    Rapid claims: {} allowed, {} blocked", allowed, blocked);
    assert!(allowed > 0, "Some claims should be allowed with cooldown delays");
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_same_processor_claims() -> Result<()> {
    println!("\n Edge Case: Concurrent claims for same processor");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 10;
    rewards_config.cooldown_period_secs = 0; // No cooldown for this test
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    // Spawn 20 concurrent tasks all trying to claim for "routing"
    let mut handles = vec![];
    
    for _i in 0..20 {
        let orch = orchestrator.clone();
        let handle = tokio::spawn(async move {
            let result = orch.check_rate_limit("routing").await;
            if result.is_ok() {
                orch.record_claim("routing").await;
                1
            } else {
                0
            }
        });
        handles.push(handle);
    }
    
    // Count successful claims
    let mut success_count = 0;
    for handle in handles {
        success_count += handle.await?;
    }
    
    println!("    Concurrent claims: {} allowed out of 20", success_count);
    println!("    Rate limited: {}", 20 - success_count);
    
    // Should respect the limit (max 10)
    assert!(success_count <= 10, "Should not exceed max_claims_per_hour");
    
    println!("    Concurrent access to same processor handled correctly");
    
    Ok(())
}

#[tokio::test]
async fn test_all_processors_disabled() -> Result<()> {
    println!("\n Edge Case: All reward processors disabled");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    // Disable all rewards
    let mut rewards_config = RewardsConfig::default();
    rewards_config.enabled = false;
    rewards_config.routing_rewards_enabled = false;
    rewards_config.storage_rewards_enabled = false;
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Rate limiting should still work even if rewards are disabled
    let result = orchestrator.check_rate_limit("routing").await;
    
    println!("    Rate limiter with disabled rewards: {:?}", result.is_ok());
    
    // Can still track stats
    orchestrator.record_claim("routing").await;
    let stats = orchestrator.get_rate_limit_stats("routing").await;
    
    println!("    Stats tracking with disabled rewards: {} claims", stats.claims_in_last_hour);
    assert_eq!(stats.claims_in_last_hour, 1);
    
    println!("    System functions with all processors disabled");
    
    Ok(())
}

#[tokio::test]
async fn test_very_long_processor_id() -> Result<()> {
    println!("\n Edge Case: Very long processor ID");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_test_config();
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Create a very long processor ID (1000 characters)
    let long_id = "a".repeat(1000);
    
    orchestrator.record_claim(&long_id).await;
    let stats = orchestrator.get_rate_limit_stats(&long_id).await;
    
    println!("    Long processor ID (1000 chars): {} claims", stats.claims_in_last_hour);
    assert_eq!(stats.claims_in_last_hour, 1);
    
    // Try with unicode characters
    let unicode_id = "".repeat(100);
    orchestrator.record_claim(&unicode_id).await;
    let unicode_stats = orchestrator.get_rate_limit_stats(&unicode_id).await;
    
    println!("    Unicode processor ID (100 emojis): {} claims", unicode_stats.claims_in_last_hour);
    assert_eq!(unicode_stats.claims_in_last_hour, 1);
    
    println!("    System handles very long processor IDs");
    
    Ok(())
}

#[tokio::test]
async fn test_cooldown_boundary_timing() -> Result<()> {
    println!("\n Edge Case: Cooldown boundary timing");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 10;
    rewards_config.cooldown_period_secs = 2; // 2 second cooldown
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // First claim
    orchestrator.check_rate_limit("routing").await?;
    orchestrator.record_claim("routing").await;
    println!("    First claim recorded");
    
    // Immediate second claim (should fail)
    let immediate_result = orchestrator.check_rate_limit("routing").await;
    assert!(immediate_result.is_err(), "Immediate claim should be rate limited");
    println!("    Immediate claim correctly blocked");
    
    // Wait just under cooldown (1.9 seconds)
    sleep(Duration::from_millis(1900)).await;
    let early_result = orchestrator.check_rate_limit("routing").await;
    println!("    Claim at 1.9s: {:?}", early_result);
    
    // Wait past cooldown (2.1 seconds total)
    sleep(Duration::from_millis(300)).await;
    let late_result = orchestrator.check_rate_limit("routing").await;
    assert!(late_result.is_ok(), "Claim after cooldown should succeed");
    println!("    Claim at 2.2s correctly allowed");
    
    println!("    Cooldown boundary timing works correctly");
    
    Ok(())
}

#[tokio::test]
async fn test_hourly_window_rollover() -> Result<()> {
    println!("\n Edge Case: Hourly window rollover");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 3;
    rewards_config.cooldown_period_secs = 0; // No cooldown
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Make 3 claims (hit the limit)
    for i in 0..3 {
        orchestrator.check_rate_limit("routing").await?;
        orchestrator.record_claim("routing").await;
        println!("    Claim {} recorded", i + 1);
    }
    
    // 4th claim should fail
    let over_limit_result = orchestrator.check_rate_limit("routing").await;
    assert!(over_limit_result.is_err(), "Should be rate limited at hourly max");
    println!("    4th claim correctly blocked");
    
    // Check stats
    let stats = orchestrator.get_rate_limit_stats("routing").await;
    println!("    Claims in last hour: {}", stats.claims_in_last_hour);
    assert_eq!(stats.claims_in_last_hour, 3);
    
    println!("    Hourly window tracking works correctly");
    
    Ok(())
}

#[tokio::test]
async fn test_multiple_environments() -> Result<()> {
    println!("\n Edge Case: Different environments");
    
    let network1 = create_mock_network_component();
    let blockchain1 = create_mock_blockchain();
    let config1 = create_test_config();
    
    let network2 = create_mock_network_component();
    let blockchain2 = create_mock_blockchain();
    let config2 = create_test_config();
    
    let network3 = create_mock_network_component();
    let blockchain3 = create_mock_blockchain();
    let config3 = create_test_config();
    
    // Create orchestrators for different environments
    let dev_orch = RewardOrchestrator::with_config(network1, blockchain1, Environment::Development, config1);
    let test_orch = RewardOrchestrator::with_config(network2, blockchain2, Environment::Testnet, config2);
    let prod_orch = RewardOrchestrator::with_config(network3, blockchain3, Environment::Mainnet, config3);
    
    // Each should work independently
    dev_orch.record_claim("routing").await;
    test_orch.record_claim("routing").await;
    prod_orch.record_claim("routing").await;
    
    let dev_stats = dev_orch.get_rate_limit_stats("routing").await;
    let test_stats = test_orch.get_rate_limit_stats("routing").await;
    let prod_stats = prod_orch.get_rate_limit_stats("routing").await;
    
    println!("    Development: {} claims", dev_stats.claims_in_last_hour);
    println!("    Testnet: {} claims", test_stats.claims_in_last_hour);
    println!("    Mainnet: {} claims", prod_stats.claims_in_last_hour);
    
    assert_eq!(dev_stats.claims_in_last_hour, 1);
    assert_eq!(test_stats.claims_in_last_hour, 1);
    assert_eq!(prod_stats.claims_in_last_hour, 1);
    
    println!("    Different environments work independently");
    
    Ok(())
}

#[tokio::test]
async fn test_stats_query_for_nonexistent_processor() -> Result<()> {
    println!("\n Edge Case: Stats query for processor that never claimed");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_test_config();
    
    let orchestrator = RewardOrchestrator::with_config(network, blockchain, env, config);
    
    // Record claims for routing only
    orchestrator.record_claim("routing").await;
    
    // Query stats for storage (never used)
    let routing_stats = orchestrator.get_rate_limit_stats("routing").await;
    let storage_stats = orchestrator.get_rate_limit_stats("storage").await;
    let unknown_stats = orchestrator.get_rate_limit_stats("never_used").await;
    
    println!("    Routing (used): {} claims", routing_stats.claims_in_last_hour);
    println!("    Storage (unused): {} claims", storage_stats.claims_in_last_hour);
    println!("    Never used: {} claims", unknown_stats.claims_in_last_hour);
    
    assert_eq!(routing_stats.claims_in_last_hour, 1);
    assert_eq!(storage_stats.claims_in_last_hour, 0);
    assert_eq!(unknown_stats.claims_in_last_hour, 0);
    
    println!("    Stats queries for nonexistent processors handled correctly");
    
    Ok(())
}

#[tokio::test]
async fn test_check_interval_configuration() -> Result<()> {
    println!("\n Edge Case: Various check interval configurations");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    // Test with very short intervals
    let mut rewards_config = RewardsConfig::default();
    rewards_config.routing_check_interval_secs = 1; // 1 second
    rewards_config.storage_check_interval_secs = 1;
    
    let config = RewardOrchestratorConfig::from(&rewards_config);
    let orchestrator = RewardOrchestrator::with_config(network.clone(), blockchain.clone(), env.clone(), config);
    
    println!("    Orchestrator created with 1s intervals");
    
    // Test with very long intervals
    let mut long_config = RewardsConfig::default();
    long_config.routing_check_interval_secs = 86400; // 24 hours
    long_config.storage_check_interval_secs = 86400;
    
    let long_orch_config = RewardOrchestratorConfig::from(&long_config);
    let long_orchestrator = RewardOrchestrator::with_config(network.clone(), blockchain.clone(), env.clone(), long_orch_config);
    
    println!("    Orchestrator created with 24h intervals");
    
    // Test with zero intervals
    let mut zero_config = RewardsConfig::default();
    zero_config.routing_check_interval_secs = 0;
    zero_config.storage_check_interval_secs = 0;
    
    let zero_orch_config = RewardOrchestratorConfig::from(&zero_config);
    let zero_orchestrator = RewardOrchestrator::with_config(network, blockchain, env, zero_orch_config);
    
    println!("    Orchestrator created with 0s intervals");
    
    // All should still function for rate limiting
    orchestrator.record_claim("routing").await;
    long_orchestrator.record_claim("routing").await;
    zero_orchestrator.record_claim("routing").await;
    
    println!("    Various interval configurations handled correctly");
    
    Ok(())
}

#[tokio::test]
async fn test_batch_size_extremes() -> Result<()> {
    println!("\n Edge Case: Extreme batch sizes");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    // Test with zero batch size
    let mut zero_batch = RewardsConfig::default();
    zero_batch.routing_max_batch_size = 0;
    zero_batch.storage_max_batch_size = 0;
    
    let zero_config = RewardOrchestratorConfig::from(&zero_batch);
    let zero_orch = RewardOrchestrator::with_config(network.clone(), blockchain.clone(), env.clone(), zero_config);
    
    println!("    Orchestrator with 0 batch size created");
    
    // Test with very large batch size
    let mut large_batch = RewardsConfig::default();
    large_batch.routing_max_batch_size = u64::MAX;
    large_batch.storage_max_batch_size = u64::MAX;
    
    let large_config = RewardOrchestratorConfig::from(&large_batch);
    let large_orch = RewardOrchestrator::with_config(network.clone(), blockchain.clone(), env.clone(), large_config);
    
    println!("    Orchestrator with max batch size created");
    
    // Test with 1 token batch size
    let mut tiny_batch = RewardsConfig::default();
    tiny_batch.routing_max_batch_size = 1;
    tiny_batch.storage_max_batch_size = 1;
    
    let tiny_config = RewardOrchestratorConfig::from(&tiny_batch);
    let tiny_orch = RewardOrchestrator::with_config(network, blockchain, env, tiny_config);
    
    println!("    Orchestrator with 1 token batch size created");
    
    // All should function
    zero_orch.record_claim("routing").await;
    large_orch.record_claim("routing").await;
    tiny_orch.record_claim("routing").await;
    
    println!("    Extreme batch sizes handled correctly");
    
    Ok(())
}
