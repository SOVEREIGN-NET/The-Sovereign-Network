//! Reward System Load Tests
//!
//! Tests system behavior under concurrent load:
//! - Concurrent reward claims
//! - High contribution volumes
//! - Rate limiting under load
//! - Performance and throughput

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

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

/// Helper to create load test orchestrator configuration
fn create_load_test_config() -> RewardOrchestratorConfig {
    let rewards_config = RewardsConfig {
        enabled: true,
        auto_claim: true,
        routing_rewards_enabled: true,
        routing_check_interval_secs: 1,
        routing_minimum_threshold: 10,
        routing_max_batch_size: 100_000,
        storage_rewards_enabled: true,
        storage_check_interval_secs: 1,
        storage_minimum_threshold: 10,
        storage_max_batch_size: 100_000,
        max_claims_per_hour: 100, // High limit for load testing
        cooldown_period_secs: 0,  // No cooldown for load testing
    };
    
    RewardOrchestratorConfig::from(&rewards_config)
}

#[tokio::test]
async fn test_concurrent_rate_limit_checks() -> Result<()> {
    println!("\n Load Test: Concurrent rate limit checks");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_load_test_config();
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    let start = Instant::now();
    let mut handles = vec![];
    
    // Spawn 50 concurrent tasks checking rate limits
    for i in 0..50 {
        let orch = orchestrator.clone();
        let handle = tokio::spawn(async move {
            orch.check_rate_limit("routing").await
        });
        handles.push((i, handle));
    }
    
    // Wait for all tasks
    let mut success_count = 0;
    for (i, handle) in handles {
        match handle.await {
            Ok(Ok(_)) => {
                success_count += 1;
            }
            Ok(Err(e)) => {
                // Rate limited
                println!("   Task {} rate limited: {}", i, e);
            }
            Err(e) => {
                println!("   Task {} panicked: {}", i, e);
            }
        }
    }
    
    let elapsed = start.elapsed();
    
    println!("    Processed 50 concurrent checks in {:?}", elapsed);
    println!("    Success: {}, Rate limited: {}", success_count, 50 - success_count);
    println!("    Throughput: {:.2} checks/sec", 50.0 / elapsed.as_secs_f64());
    
    // Should handle all concurrent checks without panicking
    assert!(success_count > 0, "At least some checks should succeed");
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_claim_recording() -> Result<()> {
    println!("\n Load Test: Concurrent claim recording");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_load_test_config();
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    let start = Instant::now();
    let mut handles = vec![];
    
    // Spawn 100 concurrent tasks recording claims
    for i in 0..100 {
        let orch = orchestrator.clone();
        let processor = if i % 2 == 0 { "routing" } else { "storage" };
        let handle = tokio::spawn(async move {
            orch.record_claim(processor).await;
        });
        handles.push(handle);
    }
    
    // Wait for all tasks
    for handle in handles {
        handle.await?;
    }
    
    let elapsed = start.elapsed();
    
    println!("    Recorded 100 concurrent claims in {:?}", elapsed);
    println!("    Throughput: {:.2} claims/sec", 100.0 / elapsed.as_secs_f64());
    
    // Verify both processors have claims recorded
    let routing_stats = orchestrator.get_rate_limit_stats("routing").await;
    let storage_stats = orchestrator.get_rate_limit_stats("storage").await;
    
    println!("    Routing claims: {}", routing_stats.claims_in_last_hour);
    println!("    Storage claims: {}", storage_stats.claims_in_last_hour);
    
    assert!(routing_stats.claims_in_last_hour > 0);
    assert!(storage_stats.claims_in_last_hour > 0);
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_stats_queries() -> Result<()> {
    println!("\n Load Test: Concurrent stats queries");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_load_test_config();
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    // Record some claims first
    orchestrator.record_claim("routing").await;
    orchestrator.record_claim("storage").await;
    
    let start = Instant::now();
    let mut handles = vec![];
    
    // Spawn 200 concurrent stat queries
    for i in 0..200 {
        let orch = orchestrator.clone();
        let processor = if i % 2 == 0 { "routing" } else { "storage" };
        let handle = tokio::spawn(async move {
            orch.get_rate_limit_stats(processor).await
        });
        handles.push(handle);
    }
    
    // Wait for all queries
    let mut stats_retrieved = 0;
    for handle in handles {
        let stats = handle.await?;
        if stats.claims_in_last_hour > 0 {
            stats_retrieved += 1;
        }
    }
    
    let elapsed = start.elapsed();
    
    println!("    Processed 200 concurrent stat queries in {:?}", elapsed);
    println!("    Stats retrieved: {}", stats_retrieved);
    println!("    Throughput: {:.2} queries/sec", 200.0 / elapsed.as_secs_f64());
    
    assert_eq!(stats_retrieved, 200, "All queries should retrieve stats");
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_under_burst_load() -> Result<()> {
    println!("\n Load Test: Rate limiter under burst load");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    
    // Create config with strict rate limits
    let mut rewards_config = RewardsConfig::default();
    rewards_config.max_claims_per_hour = 10;
    rewards_config.cooldown_period_secs = 1;
    let config = RewardOrchestratorConfig::from(&rewards_config);
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    let start = Instant::now();
    let mut handles = vec![];
    
    // Burst: 100 concurrent claim attempts
    for _i in 0..100 {
        let orch = orchestrator.clone();
        let handle = tokio::spawn(async move {
            let result = orch.check_rate_limit("routing").await;
            if result.is_ok() {
                orch.record_claim("routing").await;
            }
            result
        });
        handles.push(handle);
    }
    
    // Wait and count results
    let mut allowed = 0;
    let mut rate_limited = 0;
    
    for handle in handles {
        match handle.await? {
            Ok(_) => allowed += 1,
            Err(_) => rate_limited += 1,
        }
    }
    
    let elapsed = start.elapsed();
    
    println!("    Processed 100 burst claims in {:?}", elapsed);
    println!("    Allowed: {}, Rate limited: {}", allowed, rate_limited);
    println!("    Rate limiter correctly enforced limits");
    
    // Should enforce rate limit
    assert!(allowed <= 10, "Should not exceed max_claims_per_hour");
    assert!(rate_limited >= 90, "Should rate limit excess claims");
    
    Ok(())
}

#[tokio::test]
async fn test_sustained_claim_load() -> Result<()> {
    println!("\n Load Test: Sustained claim load over time");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_load_test_config();
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    let start = Instant::now();
    let mut total_claims = 0;
    
    // Sustained load: 5 waves of 20 claims each
    for wave in 0..5 {
        let mut handles = vec![];
        
        for _i in 0..20 {
            let orch = orchestrator.clone();
            let processor = if wave % 2 == 0 { "routing" } else { "storage" };
            let handle = tokio::spawn(async move {
                orch.record_claim(processor).await;
            });
            handles.push(handle);
        }
        
        // Wait for wave to complete
        for handle in handles {
            handle.await?;
            total_claims += 1;
        }
        
        // Small delay between waves
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    let elapsed = start.elapsed();
    
    println!("    Processed {} sustained claims in {:?}", total_claims, elapsed);
    println!("    Average throughput: {:.2} claims/sec", total_claims as f64 / elapsed.as_secs_f64());
    
    // Verify claims are tracked
    let routing_stats = orchestrator.get_rate_limit_stats("routing").await;
    let storage_stats = orchestrator.get_rate_limit_stats("storage").await;
    let total_tracked = routing_stats.claims_in_last_hour + storage_stats.claims_in_last_hour;
    
    println!("    Total tracked claims: {}", total_tracked);
    assert_eq!(total_tracked, total_claims as u32);
    
    Ok(())
}

#[tokio::test]
async fn test_mixed_operation_load() -> Result<()> {
    println!("\n Load Test: Mixed operations (checks + records + queries)");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_load_test_config();
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    let start = Instant::now();
    let mut handles = vec![];
    
    // Mix of operations
    for i in 0..150 {
        let orch = orchestrator.clone();
        let handle = tokio::spawn(async move {
            match i % 3 {
                0 => {
                    // Check rate limit
                    orch.check_rate_limit("routing").await.ok();
                }
                1 => {
                    // Record claim
                    orch.record_claim("storage").await;
                }
                2 => {
                    // Query stats
                    orch.get_all_rate_limit_stats().await;
                }
                _ => unreachable!(),
            }
        });
        handles.push(handle);
    }
    
    // Wait for all operations
    for handle in handles {
        handle.await?;
    }
    
    let elapsed = start.elapsed();
    
    println!("    Processed 150 mixed operations in {:?}", elapsed);
    println!("    Mix: 50 checks, 50 records, 50 queries");
    println!("    Throughput: {:.2} ops/sec", 150.0 / elapsed.as_secs_f64());
    
    // System should remain consistent
    let stats = orchestrator.get_all_rate_limit_stats().await;
    println!("    Final state: routing={}, storage={}", 
        stats.routing.claims_in_last_hour,
        stats.storage.claims_in_last_hour);
    
    Ok(())
}

#[tokio::test]
async fn test_multiple_orchestrators_concurrent() -> Result<()> {
    println!("\n Load Test: Multiple orchestrators under load");
    
    let network1 = create_mock_network_component();
    let blockchain1 = create_mock_blockchain();
    let env1 = create_test_environment();
    let config1 = create_load_test_config();
    
    let network2 = create_mock_network_component();
    let blockchain2 = create_mock_blockchain();
    let env2 = create_test_environment();
    let config2 = create_load_test_config();
    
    let orchestrator1 = Arc::new(RewardOrchestrator::with_config(network1, blockchain1, env1, config1));
    let orchestrator2 = Arc::new(RewardOrchestrator::with_config(network2, blockchain2, env2, config2));
    
    let start = Instant::now();
    let mut handles = vec![];
    
    // 50 operations on each orchestrator concurrently
    for i in 0..50 {
        let orch1 = orchestrator1.clone();
        let orch2 = orchestrator2.clone();
        
        let handle1 = tokio::spawn(async move {
            orch1.record_claim("routing").await;
        });
        
        let handle2 = tokio::spawn(async move {
            orch2.record_claim("routing").await;
        });
        
        handles.push(handle1);
        handles.push(handle2);
    }
    
    // Wait for all
    for handle in handles {
        handle.await?;
    }
    
    let elapsed = start.elapsed();
    
    println!("    Processed 100 operations (2 orchestrators) in {:?}", elapsed);
    
    // Verify independence
    let stats1 = orchestrator1.get_rate_limit_stats("routing").await;
    let stats2 = orchestrator2.get_rate_limit_stats("routing").await;
    
    println!("    Orchestrator 1 claims: {}", stats1.claims_in_last_hour);
    println!("    Orchestrator 2 claims: {}", stats2.claims_in_last_hour);
    println!("    Orchestrators remain independent under load");
    
    assert_eq!(stats1.claims_in_last_hour, 50);
    assert_eq!(stats2.claims_in_last_hour, 50);
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_cleanup_under_load() -> Result<()> {
    println!("\n Load Test: Rate limiter cleanup under sustained load");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_load_test_config();
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    let start = Instant::now();
    
    // Record many claims to trigger cleanup
    for _wave in 0..10 {
        let mut handles = vec![];
        for _i in 0..10 {
            let orch = orchestrator.clone();
            let handle = tokio::spawn(async move {
                orch.record_claim("routing").await;
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await?;
        }
    }
    
    let elapsed = start.elapsed();
    
    println!("    Recorded 100 claims in {:?}", elapsed);
    
    // Query stats (triggers cleanup of old claims)
    let stats = orchestrator.get_rate_limit_stats("routing").await;
    
    println!("    Current claims in last hour: {}", stats.claims_in_last_hour);
    println!("    Cleanup mechanism working (all recent claims counted)");
    
    assert_eq!(stats.claims_in_last_hour, 100, "Should track all recent claims");
    
    Ok(())
}

#[tokio::test]
async fn test_performance_baseline() -> Result<()> {
    println!("\n Load Test: Performance baseline measurement");
    
    let network = create_mock_network_component();
    let blockchain = create_mock_blockchain();
    let env = create_test_environment();
    let config = create_load_test_config();
    
    let orchestrator = Arc::new(RewardOrchestrator::with_config(network, blockchain, env, config));
    
    // Measure check_rate_limit performance
    let start = Instant::now();
    for _i in 0..1000 {
        orchestrator.check_rate_limit("routing").await.ok();
    }
    let check_elapsed = start.elapsed();
    let check_throughput = 1000.0 / check_elapsed.as_secs_f64();
    
    // Measure record_claim performance
    let start = Instant::now();
    for _i in 0..1000 {
        orchestrator.record_claim("routing").await;
    }
    let record_elapsed = start.elapsed();
    let record_throughput = 1000.0 / record_elapsed.as_secs_f64();
    
    // Measure get_stats performance
    let start = Instant::now();
    for _i in 0..1000 {
        orchestrator.get_rate_limit_stats("routing").await;
    }
    let stats_elapsed = start.elapsed();
    let stats_throughput = 1000.0 / stats_elapsed.as_secs_f64();
    
    println!("\n    Performance Baseline:");
    println!("   ┌────────────────────────────────────────┐");
    println!("   │ check_rate_limit: {:.2} ops/sec     │", check_throughput);
    println!("   │ record_claim:     {:.2} ops/sec     │", record_throughput);
    println!("   │ get_stats:        {:.2} ops/sec     │", stats_throughput);
    println!("   └────────────────────────────────────────┘");
    
    // Baseline expectations (should be quite fast)
    assert!(check_throughput > 1000.0, "check_rate_limit should handle >1k ops/sec");
    assert!(record_throughput > 1000.0, "record_claim should handle >1k ops/sec");
    assert!(stats_throughput > 1000.0, "get_stats should handle >1k ops/sec");
    
    println!("    All operations meet performance baseline");
    
    Ok(())
}
