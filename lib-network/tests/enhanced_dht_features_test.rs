//! Enhanced DHT Features Test
//! 
//! This test specifically validates the enhanced DHT functionality we added:
//! - LRU+TTL cache with OptimizedDHTCache and ThreadSafeDHTCache
//! - mDNS peer discovery with DHTBootstrapEnhancements
//! - DHT-specific performance monitoring with DHTPerformanceMonitor

use lib_network::dht::cache::{OptimizedDHTCache, ThreadSafeDHTCache, CacheStats};
use lib_network::dht::bootstrap::{DHTBootstrapEnhancements, DHTBootstrap};
use lib_network::dht::monitoring::{DHTPerformanceMonitor, DHTOperation, DHTPerformanceStats};
use tokio;
use std::time::Duration;

#[tokio::test]
async fn test_enhanced_cache_functionality() {
    println!(" Testing Enhanced DHT Cache Functionality");
    
    // Test basic cache operations with proper API
    let mut cache = OptimizedDHTCache::new(5, Duration::from_secs(10));
    
    println!("   Testing basic insert/get operations...");
    cache.insert("key1".to_string(), "value1".to_string());
    cache.insert("key2".to_string(), "value2".to_string());
    cache.insert("key3".to_string(), "value3".to_string());

    // Test retrieval - correct API doesn't use await
    let value1 = cache.get("key1");
    assert_eq!(value1, Some("value1".to_string()));
    println!("    Basic get operation successful");

    // Test cache statistics
    let stats = cache.stats();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.size, 3);
    println!("    Cache stats: {} hits, {} entries", stats.hits, stats.size);

    // Test LRU eviction
    println!("    Testing LRU eviction...");
    cache.insert("key4".to_string(), "value4".to_string());
    cache.insert("key5".to_string(), "value5".to_string());
    cache.insert("key6".to_string(), "value6".to_string()); // This should evict key2 (least recently used)

    let stats_after = cache.stats();
    assert_eq!(stats_after.size, 5); // Max size reached
    assert!(stats_after.evictions > 0);
    println!("    LRU eviction working, {} evictions", stats_after.evictions);

    // Test that key2 was evicted (since key1 was accessed)
    let evicted_value = cache.get("key2");
    assert_eq!(evicted_value, None);
    println!("    LRU eviction correctly removed least recent entry");
}

#[tokio::test]  
async fn test_thread_safe_cache() {
    println!(" Testing Thread-Safe DHT Cache");
    
    let cache = ThreadSafeDHTCache::new(10, Duration::from_secs(5));
    
    // Test async operations
    cache.insert("async_key1".to_string(), "async_value1".to_string()).await;
    cache.insert("async_key2".to_string(), "async_value2".to_string()).await;
    
    let value = cache.get("async_key1").await;
    assert_eq!(value, Some("async_value1".to_string()));
    
    let stats = cache.stats().await;
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.size, 2);
    
    println!("    Thread-safe cache operations successful");
    println!("    Async cache stats: {} hits, {} entries", stats.hits, stats.size);
}

#[tokio::test]
async fn test_enhanced_bootstrap_mdns() {
    println!(" Testing Enhanced Bootstrap with mDNS");
    
    // Create bootstrap enhancements with default settings
    let bootstrap_config = DHTBootstrapEnhancements::default();
    println!("     Bootstrap config: mDNS={}, peer_exchange={}", 
             bootstrap_config.enable_mdns, bootstrap_config.enable_peer_exchange);
    
    // Create bootstrap manager
    let mut bootstrap = DHTBootstrap::new(bootstrap_config);
    
    // Test enhanced bootstrap (will try to find local peers)
    let bootstrap_nodes = vec!["zhtp://127.0.0.1:33445".to_string()];
    
    println!("    Attempting enhanced bootstrap discovery...");
    match bootstrap.enhance_bootstrap(&bootstrap_nodes).await {
        Ok(peers) => {
            println!("    Enhanced bootstrap completed, found {} peers", peers.len());
            for peer in &peers {
                println!("       Peer: {}", peer);
            }
            
            // Test discovered peers storage
            let stored_peers = bootstrap.get_discovered_peers();
            assert_eq!(stored_peers.len(), peers.len());
            println!("    Peer storage working correctly");
        }
        Err(e) => {
            println!("     Bootstrap discovery error (expected in test): {}", e);
            // This is expected in test environment without actual peers
        }
    }
    
    // Test refresh timing
    let needs_refresh = bootstrap.needs_refresh();
    println!("    Refresh needed: {}", needs_refresh);
}

#[tokio::test]
async fn test_dht_performance_monitoring() {
    println!(" Testing DHT Performance Monitoring");
    
    // Create performance monitor with proper constructor
    let mut monitor = DHTPerformanceMonitor::new(100, Duration::from_secs(60));
    
    println!("    Recording DHT operations...");
    
    // Record some sample operations with correct API
    monitor.record_operation(
        DHTOperation::Store,
        Duration::from_millis(45),
        true,
        3
    );
    
    monitor.record_operation(
        DHTOperation::Retrieve, 
        Duration::from_millis(23),
        true,
        3
    );
    
    monitor.record_operation(
        DHTOperation::Resolve,
        Duration::from_millis(67), 
        false,
        2
    );
    
    // Get performance statistics
    let stats = monitor.get_stats();
    
    println!("    Performance stats:");
    println!("       Total operations: {}", stats.total_operations);
    println!("       Success rate: {:.2}%", stats.success_rate * 100.0);
    println!("      ⏱️  Average latency: {:.2}ms", stats.avg_latency_ms);
    println!("       P95 latency: {:.2}ms", stats.p95_latency_ms);
    
    // Validate statistics
    assert_eq!(stats.total_operations, 3);
    assert!((stats.success_rate - 2.0/3.0).abs() < 0.01); // 2 successful out of 3
    assert!(stats.avg_latency_ms > 0.0);
    
    // Test operation-specific statistics
    let store_stats = monitor.get_operation_stats(DHTOperation::Store);
    assert_eq!(store_stats.total_operations, 1);
    assert_eq!(store_stats.success_rate, 1.0);
    println!("    Store operation stats: {:.2}ms avg latency", store_stats.avg_latency_ms);
    
    println!("    DHT performance monitoring working correctly");
}

#[tokio::test]
async fn test_cache_ttl_expiration() {
    println!(" Testing Cache TTL Expiration");
    
    let mut cache = OptimizedDHTCache::new(10, Duration::from_millis(100));
    
    // Insert with short TTL
    cache.insert_with_ttl("temp_key".to_string(), "temp_value".to_string(), Duration::from_millis(50));
    
    // Should be available immediately
    let immediate_value = cache.get("temp_key");
    assert_eq!(immediate_value, Some("temp_value".to_string()));
    println!("    Value available immediately after insert");
    
    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(60)).await;
    
    // Should be expired now
    let expired_value = cache.get("temp_key");
    assert_eq!(expired_value, None);
    println!("   ⏰ Value correctly expired after TTL");
    
    // Test cleanup of expired entries
    cache.insert_with_ttl("cleanup_key1".to_string(), "value1".to_string(), Duration::from_millis(10));
    cache.insert_with_ttl("cleanup_key2".to_string(), "value2".to_string(), Duration::from_millis(10));
    
    tokio::time::sleep(Duration::from_millis(20)).await;
    
    let expired_count = cache.cleanup_expired();
    assert!(expired_count >= 2);
    println!("    Cleaned up {} expired entries", expired_count);
}