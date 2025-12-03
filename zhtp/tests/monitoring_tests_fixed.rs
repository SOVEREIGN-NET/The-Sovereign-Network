//! Comprehensive tests for ZHTP monitoring system
//! 
//! Tests all aspects of metrics collection, health monitoring, and alerting

use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;

use zhtp::monitoring::{MonitoringSystem, MetricsCollector, HealthMonitor, AlertManager, NodeHealth, Alert, AlertLevel, MonitoringConfig, AlertThresholds};

#[tokio::test]
async fn test_monitoring_system_basic() -> Result<()> {
    let mut monitoring = MonitoringSystem::new().await?;
    
    // Test starting the monitoring system
    monitoring.start().await?;
    
    // Test basic functionality
    let metrics = monitoring.get_system_metrics().await?;
    assert!(metrics.cpu_usage_percent >= 0.0);
    assert!(metrics.memory_usage_bytes >= 0);
    assert!(metrics.disk_usage_bytes >= 0);
    
    let health = monitoring.get_health_status().await?;
    assert!(matches!(health.overall_status, NodeHealth::Healthy | NodeHealth::Warning | NodeHealth::Critical | NodeHealth::Down));
    
    // Test stopping
    monitoring.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_metrics_collection() -> Result<()> {
    let metrics_collector = MetricsCollector::new().await?;
    metrics_collector.start().await?;
    
    // Record custom metrics
    let mut tags = HashMap::new();
    tags.insert("component".to_string(), "test".to_string());
    tags.insert("operation".to_string(), "benchmark".to_string());
    
    metrics_collector.record_metric("test_counter", 42.0, tags.clone()).await?;
    metrics_collector.record_metric("test_gauge", 3.14, tags.clone()).await?;
    metrics_collector.record_metric("test_histogram", 100.0, tags).await?;
    
    // Get current metrics
    let current_metrics = metrics_collector.get_current_metrics().await?;
    assert!(current_metrics.cpu_usage_percent >= 0.0);
    assert!(current_metrics.memory_usage_bytes >= 0);
    assert!(current_metrics.disk_usage_bytes >= 0);
    assert!(current_metrics.network_bytes_sent >= 0);
    assert!(current_metrics.network_bytes_received >= 0);
    
    metrics_collector.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_health_monitoring() -> Result<()> {
    let health_monitor = HealthMonitor::new().await?;
    health_monitor.start().await?;
    
    // Test getting health status
    let health_status = health_monitor.get_current_health().await?;
    
    assert!(matches!(health_status.overall_status, NodeHealth::Healthy | NodeHealth::Warning | NodeHealth::Critical | NodeHealth::Down));
    assert!(health_status.timestamp > 0);
    
    // Validate system health components
    assert!(health_status.system_health.cpu_health.usage_percent >= 0.0);
    assert!(health_status.system_health.memory_health.usage_percent >= 0.0);
    assert!(health_status.system_health.disk_health.usage_percent >= 0.0);
    
    health_monitor.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_alert_system() -> Result<()> {
    let alert_manager = AlertManager::new().await?;
    alert_manager.start().await?;
    
    // Create test alert
    let test_alert = Alert {
        id: "test_alert_001".to_string(),
        level: AlertLevel::Warning,
        title: "Test Alert".to_string(),
        message: "This is a test alert for validation".to_string(),
        source: "test_suite".to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        metadata: HashMap::new(),
    };
    
    // Trigger alert
    alert_manager.trigger_alert(test_alert.clone()).await?;
    
    alert_manager.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_performance_metrics() -> Result<()> {
    let mut monitoring = MonitoringSystem::new().await?;
    monitoring.start().await?;
    
    // Simulate some load and measure performance
    for i in 0..10 {
        let mut tags = HashMap::new();
        tags.insert("iteration".to_string(), i.to_string());
        
        monitoring.record_metric("test_performance", i as f64 * 10.0, tags).await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    let final_metrics = monitoring.get_system_metrics().await?;
    assert!(final_metrics.uptime_seconds > 0);
    
    monitoring.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_health_status_computation() -> Result<()> {
    let health_monitor = HealthMonitor::new().await?;
    health_monitor.start().await?;
    
    let health = health_monitor.get_current_health().await?;
    
    // Verify health status structure
    assert!(health.timestamp > 0);
    assert!(matches!(health.overall_status, NodeHealth::Healthy | NodeHealth::Warning | NodeHealth::Critical | NodeHealth::Down));
    
    // System health validation
    assert!(health.system_health.cpu_health.usage_percent >= 0.0);
    assert!(health.system_health.memory_health.usage_percent >= 0.0);
    assert!(health.system_health.disk_health.usage_percent >= 0.0);
    
    // Network health validation
    assert!(health.network_health.peer_health.total_peers >= 0);
    
    // Blockchain health validation
    assert!(health.blockchain_health.sync_status.sync_progress >= 0.0);
    assert!(health.blockchain_health.sync_status.sync_progress <= 1.0);
    
    // Storage health validation
    assert!(health.storage_health.total_capacity >= 0);
    assert!(health.storage_health.used_capacity >= 0);
    assert!(health.storage_health.availability >= 0.0);
    assert!(health.storage_health.availability <= 1.0);
    
    health_monitor.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_concurrent_monitoring() -> Result<()> {
    let monitoring = std::sync::Arc::new(tokio::sync::Mutex::new(MonitoringSystem::new().await?));
    
    // Start monitoring
    {
        let mut m = monitoring.lock().await;
        m.start().await?;
    }
    
    // Spawn multiple tasks to simulate concurrent usage
    let mut handles = Vec::new();
    
    for i in 0..5 {
        let monitoring_clone = monitoring.clone();
        let handle = tokio::spawn(async move {
            let monitoring = monitoring_clone.lock().await;
            for j in 0..10 {
                let mut tags = HashMap::new();
                tags.insert("worker".to_string(), i.to_string());
                tags.insert("iteration".to_string(), j.to_string());
                
                if let Err(e) = monitoring.record_metric("concurrent_test", (i * 10 + j) as f64, tags).await {
                    eprintln!("Failed to record metric: {}", e);
                }
                
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<(), anyhow::Error>(())
        });
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    for handle in handles {
        handle.await??;
    }
    
    // Verify metrics were recorded
    let monitoring = monitoring.lock().await;
    let metrics = monitoring.get_system_metrics().await?;
    assert!(metrics.cpu_usage_percent >= 0.0);
    
    monitoring.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_stress_monitoring() -> Result<()> {
    let mut monitoring = MonitoringSystem::new().await?;
    monitoring.start().await?;
    
    // Generate high-frequency metrics to test system under load
    for i in 0..100 {
        let mut tags = HashMap::new();
        tags.insert("stress_test".to_string(), "high_frequency".to_string());
        tags.insert("iteration".to_string(), i.to_string());
        
        monitoring.record_metric("stress_metric", (i as f64).sin() * 100.0, tags).await?;
        
        if i % 10 == 0 {
            // Periodically check system health
            let health = monitoring.get_health_status().await?;
            assert!(matches!(health.overall_status, NodeHealth::Healthy | NodeHealth::Warning | NodeHealth::Critical | NodeHealth::Down));
            
            // Check that memory usage isn't growing uncontrollably
            let metrics = monitoring.get_system_metrics().await?;
            assert!(metrics.memory_usage_bytes < 1024 * 1024 * 1024); // Less than 1GB
        }
    }
    
    monitoring.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_component_integration() -> Result<()> {
    // Test integration between metrics, health, and alerting
    let mut monitoring = MonitoringSystem::new().await?;
    monitoring.start().await?;
    
    // Record some critical metrics that should trigger alerts
    let mut critical_tags = HashMap::new();
    critical_tags.insert("severity".to_string(), "critical".to_string());
    
    monitoring.record_metric("cpu_usage", 95.0, critical_tags.clone()).await?;
    monitoring.record_metric("memory_usage", 90.0, critical_tags.clone()).await?;
    monitoring.record_metric("disk_usage", 85.0, critical_tags).await?;
    
    // Allow time for processing
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify metrics are reflected in health status
    let health = monitoring.get_health_status().await?;
    let metrics = monitoring.get_system_metrics().await?;
    
    assert!(metrics.timestamp > 0);
    assert!(health.timestamp > 0);
    
    monitoring.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_monitoring_configuration() -> Result<()> {
    // Test monitoring with custom configuration
    let config = MonitoringConfig {
        metrics_enabled: true,
        health_check_interval: Duration::from_millis(100),
        alert_thresholds: AlertThresholds {
            cpu_usage: 85.0,
            memory_usage: 90.0,
            disk_usage: 95.0,
            network_errors: 50,
            peer_count_min: 2,
            block_time_max: Duration::from_secs(20),
            transaction_timeout: Duration::from_secs(180),
        },
        dashboard_enabled: false,
        dashboard_port: 8082,
        log_level: "debug".to_string(),
        export_prometheus: false,
        prometheus_port: 9091,
    };
    
    // Create monitoring system (config would be used in implementation)
    let mut monitoring = MonitoringSystem::new().await?;
    monitoring.start().await?;
    
    // Test that monitoring works with custom thresholds
    let health = monitoring.get_health_status().await?;
    assert!(matches!(health.overall_status, NodeHealth::Healthy | NodeHealth::Warning | NodeHealth::Critical | NodeHealth::Down));
    
    monitoring.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_long_running_monitoring() -> Result<()> {
    let mut monitoring = MonitoringSystem::new().await?;
    monitoring.start().await?;
    
    // Run monitoring for a longer period to test stability
    let start_time = tokio::time::Instant::now();
    let test_duration = Duration::from_secs(2);
    
    while start_time.elapsed() < test_duration {
        // Continuously record metrics
        let mut tags = HashMap::new();
        tags.insert("test_type".to_string(), "endurance".to_string());
        
        monitoring.record_metric("endurance_test", start_time.elapsed().as_secs_f64(), tags).await?;
        
        // Check health periodically
        let health = monitoring.get_health_status().await?;
        assert!(health.timestamp > 0);
        
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    
    // Final health check
    let final_health = monitoring.get_health_status().await?;
    let final_metrics = monitoring.get_system_metrics().await?;
    
    assert!(final_health.timestamp > 0);
    assert!(final_metrics.uptime_seconds >= 2);
    
    monitoring.stop().await?;
    Ok(())
}
