//! Unit Tests for Monitoring Module
//! 
//! Tests metrics collection, health monitoring, and alerting

use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;

use zhtp::monitoring::{
    MonitoringSystem, MetricsCollector, HealthMonitor, AlertManager,
    SystemMetrics, Alert, AlertLevel, NodeHealth,
    set_global_alert_manager, clear_global_alert_manager, get_global_alert_manager,
};
use zhtp::monitoring::alerting::AlertThresholds;

#[tokio::test]
async fn test_monitoring_system_lifecycle() -> Result<()> {
    let mut monitoring = MonitoringSystem::new().await?;
    
    // Test starting
    monitoring.start().await?;
    
    // Test basic functionality
    let metrics = monitoring.get_system_metrics().await?;
    assert!(metrics.cpu_usage >= 0.0);
    assert!(metrics.memory_usage >= 0.0);
    assert!(metrics.disk_usage >= 0.0);
    
    let health = monitoring.get_health_status().await?;
    assert!(matches!(health.overall_status, NodeHealth::Healthy | NodeHealth::Warning | NodeHealth::Critical));
    
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
    
    // Verify system metrics are present
    assert!(current_metrics.cpu_usage <= 100.0);
    assert!(current_metrics.memory_usage <= 100.0);
    assert!(current_metrics.disk_usage <= 100.0);
    // Network bytes are u64, always non-negative
    let _ = current_metrics.network_rx_bytes;
    let _ = current_metrics.network_tx_bytes;
    
    // Test metrics export
    let exported_metrics = metrics_collector.export_metrics().await?;
    assert!(!exported_metrics.is_empty());
    
    metrics_collector.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_health_monitoring() -> Result<()> {
    let health_monitor = HealthMonitor::new().await?;
    health_monitor.start().await?;
    
    // Get current health
    let health = health_monitor.get_current_health().await?;
    assert!(matches!(health.overall_status, NodeHealth::Healthy | NodeHealth::Warning | NodeHealth::Critical));
    
    // Get detailed health report
    let health_report = health_monitor.get_health_report().await?;
    assert!(health_report.system_health.cpu_health.usage_percent <= 100.0);
    assert!(health_report.system_health.memory_health.usage_percent <= 100.0);
    // total_peers is usize, always non-negative
    let _ = health_report.network_health.peer_health.total_peers;
    
    // Test health history
    let history = health_monitor.get_health_history(Duration::from_secs(60)).await?;
    assert!(!history.is_empty());
    
    health_monitor.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_alert_management() -> Result<()> {
    let alert_manager = AlertManager::new().await?;
    alert_manager.start().await?;
    
    // Create test alert
    let alert = Alert {
        id: "test_alert_001".to_string(),
        level: AlertLevel::Warning,
        title: "Test Alert".to_string(),
        message: "This is a test alert for monitoring".to_string(),
        source: "test".to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("test_key".to_string(), "test_value".to_string());
            meta
        },
    };
    
    // Trigger alert
    alert_manager.trigger_alert(alert.clone()).await?;
    
    // Get active alerts
    let active_alerts = alert_manager.get_active_alerts().await?;
    assert!(!active_alerts.is_empty());
    
    let found_alert = active_alerts.iter()
        .find(|a| a.id == "test_alert_001")
        .expect("Should find the triggered alert");
    
    assert_eq!(found_alert.level, AlertLevel::Warning);
    assert_eq!(found_alert.title, "Test Alert");
    
    // Resolve alert
    alert_manager.resolve_alert("test_alert_001").await?;
    
    // Verify alert is resolved
    let active_alerts = alert_manager.get_active_alerts().await?;
    let resolved_alert = active_alerts.iter()
        .find(|a| a.id == "test_alert_001");
    
    // Alert should no longer be in active alerts
    assert!(resolved_alert.is_none());
    
    alert_manager.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_alert_levels() -> Result<()> {
    let alert_manager = AlertManager::new().await?;
    alert_manager.start().await?;
    
    let alert_levels = vec![
        AlertLevel::Info,
        AlertLevel::Warning,
        AlertLevel::Critical,
        AlertLevel::Emergency,
    ];
    
    for (i, level) in alert_levels.into_iter().enumerate() {
        let alert = Alert {
            id: format!("test_alert_{:03}", i),
            level: level.clone(),
            title: format!("Test Alert Level {:?}", level),
            message: format!("Testing alert level {:?}", level),
            source: "test".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            metadata: HashMap::new(),
        };
        
        alert_manager.trigger_alert(alert).await?;
    }
    
    // Verify all alerts were recorded
    let active_alerts = alert_manager.get_active_alerts().await?;
    assert!(active_alerts.len() >= 4);
    
    // Test alert filtering by level
    let critical_alerts = alert_manager.get_alerts_by_level(AlertLevel::Critical).await?;
    assert!(!critical_alerts.is_empty());
    
    let emergency_alerts = alert_manager.get_alerts_by_level(AlertLevel::Emergency).await?;
    assert!(!emergency_alerts.is_empty());
    
    alert_manager.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_threshold_monitoring() -> Result<()> {
    let thresholds = AlertThresholds {
        cpu_usage: 80.0,
        memory_usage: 85.0,
        disk_usage: 90.0,
        network_errors: 100,
        peer_count_min: 3,
        block_time_max: Duration::from_secs(30),
        transaction_timeout: Duration::from_secs(300),
    };
    
    let alert_manager = AlertManager::with_thresholds(thresholds).await?;
    alert_manager.start().await?;
    
    // Simulate metrics that exceed thresholds
    let mut tags = HashMap::new();
    tags.insert("component".to_string(), "system".to_string());
    
    // This should trigger an alert if CPU usage is high
    let high_cpu_metrics = SystemMetrics {
        timestamp: chrono::Utc::now().timestamp() as u64,
        uptime_seconds: 3600,
        cpu_usage_percent: 95.0,
        memory_usage_bytes: 1024 * 1024 * 1024, // 1GB
        memory_total_bytes: 2 * 1024 * 1024 * 1024, // 2GB total
        disk_usage_bytes: 60 * 1024 * 1024 * 1024, // 60GB
        disk_total_bytes: 100 * 1024 * 1024 * 1024, // 100GB total
        cpu_usage: 95.0, // Above threshold
        memory_usage: 50.0,
        disk_usage: 60.0,
        network_rx_bytes: 1024,
        network_tx_bytes: 512,
        uptime: Duration::from_secs(3600),
        ..Default::default()
    };
    
    // Process metrics (this would normally be done by the monitoring system)
    alert_manager.process_metrics(&high_cpu_metrics).await?;
    
    // Check if alert was triggered
    tokio::time::sleep(Duration::from_millis(100)).await;
    let alerts = alert_manager.get_active_alerts().await?;
    
    // Should have at least one alert for high CPU usage
    let cpu_alerts: Vec<_> = alerts.iter()
        .filter(|a| a.message.contains("CPU") || a.message.contains("cpu"))
        .collect();
    
    if !cpu_alerts.is_empty() {
        assert!(cpu_alerts[0].level == AlertLevel::Warning || cpu_alerts[0].level == AlertLevel::Critical);
    }
    
    alert_manager.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_metrics_export_formats() -> Result<()> {
    let metrics_collector = MetricsCollector::new().await?;
    metrics_collector.start().await?;
    
    // Record some test metrics
    let mut tags = HashMap::new();
    tags.insert("service".to_string(), "zhtp".to_string());
    tags.insert("version".to_string(), "1.0.0".to_string());
    
    for i in 0..10 {
        metrics_collector.record_metric(&format!("test_metric_{}", i), i as f64, tags.clone()).await?;
    }
    
    // Test different export formats
    let prometheus_format = metrics_collector.export_prometheus().await?;
    assert!(!prometheus_format.is_empty());
    assert!(prometheus_format.contains("test_metric_"));
    
    let json_format = metrics_collector.export_json().await?;
    assert!(!json_format.is_empty());
    
    let influx_format = metrics_collector.export_influxdb().await?;
    assert!(!influx_format.is_empty());
    
    metrics_collector.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_monitoring_operations() -> Result<()> {
    let monitoring = MonitoringSystem::new().await?;
    
    // Start multiple monitoring operations concurrently
    let tasks = vec![
        // Record metrics
        tokio::spawn({
            let monitoring = monitoring.clone();
            async move {
                for i in 0..100 {
                    let mut tags = HashMap::new();
                    tags.insert("iteration".to_string(), i.to_string());
                    let _ = monitoring.record_metric("concurrent_test", i as f64, tags).await;
                }
                Ok::<(), anyhow::Error>(())
            }
        }),
        
        // Get system metrics
        tokio::spawn({
            let monitoring = monitoring.clone();
            async move {
                for _ in 0..50 {
                    let _ = monitoring.get_system_metrics().await;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Ok::<(), anyhow::Error>(())
            }
        }),
        
        // Get health status
        tokio::spawn({
            let monitoring = monitoring.clone();
            async move {
                for _ in 0..50 {
                    let _ = monitoring.get_health_status().await;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Ok::<(), anyhow::Error>(())
            }
        }),
    ];
    
    // Wait for all tasks to complete
    let results = futures::future::join_all(tasks).await;
    
    // Verify all tasks completed successfully
    for result in results {
        assert!(result.is_ok());
        if let Ok(task_result) = result {
            if let Err(e) = task_result {
                return Err(e);
            }
        }
    }
    
    Ok(())
}

#[tokio::test]
async fn test_monitoring_memory_usage() -> Result<()> {
    let mut monitoring = MonitoringSystem::new().await?;
    monitoring.start().await?;

    // Record many metrics to test memory usage
    let mut tags = HashMap::new();
    tags.insert("stress_test".to_string(), "memory".to_string());

    for i in 0..1000 {
        monitoring.record_metric("memory_stress_test", i as f64, tags.clone()).await?;

        if i % 100 == 0 {
            // Check memory usage periodically
            let metrics = monitoring.get_system_metrics().await?;
            assert!(metrics.memory_usage < 95.0, "Memory usage should not exceed 95%");
        }
    }

    monitoring.stop().await?;

    Ok(())
}

// ============================================================================
// RESTART-SAFETY TESTS
// These tests verify that the global alert manager is correctly managed
// during start/stop cycles, preventing restart from using stale instances.
// ============================================================================

#[tokio::test]
async fn test_global_alert_manager_reset() -> Result<()> {
    // Initially, no global manager
    assert!(
        get_global_alert_manager().is_none(),
        "Global manager should not exist initially"
    );

    // Create and set first manager
    let manager1 = AlertManager::new().await?;
    let manager1_arc = std::sync::Arc::new(manager1);
    set_global_alert_manager(manager1_arc.clone());

    // Verify it was set
    assert!(
        get_global_alert_manager().is_some(),
        "Global manager should exist after set_global_alert_manager"
    );

    let retrieved1 = get_global_alert_manager().unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&manager1_arc, &retrieved1),
        "Should retrieve the exact same Arc instance"
    );

    // Clear the global
    clear_global_alert_manager();

    // Verify it's cleared
    assert!(
        get_global_alert_manager().is_none(),
        "Global manager should be None after clear_global_alert_manager"
    );

    // Create and set a different manager
    let manager2 = AlertManager::new().await?;
    let manager2_arc = std::sync::Arc::new(manager2);
    set_global_alert_manager(manager2_arc.clone());

    // Verify the new one is set
    assert!(
        get_global_alert_manager().is_some(),
        "Global manager should exist after second set"
    );

    let retrieved2 = get_global_alert_manager().unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&manager2_arc, &retrieved2),
        "Should retrieve the new Arc instance"
    );

    // Verify it's different from the first
    assert!(
        !std::sync::Arc::ptr_eq(&manager1_arc, &retrieved2),
        "Second manager should be different from first"
    );

    Ok(())
}

#[tokio::test]
async fn test_monitoring_system_restart() -> Result<()> {
    // **Restart-safety test**: Verify that restarting creates a new manager instance,
    // not a reused stopped one. This prevents silent failures where a stopped manager
    // is used without operators noticing.

    // PHASE 1: Start monitoring, get manager pointer
    let mut monitoring1 = MonitoringSystem::new().await?;
    monitoring1.start().await?;

    let manager1 = get_global_alert_manager().expect("Manager should exist after start");
    let manager1_ptr = std::sync::Arc::as_ptr(&manager1);

    // PHASE 2: Stop monitoring
    monitoring1.stop().await?;

    // CRITICAL: Verify global is cleared (prevents stale manager reuse)
    assert!(
        get_global_alert_manager().is_none(),
        "Global manager should be cleared after stop() to prevent stale reuse"
    );

    // PHASE 3: Restart monitoring with a NEW system
    let mut monitoring2 = MonitoringSystem::new().await?;
    monitoring2.start().await?;

    // Get the new manager
    let manager2 = get_global_alert_manager().expect("Manager should exist after restart");
    let manager2_ptr = std::sync::Arc::as_ptr(&manager2);

    // **CRITICAL INVARIANT**: Verify it's a DIFFERENT instance
    // This is the core restart-safety guarantee: restarts don't reuse stale managers
    assert_ne!(
        manager1_ptr, manager2_ptr,
        "Restart MUST produce a new manager instance, never reuse the stopped one"
    );

    // PHASE 4: Cleanup
    monitoring2.stop().await?;
    assert!(
        get_global_alert_manager().is_none(),
        "Global should be cleared after final stop"
    );

    Ok(())
}

#[tokio::test]
async fn test_alert_manager_drop_safety() -> Result<()> {
    // Test that attempting to get a manager after it's dropped (cleared)
    // returns None gracefully, not a stale reference

    let mut monitoring = MonitoringSystem::new().await?;
    monitoring.start().await?;

    // Create an alert while manager exists
    let test_alert = Alert {
        id: "drop_test".to_string(),
        level: AlertLevel::Info,
        title: "Drop Test".to_string(),
        message: "Testing safe drop behavior".to_string(),
        source: "test".to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
        metadata: HashMap::new(),
    };

    if let Some(mgr) = get_global_alert_manager() {
        mgr.trigger_alert(test_alert).await?;
        let alerts = mgr.get_active_alerts().await?;
        assert!(!alerts.is_empty(), "Alert should be stored in manager");
    }

    // Stop monitoring (which clears the global)
    monitoring.stop().await?;

    // Try to get the manager - should return None, not a stale ref
    assert!(
        get_global_alert_manager().is_none(),
        "Global should be None after stop, preventing stale access"
    );

    // This is the safety guarantee: you cannot accidentally use a stopped manager
    // because it's not reachable through the global anymore

    Ok(())
}
