//! Monitoring and Metrics Collection
//! 
//! Provides comprehensive monitoring, logging, and metrics for all ZHTP components

pub mod metrics;
pub mod health_check;
pub mod alerting;
pub mod dashboard;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
// Removed unused: RwLock, warn, error

pub use metrics::*;
pub use health_check::*;
pub use alerting::*;
pub use dashboard::*;

/// Central monitoring system for ZHTP node
#[derive(Clone)]
pub struct MonitoringSystem {
    metrics_collector: Arc<MetricsCollector>,
    health_monitor: Arc<HealthMonitor>,
    alert_manager: Arc<AlertManager>,
    dashboard_server: Option<Arc<DashboardServer>>,
}

impl MonitoringSystem {
    /// Create a new monitoring system
    pub async fn new() -> Result<Self> {
        let metrics_collector = Arc::new(MetricsCollector::new().await?);
        let health_monitor = Arc::new(HealthMonitor::new().await?);
        let alert_manager = Arc::new(AlertManager::new().await?);
        
        Ok(Self {
            metrics_collector,
            health_monitor,
            alert_manager,
            dashboard_server: None,
        })
    }

    /// Start the monitoring system
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting monitoring system...");

        // Start metrics collection
        self.metrics_collector.start().await?;
        
        // Start health monitoring
        self.health_monitor.start().await?;
        
        // Start alert manager
        self.alert_manager.start().await?;
        
        // Start dashboard server if enabled
        if let Ok(dashboard) = DashboardServer::new(8081).await {
            let dashboard_arc = Arc::new(dashboard);
            dashboard_arc.start().await?;
            self.dashboard_server = Some(dashboard_arc);
        }

        info!("Monitoring system started successfully");
        Ok(())
    }

    /// Stop the monitoring system
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping monitoring system...");

        // Stop dashboard server
        if let Some(dashboard) = &self.dashboard_server {
            dashboard.stop().await?;
        }

        // Stop other components
        self.alert_manager.stop().await?;
        self.health_monitor.stop().await?;
        self.metrics_collector.stop().await?;

        info!("Monitoring system stopped");
        Ok(())
    }

    /// Get current system metrics
    pub async fn get_system_metrics(&self) -> Result<SystemMetrics> {
        self.metrics_collector.get_current_metrics().await
    }

    /// Get health status
    pub async fn get_health_status(&self) -> Result<HealthStatus> {
        self.health_monitor.get_current_health().await
    }

    /// Record a custom metric
    pub async fn record_metric(&self, name: &str, value: f64, tags: HashMap<String, String>) -> Result<()> {
        self.metrics_collector.record_metric(name, value, tags).await
    }

    /// Trigger an alert
    pub async fn trigger_alert(&self, alert: Alert) -> Result<()> {
        self.alert_manager.trigger_alert(alert).await
    }
}

/// Configuration for monitoring system
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub metrics_enabled: bool,
    pub health_check_interval: std::time::Duration,
    pub alert_thresholds: AlertThresholds,
    pub dashboard_enabled: bool,
    pub dashboard_port: u16,
    pub log_level: String,
    pub export_prometheus: bool,
    pub prometheus_port: u16,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            health_check_interval: std::time::Duration::from_secs(30),
            alert_thresholds: AlertThresholds::default(),
            dashboard_enabled: true,
            dashboard_port: 8081,
            log_level: "info".to_string(),
            export_prometheus: false,
            prometheus_port: 9090,
        }
    }
}

/// Alert threshold configuration
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_errors: u64,
    pub peer_count_min: usize,
    pub block_time_max: std::time::Duration,
    pub transaction_timeout: std::time::Duration,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            cpu_usage: 80.0,              // 80% CPU usage
            memory_usage: 85.0,           // 85% memory usage
            disk_usage: 90.0,             // 90% disk usage
            network_errors: 100,          // 100 network errors per minute
            peer_count_min: 3,            // Minimum 3 peers
            block_time_max: std::time::Duration::from_secs(30), // 30 second block time
            transaction_timeout: std::time::Duration::from_secs(300), // 5 minute transaction timeout
        }
    }
}
