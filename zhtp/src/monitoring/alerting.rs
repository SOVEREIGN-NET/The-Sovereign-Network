//! Alert Management and Notification System
//! 
//! Handles alerts, notifications, and incident management for ZHTP node

use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use tokio::sync::{RwLock, mpsc};
use tokio::time::Duration;
use tracing::{info, warn, error, debug};

use crate::monitoring::metrics::SystemMetrics;

/// Alert manager for ZHTP             info!(\"Resolved alert: {} - {} ({})\", alert_id, alert.title, alert.message);\n            // Remove resolved alert from active alerts\n            alerts.retain(|a| a.id != alert_id);ode monitoring
pub struct AlertManager {
    alerts: Arc<RwLock<VecDeque<Alert>>>,
    alert_rules: Arc<RwLock<Vec<AlertRule>>>,
    notification_channels: Arc<RwLock<Vec<Box<dyn NotificationChannel>>>>,
    running: Arc<AtomicBool>,
    alert_counter: Arc<AtomicU64>,
    config: AlertConfig,
    alert_tx: mpsc::UnboundedSender<Alert>,
    alert_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<Alert>>>>,
}

/// Individual alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub level: AlertLevel,
    pub title: String,
    pub message: String,
    pub source: String,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Alert rule for automated alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub condition: AlertCondition,
    pub level: AlertLevel,
    pub enabled: bool,
    pub cooldown: Duration,
    pub last_triggered: Option<u64>,
}

/// Alert condition types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    MetricThreshold {
        metric_name: String,
        operator: ComparisonOperator,
        threshold: f64,
        duration: Duration,
    },
    ComponentStatus {
        component: String,
        status: String,
    },
    NetworkCondition {
        condition_type: NetworkConditionType,
        threshold: f64,
    },
    Custom {
        expression: String,
    },
}

/// Comparison operators for thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Equal,
    NotEqual,
}

/// Network-specific alert conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkConditionType {
    PeerCountBelow,
    ConnectivityBelow,
    LatencyAbove,
    ErrorRateAbove,
    BandwidthBelow,
}

/// Alert configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub max_alerts: usize,
    pub default_cooldown: Duration,
    pub notification_timeout: Duration,
    pub enable_email: bool,
    pub enable_webhook: bool,
    pub enable_console: bool,
    pub enable_dashboard: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            max_alerts: 1000,
            default_cooldown: Duration::from_secs(300), // 5 minutes
            notification_timeout: Duration::from_secs(30),
            enable_email: false,
            enable_webhook: false,
            enable_console: true,
            enable_dashboard: true,
        }
    }
}

/// Notification channel trait
#[async_trait::async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Send a notification
    async fn send_notification(&self, alert: &Alert) -> Result<()>;
    
    /// Channel name for identification
    fn name(&self) -> &str;
    
    /// Check if channel is enabled
    fn is_enabled(&self) -> bool;
}

/// Console notification channel
pub struct ConsoleNotificationChannel {
    enabled: bool,
}

impl ConsoleNotificationChannel {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for ConsoleNotificationChannel {
    async fn send_notification(&self, alert: &Alert) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let level_emoji = match alert.level {
            AlertLevel::Info => "INFO",
            AlertLevel::Warning => "WARNING",
            AlertLevel::Critical => "",
            AlertLevel::Emergency => "EMRG",
        };

        let timestamp = chrono::DateTime::from_timestamp(alert.timestamp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now())
            .format("%Y-%m-%d %H:%M:%S UTC");

        println!("\n{} SOV ALERT [{}] {}", level_emoji, alert.level_str(), timestamp);
        println!("{}: {}", alert.title, alert.message);
        println!("Source: {} | ID: {}", alert.source, alert.id);
        
        if !alert.metadata.is_empty() {
            println!("Metadata:");
            for (key, value) in &alert.metadata {
                println!("   {}: {}", key, value);
            }
        }
        println!();

        Ok(())
    }

    fn name(&self) -> &str {
        "console"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Email notification channel (placeholder)
pub struct EmailNotificationChannel {
    enabled: bool,
    smtp_config: Option<SmtpConfig>,
}

/// SMTP configuration for email notifications
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
}

impl EmailNotificationChannel {
    pub fn new(enabled: bool, smtp_config: Option<SmtpConfig>) -> Self {
        Self { enabled, smtp_config }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for EmailNotificationChannel {
    async fn send_notification(&self, alert: &Alert) -> Result<()> {
        if !self.enabled || self.smtp_config.is_none() {
            return Ok(());
        }

        // email sending implementation
        if let Some(config) = &self.smtp_config {
            // Removed unused std::process::Command import
            
            // Create email content
            let subject = format!("ZHTP Alert: {}", alert.title);
            let body = format!("Alert Details:\nTitle: {}\nLevel: {:?}\nMessage: {}\nTime: {}", 
                alert.title, alert.level, alert.message, alert.timestamp);
            
            // Log the email (in production, this would send via SMTP)
            info!("📧 Email notification prepared for alert: {} - Subject: {} - Recipients: {:?}", 
                alert.id, subject, config.to_addresses);
            
            // For now, write to a notification log file instead of sending email
            tokio::fs::write("./zhtp_alert_notifications.log", 
                format!("Time: {:?}\nSubject: {}\nBody: {}\n\n", 
                    std::time::SystemTime::now(), subject, body)).await?;
        }
        
        debug!("📧 Email notification processed for alert: {}", alert.id);
        Ok(())
    }

    fn name(&self) -> &str {
        "email"
    }

    fn is_enabled(&self) -> bool {
        self.enabled && self.smtp_config.is_some()
    }
}

/// Webhook notification channel
pub struct WebhookNotificationChannel {
    enabled: bool,
    webhook_url: String,
    timeout: Duration,
}

impl WebhookNotificationChannel {
    pub fn new(enabled: bool, webhook_url: String, timeout: Duration) -> Self {
        Self { enabled, webhook_url, timeout }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for WebhookNotificationChannel {
    async fn send_notification(&self, alert: &Alert) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        // webhook implementation using reqwest
        use serde_json::json;

        let payload = json!({
            "alert_id": alert.id,
            "title": alert.title,
            "level": format!("{:?}", alert.level),
            "message": alert.message,
            "timestamp": alert.timestamp,
            "source": alert.source,
            "metadata": alert.metadata
        });

        // Attempt to send webhook with timeout
        let client = reqwest::Client::new();
        let response = tokio::time::timeout(self.timeout,
            client.post(&self.webhook_url)
                .json(&payload)
                .send()
        ).await;

        match response {
            Ok(Ok(resp)) if resp.status().is_success() => {
                info!("Webhook notification sent successfully to {} for alert: {}", self.webhook_url, alert.id);
                Ok(())
            }
            Ok(Ok(resp)) => {
                let error_msg = format!("Webhook responded with error status {}: {}", resp.status(), self.webhook_url);
                error!("{}", error_msg);
                Err(anyhow::anyhow!(error_msg))
            }
            Ok(Err(e)) => {
                let error_msg = format!("Webhook request failed to {}: {}", self.webhook_url, e);
                error!("{}", error_msg);
                Err(anyhow::anyhow!(error_msg))
            }
            Err(_) => {
                let error_msg = format!("Webhook request timed out to {}", self.webhook_url);
                error!("{}", error_msg);
                Err(anyhow::anyhow!(error_msg))
            }
        }
    }

    fn name(&self) -> &str {
        "webhook"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Alert thresholds configuration
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_errors: u64,
    pub peer_count_min: usize,
    pub block_time_max: Duration,
    pub transaction_timeout: Duration,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            cpu_usage: 80.0,
            memory_usage: 85.0,
            disk_usage: 90.0,
            network_errors: 100,
            peer_count_min: 3,
            block_time_max: Duration::from_secs(30),
            transaction_timeout: Duration::from_secs(300),
        }
    }
}

impl AlertManager {
    /// Create a new alert manager
    pub async fn new() -> Result<Self> {
        let (alert_tx, alert_rx) = mpsc::unbounded_channel();
        
        Ok(Self {
            alerts: Arc::new(RwLock::new(VecDeque::new())),
            alert_rules: Arc::new(RwLock::new(Vec::new())),
            notification_channels: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            alert_counter: Arc::new(AtomicU64::new(0)),
            config: AlertConfig::default(),
            alert_tx,
            alert_rx: Arc::new(RwLock::new(Some(alert_rx))),
        })
    }

    /// Create alert manager with custom thresholds
    pub async fn with_thresholds(thresholds: AlertThresholds) -> Result<Self> {
        let manager = Self::new().await?;
        // Store the custom thresholds for use in monitoring
        // Note: AlertConfig doesn't have threshold fields, so we store them separately
        // In a production system, we'd extend AlertConfig or store thresholds in the manager
        tracing::info!("Alert manager initialized with custom thresholds: CPU={}, Memory={}, Disk={}", 
            thresholds.cpu_usage, thresholds.memory_usage, thresholds.disk_usage);
        
        // Apply thresholds by creating rules with the specified values
        manager.add_alert_rule(AlertRule {
            id: "cpu_threshold".to_string(),
            name: "CPU Usage Monitor".to_string(),
            condition: AlertCondition::MetricThreshold {
                metric_name: "cpu_usage".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: thresholds.cpu_usage,
                duration: Duration::from_secs(60), // 1 minute sustained
            },
            level: AlertLevel::Warning,
            enabled: true,
            cooldown: manager.config.default_cooldown,
            last_triggered: None,
        }).await?;
        
        manager.add_alert_rule(AlertRule {
            id: "memory_threshold".to_string(),
            name: "Memory Usage Monitor".to_string(),
            condition: AlertCondition::MetricThreshold {
                metric_name: "memory_usage".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: thresholds.memory_usage,
                duration: Duration::from_secs(60),
            },
            level: AlertLevel::Warning,
            enabled: true,
            cooldown: manager.config.default_cooldown,
            last_triggered: None,
        }).await?;
        
        manager.add_alert_rule(AlertRule {
            id: "disk_threshold".to_string(),
            name: "Disk Usage Monitor".to_string(),
            condition: AlertCondition::MetricThreshold {
                metric_name: "disk_usage".to_string(),
                operator: ComparisonOperator::GreaterThan,
                threshold: thresholds.disk_usage,
                duration: Duration::from_secs(30), // Shorter for critical disk alerts
            },
            level: AlertLevel::Critical,
            enabled: true,
            cooldown: manager.config.default_cooldown,
            last_triggered: None,
        }).await?;
        
        Ok(manager)
    }

    /// Start the alert manager
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        info!(" Starting alert manager...");

        // Initialize default notification channels
        self.setup_default_channels().await?;

        // Start alert processing loop
        let alert_rx = self.alert_rx.write().await.take()
            .ok_or_else(|| anyhow::anyhow!("Alert receiver already taken"))?;
        
        let alerts = self.alerts.clone();
        let channels = self.notification_channels.clone();
        let running = self.running.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            Self::alert_processing_loop(alert_rx, alerts, channels, running, config).await;
        });

        info!("Alert manager started");
        Ok(())
    }

    /// Stop the alert manager
    pub async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        info!(" Alert manager stopped");
        Ok(())
    }

    /// Trigger an alert
    pub async fn trigger_alert(&self, alert: Alert) -> Result<()> {
        let alert_id = self.alert_counter.fetch_add(1, Ordering::SeqCst);
        let mut enhanced_alert = alert;
        
        // Add alert ID if not provided
        if enhanced_alert.id.is_empty() {
            enhanced_alert.id = format!("alert_{}", alert_id);
        }

        // Send alert for processing
        self.alert_tx.send(enhanced_alert)
            .context("Failed to queue alert")?;

        Ok(())
    }

    /// Add an alert rule
    pub async fn add_alert_rule(&self, rule: AlertRule) -> Result<()> {
        let mut rules = self.alert_rules.write().await;
        rules.push(rule);
        Ok(())
    }

    /// Add a notification channel
    pub async fn add_notification_channel(&self, channel: Box<dyn NotificationChannel>) -> Result<()> {
        let mut channels = self.notification_channels.write().await;
        channels.push(channel);
        Ok(())
    }

    /// Get recent alerts
    pub async fn get_recent_alerts(&self, count: usize) -> Result<Vec<Alert>> {
        let alerts = self.alerts.read().await;
        Ok(alerts.iter().rev().take(count).cloned().collect())
    }

    /// Get alert statistics
    pub async fn get_alert_stats(&self) -> Result<AlertStats> {
        let alerts = self.alerts.read().await;
        let total_alerts = alerts.len();
        
        let mut stats_by_level = HashMap::new();
        let mut recent_alerts = 0;
        let now = chrono::Utc::now().timestamp() as u64;
        let hour_ago = now - 3600;

        for alert in alerts.iter() {
            // Count by level
            let level_str = alert.level_str();
            *stats_by_level.entry(level_str.to_string()).or_insert(0) += 1;

            // Count recent alerts (last hour)
            if alert.timestamp > hour_ago {
                recent_alerts += 1;
            }
        }

        Ok(AlertStats {
            total_alerts,
            recent_alerts,
            stats_by_level,
            last_alert_time: alerts.back().map(|a| a.timestamp),
        })
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Result<Vec<Alert>> {
        let alerts = self.alerts.read().await;
        Ok(alerts.iter().cloned().collect())
    }

    /// Get alerts by level
    pub async fn get_alerts_by_level(&self, level: AlertLevel) -> Result<Vec<Alert>> {
        let alerts = self.alerts.read().await;
        Ok(alerts.iter()
            .filter(|alert| alert.level == level)
            .cloned()
            .collect())
    }

    /// Resolve an alert by ID
    pub async fn resolve_alert(&self, alert_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;
        if let Some(_alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            // In a system, we'd mark it as resolved
            info!("Resolved alert: {}", alert_id);
        }
        Ok(())
    }

    /// Process metrics and check for threshold violations
    pub async fn process_metrics(&self, metrics: &SystemMetrics) -> Result<()> {
        // Check CPU threshold
        if metrics.cpu_usage_percent > 90.0 {
            let alert = Alert::new(
                AlertLevel::Critical,
                "High CPU Usage".to_string(),
                format!("CPU usage is {:.1}%", metrics.cpu_usage_percent),
                "system".to_string(),
            );
            self.trigger_alert(alert).await?;
        }

        // Check memory threshold
        let memory_percent = (metrics.memory_usage_bytes as f64 / metrics.memory_total_bytes as f64) * 100.0;
        if memory_percent > 85.0 {
            let alert = Alert::new(
                AlertLevel::Warning,
                "High Memory Usage".to_string(),
                format!("Memory usage is {:.1}%", memory_percent),
                "system".to_string(),
            );
            self.trigger_alert(alert).await?;
        }

        Ok(())
    }

    /// Setup default notification channels
    async fn setup_default_channels(&self) -> Result<()> {
        let mut channels = self.notification_channels.write().await;
        
        // Add console channel
        if self.config.enable_console {
            channels.push(Box::new(ConsoleNotificationChannel::new(true)));
        }

        // Add email channel (disabled by default)
        if self.config.enable_email {
            channels.push(Box::new(EmailNotificationChannel::new(false, None)));
        }

        // Add webhook channel (disabled by default)
        if self.config.enable_webhook {
            channels.push(Box::new(WebhookNotificationChannel::new(
                false,
                "http://localhost:3000/webhook".to_string(),
                self.config.notification_timeout,
            )));
        }

        info!("Setup {} notification channels", channels.len());
        Ok(())
    }

    /// Alert processing loop
    async fn alert_processing_loop(
        mut alert_rx: mpsc::UnboundedReceiver<Alert>,
        alerts: Arc<RwLock<VecDeque<Alert>>>,
        channels: Arc<RwLock<Vec<Box<dyn NotificationChannel>>>>,
        running: Arc<AtomicBool>,
        config: AlertConfig,
    ) {
        while running.load(Ordering::SeqCst) {
            if let Some(alert) = alert_rx.recv().await {
                debug!(" Processing alert: {} - {}", alert.id, alert.title);

                // Store alert
                {
                    let mut alerts_guard = alerts.write().await;
                    alerts_guard.push_back(alert.clone());
                    
                    // Maintain maximum alert count
                    while alerts_guard.len() > config.max_alerts {
                        alerts_guard.pop_front();
                    }
                }

                // Send notifications
                let channels_guard = channels.read().await;
                for channel in channels_guard.iter() {
                    if channel.is_enabled() {
                        if let Err(e) = channel.send_notification(&alert).await {
                            error!("Failed to send notification via {}: {}", channel.name(), e);
                        }
                    }
                }
            }
        }
    }

    /// Setup predefined alert rules
    pub async fn setup_default_alert_rules(&self) -> Result<()> {
        let default_rules = vec![
            AlertRule {
                id: "cpu_high".to_string(),
                name: "High CPU Usage".to_string(),
                condition: AlertCondition::MetricThreshold {
                    metric_name: "cpu_usage_percent".to_string(),
                    operator: ComparisonOperator::GreaterThan,
                    threshold: 80.0,
                    duration: Duration::from_secs(300),
                },
                level: AlertLevel::Warning,
                enabled: true,
                cooldown: Duration::from_secs(600),
                last_triggered: None,
            },
            AlertRule {
                id: "cpu_critical".to_string(),
                name: "Critical CPU Usage".to_string(),
                condition: AlertCondition::MetricThreshold {
                    metric_name: "cpu_usage_percent".to_string(),
                    operator: ComparisonOperator::GreaterThan,
                    threshold: 95.0,
                    duration: Duration::from_secs(60),
                },
                level: AlertLevel::Critical,
                enabled: true,
                cooldown: Duration::from_secs(300),
                last_triggered: None,
            },
            AlertRule {
                id: "memory_high".to_string(),
                name: "High Memory Usage".to_string(),
                condition: AlertCondition::MetricThreshold {
                    metric_name: "memory_usage_percent".to_string(),
                    operator: ComparisonOperator::GreaterThan,
                    threshold: 85.0,
                    duration: Duration::from_secs(300),
                },
                level: AlertLevel::Warning,
                enabled: true,
                cooldown: Duration::from_secs(600),
                last_triggered: None,
            },
            AlertRule {
                id: "peers_low".to_string(),
                name: "Low Peer Count".to_string(),
                condition: AlertCondition::NetworkCondition {
                    condition_type: NetworkConditionType::PeerCountBelow,
                    threshold: 3.0,
                },
                level: AlertLevel::Warning,
                enabled: true,
                cooldown: Duration::from_secs(300),
                last_triggered: None,
            },
            AlertRule {
                id: "mesh_disconnected".to_string(),
                name: "Mesh Network Disconnected".to_string(),
                condition: AlertCondition::NetworkCondition {
                    condition_type: NetworkConditionType::ConnectivityBelow,
                    threshold: 0.1,
                },
                level: AlertLevel::Critical,
                enabled: true,
                cooldown: Duration::from_secs(60),
                last_triggered: None,
            },
        ];

        let mut rules = self.alert_rules.write().await;
        rules.extend(default_rules);
        
        info!("Setup {} default alert rules", rules.len());
        Ok(())
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStats {
    pub total_alerts: usize,
    pub recent_alerts: usize,
    pub stats_by_level: HashMap<String, usize>,
    pub last_alert_time: Option<u64>,
}

impl Alert {
    /// Create a new alert
    pub fn new(
        level: AlertLevel,
        title: String,
        message: String,
        source: String,
    ) -> Self {
        Self {
            id: String::new(), // Will be set by alert manager
            level,
            title,
            message,
            source,
            timestamp: chrono::Utc::now().timestamp() as u64,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the alert
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Get level as string
    pub fn level_str(&self) -> &str {
        match self.level {
            AlertLevel::Info => "INFO",
            AlertLevel::Warning => "WARNING",
            AlertLevel::Critical => "CRITICAL",
            AlertLevel::Emergency => "EMERGENCY",
        }
    }

    /// Check if alert is critical or higher
    pub fn is_critical(&self) -> bool {
        matches!(self.level, AlertLevel::Critical | AlertLevel::Emergency)
    }

    /// Format alert for display
    pub fn format_for_display(&self) -> String {
        let timestamp = chrono::DateTime::from_timestamp(self.timestamp as i64, 0)
            .unwrap_or_else(|| chrono::Utc::now())
            .format("%Y-%m-%d %H:%M:%S UTC");

        format!(
            "[{}] {} - {} | {} ({})",
            self.level_str(),
            timestamp,
            self.title,
            self.message,
            self.source
        )
    }
}
