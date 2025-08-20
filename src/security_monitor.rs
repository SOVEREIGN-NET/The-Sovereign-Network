use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use log::{warn, error, info};
use std::time::{SystemTime, UNIX_EPOCH};

/// Production security monitoring system for ZHTP mainnet
#[derive(Debug)]
pub struct ZhtpSecurityMonitor {
    /// Connection rate limiting per IP
    rate_limits: Arc<RwLock<HashMap<String, RateLimit>>>,
    /// Suspicious activity tracking
    security_events: Arc<RwLock<Vec<SecurityEvent>>>,
    /// Blacklisted IPs and addresses
    blacklist: Arc<RwLock<HashSet<String>>>,
    /// Security configuration
    config: SecurityConfig,
    /// Metrics collector
    metrics: Arc<SecurityMetrics>,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    requests: Vec<Instant>,
    last_violation: Option<Instant>,
    violation_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub timestamp: u64,
    pub event_type: SecurityEventType,
    pub source_ip: String,
    pub details: String,
    pub severity: SecuritySeverity,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecurityEventType {
    RateLimitExceeded,
    InvalidAuthentication,
    SuspiciousActivity,
    MalformedRequest,
    UnauthorizedAccess,
    DDoSAttempt,
    QuantumAttackAttempt,
    ConsensusAttack,
}

#[derive(Debug, Clone, Serialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub rate_limit_requests_per_minute: u32,
    pub rate_limit_window_seconds: u64,
    pub blacklist_threshold: u32,
    pub blacklist_duration_hours: u64,
    pub enable_quantum_detection: bool,
    pub enable_consensus_monitoring: bool,
    pub auto_ban_enabled: bool,
    pub alert_webhook_url: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit_requests_per_minute: 100,
            rate_limit_window_seconds: 60,
            blacklist_threshold: 10,
            blacklist_duration_hours: 24,
            enable_quantum_detection: true,
            enable_consensus_monitoring: true,
            auto_ban_enabled: true,
            alert_webhook_url: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct SecurityMetrics {
    pub total_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub security_events: AtomicU64,
    pub active_blacklisted_ips: AtomicU64,
}

impl ZhtpSecurityMonitor {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            security_events: Arc::new(RwLock::new(Vec::new())),
            blacklist: Arc::new(RwLock::new(HashSet::new())),
            config,
            metrics: Arc::new(SecurityMetrics::default()),
        }
    }

    /// Check if a request should be allowed
    pub async fn check_request(&self, source_ip: &str, endpoint: &str) -> Result<bool> {
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check blacklist first
        if self.is_blacklisted(source_ip).await {
            self.metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Check rate limits
        if !self.check_rate_limit(source_ip).await? {
            self.log_security_event(
                SecurityEventType::RateLimitExceeded,
                source_ip,
                format!("Rate limit exceeded for endpoint: {}", endpoint),
                SecuritySeverity::Medium,
            ).await;
            
            self.metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        // Check for suspicious patterns
        if self.detect_suspicious_activity(source_ip, endpoint).await {
            self.log_security_event(
                SecurityEventType::SuspiciousActivity,
                source_ip,
                format!("Suspicious activity detected for endpoint: {}", endpoint),
                SecuritySeverity::High,
            ).await;
            
            self.metrics.blocked_requests.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }

        Ok(true)
    }

    /// Check rate limiting for an IP
    async fn check_rate_limit(&self, source_ip: &str) -> Result<bool> {
        let mut rate_limits = self.rate_limits.write().await;
        let now = Instant::now();
        let window = Duration::from_secs(self.config.rate_limit_window_seconds);

        let rate_limit = rate_limits.entry(source_ip.to_string()).or_insert(RateLimit {
            requests: Vec::new(),
            last_violation: None,
            violation_count: 0,
        });

        // Remove old requests outside the window
        rate_limit.requests.retain(|&timestamp| now.duration_since(timestamp) < window);

        // Check if under rate limit
        if rate_limit.requests.len() < self.config.rate_limit_requests_per_minute as usize {
            rate_limit.requests.push(now);
            return Ok(true);
        }

        // Rate limit exceeded
        rate_limit.last_violation = Some(now);
        rate_limit.violation_count += 1;

        // Auto-ban if threshold exceeded
        if self.config.auto_ban_enabled && rate_limit.violation_count >= self.config.blacklist_threshold {
            self.add_to_blacklist(source_ip).await;
            warn!("Auto-banned IP {} for repeated rate limit violations", source_ip);
        }

        Ok(false)
    }

    /// Detect suspicious activity patterns
    async fn detect_suspicious_activity(&self, _source_ip: &str, endpoint: &str) -> bool {
        // Check for suspicious endpoints
        let suspicious_endpoints = [
            "/admin", "/.env", "/wp-admin", "/config", 
            "/../", "/etc/", "/var/", "/root/",
            "/.git", "/backup", "/dump", "/phpMyAdmin",
            "/mysql", "/database", "/db", "/.ssh", "/keys"
        ];

        if suspicious_endpoints.iter().any(|&sus| endpoint.contains(sus)) {
            return true;
        }

        // Check for SQL injection attempts
        let sql_patterns = ["'", "union", "select", "drop", "insert", "delete", "update", "exec"];
        let endpoint_lower = endpoint.to_lowercase();
        if sql_patterns.iter().any(|&pattern| endpoint_lower.contains(pattern)) {
            return true;
        }

        // Check for path traversal attempts
        if endpoint.contains("..") || endpoint.contains("%2e%2e") {
            return true;
        }

        false
    }

    /// Check if an IP is blacklisted
    pub async fn is_blacklisted(&self, source_ip: &str) -> bool {
        let blacklist = self.blacklist.read().await;
        blacklist.contains(source_ip)
    }

    /// Add IP to blacklist
    async fn add_to_blacklist(&self, source_ip: &str) {
        let mut blacklist = self.blacklist.write().await;
        blacklist.insert(source_ip.to_string());
        
        self.metrics.active_blacklisted_ips.fetch_add(1, Ordering::Relaxed);
        
        // Schedule removal after blacklist duration
        let blacklist_clone = self.blacklist.clone();
        let metrics_clone = self.metrics.clone();
        let ip = source_ip.to_string();
        let duration = Duration::from_secs(self.config.blacklist_duration_hours * 3600);
        
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            let mut blacklist = blacklist_clone.write().await;
            blacklist.remove(&ip);
            metrics_clone.active_blacklisted_ips.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Log security event
    pub async fn log_security_event(
        &self,
        event_type: SecurityEventType,
        source_ip: &str,
        details: String,
        severity: SecuritySeverity,
    ) {
        let event = SecurityEvent {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: event_type.clone(),
            source_ip: source_ip.to_string(),
            details: details.clone(),
            severity: severity.clone(),
        };

        self.metrics.security_events.fetch_add(1, Ordering::Relaxed);

        // Log to system
        match severity {
            SecuritySeverity::Critical => error!("SECURITY: {:?} from {}: {}", event_type, source_ip, details),
            SecuritySeverity::High => warn!("SECURITY: {:?} from {}: {}", event_type, source_ip, details),
            SecuritySeverity::Medium => warn!("SECURITY: {:?} from {}: {}", event_type, source_ip, details),
            SecuritySeverity::Low => info!("SECURITY: {:?} from {}: {}", event_type, source_ip, details),
        }

        // Store event
        let mut events = self.security_events.write().await;
        events.push(event.clone());

        // Keep only last 10000 events to prevent memory issues
        if events.len() > 10000 {
            events.remove(0);
        }

        // Send alert webhook if configured and severity is high
        if let Some(webhook_url) = &self.config.alert_webhook_url {
            if matches!(severity, SecuritySeverity::High | SecuritySeverity::Critical) {
                self.send_alert_webhook(webhook_url, &event).await;
            }
        }
    }

    /// Send alert to webhook
    async fn send_alert_webhook(&self, webhook_url: &str, event: &SecurityEvent) {
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "timestamp": event.timestamp,
            "type": format!("{:?}", event.event_type),
            "source_ip": event.source_ip,
            "details": event.details,
            "severity": format!("{:?}", event.severity),
            "service": "ZHTP-Node"
        });

        if let Err(e) = client.post(webhook_url)
            .json(&payload)
            .timeout(Duration::from_secs(5))
            .send()
            .await {
            error!("Failed to send security alert webhook: {}", e);
        }
    }

    /// Get security metrics for monitoring
    pub fn get_metrics(&self) -> SecurityMetricsSnapshot {
        SecurityMetricsSnapshot {
            total_requests: self.metrics.total_requests.load(Ordering::Relaxed),
            blocked_requests: self.metrics.blocked_requests.load(Ordering::Relaxed),
            security_events: self.metrics.security_events.load(Ordering::Relaxed),
            active_blacklisted_ips: self.metrics.active_blacklisted_ips.load(Ordering::Relaxed),
            block_rate: {
                let total = self.metrics.total_requests.load(Ordering::Relaxed);
                let blocked = self.metrics.blocked_requests.load(Ordering::Relaxed);
                if total > 0 { (blocked as f64 / total as f64) * 100.0 } else { 0.0 }
            },
        }
    }

    /// Get recent security events
    pub async fn get_recent_events(&self, limit: usize) -> Vec<SecurityEvent> {
        let events = self.security_events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Manually blacklist an IP
    pub async fn manual_blacklist(&self, ip: &str, reason: String) {
        self.add_to_blacklist(ip).await;
        self.log_security_event(
            SecurityEventType::UnauthorizedAccess,
            ip,
            format!("Manually blacklisted: {}", reason),
            SecuritySeverity::High,
        ).await;
    }

    /// Remove IP from blacklist
    pub async fn remove_from_blacklist(&self, ip: &str) {
        let mut blacklist = self.blacklist.write().await;
        if blacklist.remove(ip) {
            self.metrics.active_blacklisted_ips.fetch_sub(1, Ordering::Relaxed);
            info!("Removed IP {} from blacklist", ip);
        }
    }

    /// Get security metrics
    pub async fn get_security_metrics(&self) -> SecurityMetricsSnapshot {
        self.get_metrics()
    }

    /// Get overall security status
    pub async fn get_overall_status(&self) -> String {
        let events = self.security_events.read().await;
        let recent_critical = events.iter()
            .rev()
            .take(10)
            .any(|e| matches!(e.severity, SecuritySeverity::High));
        
        if recent_critical {
            "CRITICAL".to_string()
        } else if events.len() > 100 {
            "WARNING".to_string()
        } else {
            "HEALTHY".to_string()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SecurityMetricsSnapshot {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub security_events: u64,
    pub active_blacklisted_ips: u64,
    pub block_rate: f64, // Percentage
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_security_monitor_creation() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);
        
        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.blocked_requests, 0);
        assert_eq!(metrics.security_events, 0);
        assert_eq!(metrics.active_blacklisted_ips, 0);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = SecurityConfig::default();
        config.rate_limit_requests_per_minute = 2; // Very low for testing
        let monitor = ZhtpSecurityMonitor::new(config);

        // First two requests should pass
        assert!(monitor.check_request("127.0.0.1", "/api/test").await.unwrap());
        assert!(monitor.check_request("127.0.0.1", "/api/test").await.unwrap());

        // Third request should be blocked
        assert!(!monitor.check_request("127.0.0.1", "/api/test").await.unwrap());

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.blocked_requests, 1);
    }

    #[tokio::test]
    async fn test_suspicious_endpoint_detection() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);

        // Normal endpoint should pass
        assert!(monitor.check_request("127.0.0.1", "/api/balance").await.unwrap());

        // Suspicious endpoints should be blocked
        assert!(!monitor.check_request("127.0.0.1", "/admin").await.unwrap());
        assert!(!monitor.check_request("127.0.0.1", "/.env").await.unwrap());
        assert!(!monitor.check_request("127.0.0.1", "/wp-admin").await.unwrap());
        assert!(!monitor.check_request("127.0.0.1", "/../etc/passwd").await.unwrap());

        let metrics = monitor.get_metrics();
        assert!(metrics.security_events > 0);
    }

    #[tokio::test]
    async fn test_sql_injection_detection() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);

        // SQL injection attempts should be blocked
        assert!(!monitor.check_request("127.0.0.1", "/api/user?id=1' OR '1'='1").await.unwrap());
        assert!(!monitor.check_request("127.0.0.1", "/api/data?query=SELECT * FROM users").await.unwrap());
        assert!(!monitor.check_request("127.0.0.1", "/api/admin?cmd=DROP TABLE users").await.unwrap());
    }

    #[tokio::test]
    async fn test_path_traversal_detection() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);

        // Path traversal attempts should be blocked
        assert!(!monitor.check_request("127.0.0.1", "/api/../../../etc/passwd").await.unwrap());
        assert!(!monitor.check_request("127.0.0.1", "/files?path=..%2F..%2Fetc%2Fpasswd").await.unwrap());
    }

    #[tokio::test]
    async fn test_blacklist_functionality() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);

        // Initially should not be blacklisted
        assert!(!monitor.is_blacklisted("192.168.1.1").await);

        // Manual blacklist
        monitor.manual_blacklist("192.168.1.1", "Test blacklist".to_string()).await;
        assert!(monitor.is_blacklisted("192.168.1.1").await);

        // Blacklisted IP should be blocked
        assert!(!monitor.check_request("192.168.1.1", "/api/test").await.unwrap());

        // Remove from blacklist
        monitor.remove_from_blacklist("192.168.1.1").await;
        assert!(!monitor.is_blacklisted("192.168.1.1").await);
    }

    #[tokio::test]
    async fn test_auto_ban_on_violations() {
        let mut config = SecurityConfig::default();
        config.rate_limit_requests_per_minute = 1;
        config.blacklist_threshold = 2;
        config.auto_ban_enabled = true;
        let monitor = ZhtpSecurityMonitor::new(config);

        let test_ip = "10.0.0.1";

        // Trigger rate limit violations
        assert!(monitor.check_request(test_ip, "/api/test").await.unwrap()); // First request OK
        assert!(!monitor.check_request(test_ip, "/api/test").await.unwrap()); // Second blocked
        assert!(!monitor.check_request(test_ip, "/api/test").await.unwrap()); // Third blocked and should trigger auto-ban

        // IP should now be blacklisted
        assert!(monitor.is_blacklisted(test_ip).await);
    }

    #[tokio::test]
    async fn test_security_metrics() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);

        // Generate some traffic
        monitor.check_request("127.0.0.1", "/api/test").await.unwrap();
        monitor.check_request("127.0.0.1", "/admin").await.unwrap(); // Should be blocked
        monitor.manual_blacklist("192.168.1.1", "Test".to_string()).await;

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_requests, 2);
        assert_eq!(metrics.blocked_requests, 1);
        assert_eq!(metrics.active_blacklisted_ips, 1);
        assert_eq!(metrics.block_rate, 50.0);
    }

    #[tokio::test]
    async fn test_security_events_logging() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);

        // Trigger security events
        monitor.check_request("127.0.0.1", "/admin").await.unwrap();
        monitor.check_request("127.0.0.1", "/.env").await.unwrap();

        let events = monitor.get_recent_events(10).await;
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| matches!(e.event_type, SecurityEventType::SuspiciousActivity)));
    }

    #[tokio::test]
    async fn test_overall_status() {
        let config = SecurityConfig::default();
        let monitor = ZhtpSecurityMonitor::new(config);

        // Initial status should be healthy
        let status = monitor.get_overall_status().await;
        assert_eq!(status, "HEALTHY");

        // After some suspicious activity, status should change
        for _ in 0..10 {
            monitor.check_request("127.0.0.1", "/admin").await.unwrap();
        }

        let status = monitor.get_overall_status().await;
        assert_eq!(status, "WARNING");
    }

    #[tokio::test]
    async fn test_rate_limit_window_reset() {
        let mut config = SecurityConfig::default();
        config.rate_limit_requests_per_minute = 1;
        config.rate_limit_window_seconds = 1; // 1 second window for testing
        let monitor = ZhtpSecurityMonitor::new(config);

        let test_ip = "10.0.0.2";

        // First request should pass
        assert!(monitor.check_request(test_ip, "/api/test").await.unwrap());

        // Second request should be blocked (rate limited)
        assert!(!monitor.check_request(test_ip, "/api/test").await.unwrap());

        // Wait for window to reset
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be able to make request again
        assert!(monitor.check_request(test_ip, "/api/test").await.unwrap());
    }
}

// (removed duplicate import of HashSet)
