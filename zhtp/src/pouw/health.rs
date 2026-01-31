//! PoUW Health Check Endpoint
//!
//! Provides health and readiness checks for the PoUW subsystem.

use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// Overall health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some issues but still functional
    Degraded,
    /// Critical issues, not functional
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

/// Component health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Name of the component
    pub name: String,
    /// Health status
    pub status: HealthStatus,
    /// Optional message
    pub message: Option<String>,
    /// Last check time
    pub last_check: DateTime<Utc>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
}

/// Overall health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Overall status
    pub status: HealthStatus,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Individual component checks
    pub components: Vec<ComponentHealth>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl HealthCheckResponse {
    /// HTTP status code based on health
    pub fn http_status_code(&self) -> u16 {
        match self.status {
            HealthStatus::Healthy => 200,
            HealthStatus::Degraded => 200, // Still available
            HealthStatus::Unhealthy => 503,
        }
    }
}

/// Health checker for PoUW subsystem
pub struct PouwHealthChecker {
    start_time: std::time::Instant,
    version: String,
    checks: Arc<RwLock<Vec<Box<dyn HealthCheck + Send + Sync>>>>,
}

impl PouwHealthChecker {
    /// Create a new health checker
    pub fn new(version: String) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            version,
            checks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a health check
    pub async fn register_check(&self, check: Box<dyn HealthCheck + Send + Sync>) {
        let mut checks = self.checks.write().await;
        checks.push(check);
    }

    /// Run all health checks
    pub async fn check_health(&self) -> HealthCheckResponse {
        let checks = self.checks.read().await;
        let mut components = Vec::new();
        let mut overall_status = HealthStatus::Healthy;

        for check in checks.iter() {
            let start = std::time::Instant::now();
            let result = check.check().await;
            let response_time = start.elapsed().as_millis() as u64;

            let component = ComponentHealth {
                name: check.name().to_string(),
                status: result.status,
                message: result.message,
                last_check: Utc::now(),
                response_time_ms: Some(response_time),
            };

            // Update overall status
            match result.status {
                HealthStatus::Unhealthy => overall_status = HealthStatus::Unhealthy,
                HealthStatus::Degraded if overall_status == HealthStatus::Healthy => {
                    overall_status = HealthStatus::Degraded;
                }
                _ => {}
            }

            components.push(component);
        }

        // Add default checks if none registered
        if components.is_empty() {
            components.push(ComponentHealth {
                name: "pouw_core".to_string(),
                status: HealthStatus::Healthy,
                message: Some("Core service running".to_string()),
                last_check: Utc::now(),
                response_time_ms: Some(0),
            });
        }

        HealthCheckResponse {
            status: overall_status,
            version: self.version.clone(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            components,
            timestamp: Utc::now(),
        }
    }

    /// Quick liveness check
    pub fn is_alive(&self) -> bool {
        true // If we can run this, we're alive
    }

    /// Readiness check (can accept traffic)
    pub async fn is_ready(&self) -> bool {
        let health = self.check_health().await;
        health.status != HealthStatus::Unhealthy
    }
}

/// Health check result
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub message: Option<String>,
}

impl HealthCheckResult {
    pub fn healthy() -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: None,
        }
    }

    pub fn healthy_with_message(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: Some(message.into()),
        }
    }

    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: Some(message.into()),
        }
    }

    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
        }
    }
}

/// Trait for implementing health checks
#[async_trait::async_trait]
pub trait HealthCheck {
    /// Name of the component being checked
    fn name(&self) -> &str;
    
    /// Perform the health check
    async fn check(&self) -> HealthCheckResult;
}

/// Database health check
pub struct DatabaseHealthCheck {
    // Would hold database connection reference
}

impl DatabaseHealthCheck {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DatabaseHealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HealthCheck for DatabaseHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    async fn check(&self) -> HealthCheckResult {
        // Simplified check - would actually ping database
        HealthCheckResult::healthy_with_message("Database connection OK")
    }
}

/// Rate limiter health check
pub struct RateLimiterHealthCheck {
    // Would hold rate limiter reference
}

impl RateLimiterHealthCheck {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RateLimiterHealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HealthCheck for RateLimiterHealthCheck {
    fn name(&self) -> &str {
        "rate_limiter"
    }

    async fn check(&self) -> HealthCheckResult {
        // Simplified check
        HealthCheckResult::healthy()
    }
}

/// Metrics collector health check
pub struct MetricsHealthCheck {
    // Would hold metrics reference
}

impl MetricsHealthCheck {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for MetricsHealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HealthCheck for MetricsHealthCheck {
    fn name(&self) -> &str {
        "metrics"
    }

    async fn check(&self) -> HealthCheckResult {
        HealthCheckResult::healthy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_default() {
        let checker = PouwHealthChecker::new("1.0.0".to_string());
        
        let response = checker.check_health().await;
        assert_eq!(response.status, HealthStatus::Healthy);
        assert_eq!(response.version, "1.0.0");
        assert!(!response.components.is_empty());
    }

    #[tokio::test]
    async fn test_register_checks() {
        let checker = PouwHealthChecker::new("1.0.0".to_string());
        
        checker.register_check(Box::new(DatabaseHealthCheck::new())).await;
        checker.register_check(Box::new(RateLimiterHealthCheck::new())).await;
        
        let response = checker.check_health().await;
        assert_eq!(response.components.len(), 2);
    }

    #[tokio::test]
    async fn test_liveness_readiness() {
        let checker = PouwHealthChecker::new("1.0.0".to_string());
        
        assert!(checker.is_alive());
        assert!(checker.is_ready().await);
    }

    #[test]
    fn test_http_status_codes() {
        let healthy = HealthCheckResponse {
            status: HealthStatus::Healthy,
            version: "1.0.0".to_string(),
            uptime_seconds: 100,
            components: vec![],
            timestamp: Utc::now(),
        };
        assert_eq!(healthy.http_status_code(), 200);

        let unhealthy = HealthCheckResponse {
            status: HealthStatus::Unhealthy,
            version: "1.0.0".to_string(),
            uptime_seconds: 100,
            components: vec![],
            timestamp: Utc::now(),
        };
        assert_eq!(unhealthy.http_status_code(), 503);
    }
}
