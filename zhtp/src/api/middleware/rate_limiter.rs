//! Rate Limiting Middleware for API Endpoints
//!
//! Provides IP-based rate limiting using dependency injection pattern.
//! Avoids global state for better testability and flexibility.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

/// Configuration for rate limiting
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum attempts within the window
    pub max_attempts: usize,
    /// Time window in seconds
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            window_seconds: 900, // 15 minutes
        }
    }
}

/// Rate limiter state for a single IP
#[derive(Clone, Debug)]
struct RateLimitEntry {
    /// Timestamps of recent attempts
    attempts: Vec<u64>,
}

/// Rate limiter that can be injected as a dependency
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    state: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
}

impl RateLimiter {
    /// Create a new rate limiter with default config
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a rate limiter with custom config
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check rate limit with custom limits (for critical operations like recovery)
    pub async fn check_rate_limit_aggressive(&self, ip: &str, max_attempts: usize, window_seconds: u64) -> Result<(), ZhtpResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut state = self.state.write().await;
        let entry = state.entry(ip.to_string()).or_insert_with(|| RateLimitEntry {
            attempts: Vec::new(),
        });

        // Remove old attempts outside the window
        entry.attempts.retain(|&timestamp| now - timestamp < window_seconds);

        // Check if limit exceeded
        if entry.attempts.len() >= max_attempts {
            tracing::warn!(
                "Aggressive rate limit exceeded for IP {} (attempt #{}/{})",
                ip,
                entry.attempts.len() + 1,
                max_attempts
            );

            return Err(ZhtpResponse::error(
                ZhtpStatus::TooManyRequests,
                format!("Too many attempts. Please try again later."),
            ));
        }

        // Record this attempt
        entry.attempts.push(now);
        Ok(())
    }

    /// Check if an IP is allowed to proceed
    pub async fn check_rate_limit(&self, ip: &str) -> Result<(), ZhtpResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut state = self.state.write().await;
        let entry = state.entry(ip.to_string()).or_insert_with(|| RateLimitEntry {
            attempts: Vec::new(),
        });

        // Remove old attempts outside the window
        entry.attempts.retain(|&timestamp| now - timestamp < self.config.window_seconds);

        // Check if limit exceeded
        if entry.attempts.len() >= self.config.max_attempts {
            tracing::warn!(
                "Rate limit exceeded for IP {} (attempt #{}/{})",
                ip,
                entry.attempts.len() + 1,
                self.config.max_attempts
            );

            return Err(ZhtpResponse::error(
                ZhtpStatus::TooManyRequests,
                "Too many authentication attempts. Please try again later.".to_string(),
            ));
        }

        // Record this attempt
        entry.attempts.push(now);
        Ok(())
    }

    /// Clean up old entries (prevents unbounded growth)
    pub async fn cleanup(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut state = self.state.write().await;

        // P2 fix: Prevent unbounded HashMap growth
        state.retain(|_, entry| {
            entry.attempts.retain(|&ts| now - ts < self.config.window_seconds);
            !entry.attempts.is_empty()
        });

        let entries_remaining = state.len();
        drop(state);

        if entries_remaining > 0 {
            tracing::debug!("Rate limiter cleanup: {} IPs tracked", entries_remaining);
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(&self) {
        let limiter = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                limiter.cleanup().await;
            }
        });
    }

    /// Get current stats for monitoring
    pub async fn stats(&self) -> RateLimiterStats {
        let state = self.state.read().await;
        RateLimiterStats {
            tracked_ips: state.len(),
            total_attempts: state.values().map(|e| e.attempts.len()).sum(),
        }
    }
}

/// Statistics for monitoring
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub tracked_ips: usize,
    pub total_attempts: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new();

        // First 10 attempts should succeed
        for i in 0..10 {
            assert!(limiter.check_rate_limit("test_ip").await.is_ok(), "Attempt {} should succeed", i);
        }

        // 11th attempt should fail
        assert!(limiter.check_rate_limit("test_ip").await.is_err(), "11th attempt should fail");
    }

    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new();

        // Different IPs should have separate limits
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("ip1").await.is_ok());
            assert!(limiter.check_rate_limit("ip2").await.is_ok());
        }

        // Both IPs should now be rate limited
        assert!(limiter.check_rate_limit("ip1").await.is_err());
        assert!(limiter.check_rate_limit("ip2").await.is_err());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let limiter = RateLimiter::new();

        // Add some attempts
        for _ in 0..5 {
            limiter.check_rate_limit("test_ip").await.ok();
        }

        // Verify tracked
        let stats = limiter.stats().await;
        assert_eq!(stats.tracked_ips, 1);

        // Cleanup shouldn't remove recent attempts
        limiter.cleanup().await;
        let stats = limiter.stats().await;
        assert_eq!(stats.tracked_ips, 1);
    }
}
