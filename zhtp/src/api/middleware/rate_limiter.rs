//! Rate Limiting Middleware for API Endpoints
//!
//! Provides IP-based rate limiting using dependency injection pattern.
//! Only counts FAILED attempts - successful requests don't count against the limit.
//! Avoids global state for better testability and flexibility.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_protocols::types::{ZhtpResponse, ZhtpStatus};

/// Configuration for rate limiting
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum FAILED attempts within the window
    pub max_attempts: usize,
    /// Time window in seconds
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 100,       // 100 failed attempts allowed
            window_seconds: 900,     // per 15 minutes
        }
    }
}

/// Rate limiter state for a single IP
#[derive(Clone, Debug)]
struct RateLimitEntry {
    /// Timestamps of recent FAILED attempts
    failed_attempts: Vec<u64>,
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
    /// This checks BEFORE the operation - call record_failed_attempt() after if it fails
    pub async fn check_rate_limit_aggressive(&self, ip: &str, max_attempts: usize, window_seconds: u64) -> Result<(), ZhtpResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut state = self.state.write().await;
        let entry = state.entry(ip.to_string()).or_insert_with(|| RateLimitEntry {
            failed_attempts: Vec::new(),
        });

        // Remove old attempts outside the window
        entry.failed_attempts.retain(|&timestamp| now - timestamp < window_seconds);

        // Check if limit exceeded
        if entry.failed_attempts.len() >= max_attempts {
            tracing::warn!(
                "Aggressive rate limit exceeded for IP {} ({} failed attempts in window)",
                ip,
                entry.failed_attempts.len()
            );

            return Err(ZhtpResponse::error(
                ZhtpStatus::TooManyRequests,
                format!("Too many failed attempts. Please try again later."),
            ));
        }

        Ok(())
    }

    /// Check if an IP is allowed to proceed (check BEFORE operation)
    /// Only checks against failed attempts - successful requests don't count
    pub async fn check_rate_limit(&self, ip: &str) -> Result<(), ZhtpResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut state = self.state.write().await;
        let entry = state.entry(ip.to_string()).or_insert_with(|| RateLimitEntry {
            failed_attempts: Vec::new(),
        });

        // Remove old attempts outside the window
        entry.failed_attempts.retain(|&timestamp| now - timestamp < self.config.window_seconds);

        // Check if limit exceeded
        if entry.failed_attempts.len() >= self.config.max_attempts {
            tracing::warn!(
                "Rate limit exceeded for IP {} ({} failed attempts in {} seconds)",
                ip,
                entry.failed_attempts.len(),
                self.config.window_seconds
            );

            return Err(ZhtpResponse::error(
                ZhtpStatus::TooManyRequests,
                "Too many failed attempts. Please try again later.".to_string(),
            ));
        }

        Ok(())
    }

    /// Record a failed attempt for an IP (call AFTER operation fails)
    pub async fn record_failed_attempt(&self, ip: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut state = self.state.write().await;
        let entry = state.entry(ip.to_string()).or_insert_with(|| RateLimitEntry {
            failed_attempts: Vec::new(),
        });

        entry.failed_attempts.push(now);
        tracing::debug!("Recorded failed attempt for IP {} (total: {})", ip, entry.failed_attempts.len());
    }

    /// Clear failed attempts for an IP (call after successful auth to reset)
    pub async fn clear_failed_attempts(&self, ip: &str) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.get_mut(ip) {
            entry.failed_attempts.clear();
            tracing::debug!("Cleared failed attempts for IP {}", ip);
        }
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
            entry.failed_attempts.retain(|&ts| now - ts < self.config.window_seconds);
            !entry.failed_attempts.is_empty()
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
            total_failed_attempts: state.values().map(|e| e.failed_attempts.len()).sum(),
        }
    }
}

/// Statistics for monitoring
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub tracked_ips: usize,
    pub total_failed_attempts: usize,
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
    async fn test_rate_limiter_only_counts_failures() {
        let config = RateLimitConfig {
            max_attempts: 5,
            window_seconds: 900,
        };
        let limiter = RateLimiter::with_config(config);

        // Successful checks don't count - should always pass
        for _ in 0..100 {
            assert!(limiter.check_rate_limit("test_ip").await.is_ok());
        }

        // Record 5 failures
        for _ in 0..5 {
            limiter.record_failed_attempt("test_ip").await;
        }

        // Now should be rate limited
        assert!(limiter.check_rate_limit("test_ip").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_seconds: 900,
        };
        let limiter = RateLimiter::with_config(config);

        // Record failures for ip1 only
        for _ in 0..3 {
            limiter.record_failed_attempt("ip1").await;
        }

        // ip1 should be rate limited, ip2 should not
        assert!(limiter.check_rate_limit("ip1").await.is_err());
        assert!(limiter.check_rate_limit("ip2").await.is_ok());
    }

    #[tokio::test]
    async fn test_clear_failed_attempts() {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_seconds: 900,
        };
        let limiter = RateLimiter::with_config(config);

        // Record failures
        for _ in 0..3 {
            limiter.record_failed_attempt("test_ip").await;
        }

        // Should be rate limited
        assert!(limiter.check_rate_limit("test_ip").await.is_err());

        // Clear attempts (e.g., after successful login)
        limiter.clear_failed_attempts("test_ip").await;

        // Should be allowed again
        assert!(limiter.check_rate_limit("test_ip").await.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let limiter = RateLimiter::new();

        // Record some failures
        for _ in 0..5 {
            limiter.record_failed_attempt("test_ip").await;
        }

        // Verify tracked
        let stats = limiter.stats().await;
        assert_eq!(stats.tracked_ips, 1);
        assert_eq!(stats.total_failed_attempts, 5);

        // Cleanup shouldn't remove recent attempts
        limiter.cleanup().await;
        let stats = limiter.stats().await;
        assert_eq!(stats.tracked_ips, 1);
    }
}
