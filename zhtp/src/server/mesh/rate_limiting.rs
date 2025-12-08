//! Connection Rate Limiting (HIGH-4 Security Fix)
//!
//! Implements per-IP and per-DID rate limiting with exponential backoff
//! to prevent DoS attacks and connection flooding.
//!
//! # Security Features
//!
//! 1. **Per-IP Rate Limiting**: Limits connection attempts per IP address
//! 2. **Per-DID Rate Limiting**: Limits connection attempts per blockchain DID
//! 3. **Exponential Backoff**: Increasing delays for repeated failures
//! 4. **Automatic Cleanup**: Expired entries removed periodically
//! 5. **Audit Logging**: All rate limit violations logged for security monitoring

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, warn, info};

/// Global counter for rate limit violations (for security monitoring)
static RATE_LIMIT_VIOLATIONS: AtomicU64 = AtomicU64::new(0);

/// Get total rate limit violations for monitoring
pub fn get_rate_limit_violation_count() -> u64 {
    RATE_LIMIT_VIOLATIONS.load(Ordering::Relaxed)
}

/// Rate limit entry for a single IP or DID
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    /// Number of connection attempts in current window
    pub attempt_count: u32,
    /// Start of current rate limit window (Unix timestamp)
    pub window_start: u64,
    /// Number of consecutive windows with violations
    pub violation_count: u32,
    /// Time until which this entity is blocked (Unix timestamp, 0 = not blocked)
    pub blocked_until: u64,
    /// Last attempt timestamp
    pub last_attempt: u64,
}

impl RateLimitEntry {
    pub fn new() -> Self {
        let now = current_timestamp();
        Self {
            attempt_count: 0,
            window_start: now,
            violation_count: 0,
            blocked_until: 0,
            last_attempt: now,
        }
    }

    /// Check if currently blocked
    pub fn is_blocked(&self) -> bool {
        self.blocked_until > current_timestamp()
    }

    /// Get remaining block time in seconds
    pub fn block_remaining_secs(&self) -> u64 {
        let now = current_timestamp();
        if self.blocked_until > now {
            self.blocked_until - now
        } else {
            0
        }
    }
}

/// Connection rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum connection attempts per IP per window
    pub max_attempts_per_ip: u32,
    /// Maximum connection attempts per DID per window
    pub max_attempts_per_did: u32,
    /// Window duration in seconds
    pub window_secs: u64,
    /// Base block duration in seconds (exponential backoff)
    pub base_block_secs: u64,
    /// Maximum block duration in seconds
    pub max_block_secs: u64,
    /// Cleanup interval in seconds
    pub cleanup_interval_secs: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_ip: 10,      // 10 connection attempts per IP per window
            max_attempts_per_did: 5,       // 5 connection attempts per DID per window
            window_secs: 60,               // 1 minute window
            base_block_secs: 30,           // Start with 30 second block
            max_block_secs: 3600,          // Max 1 hour block
            cleanup_interval_secs: 300,    // Cleanup every 5 minutes
        }
    }
}

/// Connection rate limiter for DoS protection
pub struct ConnectionRateLimiter {
    /// Rate limit entries by IP address
    ip_limits: RwLock<HashMap<IpAddr, RateLimitEntry>>,
    /// Rate limit entries by DID
    did_limits: RwLock<HashMap<String, RateLimitEntry>>,
    /// Configuration
    config: RateLimiterConfig,
}

impl ConnectionRateLimiter {
    /// Create a new rate limiter with default configuration
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// Create a new rate limiter with custom configuration
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            ip_limits: RwLock::new(HashMap::new()),
            did_limits: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Check if a connection attempt from an IP is allowed
    /// Returns Ok(()) if allowed, Err(block_duration) if blocked
    pub async fn check_ip(&self, ip: IpAddr) -> Result<(), Duration> {
        let mut limits = self.ip_limits.write().await;
        let now = current_timestamp();

        let entry = limits.entry(ip).or_insert_with(RateLimitEntry::new);

        // Check if blocked
        if entry.is_blocked() {
            let remaining = entry.block_remaining_secs();
            warn!("🚫 RATE LIMIT: IP {} blocked for {} more seconds (violations: {})",
                  ip, remaining, entry.violation_count);
            RATE_LIMIT_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            return Err(Duration::from_secs(remaining));
        }

        // Reset window if expired
        if now - entry.window_start >= self.config.window_secs {
            entry.attempt_count = 0;
            entry.window_start = now;
        }

        // Increment attempt count
        entry.attempt_count += 1;
        entry.last_attempt = now;

        // Check if over limit
        if entry.attempt_count > self.config.max_attempts_per_ip {
            entry.violation_count += 1;

            // Calculate exponential backoff: base * 2^(violations-1), capped at max
            let backoff = std::cmp::min(
                self.config.base_block_secs * (1 << (entry.violation_count.saturating_sub(1))),
                self.config.max_block_secs
            );
            entry.blocked_until = now + backoff;

            error!("🚨 RATE LIMIT VIOLATION: IP {} exceeded {} attempts/{}s, blocked for {}s (violation #{})",
                   ip, self.config.max_attempts_per_ip, self.config.window_secs,
                   backoff, entry.violation_count);
            RATE_LIMIT_VIOLATIONS.fetch_add(1, Ordering::Relaxed);

            return Err(Duration::from_secs(backoff));
        }

        Ok(())
    }

    /// Check if a connection attempt from a DID is allowed
    /// Returns Ok(()) if allowed, Err(block_duration) if blocked
    pub async fn check_did(&self, did: &str) -> Result<(), Duration> {
        let mut limits = self.did_limits.write().await;
        let now = current_timestamp();

        let entry = limits.entry(did.to_string()).or_insert_with(RateLimitEntry::new);

        // Check if blocked
        if entry.is_blocked() {
            let remaining = entry.block_remaining_secs();
            warn!("🚫 RATE LIMIT: DID {} blocked for {} more seconds (violations: {})",
                  did, remaining, entry.violation_count);
            RATE_LIMIT_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            return Err(Duration::from_secs(remaining));
        }

        // Reset window if expired
        if now - entry.window_start >= self.config.window_secs {
            entry.attempt_count = 0;
            entry.window_start = now;
        }

        // Increment attempt count
        entry.attempt_count += 1;
        entry.last_attempt = now;

        // Check if over limit
        if entry.attempt_count > self.config.max_attempts_per_did {
            entry.violation_count += 1;

            // Calculate exponential backoff
            let backoff = std::cmp::min(
                self.config.base_block_secs * (1 << (entry.violation_count.saturating_sub(1))),
                self.config.max_block_secs
            );
            entry.blocked_until = now + backoff;

            error!("🚨 RATE LIMIT VIOLATION: DID {} exceeded {} attempts/{}s, blocked for {}s (violation #{})",
                   did, self.config.max_attempts_per_did, self.config.window_secs,
                   backoff, entry.violation_count);
            RATE_LIMIT_VIOLATIONS.fetch_add(1, Ordering::Relaxed);

            return Err(Duration::from_secs(backoff));
        }

        Ok(())
    }

    /// Combined check for both IP and DID
    /// Fails if either is rate limited
    pub async fn check_connection(&self, ip: IpAddr, did: Option<&str>) -> Result<(), Duration> {
        // Check IP first
        self.check_ip(ip).await?;

        // Check DID if provided
        if let Some(did) = did {
            self.check_did(did).await?;
        }

        Ok(())
    }

    /// Record a successful connection (reduces violation count over time)
    pub async fn record_success(&self, ip: IpAddr, did: Option<&str>) {
        // Reduce IP violation count on success
        {
            let mut limits = self.ip_limits.write().await;
            if let Some(entry) = limits.get_mut(&ip) {
                if entry.violation_count > 0 {
                    entry.violation_count = entry.violation_count.saturating_sub(1);
                    info!("✅ Rate limit: IP {} violation count reduced to {}", ip, entry.violation_count);
                }
            }
        }

        // Reduce DID violation count on success
        if let Some(did) = did {
            let mut limits = self.did_limits.write().await;
            if let Some(entry) = limits.get_mut(did) {
                if entry.violation_count > 0 {
                    entry.violation_count = entry.violation_count.saturating_sub(1);
                    info!("✅ Rate limit: DID {} violation count reduced to {}", did, entry.violation_count);
                }
            }
        }
    }

    /// Cleanup expired entries
    pub async fn cleanup(&self) {
        let now = current_timestamp();
        let expiry_threshold = now - (self.config.window_secs * 10); // Keep entries for 10 windows

        // Cleanup IP entries
        {
            let mut limits = self.ip_limits.write().await;
            let before = limits.len();
            limits.retain(|_, entry| {
                // Keep if: recently active OR still blocked
                entry.last_attempt > expiry_threshold || entry.is_blocked()
            });
            let removed = before - limits.len();
            if removed > 0 {
                info!("🧹 Rate limiter cleanup: removed {} expired IP entries", removed);
            }
        }

        // Cleanup DID entries
        {
            let mut limits = self.did_limits.write().await;
            let before = limits.len();
            limits.retain(|_, entry| {
                entry.last_attempt > expiry_threshold || entry.is_blocked()
            });
            let removed = before - limits.len();
            if removed > 0 {
                info!("🧹 Rate limiter cleanup: removed {} expired DID entries", removed);
            }
        }
    }

    /// Get statistics for monitoring
    pub async fn get_stats(&self) -> RateLimiterStats {
        let ip_limits = self.ip_limits.read().await;
        let did_limits = self.did_limits.read().await;

        let ip_blocked = ip_limits.values().filter(|e| e.is_blocked()).count();
        let did_blocked = did_limits.values().filter(|e| e.is_blocked()).count();

        RateLimiterStats {
            tracked_ips: ip_limits.len(),
            tracked_dids: did_limits.len(),
            blocked_ips: ip_blocked,
            blocked_dids: did_blocked,
            total_violations: get_rate_limit_violation_count(),
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: std::sync::Arc<Self>) {
        let interval = Duration::from_secs(self.config.cleanup_interval_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                self.cleanup().await;
            }
        });
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub tracked_ips: usize,
    pub tracked_dids: usize,
    pub blocked_ips: usize,
    pub blocked_dids: usize,
    pub total_violations: u64,
}

/// Helper function to get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ip_rate_limiting() {
        let config = RateLimiterConfig {
            max_attempts_per_ip: 3,
            max_attempts_per_did: 2,
            window_secs: 60,
            base_block_secs: 10,
            max_block_secs: 100,
            cleanup_interval_secs: 300,
        };

        let limiter = ConnectionRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 attempts should succeed
        assert!(limiter.check_ip(ip).await.is_ok());
        assert!(limiter.check_ip(ip).await.is_ok());
        assert!(limiter.check_ip(ip).await.is_ok());

        // 4th attempt should fail
        let result = limiter.check_ip(ip).await;
        assert!(result.is_err());

        // Should return block duration
        if let Err(duration) = result {
            assert!(duration.as_secs() >= 10);
        }
    }

    #[tokio::test]
    async fn test_did_rate_limiting() {
        let config = RateLimiterConfig {
            max_attempts_per_ip: 10,
            max_attempts_per_did: 2,
            window_secs: 60,
            base_block_secs: 10,
            max_block_secs: 100,
            cleanup_interval_secs: 300,
        };

        let limiter = ConnectionRateLimiter::with_config(config);
        let did = "did:zhtp:test123";

        // First 2 attempts should succeed
        assert!(limiter.check_did(did).await.is_ok());
        assert!(limiter.check_did(did).await.is_ok());

        // 3rd attempt should fail
        assert!(limiter.check_did(did).await.is_err());
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        let config = RateLimiterConfig {
            max_attempts_per_ip: 1, // Very restrictive for test
            max_attempts_per_did: 1,
            window_secs: 60,
            base_block_secs: 10,
            max_block_secs: 1000,
            cleanup_interval_secs: 300,
        };

        let limiter = ConnectionRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // First attempt succeeds
        assert!(limiter.check_ip(ip).await.is_ok());

        // Second attempt triggers first violation (10s block)
        let result1 = limiter.check_ip(ip).await;
        assert!(result1.is_err());

        // Manually reset for next test
        {
            let mut limits = limiter.ip_limits.write().await;
            if let Some(entry) = limits.get_mut(&ip) {
                entry.blocked_until = 0; // Unblock
                entry.window_start = current_timestamp(); // Reset window
                entry.attempt_count = 0;
            }
        }

        // Next attempt succeeds after reset
        assert!(limiter.check_ip(ip).await.is_ok());

        // Next violation should have exponential backoff (20s = 10 * 2^1)
        let result2 = limiter.check_ip(ip).await;
        if let Err(duration) = result2 {
            // Should be 20 seconds (10 * 2^1) for second violation
            assert!(duration.as_secs() >= 20);
        }
    }

    #[tokio::test]
    async fn test_combined_check() {
        let limiter = ConnectionRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let did = "did:zhtp:combined_test";

        // Should pass when both are under limit
        assert!(limiter.check_connection(ip, Some(did)).await.is_ok());
    }

    #[tokio::test]
    async fn test_success_reduces_violations() {
        let config = RateLimiterConfig {
            max_attempts_per_ip: 1,
            max_attempts_per_did: 1,
            window_secs: 60,
            base_block_secs: 10,
            max_block_secs: 100,
            cleanup_interval_secs: 300,
        };

        let limiter = ConnectionRateLimiter::with_config(config);
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

        // Trigger violation
        assert!(limiter.check_ip(ip).await.is_ok());
        assert!(limiter.check_ip(ip).await.is_err());

        // Check violation count
        {
            let limits = limiter.ip_limits.read().await;
            let entry = limits.get(&ip).unwrap();
            assert!(entry.violation_count >= 1);
        }

        // Record success
        limiter.record_success(ip, None).await;

        // Violation count should be reduced
        {
            let limits = limiter.ip_limits.read().await;
            let entry = limits.get(&ip).unwrap();
            assert_eq!(entry.violation_count, 0);
        }
    }
}
