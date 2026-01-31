//! Rate Limiting for PoUW Endpoints
//!
//! Implements per-IP and per-client-DID rate limiting to prevent DoS attacks.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{warn, debug};

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per IP per window
    pub max_requests_per_ip: u32,
    /// Maximum requests per client DID per window
    pub max_requests_per_did: u32,
    /// Time window for rate limiting
    pub window_duration: Duration,
    /// Maximum batch size for receipt submissions
    pub max_batch_size: usize,
    /// Request timeout
    pub request_timeout: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests_per_ip: 100,
            max_requests_per_did: 50,
            window_duration: Duration::from_secs(60),
            max_batch_size: 100,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Entry tracking request counts within a time window
#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            count: 1,
            window_start: Instant::now(),
        }
    }

    fn increment(&mut self, window_duration: Duration) -> u32 {
        let now = Instant::now();
        if now.duration_since(self.window_start) > window_duration {
            // Window expired, reset
            self.count = 1;
            self.window_start = now;
        } else {
            self.count += 1;
        }
        self.count
    }
}

/// Rate limiter for PoUW endpoints
pub struct PouwRateLimiter {
    config: RateLimitConfig,
    ip_limits: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
    did_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
}

impl PouwRateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_limits: Arc::new(RwLock::new(HashMap::new())),
            did_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a rate limiter with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a request from the given IP is allowed
    pub async fn check_ip(&self, ip: IpAddr) -> RateLimitResult {
        let mut limits = self.ip_limits.write().await;
        
        let count = if let Some(entry) = limits.get_mut(&ip) {
            entry.increment(self.config.window_duration)
        } else {
            limits.insert(ip, RateLimitEntry::new());
            1
        };

        if count > self.config.max_requests_per_ip {
            warn!(ip = %ip, count = count, limit = self.config.max_requests_per_ip, "IP rate limit exceeded");
            RateLimitResult::Denied {
                reason: RateLimitReason::IpLimitExceeded,
                retry_after: self.config.window_duration,
            }
        } else {
            debug!(ip = %ip, count = count, limit = self.config.max_requests_per_ip, "IP rate check passed");
            RateLimitResult::Allowed { remaining: self.config.max_requests_per_ip - count }
        }
    }

    /// Check if a request from the given client DID is allowed
    pub async fn check_did(&self, did: &str) -> RateLimitResult {
        let mut limits = self.did_limits.write().await;
        
        let count = if let Some(entry) = limits.get_mut(did) {
            entry.increment(self.config.window_duration)
        } else {
            limits.insert(did.to_string(), RateLimitEntry::new());
            1
        };

        if count > self.config.max_requests_per_did {
            warn!(did = %did, count = count, limit = self.config.max_requests_per_did, "DID rate limit exceeded");
            RateLimitResult::Denied {
                reason: RateLimitReason::DidLimitExceeded,
                retry_after: self.config.window_duration,
            }
        } else {
            debug!(did = %did, count = count, limit = self.config.max_requests_per_did, "DID rate check passed");
            RateLimitResult::Allowed { remaining: self.config.max_requests_per_did - count }
        }
    }

    /// Check both IP and DID limits
    pub async fn check_request(&self, ip: IpAddr, did: &str) -> RateLimitResult {
        // Check IP first
        let ip_result = self.check_ip(ip).await;
        if let RateLimitResult::Denied { .. } = ip_result {
            return ip_result;
        }

        // Then check DID
        self.check_did(did).await
    }

    /// Validate batch size
    pub fn check_batch_size(&self, size: usize) -> RateLimitResult {
        if size > self.config.max_batch_size {
            warn!(size = size, limit = self.config.max_batch_size, "Batch size limit exceeded");
            RateLimitResult::Denied {
                reason: RateLimitReason::BatchSizeExceeded,
                retry_after: Duration::ZERO,
            }
        } else {
            RateLimitResult::Allowed { remaining: (self.config.max_batch_size - size) as u32 }
        }
    }

    /// Get request timeout configuration
    pub fn request_timeout(&self) -> Duration {
        self.config.request_timeout
    }

    /// Clean up expired entries (call periodically)
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        
        {
            let mut ip_limits = self.ip_limits.write().await;
            ip_limits.retain(|_, entry| {
                now.duration_since(entry.window_start) <= self.config.window_duration * 2
            });
        }
        
        {
            let mut did_limits = self.did_limits.write().await;
            did_limits.retain(|_, entry| {
                now.duration_since(entry.window_start) <= self.config.window_duration * 2
            });
        }
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed { remaining: u32 },
    /// Request is denied
    Denied {
        reason: RateLimitReason,
        retry_after: Duration,
    },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }
}

/// Reason for rate limit denial
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReason {
    /// IP address exceeded request limit
    IpLimitExceeded,
    /// Client DID exceeded request limit
    DidLimitExceeded,
    /// Batch size exceeded limit
    BatchSizeExceeded,
}

impl std::fmt::Display for RateLimitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpLimitExceeded => write!(f, "IP rate limit exceeded"),
            Self::DidLimitExceeded => write!(f, "Client DID rate limit exceeded"),
            Self::BatchSizeExceeded => write!(f, "Batch size limit exceeded"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_rate_limiting() {
        let config = RateLimitConfig {
            max_requests_per_ip: 3,
            window_duration: Duration::from_secs(60),
            ..Default::default()
        };
        let limiter = PouwRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First 3 requests should be allowed
        assert!(limiter.check_ip(ip).await.is_allowed());
        assert!(limiter.check_ip(ip).await.is_allowed());
        assert!(limiter.check_ip(ip).await.is_allowed());

        // 4th request should be denied
        assert!(!limiter.check_ip(ip).await.is_allowed());
    }

    #[tokio::test]
    async fn test_did_rate_limiting() {
        let config = RateLimitConfig {
            max_requests_per_did: 2,
            window_duration: Duration::from_secs(60),
            ..Default::default()
        };
        let limiter = PouwRateLimiter::new(config);
        let did = "did:sov:abc123";

        // First 2 requests should be allowed
        assert!(limiter.check_did(did).await.is_allowed());
        assert!(limiter.check_did(did).await.is_allowed());

        // 3rd request should be denied
        assert!(!limiter.check_did(did).await.is_allowed());
    }

    #[tokio::test]
    async fn test_batch_size_limiting() {
        let config = RateLimitConfig {
            max_batch_size: 100,
            ..Default::default()
        };
        let limiter = PouwRateLimiter::new(config);

        assert!(limiter.check_batch_size(50).is_allowed());
        assert!(limiter.check_batch_size(100).is_allowed());
        assert!(!limiter.check_batch_size(101).is_allowed());
    }

    #[tokio::test]
    async fn test_combined_rate_check() {
        let config = RateLimitConfig {
            max_requests_per_ip: 5,
            max_requests_per_did: 3,
            window_duration: Duration::from_secs(60),
            ..Default::default()
        };
        let limiter = PouwRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let did = "did:sov:test";

        // First 3 requests should be allowed (DID limit)
        assert!(limiter.check_request(ip, did).await.is_allowed());
        assert!(limiter.check_request(ip, did).await.is_allowed());
        assert!(limiter.check_request(ip, did).await.is_allowed());

        // 4th request should be denied (DID limit reached)
        assert!(!limiter.check_request(ip, did).await.is_allowed());

        // Different DID should still be allowed for same IP
        assert!(limiter.check_request(ip, "did:sov:other").await.is_allowed());
    }
}
