//! Rate limiting for Unified Handshake Protocol
//!
//! **FINDING 8 FIX:** Implements rate limiting to prevent DoS attacks via
//! handshake flooding. Uses token bucket algorithm with per-IP tracking.
//!
//! This prevents attackers from:
//! - Exhausting server resources via handshake floods
//! - Filling nonce cache with garbage nonces
//! - Performing timing attacks via mass handshake attempts

use anyhow::{Result, anyhow};
use governor::{Quota, RateLimiter as GovernorRateLimiter, DefaultDirectRateLimiter};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max handshake attempts per second per IP
    pub handshakes_per_second: u32,

    /// Burst capacity (allows short bursts above rate)
    pub burst_capacity: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // Conservative defaults: 10 handshakes/sec with burst of 50
            handshakes_per_second: 10,
            burst_capacity: 50,
        }
    }
}

impl RateLimitConfig {
    /// Create permissive config for testing (higher limits)
    pub fn permissive() -> Self {
        Self {
            handshakes_per_second: 1000,
            burst_capacity: 5000,
        }
    }

    /// Create strict config for production (lower limits)
    pub fn strict() -> Self {
        Self {
            handshakes_per_second: 5,
            burst_capacity: 20,
        }
    }
}

/// Rate limiter for handshake operations
///
/// Uses token bucket algorithm with per-IP tracking to prevent
/// DoS attacks while allowing legitimate traffic.
pub struct RateLimiter {
    /// Per-IP rate limiters
    limiters: Arc<RwLock<HashMap<IpAddr, DefaultDirectRateLimiter>>>,

    /// Configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter with given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a handshake from this IP is allowed
    ///
    /// # Returns
    /// - `Ok(())` if handshake is allowed (within rate limit)
    /// - `Err(...)` if rate limit exceeded
    ///
    /// # Example
    /// ```no_run
    /// # use lib_network::handshake::RateLimiter;
    /// # use std::net::IpAddr;
    /// let limiter = RateLimiter::default();
    /// let ip: IpAddr = "192.168.1.1".parse().unwrap();
    ///
    /// match limiter.check_handshake(ip) {
    ///     Ok(()) => println!("Handshake allowed"),
    ///     Err(e) => println!("Rate limit exceeded: {}", e),
    /// }
    /// ```
    pub fn check_handshake(&self, ip: IpAddr) -> Result<()> {
        let mut limiters = self.limiters.write()
            .map_err(|e| anyhow!("Rate limiter lock poisoned: {}", e))?;

        // Get or create limiter for this IP
        let limiter = limiters.entry(ip).or_insert_with(|| {
            // Create quota: X per second with burst capacity Y
            let quota = Quota::per_second(
                NonZeroU32::new(self.config.handshakes_per_second)
                    .expect("handshakes_per_second must be > 0")
            ).allow_burst(
                NonZeroU32::new(self.config.burst_capacity)
                    .expect("burst_capacity must be > 0")
            );

            GovernorRateLimiter::direct(quota)
        });

        // Check if request is allowed
        match limiter.check() {
            Ok(_) => Ok(()),
            Err(_) => Err(anyhow!(
                "Rate limit exceeded for IP {}: {} handshakes/sec (burst: {})",
                ip,
                self.config.handshakes_per_second,
                self.config.burst_capacity
            )),
        }
    }

    /// Get number of IPs being tracked
    pub fn tracked_ips(&self) -> usize {
        self.limiters.read()
            .map(|l| l.len())
            .unwrap_or(0)
    }

    /// Clear all rate limiters (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut limiters) = self.limiters.write() {
            limiters.clear();
        }
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            limiters: Arc::clone(&self.limiters),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, IpAddr};

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            handshakes_per_second: 10,
            burst_capacity: 50,
        });

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 50 should succeed (burst capacity)
        for _ in 0..50 {
            assert!(limiter.check_handshake(ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            handshakes_per_second: 10,
            burst_capacity: 50,
        });

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Exhaust burst capacity
        for _ in 0..50 {
            limiter.check_handshake(ip).unwrap();
        }

        // 51st should fail
        assert!(limiter.check_handshake(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_per_ip_tracking() {
        let limiter = RateLimiter::new(RateLimitConfig {
            handshakes_per_second: 10,
            burst_capacity: 50,
        });

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust IP1's burst
        for _ in 0..50 {
            limiter.check_handshake(ip1).unwrap();
        }

        // IP1 should be blocked
        assert!(limiter.check_handshake(ip1).is_err());

        // IP2 should still be allowed (separate limit)
        assert!(limiter.check_handshake(ip2).is_ok());
    }

    #[test]
    fn test_tracked_ips() {
        let limiter = RateLimiter::default();

        assert_eq!(limiter.tracked_ips(), 0);

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        limiter.check_handshake(ip1).unwrap();
        assert_eq!(limiter.tracked_ips(), 1);

        limiter.check_handshake(ip2).unwrap();
        assert_eq!(limiter.tracked_ips(), 2);
    }

    #[test]
    fn test_permissive_config() {
        let config = RateLimitConfig::permissive();
        assert!(config.handshakes_per_second >= 1000);
        assert!(config.burst_capacity >= 5000);
    }

    #[test]
    fn test_strict_config() {
        let config = RateLimitConfig::strict();
        assert!(config.handshakes_per_second <= 5);
        assert!(config.burst_capacity <= 20);
    }
}
