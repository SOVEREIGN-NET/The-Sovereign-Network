//! Nonce cache for replay attack prevention
//!
//! Tracks used nonces to prevent replay attacks. Nonces expire after
//! a configurable TTL and are automatically cleaned up.
//!
//! **Security Fixes:**
//! - VULN-002: Bounded cache size with LRU eviction (prevents memory exhaustion)
//! - VULN-005: Atomic check-and-insert using entry API (prevents race conditions)

use anyhow::{Result, anyhow};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};
use std::time::{Instant, Duration};

/// Nonce cache entry with timestamp
#[derive(Debug, Clone)]
struct NonceEntry {
    timestamp: Instant,
    message_timestamp: u64,
}

/// Thread-safe nonce cache for replay attack prevention with bounded size
///
/// **Security Features:**
/// - LRU eviction prevents unbounded memory growth
/// - Atomic operations prevent race conditions
/// - TTL-based expiration for additional cleanup
#[derive(Debug, Clone)]
pub struct NonceCache {
    /// LRU cache of nonce → entry (bounded size)
    cache: Arc<RwLock<LruCache<[u8; 32], NonceEntry>>>,
    /// Maximum number of entries (prevents DoS via memory exhaustion)
    max_size: usize,
    /// Time-to-live for nonces
    ttl: Duration,
}

impl NonceCache {
    /// Default maximum cache size: 1 million entries (~64 MB memory)
    pub const DEFAULT_MAX_SIZE: usize = 1_000_000;

    /// Create new nonce cache with TTL and max size
    ///
    /// # Arguments
    /// * `ttl_secs` - Time-to-live for nonces in seconds (default: 300 = 5 minutes)
    /// * `max_size` - Maximum number of nonces to store (default: 1 million)
    ///
    /// # Example
    /// ```
    /// use lib_network::handshake::NonceCache;
    /// let cache = NonceCache::new(300, 1_000_000);
    /// ```
    pub fn new(ttl_secs: u64, max_size: usize) -> Self {
        let capacity = NonZeroUsize::new(max_size).expect("max_size must be > 0");
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(capacity))),
            max_size,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Create new nonce cache with default max size (1 million entries)
    pub fn with_default_size(ttl_secs: u64) -> Self {
        Self::new(ttl_secs, Self::DEFAULT_MAX_SIZE)
    }

    /// Check if nonce was already used, and store it if not (atomic operation)
    ///
    /// **Security:** This method is atomic - no race condition window between
    /// check and insert. Uses LRU eviction when cache is full.
    ///
    /// # Returns
    /// - `Ok(())` if nonce is new and was stored
    /// - `Err(...)` if nonce was already used (replay attack detected)
    ///
    /// # Example
    /// ```no_run
    /// # use lib_network::handshake::NonceCache;
    /// # fn example() -> anyhow::Result<()> {
    /// let cache = NonceCache::with_default_size(300);
    /// let nonce = [0u8; 32];
    /// cache.check_and_store(&nonce, 1234567890)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn check_and_store(&self, nonce: &[u8; 32], message_timestamp: u64) -> Result<()> {
        let mut cache = self.cache.write()
            .map_err(|e| anyhow!("Nonce cache lock poisoned: {}", e))?;

        // Atomic check-and-insert: no race condition window
        if cache.contains(nonce) {
            // Nonce already exists - replay attack detected!
            return Err(anyhow!("Replay detected: nonce already used"));
        }

        // Insert nonce (LRU automatically evicts oldest if at max_size)
        cache.put(*nonce, NonceEntry {
            timestamp: Instant::now(),
            message_timestamp,
        });

        Ok(())
    }

    /// Remove expired nonces (cleanup)
    ///
    /// This provides additional cleanup beyond LRU eviction. Removes nonces
    /// that have exceeded their TTL even if cache isn't full.
    pub fn cleanup_expired(&self) {
        let mut cache = match self.cache.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("Nonce cache lock poisoned during cleanup: {}", e);
                return;
            }
        };
        let now = Instant::now();

        // Collect expired nonces
        let expired_nonces: Vec<[u8; 32]> = cache
            .iter()
            .filter_map(|(nonce, entry)| {
                if now.duration_since(entry.timestamp) >= self.ttl {
                    Some(*nonce)
                } else {
                    None
                }
            })
            .collect();

        // Remove expired nonces
        for nonce in expired_nonces {
            cache.pop(&nonce);
        }
    }

    /// Get cache size (for monitoring)
    pub fn size(&self) -> usize {
        self.cache.read()
            .map(|cache| cache.len())
            .unwrap_or(0)
    }

    /// Get maximum cache size
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Get cache utilization percentage (0.0 to 1.0)
    pub fn utilization(&self) -> f64 {
        let current = self.size() as f64;
        let max = self.max_size as f64;
        current / max
    }

    /// Clear all nonces (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

/// Background task to periodically cleanup expired nonces
///
/// Should be spawned as a background task when the system starts.
///
/// # Example
/// ```no_run
/// # use lib_network::handshake::{NonceCache, start_nonce_cleanup_task};
/// # async fn example() {
/// let cache = NonceCache::with_default_size(300);
/// tokio::spawn(start_nonce_cleanup_task(cache.clone(), 60));
/// # }
/// ```
pub async fn start_nonce_cleanup_task(cache: NonceCache, interval_secs: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        cache.cleanup_expired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_stored_and_detected() {
        let cache = NonceCache::new(60, 1000);
        let nonce = [1u8; 32];

        // First use - should succeed
        assert!(cache.check_and_store(&nonce, 1234567890).is_ok());

        // Second use - should fail (replay)
        let result = cache.check_and_store(&nonce, 1234567890);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Replay detected"));
    }

    #[test]
    fn test_different_nonces_allowed() {
        let cache = NonceCache::new(60, 1000);
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];

        // Both should succeed (different nonces)
        assert!(cache.check_and_store(&nonce1, 1234567890).is_ok());
        assert!(cache.check_and_store(&nonce2, 1234567890).is_ok());
    }

    #[test]
    fn test_nonce_expiration() {
        let cache = NonceCache::new(1, 1000); // 1 second TTL
        let nonce = [1u8; 32];

        // Store nonce
        cache.check_and_store(&nonce, 1234567890).unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_secs(2));

        // Cleanup
        cache.cleanup_expired();

        // Should be able to use again (expired and cleaned)
        assert!(cache.check_and_store(&nonce, 1234567890).is_ok());
    }

    #[test]
    fn test_cache_size() {
        let cache = NonceCache::new(60, 1000);

        assert_eq!(cache.size(), 0);

        cache.check_and_store(&[1u8; 32], 1234567890).unwrap();
        assert_eq!(cache.size(), 1);

        cache.check_and_store(&[2u8; 32], 1234567890).unwrap();
        assert_eq!(cache.size(), 2);
    }

    #[test]
    fn test_bounded_cache_lru_eviction() {
        // VULN-002 FIX: Test that cache doesn't grow unbounded
        let cache = NonceCache::new(60, 100); // Small cache for testing

        // Fill cache to capacity
        for i in 0..100 {
            let mut nonce = [0u8; 32];
            nonce[0] = i as u8;
            cache.check_and_store(&nonce, 1234567890).unwrap();
        }

        assert_eq!(cache.size(), 100);

        // Add one more - should evict oldest (LRU)
        let nonce = [255u8; 32];
        cache.check_and_store(&nonce, 1234567890).unwrap();

        // Size should still be 100 (oldest evicted)
        assert_eq!(cache.size(), 100);

        // Newest should still be present
        assert!(cache.check_and_store(&nonce, 1234567890).is_err());

        // Oldest should have been evicted - can be re-added
        let oldest = [0u8; 32];
        assert!(cache.check_and_store(&oldest, 1234567890).is_ok());
    }

    #[test]
    fn test_concurrent_nonce_insertion_no_race() {
        // VULN-005 FIX: Test that concurrent insertions don't create race condition
        let cache = NonceCache::new(60, 10000);
        let nonce = [42u8; 32];

        // Try to insert same nonce concurrently 100 times
        let handles: Vec<_> = (0..100)
            .map(|_| {
                let cache = cache.clone();
                std::thread::spawn(move || {
                    cache.check_and_store(&nonce, 1234567890)
                })
            })
            .collect();

        // Wait for all threads
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // Exactly ONE should succeed, rest should fail
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        assert_eq!(successes, 1, "Exactly one insertion should succeed");
        assert_eq!(failures, 99, "99 insertions should fail (replay detected)");

        // Verify nonce is in cache
        assert!(cache.check_and_store(&nonce, 1234567890).is_err());
    }

    #[test]
    fn test_utilization_percentage() {
        let cache = NonceCache::new(60, 100);

        // Empty cache
        assert_eq!(cache.utilization(), 0.0);

        // Half full
        for i in 0..50 {
            let mut nonce = [0u8; 32];
            nonce[0] = i as u8;
            cache.check_and_store(&nonce, 1234567890).unwrap();
        }
        assert_eq!(cache.utilization(), 0.5);

        // Full
        for i in 50..100 {
            let mut nonce = [0u8; 32];
            nonce[0] = i as u8;
            cache.check_and_store(&nonce, 1234567890).unwrap();
        }
        assert_eq!(cache.utilization(), 1.0);
    }

    #[test]
    fn test_max_size_accessor() {
        let cache = NonceCache::new(60, 5000);
        assert_eq!(cache.max_size(), 5000);
    }

    #[test]
    fn test_default_size_constructor() {
        let cache = NonceCache::with_default_size(300);
        assert_eq!(cache.max_size(), NonceCache::DEFAULT_MAX_SIZE);
    }
}
